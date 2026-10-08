<script setup lang="ts">
/**
 * 網路拓樸圖 — Cytoscape.js + cose-bilkent layout。
 *
 * Phase 3 MVP：
 *  - 節點 = device，依 type 顏色編碼
 *  - 邊 = cable / wireless / vpn，三種樣式可區分
 *  - 點節點顯示資訊
 *  - 切換 wireless / vpn 顯示
 */
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { NAlert,
  NCard,
  NSpace,
  NCheckbox,
  NSpin,
  NButton,
  NButtonGroup,
  NDropdown,
  NSelect,
  useMessage,
  NTooltip,
} from "naive-ui";
import { NIcon } from "naive-ui";
import { TopologyIcon, RefreshIcon, FitIcon, ExportIcon } from "@/icons";
import { useRouter } from "vue-router";
import cytoscape from "cytoscape";
import coseBilkent from "cytoscape-cose-bilkent";
import { getTopology, type TopologyData } from "@/api/topology";
import { listSubnets } from "@/api/subnets";
import { usePinnedSubnets } from "@/composables/usePinnedSubnets";

cytoscape.use(coseBilkent as any);

const { t } = useI18n();
const msg = useMessage();
const containerRef = ref<HTMLDivElement | null>(null);
const includeWireless = ref(true);
const includeVpn = ref(true);
const includeL3 = ref(true);
// 預設不開：FDB 會把所有端點拉進來，圖一下子變密。要看存取層的人自己勾，
// 或直接選「只看存取層」視圖。
const includeFdb = ref(false);
// 虛擬機同樣預設不開：實機一次會多出上百顆節點。
const includeVms = ref(false);
// 只留「有人登記過」的線。圖上同時有登記的與推導的，把兩者畫成一樣等於宣稱我們對
// 它們有一樣的把握 —— 這個開關讓人一鍵看出「拿掉所有推測之後還剩什麼」。
const assertedOnly = ref(false);

/**
 * 視圖模式 —— 同一批資料有兩種完全不同的看法，硬要合成一張圖只會兩邊都難看：
 *   l3     子網路視角：誰在哪個網段（沒有 FDB 時唯一畫得出來的東西）
 *   l2     實體／存取層視角：誰插在哪台交換器的哪個埠、交換器之間怎麼接
 *   switch 混合，但版面以交換器為中心，子網路掛在它下面
 *   auto   混合，有存取層資料就用交換器為中心，沒有就退回子網路為中心
 */
type ViewMode = "auto" | "switch" | "l2" | "l3";
// 預設「只看子網路」：那是進來就看得懂的一張圖；要看實體位置再自己切。
const viewMode = ref<ViewMode>("l3");
const viewModeOptions = computed(() => [
  { label: t("topology.view_auto"), value: "auto" },
  { label: t("topology.view_switch"), value: "switch" },
  { label: t("topology.view_l2"), value: "l2" },
  { label: t("topology.view_l3"), value: "l3" },
]);
// 「只看…」的模式自己決定要抓什麼，勾選框在那兩種模式下沒有意義（會互相矛盾）
const modeDrivesSources = computed(() => viewMode.value === "l2" || viewMode.value === "l3");
const onlineOnly = ref(false);   // 預設：不管上線與否都畫
const loading = ref(false);
// 超大規模：裝置太多時後端不建圖，只回裝置數與上限
const tooLarge = ref<{ devices: number; limit: number } | null>(null);
const selected = ref<Record<string, any> | null>(null);
// 連線(edge)兩端資訊：name=裝置/子網路、ip、port=連接埠、endpoint=VPN 端點
type EdgeEnd = { name: string | null; ip: string | null; port: string | null; endpoint: string | null };
const edgeEnds = ref<{ a: EdgeEnd; b: EdgeEnd } | null>(null);

// 友善欄位名稱（中文），對應 cytoscape node/edge data 的 key
const FIELD_LABELS = computed<Record<string, string>>(() => ({
  label: t("cols.name"),
  type: t("topology.field_type"),
  vendor: t("topology.field_vendor"),
  model: t("topology.field_model"),
  kind: t("topology.field_kind"),
  b_endpoint: t("topology.field_b_endpoint"),
  ip: "IP",
  mac: "MAC",
  serial: t("topology.field_serial"),
  rack: t("topology.field_rack"),
  location: t("topology.field_location"),
  os: t("topology.field_os"),
  hardware: t("topology.field_hardware"),
  sw_version: t("topology.field_sw_version"),
  sysname: t("topology.field_sysname"),
  status: t("topology.field_status"),
  description: t("topology.field_description"),
  via: t("topology.field_via"),
  evidence: t("topology.field_evidence"),
  port: t("topology.port"),
  peer_port: t("topology.field_peer_port"),
  vlan: "VLAN",
  direct: t("topology.field_direct"),
  port_mac_count: t("topology.field_port_mac_count"),
  host: t("topology.field_host"),
  cluster: t("topology.field_cluster"),
  vcpus: "vCPU",
  memory_mb: t("topology.field_memory"),
}));
const EVIDENCE_LABELS = computed<Record<string, string>>(() => ({
  asserted: t("topology.ev_asserted"),
  monitored: t("topology.ev_monitored"),
  learned: t("topology.ev_learned"),
  inferred: t("topology.ev_inferred"),
}));
const VIA_LABELS = computed<Record<string, string>>(() => ({
  ip: t("topology.via_ip"),
  name: t("topology.via_name"),
  arp: t("topology.via_arp"),
  librenms: t("topology.via_librenms"),
  fdb: t("topology.via_fdb"),
  virtualization: t("topology.via_virtualization"),
  neighbor: t("topology.via_neighbor"),
}));
const TYPE_LABELS = computed<Record<string, string>>(() => ({
  router: t("topology.type_router"),
  switch: t("topology.type_switch"),
  firewall: t("topology.type_firewall"),
  ap: t("topology.type_ap"),
  server: t("topology.type_server"),
  storage: t("topology.type_storage"),
  workstation: t("topology.type_workstation"),
  ipmi: "IPMI",
  other: t("topology.type_other"),
  subnet: t("topology.type_subnet"),
  vpn_site: t("topology.type_vpn_site"),
}));
const KIND_LABELS = computed<Record<string, string>>(() => ({
  cable: t("topology.kind_cable"),
  wireless: t("topology.kind_wireless"),
  vpn: t("topology.kind_vpn"),
  l3: t("topology.kind_l3"),
  l2: t("topology.kind_l2"),
  l2_uplink: t("topology.kind_l2_uplink"),
  vm_host: t("topology.kind_vm_host"),
}));
// 內部欄位不顯示給使用者看
const HIDDEN_FIELDS = new Set([
  "id", "source", "target", "a_device_id", "b_device_id",
  "rack_id", "location_id", "subnet_uuid", "label",
  // 連線兩端資訊改用專屬區塊呈現，這裡不重複列出
  "source_port", "target_port", "a_endpoint", "b_endpoint", "ip",
]);

function displayValue(key: string, val: any): string {
  if (key === "type") return TYPE_LABELS.value[val] ?? String(val);
  if (key === "kind") return KIND_LABELS.value[val] ?? String(val);
  if (key === "via") {
    return String(val).split(",").map((v) => VIA_LABELS.value[v] ?? v).join("、");
  }
  // 直連與否是這條線最重要的一件事，不能只印 true/false
  if (key === "direct") return val ? t("topology.direct_yes") : t("topology.direct_no");
  if (key === "evidence") return EVIDENCE_LABELS.value[String(val)] ?? String(val);
  if (key === "status") {
    if (val === "up") return t("topology.status_up");
    if (val === "down") return t("topology.status_down");
  }
  return String(val);
}

const selectedRows = computed(() => {
  const d = selected.value;
  if (!d) return [];
  return Object.keys(d)
    .filter((k) => !HIDDEN_FIELDS.has(k) && d[k] != null && d[k] !== "")
    .map((k) => ({ key: k, label: FIELD_LABELS.value[k] ?? k, value: displayValue(k, d[k]) }));
});
const selectedTitle = computed(() =>
  selected.value ? (selected.value.label ?? selected.value.id ?? t("topology.element")) : "",
);
const router = useRouter();
// 是 device 節點（非 subnet:/vpnsite: 合成節點）→ 可連到裝置頁
const selectedDeviceId = computed<string | null>(() => {
  const d = selected.value;
  if (!d || typeof d.id !== "string") return null;
  if (d.id.includes(":")) return null;            // subnet:/vpnsite:
  if (d.type === "subnet" || d.type === "vpn_site") return null;
  return d.id;
});
const selectedSubnetId = computed<string | null>(() => {
  const d = selected.value;
  return d && d.type === "subnet" && d.subnet_uuid ? String(d.subnet_uuid) : null;
});
function goDevice() {
  if (selectedDeviceId.value) router.push({ name: "device-detail", params: { id: selectedDeviceId.value } });
}
function goSubnet() {
  if (selectedSubnetId.value) router.push({ name: "subnet-detail", params: { id: selectedSubnetId.value } });
}
const subnetIds = ref<string[]>([]);
const subnetOptions = ref<{ label: string; value: string }[]>([]);

async function loadSubnetOptions() {
  try {
    const r = await listSubnets({ page: 1, pageSize: 500 });
    subnetOptions.value = r.items.map((s) => ({
      label: s.description ? `${s.cidr} — ${s.description}` : s.cidr,
      value: s.id,
    }));
  } catch { /* silent */ }
}

let cy: cytoscape.Core | null = null;

const NODE_COLOURS: Record<string, string> = {
  router: "#6366f1",
  switch: "#22c55e",
  firewall: "#ef4444",
  ap: "#3b82f6",
  server: "#6b7280",
  storage: "#f59e0b",
  workstation: "#0ea5e9",
  ipmi: "#ec4899",
  other: "#9ca3af",
  subnet: "#0ea5e9",  // L3 subnet 節點 — 青藍色，跟 device 區分
  vpn_site: "#9333ea",  // site-to-site VPN 遠端站點 — 紫色（跟 vpn 邊一致）
};

const { pinned, ensureLoaded } = usePinnedSubnets();

// 圖例可點：點暗某類別 → 圖上隱藏該類節點（及其連線）
// 預設先把「伺服器 / 其他」這類點暗——它們數量最多、最會把網路骨幹（防火牆/路由器/
// 交換器/AP/子網路/VPN）洗掉。使用者點圖例即可重新顯示。
// 端點類節點預設不畫：一個實際環境有上百台，全畫進來就沒人看得懂了。
const hiddenTypes = ref<Set<string>>(new Set(["server", "storage", "workstation", "ipmi", "other"]));
// ...但「查得出插在哪台交換器哪個埠」的端點是例外：它在網路裡有明確位置，不是雜訊。
// 這是 FDB 存取層的重點，如果照樣被藏起來，那個功能等於沒有。
// 使用者一旦自己動過「伺服器 / 其他」圖例，就以他的選擇為準，不再自動放行。
const fdbPlaced = ref<Set<string>>(new Set());
const endpointGroupTouched = ref(false);
const LEGEND_GROUPS: Record<string, string[]> = {
  firewall: ["firewall"], router: ["router"], switch: ["switch"], ap: ["ap"],
  server: ["server", "storage", "workstation", "ipmi", "other"], vpn_site: ["vpn_site"], subnet: ["subnet"],
  vm: ["vm"],
};
function isGroupOff(group: string): boolean {
  // 虛擬機比較特別：它不是「畫了再隱藏」，而是**根本沒抓進來**（實機一次會多出上百顆）。
  // 所以圖例上的狀態要看資料有沒有載入，否則使用者按了會覺得沒反應。
  if (group === "vm") return !includeVms.value;
  return (LEGEND_GROUPS[group] || [group]).every((ty) => hiddenTypes.value.has(ty));
}
function toggleGroup(group: string) {
  if (group === "vm") {
    // 切換「要不要載入虛擬機」，watch 會重抓資料並重畫。
    // 先前這裡只把節點藏起來，但虛擬機根本還沒被抓進來 —— 按了什麼都不會發生。
    includeVms.value = !includeVms.value;
    const next = new Set(hiddenTypes.value);
    next.delete("vm");
    hiddenTypes.value = next;
    return;
  }
  if (group === "server") endpointGroupTouched.value = true;
  const types = LEGEND_GROUPS[group] || [group];
  const off = isGroupOff(group);
  const next = new Set(hiddenTypes.value);
  for (const ty of types) { if (off) next.delete(ty); else next.add(ty); }
  hiddenTypes.value = next;
  applyVisibility();
}
function applyVisibility() {
  if (!cy) return;
  cy.batch(() => {
    cy!.nodes().forEach((n) => {
      // 「只看存取層」時，查不出插在哪裡的裝置在這個視角下沒有東西可說 —— 畫成一顆
      // 飄在旁邊的點只是雜訊。實機上這差別很大：105 台裝置裡只有約 10 台有 FDB 資訊，
      // 其餘 95 顆孤點會把整張圖的縮放拉爆、也讓人以為那是「未連線」。
      if (viewMode.value === "l2") {
        const linked = n.connectedEdges('[kind = "l2"], [kind = "l2_uplink"]').length > 0;
        n.style("display", linked ? "element" : "none");
        return;
      }
      const hiddenByType = hiddenTypes.value.has(n.data("type") as string);
      const placed = !endpointGroupTouched.value && fdbPlaced.value.has(n.id());
      n.style("display", hiddenByType && !placed ? "none" : "element");
    });
    cy!.edges().forEach((e) => {
      const endHidden = e.source().style("display") === "none"
        || e.target().style("display") === "none";
      const notAsserted = assertedOnly.value && e.data("evidence") !== "asserted";
      e.style("display", endHidden || notAsserted ? "none" : "element");
    });
  });
}
function zoomBy(f: number) {
  if (!cy) return;
  cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
}
function fitView() { if (cy) cy.fit(undefined, 30); }

// ── 匯出：PNG(cytoscape 內建) / SVG / draw.io(依節點座標重建) ──
const EDGE_STYLE: Record<string, { color: string; width: number; dash: string }> = {
  cable: { color: "#475569", width: 2, dash: "" },
  wireless: { color: "#3b82f6", width: 2, dash: "6,4" },
  vpn: { color: "#9333ea", width: 4, dash: "10,5" },
  l3: { color: "#0ea5e9", width: 1.5, dash: "5,3" },
};
function dlBlob(blob: Blob, name: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
  URL.revokeObjectURL(a.href);
}
function escXml(s: string): string {
  return String(s ?? "").replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c] as string));
}
function visibleEls(): { nodes: any[]; edges: any[] } {
  const nodes = cy!.nodes().filter((n) => n.style("display") !== "none").toArray() as any[];
  const edges = cy!.edges().filter((e) => e.style("display") !== "none").toArray() as any[];
  return { nodes, edges };
}
function exportPng() {
  if (!cy) return;
  const blob = cy.png({ full: true, scale: 2, bg: "#ffffff", output: "blob" }) as Blob;
  dlBlob(blob, "ip-topology.png");
}
function exportSvg() {
  if (!cy) return;
  const { nodes, edges } = visibleEls();
  if (!nodes.length) return;
  const R = 19, pad = 50;
  const pos = nodes.map((n) => n.position());
  const minX = Math.min(...pos.map((p) => p.x)), maxX = Math.max(...pos.map((p) => p.x));
  const minY = Math.min(...pos.map((p) => p.y)), maxY = Math.max(...pos.map((p) => p.y));
  const W = (maxX - minX) + pad * 2, H = (maxY - minY) + pad * 2;
  const X = (x: number) => x - minX + pad, Y = (y: number) => y - minY + pad;
  let s = `<svg xmlns="http://www.w3.org/2000/svg" width="${Math.round(W)}" height="${Math.round(H)}" viewBox="0 0 ${Math.round(W)} ${Math.round(H)}" font-family="sans-serif"><rect width="100%" height="100%" fill="#ffffff"/>`;
  edges.forEach((e) => {
    const sp = e.source().position(), tp = e.target().position();
    const st = EDGE_STYLE[e.data("kind") as string] || { color: "#94a3b8", width: 2, dash: "" };
    s += `<line x1="${X(sp.x)}" y1="${Y(sp.y)}" x2="${X(tp.x)}" y2="${Y(tp.y)}" stroke="${st.color}" stroke-width="${st.width}"${st.dash ? ` stroke-dasharray="${st.dash}"` : ""}/>`;
  });
  nodes.forEach((n) => {
    const p = n.position(); const fill = NODE_COLOURS[n.data("type") as string] || NODE_COLOURS.other;
    s += `<circle cx="${X(p.x)}" cy="${Y(p.y)}" r="${R}" fill="${fill}"/>`;
    s += `<text x="${X(p.x)}" y="${Y(p.y) + 3}" font-size="10" font-weight="600" text-anchor="middle" fill="#fff" paint-order="stroke" stroke="#0f172a" stroke-width="0.6">${escXml(n.data("label"))}</text>`;
  });
  s += `</svg>`;
  dlBlob(new Blob([s], { type: "image/svg+xml" }), "ip-topology.svg");
}
function exportDrawio() {
  if (!cy) return;
  const { nodes, edges } = visibleEls();
  if (!nodes.length) return;
  const pos = nodes.map((n) => n.position());
  const minX = Math.min(...pos.map((p) => p.x)), minY = Math.min(...pos.map((p) => p.y));
  const cells: string[] = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>'];
  const id: Record<string, string> = {};
  nodes.forEach((n, i) => {
    id[n.id()] = `n${i}`; const p = n.position();
    const fill = NODE_COLOURS[n.data("type") as string] || NODE_COLOURS.other;
    cells.push(`<mxCell id="n${i}" value="${escXml(n.data("label"))}" style="ellipse;whiteSpace=wrap;html=1;fillColor=${fill};strokeColor=#0f172a;fontColor=#ffffff;" vertex="1" parent="1"><mxGeometry x="${Math.round(p.x - minX + 40)}" y="${Math.round(p.y - minY + 40)}" width="56" height="56" as="geometry"/></mxCell>`);
  });
  edges.forEach((e, i) => {
    const st = EDGE_STYLE[e.data("kind") as string] || { color: "#94a3b8", width: 2, dash: "" };
    if (!id[e.source().id()] || !id[e.target().id()]) return;
    const style = `endArrow=none;html=1;strokeColor=${st.color};strokeWidth=${st.width};${st.dash ? "dashed=1;" : ""}`;
    cells.push(`<mxCell id="e${i}" style="${style}" edge="1" parent="1" source="${id[e.source().id()]}" target="${id[e.target().id()]}"><mxGeometry relative="1" as="geometry"/></mxCell>`);
  });
  const xml = `<mxfile host="jt-ipam"><diagram name="IP topology"><mxGraphModel dx="800" dy="600" grid="1" gridSize="10" guides="1" connect="1" arrows="1" page="1" pageScale="1"><root>${cells.join("")}</root></mxGraphModel></diagram></mxfile>`;
  dlBlob(new Blob([xml], { type: "application/xml" }), "ip-topology.drawio");
}
const exportOptions = [
  { label: "PNG", key: "png" },
  { label: "SVG", key: "svg" },
  { label: "draw.io", key: "drawio" },
];
function onExport(key: string) {
  if (!cy) { msg.warning(t("errors.network")); return; }
  if (key === "png") exportPng();
  else if (key === "svg") exportSvg();
  else if (key === "drawio") exportDrawio();
}

async function refresh() {
  loading.value = true;
  try {
    const m = viewMode.value;
    const data = await getTopology({
      includeWireless: m === "l3" ? false : includeWireless.value,
      // 「只看子網路」是第三層的圖：站對站 VPN 本來就是第三層的連線，要畫（使用者回報兩台 WireGuard
      // 對接卻沒有線）。只有「只看存取層」不畫
      includeVpn: m === "l2" ? false : m === "l3" ? true : includeVpn.value,
      includeL3: m === "l2" ? false : m === "l3" ? true : includeL3.value,
      // 「以交換器為中心」與「只看存取層」都得有 FDB 才畫得出中心，不看勾選框
      includeFdb: m === "l3" ? false : m === "l2" || m === "switch" ? true : includeFdb.value,
      includeVms: includeVms.value,
      onlineOnly: onlineOnly.value,
      subnetIds: subnetIds.value,
    });
    tooLarge.value = data.too_large ?? null;
    render(data);
  } catch {
    msg.error(t("errors.network"));
  } finally {
    loading.value = false;
  }
}

/**
 * 混合視角的資料轉換：子網路不再是「另一顆節點加一整組線」，而是**一個框**，
 * 它的成員（含交換器）畫在框裡面。
 *
 * 不這樣做的話，每台主機會有兩條線 —— 一條到交換器、一條到網段 —— 同一件事講兩次，
 * 線還互相打結。網段成員本來就是一種「屬於」關係，用包含畫比用連線畫誠實也乾淨。
 *
 * 跨多個網段的裝置（路由器 / 防火牆）**不塞進任何一個框**：塞進去等於宣稱它只屬於
 * 其中一個。它們維持原本的 L3 連線，一眼就看得出來是跨網段的那幾台。
 */
function groupBySubnet(data: TopologyData): TopologyData {
  const subnetIdSet = new Set(
    data.nodes.filter((n) => n.data.type === "subnet").map((n) => n.data.id),
  );
  if (!subnetIdSet.size) return data;

  const subsOfDevice = new Map<string, Set<string>>();
  for (const e of data.edges) {
    if (e.data.kind !== "l3") continue;
    const sub = subnetIdSet.has(e.data.source) ? e.data.source : e.data.target;
    const dev = sub === e.data.source ? e.data.target : e.data.source;
    if (!subnetIdSet.has(sub) || subnetIdSet.has(dev)) continue;
    (subsOfDevice.get(dev) ?? subsOfDevice.set(dev, new Set()).get(dev)!).add(sub);
  }
  const parentOf = new Map<string, string>();
  for (const [dev, subs] of subsOfDevice) {
    if (subs.size === 1) parentOf.set(dev, [...subs][0]);
  }
  if (!parentOf.size) return data;

  // 虛擬機沒有自己的 L3 邊，會落在框外面、線卻連進框裡的主機 —— 跟著主機進同一個框。
  for (const e of data.edges) {
    if (e.data.kind !== "vm_host") continue;
    const box = parentOf.get(e.data.target);
    if (box && !parentOf.has(e.data.source)) parentOf.set(e.data.source, box);
  }

  // 有 FDB、但自己沒有 IP 記錄的交換器（沒有 L3 邊）會落在框外面，它的主機卻在框裡，
  // 於是一堆線穿過框線 —— 看起來像壞掉。若它的主機**全都**屬於同一個框，就把它併進去：
  // 「它服務的機器全在這個廣播域」是真的證據。主機跨多個框時維持在外面 ——
  // 那是真的跨網段交換器，挑一個框就是編造。
  const l2Edges = data.edges.filter((e) => e.data.kind === "l2");
  for (const sw of new Set(l2Edges.map((e) => e.data.target))) {
    if (parentOf.has(sw)) continue;
    const mine = l2Edges.filter((x) => x.data.target === sw);
    const hostBoxes = new Set(
      mine.map((x) => parentOf.get(x.data.source)).filter(Boolean) as string[],
    );
    if (hostBoxes.size === 1 && mine.length > 0) parentOf.set(sw, [...hostBoxes][0]);
  }

  // 有存取層位置的成員（插在某台交換器上、或跑在某台主機上）
  const located = new Set<string>();
  for (const e of data.edges) {
    if (e.data.kind === "l2" || e.data.kind === "l2_uplink" || e.data.kind === "vm_host") {
      located.add(e.data.source);
      located.add(e.data.target);
    }
  }

  // 其餘成員只知道「在這個網段」。單純放進框裡看起來就是一排斷線的裝置 ——
  // 它們不是沒連線，是**我們查不出它接在哪台交換器的哪個埠**。用一個講明白的
  // 次區塊把這件事說出來，比讓人自己猜好。
  // 只有在該框裡確實有「查得出位置」的東西時才分區：整框都查不出來時分區沒有意義。
  const unplacedBox = new Map<string, string>();      // subnet id → 次區塊 id
  const boxHasLocated = new Set<string>();
  for (const [dev, box] of parentOf) if (located.has(dev)) boxHasLocated.add(box);
  const extraNodes: TopologyData["nodes"] = [];
  for (const [dev, box] of [...parentOf]) {
    if (located.has(dev) || !boxHasLocated.has(box)) continue;
    let gid = unplacedBox.get(box);
    if (!gid) {
      gid = `unplaced:${box}`;
      unplacedBox.set(box, gid);
      extraNodes.push({ data: { id: gid, label: t("topology.unplaced_group"),
                                type: "unplaced", isGroup: true, parent: box } } as never);
    }
    parentOf.set(dev, gid);
  }

  return {
    nodes: [
      ...data.nodes.map((n) =>
        subnetIdSet.has(n.data.id)
          ? { data: { ...n.data, isGroup: true } }
          : parentOf.has(n.data.id)
            ? { data: { ...n.data, parent: parentOf.get(n.data.id) } }
            : n,
      ),
      ...extraNodes,
    ],
    // 已經用「在框裡」表達的 L3 邊就不要再畫一次；跨網段那幾條留著
    edges: data.edges.filter(
      (e) =>
        e.data.kind !== "l3" ||
        !(parentOf.has(e.data.source) || parentOf.has(e.data.target)),
    ),
  };
}

function render(data: TopologyData) {
  if (!containerRef.value) return;
  if (cy) {
    cy.destroy();
    cy = null;
  }
  cy = cytoscape({
    container: containerRef.value,
    elements: (() => {
      const m = viewMode.value;
      const grouped = m === "l2" || m === "l3" ? data
        : groupBySubnet(data);   // auto / switch：網段與交換器合成一組
      return [...grouped.nodes, ...grouped.edges];
    })(),
    style: [
      {
        selector: "node",
        style: {
          "background-color": ((node: any) =>
            NODE_COLOURS[node.data("type") as string] || NODE_COLOURS.other) as any,
          label: "data(label)",
          color: "#fff",
          "text-outline-color": "#0f172a",
          "text-outline-width": 1,
          "font-size": 11,
          "text-valign": "center",
          "text-halign": "center",
          width: 38,
          height: 38,
        },
      },
      {
        selector: "edge",
        style: {
          width: 2,
          "curve-style": "bezier",
          "line-color": "#94a3b8",
          "target-arrow-shape": "none",
        },
      },
      {
        selector: 'edge[kind = "cable"]',
        style: {
          "line-color": "#475569",
          width: 2,
        },
      },
      {
        selector: 'edge[kind = "wireless"]',
        style: {
          "line-color": "#3b82f6",
          "line-style": "dashed",
        },
      },
      {
        selector: 'edge[kind = "vpn"]',
        style: {
          "line-color": "#9333ea",
          "line-style": "dashed",
          "line-dash-pattern": [10, 5],
          width: 4,
          // 中間標 tunnel 類型；兩端各自標「該端的對外位址」，貼在各自節點旁，不互蓋
          label: "data(type)",
          "source-label": "data(a_endpoint)",
          "target-label": "data(b_endpoint)",
          "source-text-offset": 46 as any,
          "target-text-offset": 46 as any,
          "font-size": 10,
          "font-weight": "bold",
          color: "#6b21a8",
          "text-rotation": 0 as any,
          "text-background-color": "#ffffff",
          "text-background-opacity": 1,
          "text-background-padding": "3px",
          "text-background-shape": "roundrectangle",
          "text-border-color": "#9333ea",
          "text-border-width": 1,
          "text-border-opacity": 1,
          "z-index": 9999,
        },
      },
      {
        // 存取層（FDB）：這台機器實際插在某台交換器的某個埠上 —— 比 L3 那種
        // 「有介面在這個網段」的推導確定，所以用實線、不用虛線。
        selector: 'edge[kind = "l2"]',
        style: {
          "line-color": "#14b8a6",
          width: 1.6,
          "line-style": "dashed",   // 預設是「在這個埠後面」，直連的在下一條規則轉實線
          label: "data(port)",
          "font-size": 9,
          color: "#0f766e",
          "text-background-color": "#ffffff",
          "text-background-opacity": 0.85,
          "text-background-padding": "2px",
          "text-rotation": "autorotate" as any,
        },
      },
      {
        // 埠上只有這一個 MAC → 真的插在上面，畫實線。有好幾個 MAC 的維持虛線：
        // 那些機器在這個埠「後面」，中間可能還隔著一台笨集線器或一台虛擬化主機。
        selector: 'edge[kind = "l2"][?direct]',
        style: { "line-style": "solid" },
      },
      {
        // 交換器之間的骨幹：畫得比存取層重，兩端標各自的埠名
        selector: 'edge[kind = "l2_uplink"]',
        style: {
          "line-color": "#0d9488",
          width: 3.5,
          label: "data(label)",
          "text-margin-y": -12,
          "font-size": 10,
          "font-weight": "bold",
          color: "#0f766e",
          "text-background-color": "#ffffff",
          "text-background-opacity": 0.9,
          "text-background-padding": "3px",
          "text-rotation": "autorotate" as any,
        },
      },
      {
        // 推導出來的線畫淡一點。不動顏色與虛實 —— 那兩個維度已經各有意義（種類、
        // 是否直連），再疊上去只會讓人讀不出來。
        selector: 'edge[evidence = "inferred"]',
        style: { opacity: 0.45, "line-style": "dotted" },
      },
      {
        // VM 跑在哪台實體主機上：細線、不搶戲（它是包含關係不是網路連線）
        selector: 'edge[kind = "vm_host"]',
        style: {
          "line-color": "#a78bfa",
          width: 1.2,
          opacity: 0.75,
        },
      },
      {
        selector: 'edge[kind = "l3"]',
        style: {
          "line-color": "#0ea5e9",
          "line-style": "dashed",
          width: 1.5,
          opacity: 0.7,
        },
      },
      {
        selector: 'node[type = "subnet"]',
        style: {
          shape: "round-rectangle",
          width: 70,
          height: 28,
          "font-size": 10,
          "font-weight": "bold",
        },
      },
      {
        // 網段框（混合視角）：標題放在框上緣，框本身淡到不搶戲
        selector: "node[?isGroup]",
        style: {
          shape: "round-rectangle",
          width: "label" as any,
          height: "label" as any,
          "background-color": "#0ea5e9",
          "background-opacity": 0.06,
          "border-width": 1.5,
          "border-color": "#0ea5e9",
          "border-style": "dashed",
          "border-opacity": 0.7,
          label: "data(label)",
          "text-valign": "top",
          "text-halign": "center",
          "text-margin-y": -6,
          "font-size": 13,
          "font-weight": "bold",
          color: "#0369a1",
          "text-outline-width": 0,
          padding: "26px" as any,
        },
      },
      {
        // 「同網段但查不出位置」的次區塊：比網段框更淡，標題說明白
        selector: 'node[type = "unplaced"]',
        style: {
          "background-color": "#94a3b8",
          "background-opacity": 0.07,
          "border-color": "#94a3b8",
          "border-style": "dashed",
          "border-width": 1,
          "border-opacity": 0.6,
          "font-size": 11,
          "font-weight": "normal",
          color: "#64748b",
          "text-margin-y": -4,
          padding: "18px" as any,
        },
      },
      {
        // 虛擬機：畫得比實體小一點，一眼分得出這不是實體機
        selector: 'node[type = "vm"]',
        style: {
          shape: "round-rectangle",
          width: 46,
          height: 26,
          "background-color": "#8b5cf6",
          "font-size": 9,
        },
      },
      {
        selector: 'node[type = "vpn_site"]',
        style: {
          shape: "diamond",
          width: 44,
          height: 44,
          "font-size": 10,
        },
      },
      {
        selector: "node:selected",
        style: {
          "border-width": 4,
          "border-color": "#fbbf24",
        },
      },
      {
        selector: "edge:selected",
        style: {
          "line-color": "#fbbf24",
          "target-arrow-color": "#fbbf24",
          "source-arrow-color": "#fbbf24",
          width: 5,
          opacity: 1,
          "z-index": 9999,
        },
      },
    ],
    layout: {
      name: "cose-bilkent",
      // 拉長邊、加大斥力，並把「標籤尺寸」算進節點碰撞 → 節點與邊上的文字
      // （VPN 端點 / tunnel 名 / IP）才不會疊在一起。
      idealEdgeLength: 150,
      nodeRepulsion: 9000,
      edgeElasticity: 0.4,
      nodeDimensionsIncludeLabels: true,
      gravity: 0.25,
      animate: false,
    } as any,
  });

  cy.on("tap", "node", (evt) => {
    evt.cy.elements().unselect();
    evt.target.select();                 // 維持選定高亮
    edgeEnds.value = null;
    selected.value = { ...evt.target.data() };
  });
  cy.on("tap", "edge", (evt) => {
    evt.cy.elements().unselect();
    evt.target.select();                 // 點線後維持選定狀態（放開滑鼠不會消失）
    const d = { ...evt.target.data() };
    const sn = (evt.cy.getElementById(d.source)?.data() ?? {}) as Record<string, any>;
    const tn = (evt.cy.getElementById(d.target)?.data() ?? {}) as Record<string, any>;
    edgeEnds.value = {
      a: { name: sn.label ?? null, ip: sn.ip ?? null, port: d.source_port ?? null, endpoint: d.a_endpoint ?? null },
      b: { name: tn.label ?? null, ip: tn.ip ?? null, port: d.target_port ?? null, endpoint: d.b_endpoint ?? null },
    };
    selected.value = d;
  });
  cy.on("tap", (evt) => {
    if (evt.target === evt.cy) {
      evt.cy.elements().unselect();
      edgeEnds.value = null;
      selected.value = null;
    }
  });
  // 有 FDB 存取層邊的端點＝查得出位置的，預設放行（見 hiddenTypes 上方說明）
  fdbPlaced.value = new Set(
    (data.edges ?? [])
      .filter((e) => e.data.kind === "l2" || e.data.kind === "l2_uplink")
      .flatMap((e) => [e.data.source, e.data.target]),
  );
  applyVisibility();   // 套用圖例的點暗（隱藏類別）狀態
  arrangeLayout();
}

/** 有沒有存取層資料，決定 auto 模式要走哪一種版面。 */
function hasAccessLayer(): boolean {
  return !!cy && cy.edges('[kind = "l2"], [kind = "l2_uplink"]').length > 0;
}

function arrangeLayout() {
  if (!cy) return;
  const m = viewMode.value;
  const switchCentric =
    m === "l2" || m === "switch" || (m === "auto" && hasAccessLayer());
  // 選了交換器為中心卻沒有存取層資料時退回子網路版面：畫不出來的東西不要硬畫，
  // 一個沒有中心的「以中心為版面」只會變成一團亂。
  if (switchCentric && hasAccessLayer()) arrangeSwitchCentric();
  else spreadSubnets();
}

/**
 * 以交換器為中心的版面。
 *
 * 交換器排成一列在中間，插在它上面的機器呈扇形排在**上方**，該網段的子網路節點放在
 * **下方**、和交換器算同一組（使用者的說法是「放在 switch 下面當做一起」），只連到
 * 子網路、沒有存取層資訊的節點再排在子網路下面。
 *
 * 這裡是自己算座標而不是換一種力導向版面：力導向沒有「上下」的概念，
 * 「交換器在中間、機器在上、網段在下」這種語意它表達不出來。
 */
function arrangeSwitchCentric() {
  if (!cy) return;

  // 交換器＝存取層邊的「交換器端」（l2 邊的 target 就是交換器）＋骨幹兩端
  const centres: string[] = [];
  const seen = new Set<string>();
  cy.edges('[kind = "l2"]').forEach((e) => {
    const id = e.target().id();
    if (!seen.has(id)) { seen.add(id); centres.push(id); }
  });
  cy.edges('[kind = "l2_uplink"]').forEach((e) => {
    for (const n of [e.source(), e.target()]) {
      if (!seen.has(n.id())) { seen.add(n.id()); centres.push(n.id()); }
    }
  });
  if (!centres.length) { spreadSubnets(); return; }

  // 交換器的左右順序：有骨幹相連的排在一起。否則骨幹線會從第三台交換器身上穿過去，
  // 線上的埠名也剛好蓋在那台的名字上 —— 圖沒有錯，但看起來像壞掉。
  const adj = new Map<string, string[]>();
  cy.edges('[kind = "l2_uplink"]').forEach((e) => {
    const [a, b] = [e.source().id(), e.target().id()];
    (adj.get(a) ?? adj.set(a, []).get(a)!).push(b);
    (adj.get(b) ?? adj.set(b, []).get(b)!).push(a);
  });
  const ordered: string[] = [];
  const queued = new Set<string>();
  for (const start of centres) {
    if (queued.has(start)) continue;
    const stack = [start];
    while (stack.length) {
      const id = stack.pop()!;
      if (queued.has(id) || !centres.includes(id)) continue;
      queued.add(id);
      ordered.push(id);
      for (const nb of adj.get(id) ?? []) if (!queued.has(nb)) stack.push(nb);
    }
  }
  centres.length = 0;
  centres.push(...ordered);

  const visible = (n: any) => n.style("display") !== "none";
  const hostsOf = new Map<string, any>();
  for (const id of centres) {
    hostsOf.set(id, cy.getElementById(id).connectedEdges('[kind = "l2"]').sources()
      .filter((n: any) => n.id() !== id && visible(n)));
  }

  // 間距跟著實際節點數走。寫死大間距的話，節點少時整張圖會被 fit() 縮到看不清標籤 ——
  // 版面「結構對」跟「看得懂」是兩回事，量過才知道。
  // 主機排在交換器上方的網格（每列最多 3 台）。原本用半圓扇形，主機一多就把整張圖
  // 拉得很寬 —— 實測 8 台主機 ×3 台交換器時整體寬 2274px、縮放掉到 0.53，字全糊了。
  // 有畫虛擬機時，每台主機底下要放得下一小格 VM，主機之間就得留更多空間；
  // 沒畫時維持原本較緊的排法，不要為了用不到的東西把圖撐大。
  const hasVms = cy.edges('[kind = "vm_host"]').length > 0;
  const HOST_PER_ROW = 3;
  const HOST_DX = hasVms ? 215 : 145;
  const HOST_DY = hasVms ? 155 : 105;
  const HOST_TOP = hasVms ? 255 : 150;
  const COL = Math.max(430, HOST_PER_ROW * HOST_DX + 110);
  const MEMBER_DY = 165;   // 同網段但查不出埠的成員：排在交換器下面
  const PER_ROW = 6;

  const placed = new Set<string>(centres);
  const x0 = -((centres.length - 1) * COL) / 2;
  let lowestY = 0;

  centres.forEach((swId, ci) => {
    const sw = cy!.getElementById(swId);
    const cx = x0 + ci * COL;
    sw.position({ x: cx, y: 0 });

    // 插在這台交換器上的機器：上方扇形（多的話分兩層，免得擠成一條）
    const hosts = hostsOf.get(swId).filter((h: any) => !placed.has(h.id()));
    const n = hosts.length;
    hosts.forEach((h: any, i: number) => {
      placed.add(h.id());
      const row = Math.floor(i / HOST_PER_ROW);
      const inRow = Math.min(HOST_PER_ROW, n - row * HOST_PER_ROW);
      const col = (i % HOST_PER_ROW) - (inRow - 1) / 2;
      h.position({ x: cx + col * HOST_DX, y: -(HOST_TOP + row * HOST_DY) });
    });

  });

  // 同一個網段裡「查不出插在哪個埠」的成員：置中排在**整個框**底下，而不是硬掛在
  // 第一台交換器下面 —— 一個網段跨好幾台交換器（核心＋接取）是常態，沒有資訊說它們
  // 屬於其中哪一台，挑一台就是編造。
  const boxes = new Map<string, string[]>();
  for (const id of centres) {
    const box = cy.getElementById(id).parent();
    if (box.nonempty()) {
      const bid = box[0].id();
      (boxes.get(bid) ?? boxes.set(bid, []).get(bid)!).push(id);
    }
  }
  boxes.forEach((swIds, boxId) => {
    const centreX = swIds.reduce((a, id) => a + cy!.getElementById(id).position("x"), 0)
      / swIds.length;
    // 虛擬機不排進這格網格：它們要貼著自己的實體主機（見下方），
    // 被掃進來的話會排到框底下，跟主機之間拉出一堆橫跨整張圖的長線。
    // 用 descendants：網段框底下現在可能還有一層「位置未知」的次區塊
    const members = cy!.getElementById(boxId).descendants()
      .filter((c: any) => !c.isParent() && !placed.has(c.id()) && visible(c)
        && c.data("type") !== "vm");
    const mn = members.length;
    // 每列幾個跟著數量走：固定 6 個一列時，一個有上百台的網段會排成十幾列的長條，
    // 整張圖被拉得很高、縮放又掉下去。開根號讓它維持接近方形。
    const perRow = Math.max(PER_ROW, Math.ceil(Math.sqrt(mn * 1.8)));
    members.forEach((m2: any, j: number) => {
      placed.add(m2.id());
      const row = Math.floor(j / perRow);
      const inRow = Math.min(perRow, mn - row * perRow);
      const col = (j % perRow) - (inRow - 1) / 2;
      const y = MEMBER_DY + row * 105;
      m2.position({ x: centreX + col * 145, y });
      lowestY = Math.max(lowestY, y);
    });
  });

  // 虛擬機排在它所在實體主機的正下方（小格子）—— 它是「跑在上面」，不是網路鄰居，
  // 位置貼著主機才讀得出這層關係。
  const VM_PER_ROW = 2;
  cy.edges('[kind = "vm_host"]').forEach((e) => {
    const host = e.target();
    if (!placed.has(host.id())) return;
    const vms = host.connectedEdges('[kind = "vm_host"]').sources()
      .filter((n: any) => n.id() !== host.id() && visible(n));
    const vn = vms.length;
    vms.forEach((vm: any, i: number) => {
      if (placed.has(vm.id())) return;
      placed.add(vm.id());
      const row = Math.floor(i / VM_PER_ROW);
      const inRow = Math.min(VM_PER_ROW, vn - row * VM_PER_ROW);
      const col = (i % VM_PER_ROW) - (inRow - 1) / 2;
      const y = host.position("y") + 52 + row * 32;
      vm.position({ x: host.position("x") + col * 68, y });
      lowestY = Math.max(lowestY, y);
    });
  });

  // 框外的節點（跨網段的路由器 / 防火牆、VPN 對端…）：排在框下方一列，
  // 不要散到很遠 —— 一顆放很遠的節點就足以把整張圖的縮放拉小、其他全變小字。
  const rest = cy.nodes().filter(
    (n) => !placed.has(n.id()) && !n.isParent() && visible(n),
  );
  const restY = lowestY + MEMBER_DY;
  const rn = rest.length;
  rest.forEach((n, i) => {
    const row = Math.floor(i / PER_ROW);
    const inRow = Math.min(PER_ROW, rn - row * PER_ROW);
    const col = (i % PER_ROW) - (inRow - 1) / 2;
    n.position({ x: col * 175, y: restY + row * 105 });
  });

  cy.fit(undefined, 40);
}

// 把多個 subnet 中心節點沿水平等距推開；只屬單一 subnet 的節點跟著平移，
// 同時連多個 subnet 的裝置留在原處（落在兩團中間），避免被夾擠。
function spreadSubnets() {
  if (!cy) return;
  const subs: any = cy.nodes().filter((n) => String(n.id()).startsWith("subnet:"));
  if (subs.length < 2) return;
  const cx = subs.reduce((a: number, n: any) => a + n.position("x"), 0) / subs.length;
  const cyy = subs.reduce((a: number, n: any) => a + n.position("y"), 0) / subs.length;
  const SPACING = 760;
  subs.forEach((sn: any, i: number) => {
    const tx = cx + (i - (subs.length - 1) / 2) * SPACING;
    const dx = tx - sn.position("x");
    const dy = cyy - sn.position("y");
    sn.position({ x: tx, y: cyy });
    sn.openNeighborhood().nodes().forEach((nbEle: any) => {
      const nb = nbEle as any;
      // VPN 端點（站對站對連的防火牆等）不跟著子網路被推到最遠端：留在 cose-bilkent
      // 因 VPN 邊互相吸引而靠近的中間位置，VPN 對連線才不會被拉成橫跨全圖的長線。
      if (nb.connectedEdges('[kind = "vpn"]').length > 0) return;
      const conn = nb.openNeighborhood().nodes().filter((x: any) => String(x.id()).startsWith("subnet:"));
      if (conn.length === 1 && conn[0].id() === sn.id()) {
        nb.position({ x: nb.position("x") + dx, y: nb.position("y") + dy });
      }
    });
  });
  cy.fit(undefined, 40);
}

watch(subnetIds, () => { void refresh(); });
watch([includeWireless, includeVpn, includeL3, includeFdb, includeVms, onlineOnly, viewMode], () => {
  void refresh();
});

onMounted(async () => {
  await loadSubnetOptions();
  // 有設常用子網路 → 進來預設只畫這些；否則畫全部
  let usedPinned = false;
  try {
    await ensureLoaded();
    if (pinned.value.length) { subnetIds.value = [...pinned.value]; usedPinned = true; }
  } catch { /* ignore */ }
  // 設了 subnetIds 會觸發 watch → refresh；沒設才在這裡主動畫一次
  if (!usedPinned) void refresh();
});
onUnmounted(() => {
  if (cy) cy.destroy();
});
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><TopologyIcon /></n-icon>
        <span>{{ t("nav.topology") }}</span>
      </n-space>
    </template>
    <!-- 動作靠右、與篩選同一列。原本它們自己獨占一列靠右對齊，畫面上多一條空帶，
         視窗一窄又會跟篩選擠在一起；卡片標題列則只放標題（使用者回報兩次）。 -->
    <n-space class="topo-toolbar" align="center" :wrap="true"
             style="margin-bottom: 12px; row-gap: 8px">
      <n-select
        v-model:value="subnetIds"
        :options="subnetOptions"
        multiple filterable clearable
        :placeholder="t('topology.filter_subnets')"
        style="width: 250px"
        :consistent-menu-width="false"
        max-tag-count="responsive"
      />
        <n-select v-model:value="viewMode" :options="viewModeOptions"
                  style="width: 190px" :consistent-menu-width="false" />
        <n-checkbox v-if="!modeDrivesSources" v-model:checked="includeWireless">{{ t("topology.wireless") }}</n-checkbox>
        <n-checkbox v-if="!modeDrivesSources" v-model:checked="includeVpn">{{ t("topology.vpn") }}</n-checkbox>
        <n-checkbox v-if="!modeDrivesSources" v-model:checked="includeL3">{{ t("topology.l3") }}</n-checkbox>
        <n-checkbox v-if="!modeDrivesSources" v-model:checked="includeFdb">{{ t("topology.fdb") }}</n-checkbox>
        <n-tooltip trigger="hover">
          <template #trigger>
            <n-checkbox v-model:checked="assertedOnly" @update:checked="applyVisibility">
              {{ t("topology.asserted_only") }}
            </n-checkbox>
          </template>
          {{ t("topology.asserted_only_hint") }}
        </n-tooltip>
        <n-checkbox v-model:checked="onlineOnly">{{ t("topology.online_only") }}</n-checkbox>
        <n-button-group>
          <n-button @click="zoomBy(1.2)" :title="t('topology.zoom_in')">＋</n-button>
          <n-button @click="zoomBy(0.83)" :title="t('topology.zoom_out')">－</n-button>
          <n-button @click="fitView">
            <template #icon><n-icon><FitIcon /></n-icon></template>
            {{ t("topology.fit") }}
          </n-button>
        </n-button-group>
        <!-- 兩顆動作綁成同一個 flex 子項：換行時一起換 -->
        <n-space align="center" :size="8" :wrap-item="false">
          <n-dropdown trigger="click" :options="exportOptions" @select="onExport">
            <n-button>
              <template #icon><n-icon><ExportIcon /></n-icon></template>
              {{ t("common.export") }}
            </n-button>
          </n-dropdown>
          <n-button @click="refresh">
            <template #icon><n-icon><RefreshIcon /></n-icon></template>
            {{ t("common.refresh") }}
          </n-button>
        </n-space>
      </n-space>
    <n-alert v-if="tooLarge" type="warning" :bordered="false" style="margin-bottom: 10px" data-testid="topology-too-large">
      {{ t("topology.too_large", { n: tooLarge.devices.toLocaleString(), limit: tooLarge.limit.toLocaleString() }) }}
    </n-alert>
    <n-spin :show="loading">
      <div class="topology-shell">
        <div ref="containerRef" class="cy"></div>
        <n-card v-if="selected" size="small" class="info-pane" :title="selectedTitle" closable @close="selected = null">
          <table class="info-table">
            <tbody>
              <tr v-for="row in selectedRows" :key="row.key">
                <th>{{ row.label }}</th>
                <td>{{ row.value }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="edgeEnds" class="edge-ends">
            <div class="ee-title">{{ t("topology.connection_ends") }}</div>
            <div class="ee-grid">
              <div v-for="(e, i) in [{ label: t('topology.end_a'), d: edgeEnds.a }, { label: t('topology.end_b'), d: edgeEnds.b }]"
                   :key="i" class="ee-col">
                <div class="ee-h">{{ e.label }}</div>
                <div v-if="e.d.name" class="ee-row"><span>{{ t('topology.end_name') }}</span><b>{{ e.d.name }}</b></div>
                <div v-if="e.d.ip" class="ee-row"><span>IP</span><b>{{ e.d.ip }}</b></div>
                <div v-if="e.d.port" class="ee-row"><span>{{ t('topology.port') }}</span><b>{{ e.d.port }}</b></div>
                <div v-if="e.d.endpoint" class="ee-row"><span>{{ t('topology.endpoint') }}</span><b>{{ e.d.endpoint }}</b></div>
                <div v-if="!e.d.name && !e.d.ip && !e.d.port && !e.d.endpoint" class="ee-empty">{{ t('topology.end_unknown') }}</div>
              </div>
            </div>
          </div>
          <template v-if="selectedDeviceId || selectedSubnetId" #action>
            <n-button v-if="selectedDeviceId" size="small" type="primary" ghost block @click="goDevice">
              {{ t("topology.open_device") }}
            </n-button>
            <n-button v-else size="small" type="primary" ghost block @click="goSubnet">
              {{ t("topology.open_subnet") }}
            </n-button>
          </template>
        </n-card>
      </div>
    </n-spin>
    <div class="topo-legend">
      <span class="lg lg-head">{{ t("topology.legend_links") }}</span>
      <span class="lg"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="#475569" stroke-width="2"/></svg>{{ t("topology.kind_cable") }}</span>
      <span class="lg"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="#3b82f6" stroke-width="2" stroke-dasharray="5,3"/></svg>{{ t("topology.kind_wireless") }}</span>
      <span class="lg"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="#9333ea" stroke-width="4" stroke-dasharray="8,4"/></svg>{{ t("topology.kind_vpn") }}</span>
      <span class="lg"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="#0ea5e9" stroke-width="1.5" stroke-dasharray="5,3"/></svg>{{ t("topology.kind_l3") }}</span>
      <span class="lg"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="#14b8a6" stroke-width="1.6"/></svg>{{ t("topology.kind_l2") }}</span>
      <span class="lg"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="#14b8a6" stroke-width="1.6" stroke-dasharray="5,3"/></svg>{{ t("topology.kind_l2_behind") }}</span>
      <span class="lg"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="#0d9488" stroke-width="3.5"/></svg>{{ t("topology.kind_l2_uplink") }}</span>
      <span class="lg"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="#a78bfa" stroke-width="1.2"/></svg>{{ t("topology.kind_vm_host") }}</span>
      <span class="lg lg-sep"></span>
      <span class="lg lg-head">{{ t("topology.legend_nodes") }}</span>
      <span class="lg clickable" :class="{ off: isGroupOff('firewall') }" @click="toggleGroup('firewall')"><i class="dot" style="background:#ef4444"></i>{{ t("topology.type_firewall") }}</span>
      <span class="lg clickable" :class="{ off: isGroupOff('router') }" @click="toggleGroup('router')"><i class="dot" style="background:#6366f1"></i>{{ t("topology.type_router") }}</span>
      <span class="lg clickable" :class="{ off: isGroupOff('switch') }" @click="toggleGroup('switch')"><i class="dot" style="background:#22c55e"></i>{{ t("topology.type_switch") }}</span>
      <span class="lg clickable" :class="{ off: isGroupOff('ap') }" @click="toggleGroup('ap')"><i class="dot" style="background:#3b82f6"></i>AP</span>
      <span class="lg clickable" :class="{ off: isGroupOff('server') }" @click="toggleGroup('server')"><i class="dot" style="background:#9ca3af"></i>{{ t("topology.server_other") }}</span>
      <span class="lg clickable" :class="{ off: isGroupOff('vm') }" @click="toggleGroup('vm')"><i class="dot dot-rect" style="background:#8b5cf6"></i>{{ t("topology.type_vm") }}</span>
      <span class="lg clickable" :class="{ off: isGroupOff('vpn_site') }" @click="toggleGroup('vpn_site')"><svg width="14" height="14"><rect x="2" y="2" width="9" height="9" transform="rotate(45 7 7)" fill="#9333ea"/></svg>{{ t("topology.type_vpn_site") }}</span>
      <span class="lg clickable" :class="{ off: isGroupOff('subnet') }" @click="toggleGroup('subnet')"><i class="dot dot-rect" style="background:#0ea5e9"></i>{{ t("topology.type_subnet") }}</span>
      <span class="lg"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="#94a3b8" stroke-width="1.6" stroke-dasharray="1,3"/></svg>{{ t("topology.kind_inferred") }}</span>
      <span class="lg muted">{{ t("topology.toggle_hint") }}</span>
    </div>
  </n-card>
</template>

<style scoped>
.topo-legend {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 16px;
  margin-top: 8px;
  font-size: 12px;
  opacity: 0.85;
}
.topo-legend .lg { display: inline-flex; align-items: center; gap: 6px; }
.topo-legend .lg.clickable { cursor: pointer; user-select: none; padding: 1px 4px; border-radius: 4px; }
.topo-legend .lg.clickable:hover { background: rgba(127,127,127,0.12); }
.topo-legend .lg.off { opacity: 0.32; text-decoration: line-through; }
.topo-legend .lg.muted { opacity: 0.6; margin-left: auto; }
.topo-legend .lg-head { font-weight: 600; opacity: 0.55; }
.topo-legend .lg-sep { width: 1px; height: 14px; background: rgba(127,127,127,0.3); }
.topo-legend .dot { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
.topo-legend .dot-rect { width: 16px; height: 9px; border-radius: 3px; }
.info-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.info-table th {
  text-align: left;
  white-space: nowrap;
  padding: 3px 10px 3px 0;
  color: var(--n-text-color-3, #888);
  font-weight: 500;
  vertical-align: top;
}
.info-table td { padding: 3px 0; word-break: break-all; }
.topology-shell {
  position: relative;
  width: 100%;
  /* 自動延展到接近視窗底部（扣掉頂列／卡片頭／工具列／圖例的概略高度） */
  height: calc(100vh - 270px);
  min-height: 420px;
  background: rgba(127, 127, 127, 0.04);
  border-radius: 6px;
}
.cy {
  width: 100%;
  height: 100%;
}
.info-pane {
  position: absolute;
  top: 8px;
  right: 8px;
  width: 320px;
  max-height: 60vh;
  overflow: auto;
  z-index: 10;
}
.edge-ends { margin-top: 10px; }
.ee-title { font-size: 12px; font-weight: 600; opacity: .75; margin-bottom: 6px; }
.ee-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.ee-col { border: 1px solid rgba(127,127,127,.2); border-radius: 6px; padding: 6px 8px; min-width: 0; }
.ee-h { font-size: 12px; font-weight: 600; margin-bottom: 4px; }
.ee-row { display: flex; justify-content: space-between; gap: 6px; font-size: 11.5px; line-height: 1.6; }
.ee-row span { opacity: .6; flex: none; }
.ee-row b { font-weight: 600; text-align: right; word-break: break-all; }
.ee-empty { font-size: 11.5px; opacity: .5; }
.info-pane pre {
  font-size: 11px;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
