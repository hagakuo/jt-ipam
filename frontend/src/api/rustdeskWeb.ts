// 相容 RustDesk 的網頁連線：換發單次票證、組 WebSocket 網址。協定本身在 src/rdweb/（瀏覽器裡跑）。
import { apiClient } from "@/api/client";

export interface RustDeskWebTicket {
  ticket: string;
  ws_path: string;
  /** 受控端的 RustDesk ID（票證就綁這一台） */
  peer_id: string;
  server_name: string;
  /** 7.3：給受控端看的控制端名稱「帳號 (jt-ipam)」 */
  my_name: string;
  transport: "tcp" | "ws";
  /** 附錄 D.5：這個人在這個 IP 有沒有記住的密碼（比照 VNC 票證的 has_saved_creds） */
  has_saved_password: boolean;
  ttl: number;
  /** 附錄 J.6：這張票證給哪一種連線（舊版後端沒有這個欄位＝desktop） */
  kind?: "desktop" | "file";
  /** 附錄 J.6：檔案傳輸的上傳上限（位元組，伺服器設定）；只有 kind = file 才有 */
  file_limits?: { max_file_bytes: number; max_total_bytes: number };
}

/** kind = "file"：檔案傳輸的票證（伺服器沒開「允許網頁檔案傳輸」時回 409 rd_file_disabled）。 */
export async function requestRustDeskTicket(addressId: string, kind: "desktop" | "file" = "desktop"):
    Promise<RustDeskWebTicket> {
  const url = `/api/v1/addresses/${addressId}/rustdesk/ticket`;
  const { data } = kind === "file"
    ? await apiClient.post<RustDeskWebTicket>(url, { kind })
    : await apiClient.post<RustDeskWebTicket>(url);
  return data;
}

/** 用本機的 RustDesk 客戶端軟體開啟時記一筆稽核（連線本身不經 jt-ipam）。失敗不擋開啟。 */
export async function logRustDeskLocalOpen(addressId: string): Promise<void> {
  await apiClient.post(`/api/v1/addresses/${addressId}/rustdesk/local-open`);
}

export function buildRustDeskWsUrl(wsPath: string, ticket: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${wsPath}?ticket=${encodeURIComponent(ticket)}`;
}

// ── 記住密碼（附錄 D）：沿用連線帳密金庫（ssh-credentials，protocol=rustdesk），只回遮罩 ──
// 瀏覽器只拿得到 credential_id；密碼明文與雜湊都不會回到前端，也不放進瀏覽器的任何儲存空間。

export interface RustDeskCredential {
  id: string;
  label: string;
  protocol: string;
  target_ip_id: string | null;
  has_password: boolean;
  last_used_at: string | null;
  created_at: string;
}

/** 這個 IP 已存的 RustDesk 密碼（照 VNC 的 listVncCredentials；一律綁定 IP，同一個人同一個 IP 最多一筆）。 */
export async function listRustDeskCredentials(addressId: string): Promise<RustDeskCredential[]> {
  const { data } = await apiClient.get<RustDeskCredential[]>("/api/v1/ssh-credentials", {
    params: { protocol: "rustdesk", target_ip_id: addressId },
  });
  return data.filter((c) => c.protocol === "rustdesk" && c.target_ip_id === addressId && c.has_password);
}

/** 登入成功後才呼叫（D.2）。後端會取代這個 IP 原本的那一筆。名稱留空＝「RustDesk <對方 ID>」 */
export async function saveRustDeskPassword(p: {
  addressId: string; peerId: string; password: string; label?: string;
}): Promise<RustDeskCredential> {
  const { data } = await apiClient.post<RustDeskCredential>("/api/v1/ssh-credentials", {
    label: (p.label || "").trim() || (p.peerId ? `RustDesk ${p.peerId}` : "RustDesk"),
    username: "",
    auth_type: "password",
    protocol: "rustdesk",
    target_ip_id: p.addressId,
    password: p.password,
  });
  return data;
}

export async function deleteSavedRustDeskPassword(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/ssh-credentials/${id}`);
}
