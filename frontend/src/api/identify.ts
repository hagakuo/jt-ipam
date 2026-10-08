import { apiClient } from "./client";

/**
 * IP 的「探測」（只有管理員）：由負責該子網路的掃描代理對這個 IP 做非侵入式識別。
 * 後端見 endpoints/ip_identify.py；結果經代理的工作佇列回來，前端輪詢。每次的結果都保留。
 */
export interface IdentifyPort {
  port: number; proto: string; state?: string; service?: string; product?: string;
  version?: string; extrainfo?: string; tunnel?: string; scripts?: Record<string, string>;
  /** nmap 怎麼認出服務：table ＝沒有探針比中，名稱只是照埠號表寫的 */
  method?: string;
  /** 輸出被截斷的腳本（代理 1.17.4 起） */
  truncated?: string[];
}
export interface IdentifyNote { code: string; params: Record<string, string | number> }
export interface IdentifyCert {
  port: string; subject: string | null; issuer: string | null; self_signed: boolean;
  not_before: string | null; not_after: string | null; sha256: string | null; sha1: string | null;
  key: string | null; san: string[];
}
export interface IdentifySshKey { port: string; type: string | null; bits: number | null; fingerprint: string | null }
export interface IdentifySummary {
  device_type: string; os: string | null; vendor: string | null; names: string[];
  /** Recog 指紋比中的硬體型號／系列 */
  model?: string | null;
  /** 摘要用了哪一版 Recog 指紋庫；沒安裝是 null */
  recog?: string | null;
  applications: string[]; services: string[]; evidence: string[]; nmap_available: boolean;
  /** 探測時主機完全沒有回應（沒有開或關的埠、沒有 MAC 回應、沒有 OS 指紋） */
  no_response?: boolean;
  /** 網卡廠牌（MAC 的 OUI）；`vendor` 是設備本身的廠牌（服務自己講的、可信的指紋），兩者不一定相同 */
  nic_vendor?: string | null;
  /** IP 記錄對照 IPAM 已知的事實後採用的類型與依據（device:／librenms:／wazuh:／rustdesk:／ocs:／virt:） */
  ipam?: { kind: string | null; reason: string } | null;
  /** nmap 本身失敗（不是主機沒回應） */
  scan_failed?: boolean;
  scan_error?: string | null;
  name_sources?: { name: string; sources: string[] }[];
  windows?: { computer: string | null; domain: string | null; dns_domain: string | null; fqdn: string | null;
              workgroup: string | null; product_version: string | null } | null;
  certs?: IdentifyCert[];
  ssh_keys?: IdentifySshKey[];
  /** filtered 為 null ＝舊代理沒回報 */
  port_counts?: { open: number; closed: number; filtered: number | null } | null;
  distance?: number | null;
  uptime_seconds?: number | null;
  elapsed?: number | null;
  /** false ＝代理不是 root，nmap 沒做 OS 指紋；null ＝舊代理沒回報 */
  os_scan?: boolean | null;
  /** 顯示的 MAC（算網卡廠牌用的那個）與這次 nmap 看到的 */
  mac?: string | null;
  mac_seen?: string | null;
  notes?: IdentifyNote[];
}
export interface IdentifyChanges {
  previous_job_id: string; previous_at: string;
  opened: string[]; closed: string[]; changed: { port: string; before: string; after: string }[];
  /** 其中一次沒回應／失敗／沒有 nmap：連接埠不比 */
  baseline?: string | null; current?: string | null;
  fields?: { field: string; before: string; after: string }[];
  names_added?: string[]; names_removed?: string[];
  ssh_keys?: { port: string; type: string | null; before: string; after: string }[];
  certs?: { port: string; before: Record<string, string | null>; after: Record<string, string | null> }[];
}
export type IdentifyStatus = "pending" | "running" | "done" | "failed" | "expired";
/** 清單用的精簡版（不帶原始結果） */
export interface IdentifyBrief {
  job_id: string;
  status: IdentifyStatus;
  error?: string | null;
  error_code?: string | null;
  agent_name?: string | null;
  created_at: string; claimed_at?: string | null; finished_at?: string | null;
  summary?: IdentifySummary | null;
}
export interface IdentifyJob extends IdentifyBrief {
  result?: {
    target?: string;
    names?: { rdns?: string | null; netbios?: string | null; mdns?: string | null };
    nmap?: { available?: boolean; error?: string; ports?: IdentifyPort[]; mac?: string | null;
             mac_vendor?: string | null; os?: { name: string; accuracy: number }[] };
    elapsed?: number;
  } | null;
  /** 代理回報的目前階段：names（名稱查詢）→ scan（連接埠／服務／OS） */
  progress?: { stage?: string; elapsed?: number } | null;
  changes?: IdentifyChanges | null;
}

/**
 * 探測的對象：IPAM 裡的一筆 IP 記錄，或（IPAM 沒有記錄的）管理網段內的位址 ——
 * 後者給異常偵測的「未授權 IP」用，後端會確認位址在管理的子網路內、由那個子網路的代理執行。
 */
export type IdentifyTarget = { addressId: string } | { ip: string };

function base(target: IdentifyTarget | string): string {
  if (typeof target === "string") return `/api/v1/addresses/${target}/identify`;
  return "addressId" in target
    ? `/api/v1/addresses/${target.addressId}/identify`
    : `/api/v1/identify/ip/${encodeURIComponent(target.ip)}`;
}

export async function startIdentify(target: IdentifyTarget | string): Promise<{ job_id: string; agent_name: string; status: string }> {
  const { data } = await apiClient.post(base(target));
  return data;
}

export async function identifyHistory(target: IdentifyTarget | string): Promise<IdentifyBrief[]> {
  const { data } = await apiClient.get<{ items: IdentifyBrief[] }>(`${base(target)}/history`);
  return data.items;
}

export async function getIdentify(target: IdentifyTarget | string, jobId: string): Promise<IdentifyJob> {
  const { data } = await apiClient.get<IdentifyJob>(`${base(target)}/${jobId}`);
  return data;
}

/** 取消還在等待或執行中的探測（卡住時不必等滿逾時） */
export async function cancelIdentify(target: IdentifyTarget | string, jobId: string): Promise<void> {
  await apiClient.post(`${base(target)}/${jobId}/cancel`);
}

/** 以位址探測時的標題資訊；已經登記的位址會帶 address_id（畫面改用那筆記錄的探測頁） */
export interface IdentifyIpTarget {
  ip: string; subnet_id: string; subnet_cidr: string; agent_name: string | null; address_id: string | null;
  arp_last_seen?: string | null; arp_source?: string | null;
  /** 0＝IPAM 沒有記錄；>1＝重複記錄（不是未登記） */
  record_count: number;
}
export async function getIdentifyIpTarget(ip: string): Promise<IdentifyIpTarget> {
  const { data } = await apiClient.get<IdentifyIpTarget>(`/api/v1/identify/ip/${encodeURIComponent(ip)}`);
  return data;
}
