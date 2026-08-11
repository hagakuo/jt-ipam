import { apiClient } from "@/api/client";

export interface GraylogDsv { enabled: boolean; fmt: string; path: string; token: string; }
export async function getGraylogDsv(): Promise<GraylogDsv> {
  const { data } = await apiClient.get<GraylogDsv>("/api/v1/system/graylog-dsv");
  return data;
}
export async function putGraylogDsv(p: {
  enabled: boolean; fmt: string; path: string; regenerate_token?: boolean;
}): Promise<GraylogDsv> {
  const { data } = await apiClient.put<GraylogDsv>("/api/v1/system/graylog-dsv", p);
  return data;
}

// ── 外部認證 / LDAP（AD） ──
export interface LdapConfig {
  enabled: boolean; server: string | null; port: number;
  use_ssl: boolean; use_starttls: boolean;
  bind_dn: string | null; password_set: boolean;
  search_base: string | null; user_filter: string;
  attr_email: string; attr_display_name: string; attr_member_of: string;
  admin_groups: string[];
  default_group_id: string | null;
}
export type LdapPatch = Omit<LdapConfig, "password_set"> & { bind_password?: string | null };

export async function getLdap(): Promise<LdapConfig> {
  const { data } = await apiClient.get<LdapConfig>("/api/v1/system/ldap");
  return data;
}
export async function putLdap(p: LdapPatch): Promise<LdapConfig> {
  const { data } = await apiClient.put<LdapConfig>("/api/v1/system/ldap", p);
  return data;
}
export async function testLdap(): Promise<{ bound: boolean; server: string; port: number; tls: string; who_am_i?: string }> {
  const { data } = await apiClient.post("/api/v1/system/ldap/test", {});
  return data;
}
export async function testLdapAuth(username: string, password: string): Promise<{ ok: boolean; dn: string; username: string; display_name: string | null; email: string | null; is_admin: boolean }> {
  const { data } = await apiClient.post("/api/v1/system/ldap/test-auth", { username, password });
  return data;
}

// ── 稽核轉送到 Graylog ──
export interface AuditForward { enabled: boolean; host: string | null; port: number; protocol: "tcp" | "udp"; fmt: "gelf" | "syslog" | "cef"; }
export async function getAuditForward(): Promise<AuditForward> {
  const { data } = await apiClient.get<AuditForward>("/api/v1/system/audit-forward");
  return data;
}
export async function putAuditForward(p: AuditForward): Promise<AuditForward> {
  const { data } = await apiClient.put<AuditForward>("/api/v1/system/audit-forward", p);
  return data;
}
export async function testAuditForward(p: AuditForward): Promise<{ ok: boolean; sent_to: string; fmt: string }> {
  const { data } = await apiClient.post("/api/v1/system/audit-forward/test", p);
  return data;
}

// ── OIDC SSO 設定（webui 管理）──
export interface OidcConfig {
  enabled: boolean;
  issuer: string | null;
  client_id: string | null;
  client_secret_set: boolean;
  redirect_uri: string | null;
  scope: string;
  groups_claim: string;
  username_claim: string;
  admin_groups: string[];
  default_group_id: string | null;
}
export interface OidcConfigPatch {
  enabled: boolean;
  issuer: string | null;
  client_id: string | null;
  client_secret?: string | null;  // 留空(undefined)=不變更；空字串=清除
  redirect_uri: string | null;
  scope: string;
  groups_claim: string;
  username_claim: string;
  admin_groups: string[];
  default_group_id: string | null;
}
export async function getOidcConfig(): Promise<OidcConfig> {
  const { data } = await apiClient.get<OidcConfig>("/api/v1/auth/oidc/config");
  return data;
}
export async function putOidcConfig(p: OidcConfigPatch): Promise<OidcConfig> {
  const { data } = await apiClient.put<OidcConfig>("/api/v1/auth/oidc/config", p);
  return data;
}
export async function testOidc(): Promise<{ ok: boolean; issuer?: string; authorization_endpoint?: string; error?: string }> {
  const { data } = await apiClient.get("/api/v1/auth/oidc/test");
  return data;
}

// ── SAML SSO 設定（webui 管理）──
export interface SamlConfig {
  enabled: boolean;
  idp_metadata_url: string | null;
  idp_metadata_xml: string | null;
  sp_entity_id: string | null;
  sp_acs_url: string | null;
  sp_sls_url: string | null;
  sp_x509_cert: string | null;
  sp_private_key_set: boolean;
  want_assertions_signed: boolean;
  want_assertions_encrypted: boolean;
  want_name_id_encrypted: boolean;
  authn_requests_signed: boolean;
  attr_username: string;
  attr_email: string;
  attr_displayname: string;
  attr_groups: string;
  admin_groups: string[];
  default_group_id: string | null;
}
export type SamlConfigPatch = Omit<SamlConfig, "sp_private_key_set"> & { sp_private_key?: string | null };
export async function getSamlConfig(): Promise<SamlConfig> {
  const { data } = await apiClient.get<SamlConfig>("/api/v1/auth/saml/config");
  return data;
}
export async function putSamlConfig(p: SamlConfigPatch): Promise<SamlConfig> {
  const { data } = await apiClient.put<SamlConfig>("/api/v1/auth/saml/config", p);
  return data;
}
export async function testSaml(): Promise<{ entity_id?: string; sso_url?: string; error?: string }> {
  const { data } = await apiClient.get("/api/v1/auth/saml/test");
  return data;
}

export interface LLMConfig {
  enabled: boolean;
  /** ollama（自架）或 openai（OpenAI 相容端點）。舊設定沒有這個欄位，視為 ollama。 */
  provider?: string;
  url: string;
  /** 金鑰只回「有沒有設」，本身不回傳到瀏覽器。 */
  api_key_set?: boolean;
  embedding_model: string;
  chat_model: string;
  timeout: number;
  num_ctx?: number | null;
  mcp_external_enabled: boolean;
  mcp_api_key_set: boolean;
  ai_audit_enabled: boolean;
  ai_audit_times: string[];
  ai_audit_model: string | null;
  ai_audit_num_ctx: number | null;
  server_timezone: string;
}

export interface LLMConfigPatch {
  enabled?: boolean;
  provider?: string;
  url?: string;
  api_key?: string;
  embedding_model?: string;
  chat_model?: string;
  timeout?: number;
  num_ctx?: number | null;
  mcp_external_enabled?: boolean;
  ai_audit_enabled?: boolean;
  ai_audit_times?: string[];
  ai_audit_model?: string;
  ai_audit_num_ctx?: number;
}

export async function getLLMConfig(): Promise<LLMConfig> {
  const { data } = await apiClient.get<LLMConfig>("/api/v1/system/llm");
  return data;
}

export async function patchLLMConfig(payload: LLMConfigPatch): Promise<LLMConfig> {
  const { data } = await apiClient.patch<LLMConfig>("/api/v1/system/llm", payload);
  return data;
}

// 對外 MCP 金鑰（唯讀）：檢視目前明文 / 重新產生
export async function revealMcpKey(): Promise<string | null> {
  const { data } = await apiClient.get<{ api_key: string | null }>("/api/v1/system/llm/mcp-key");
  return data.api_key;
}

export async function rotateMcpKey(): Promise<string> {
  const { data } = await apiClient.post<{ api_key: string }>("/api/v1/system/llm/mcp-key/rotate");
  return data.api_key;
}

export interface OllamaModel {
  name: string;
  size: number | null;
  modified_at: string | null;
  family: string | null;
  parameter_size: string | null;
}

export async function listOllamaModels(): Promise<{ models: OllamaModel[]; error?: string }> {
  const { data } = await apiClient.get<{ models: OllamaModel[]; error?: string }>(
    "/api/v1/system/llm/models",
  );
  return data;
}

export interface VersionInfo {
  current: string;
  python: string;
  packages: Record<string, string | null>;
  frontend?: Record<string, string | null>;
  host?: {
    os: string | null;
    kernel: string | null;
    nginx: string | null;
    node: string | null;
    postgres: string | null;
    /** 選用的作業系統相依：功能存在但主機不一定裝了對應執行檔 */
    optional_tools?: Record<string, { present: boolean; package: string; used_by: string }>;
  };
}

export interface LatestVersion {
  current: string;
  latest: string | null;
  update_available: boolean;
  release_url: string;
  error: string | null;
}

export async function getVersionInfo(): Promise<VersionInfo> {
  const { data } = await apiClient.get<VersionInfo>("/api/v1/system/version");
  return data;
}

export async function checkLatestVersion(): Promise<LatestVersion> {
  const { data } = await apiClient.get<LatestVersion>("/api/v1/system/version/check-latest");
  return data;
}

// 連線管理資安設定（目前：RDP 控制端貼上文字到被控端）
export interface ConsoleSecurity { rdp_clipboard_paste: boolean }
export async function getConsoleSecurity(): Promise<ConsoleSecurity> {
  const { data } = await apiClient.get<ConsoleSecurity>("/api/v1/system/console-security");
  return data;
}
export async function setConsoleSecurity(p: ConsoleSecurity): Promise<ConsoleSecurity> {
  const { data } = await apiClient.put<ConsoleSecurity>("/api/v1/system/console-security", p);
  return data;
}

// 介面顯示設定（系統層；目前：異動記錄淡化天數）
export interface UiDisplay { change_log_dim_days: number }
export async function getUiDisplay(): Promise<UiDisplay> {
  const { data } = await apiClient.get<UiDisplay>("/api/v1/system/ui-display");
  return data;
}
export async function setUiDisplay(p: UiDisplay): Promise<UiDisplay> {
  const { data } = await apiClient.put<UiDisplay>("/api/v1/system/ui-display", p);
  return data;
}


// ── AI 巡檢 ──
export interface AIFinding {
  id: string; run_id: string; severity: "low" | "medium" | "high"; category: string;
  title: string; detail: string; recommendation: string | null;
  evidence: Record<string, unknown> | null;
  object_type: string | null; object_id: string | null;
  status: string; created_at: string | null;
  /** 寫出這條結論的模型 —— 換過模型後要分得出哪幾條出自哪一個 */
  model?: string | null;
}
export interface AIAuditSummary {
  ip_count: number;
  counts: { low: number; medium: number; high: number };
  total: number; last_run_at: string | null;
}

export async function getAIAuditSummary(): Promise<AIAuditSummary> {
  const { data } = await apiClient.get("/api/v1/ai-audit/summary");
  return data;
}
export async function listAIFindings(params: { status?: string; severity?: string; category?: string; page?: number; page_size?: number } = {}) {
  const { data } = await apiClient.get("/api/v1/ai-audit/findings", { params });
  return data as { items: AIFinding[]; total: number; page: number; page_size: number };
}
export async function runAIAudit(): Promise<{ task_id: string; status: string }> {
  const { data } = await apiClient.post("/api/v1/ai-audit/run");
  return data;
}

// 巡檢跑十幾分鐘，而且是背景作業 —— 進度存在作業列，不在瀏覽器裡。
// 所以關掉分頁、切走再回來都看得到現況（之前綁在連線上，一離開就整個消失）。
export interface AIAuditProgress {
  stage?: "collecting" | "analyzing" | "saving" | "done";
  current?: number;
  total?: number;
  ips?: number;
  model?: string;
  found?: number;
  batch?: number;
  written?: number;
  phase?: string;
}

export interface AIAuditTask {
  id: string;
  status: "pending" | "running" | "succeeded" | "failed" | "cancelled";
  progress: number;
  summary: { live?: AIAuditProgress; findings?: number; error?: string | null } | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export async function getAIAuditStatus(): Promise<{ task: AIAuditTask | null }> {
  const { data } = await apiClient.get("/api/v1/ai-audit/status");
  return data;
}

export async function dismissAIFindings(ids: string[]): Promise<{ dismissed: number }> {
  const { data } = await apiClient.post("/api/v1/ai-audit/dismiss", { ids });
  return data;
}

// 忽略會影響往後每一次巡檢（同一件事之後都自動忽略）→ 一定要能反悔
/** 清空整份發現清單（含已忽略）。是刪除不是忽略 —— 忽略會讓下次巡檢自動略過同一件事。 */
export async function clearAIFindings(): Promise<{ deleted: number }> {
  const { data } = await apiClient.delete("/api/v1/ai-audit/findings");
  return data;
}

export async function restoreAIFindings(ids: string[]): Promise<{ restored: number }> {
  const { data } = await apiClient.post("/api/v1/ai-audit/restore", { ids });
  return data;
}

export interface EmbeddingCheck {
  ok: boolean;
  dim: number | null;
  expected: number;
  error: string | null;
}

/** 實際取一次向量，確認嵌入模型的維度與資料庫欄位相符。 */
export async function checkEmbedding(): Promise<EmbeddingCheck> {
  const { data } = await apiClient.get<EmbeddingCheck>("/api/v1/ai/embedding-check");
  return data;
}

export interface ReindexResult {
  subnets: number;
  ip_addresses: number;
  devices: number;
  failed: number;
  error: string | null;
}

/** 重新計算所有描述的向量。慢（依資料量可能數分鐘），只在換模型或初次設定後需要。 */
export async function reindexEmbeddings(): Promise<ReindexResult> {
  const { data } = await apiClient.post<ReindexResult>("/api/v1/ai/reindex");
  return data;
}

export interface AutolinkConfig {
  enabled: boolean;
  scope_subnet_ids: string[] | null;
}

export interface AutolinkPreview {
  would_link: number;
  samples: { ip: string; hostname: string | null; device: string | null }[];
  skipped: Record<string, number>;
}

export async function getAutolink(): Promise<AutolinkConfig> {
  const { data } = await apiClient.get<AutolinkConfig>("/api/v1/system/ip-device-autolink");
  return data;
}

export async function putAutolink(p: Partial<AutolinkConfig>): Promise<AutolinkConfig> {
  const { data } = await apiClient.put<AutolinkConfig>("/api/v1/system/ip-device-autolink", p);
  return data;
}

/** 只計算不寫入 —— 開啟前先看會動到什麼。 */
export async function previewAutolink(): Promise<AutolinkPreview> {
  const { data } = await apiClient.post<AutolinkPreview>(
    "/api/v1/system/ip-device-autolink/preview");
  return data;
}
