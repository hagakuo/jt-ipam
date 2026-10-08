/**
 * nmap 輸出的小工具（IP 探測頁用）。
 *
 * nmap 的 NSE 腳本把非 ASCII 位元組寫成 `\xHH`：中文網頁標題「裂縫…」會變成
 * `\xE8\xA3\x82…`，畫面上完全看不懂（使用者回報）。連續的 `\xHH` 當成 UTF-8 解回文字；
 * 解不出來（不是合法 UTF-8）就原樣留著，不要猜。
 */
export function decodeNmapEscapes(text: string): string {
  if (!text || !text.includes("\\x")) return text;
  return text.replace(/(?:\\x[0-9A-Fa-f]{2})+/g, (run) => {
    const bytes = new Uint8Array(run.length / 4);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(run.slice(i * 4 + 2, i * 4 + 4), 16);
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return run;
    }
  });
}

/** 服務分類：連接埠表上色用 */
export type ServiceKind = "remote" | "web" | "data" | "file" | "mail" | "infra" | "other";

const KINDS: [ServiceKind, RegExp][] = [
  ["remote", /^(ssh|telnet|ms-wbt-server|rdp|vnc|x11|nomachine|rfb|realserver|teamviewer|anydesk)/],
  ["web", /^(https?|http-proxy|http-alt|ssl\/http|https-alt|www)/],
  ["data", /^(ldap|ldaps|mysql|postgresql|ms-sql|oracle|redis|mongodb|memcache|elasticsearch|kerberos|domain|dns)/],
  ["file", /^(microsoft-ds|netbios|smb|nfs|ftp|ftps|sftp|rsync|afp|ipp|printer|jetdirect|iscsi)/],
  ["mail", /^(smtp|submission|imap|pop3|imaps|pop3s)/],
  ["infra", /^(snmp|ntp|syslog|rpcbind|msrpc|sip|mqtt|zabbix|nrpe|upnp|ssdp|bgp|dhcp)/],
];

export function serviceKind(service: string | undefined | null): ServiceKind {
  const s = (service || "").toLowerCase();
  for (const [kind, re] of KINDS) if (re.test(s)) return kind;
  return "other";
}
