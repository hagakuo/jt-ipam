/**
 * MAC 位址的共用判斷。
 *
 * **隨機（私人）MAC**：iOS 14+、Android 10+、Windows 10/11、macOS 連 Wi‑Fi 預設用的位址，
 * 第一個位元組的 bit 1（本地管理位元）是 1 ── 也就是第二個十六進位字是 2、6、A、E。
 * 它不是廠商燒錄的硬體位址：大多每個 Wi‑Fi 網路固定一個，有些設定會定期輪替，
 * 所以「同一個 IP 上看到好幾個 MAC」很可能只是同一台換了位址。虛擬機、容器也常用這類位址。
 */

/** 各種寫法（`aa:bb…`、`AA-BB…`、`aabb.ccdd.eeff`、`aabbccddeeff`）→ `aa:bb:cc:dd:ee:ff`；不是 MAC 回 null */
export function normalizeMac(input: string | null | undefined): string | null {
  const hex = String(input ?? "").trim().toLowerCase().replace(/[^0-9a-f]/g, "");
  const raw = String(input ?? "").trim();
  if (hex.length !== 12 || !/^[0-9a-fA-F:.\-\s]+$/.test(raw)) return null;
  return hex.match(/.{2}/g)!.join(":");
}

/** 本地管理位址（隨機／私人 MAC、虛擬機、容器）—— 不是廠商燒錄的硬體位址 */
export function isRandomMac(mac: string | null | undefined): boolean {
  const n = normalizeMac(mac);
  return !!n && (parseInt(n.slice(0, 2), 16) & 0x02) === 0x02;
}
