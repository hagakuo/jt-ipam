/**
 * 機櫃與地點的關聯。
 *
 * 機櫃本身就掛在一個地點上，所以「選了機櫃還要再選地點」是叫使用者把同一件事講兩次
 * —— 客戶直接反映過。能推出來的就不要問；真正該擋的只有「兩邊都填了卻互相矛盾」，
 * 那代表其中一個是錯的，替使用者挑一個等於在猜。
 *
 * 抽成純函式是因為裝置有兩個編輯入口（清單頁與詳細資料頁的編輯視窗），
 * 同一段邏輯寫兩份遲早會各自漂移。
 */

export interface RackLike {
  id: string;
  location_id: string | null;
}

export type RackLocationResult =
  | { ok: true; location_id: string | null }
  | { ok: false; reason: "mismatch" };

/**
 * 依所選機櫃決定要送出的地點。
 *
 * - 沒選機櫃 → 地點照使用者填的
 * - 選了機櫃、沒填地點 → 用機櫃的地點
 * - 選了機櫃、也填了地點且一致 → 照填的
 * - 兩者矛盾 → 不猜，回報讓使用者自己修
 */
export function resolveRackLocation(
  rackId: string | null,
  locationId: string | null,
  racks: RackLike[],
): RackLocationResult {
  if (!rackId) return { ok: true, location_id: locationId };
  const rackLoc = racks.find((r) => r.id === rackId)?.location_id ?? null;
  if (!locationId) return { ok: true, location_id: rackLoc };
  if (rackLoc && locationId !== rackLoc) return { ok: false, reason: "mismatch" };
  return { ok: true, location_id: locationId };
}
