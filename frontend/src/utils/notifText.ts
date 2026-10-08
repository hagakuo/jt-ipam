/** 通知文字的翻譯：伺服器只給 key 與參數，顯示語言由瀏覽器這端決定。 */

type Params = Record<string, unknown>;
type Translate = (key: string, params?: Params) => string;

export interface NotifLike {
  title: string;
  body?: string | null;
  title_key?: string | null;
  body_key?: string | null;
  params?: Params | null;
}

/** 把結尾是 `_key` 的參數當成翻譯鍵先翻好，換成去掉後綴的同名參數。
 *
 * 例：`{label_key: "anomaly.ip_conflicts", count: 3}` → `{label: "IP 衝突", count: 3}`，
 * 於是一句「{label}：新增 {count} 筆」就能套用到十一個類別，不必為每個類別各寫一份
 * 幾乎一樣的句子。後端無從得知瀏覽器的語言，所以組句子只能組到「鍵」為止。
 */
function resolve(params: Params | null | undefined, t: Translate): Params {
  const out: Params = {};
  for (const [k, v] of Object.entries(params || {})) {
    if (k.endsWith("_key") && typeof v === "string") out[k.slice(0, -4)] = t(v);
    else out[k] = v;
  }
  return out;
}

// 有 i18n key 就依當前語言渲染（帶參數）；沒有則退回存起來的原字串（向下相容舊通知）
export function notifTitle(n: NotifLike, t: Translate): string {
  return n.title_key ? t(n.title_key, resolve(n.params, t)) : n.title;
}

export function notifBody(n: NotifLike, t: Translate): string {
  return n.body_key ? t(n.body_key, resolve(n.params, t)) : (n.body || "");
}
