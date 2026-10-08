/**
 * 主控台狀態列的「引擎」標示：這次連線實際用的是哪個引擎（使用者要求，2026-09-25）。
 * 值來自發票證的回應（後端當下的設定），不是前端自己猜的。
 */
import { i18n } from "@/i18n";

const NAMES: Record<string, string> = { aardwolf: "aardwolf", freerdp: "FreeRDP", guacd: "guacd" };

export function consoleEngineLabel(engine: string | null | undefined): string {
  if (!engine) return "";
  const t = (i18n.global as any).t;
  const name = engine === "builtin" ? t("common.console_engine_builtin") : (NAMES[engine] ?? engine);
  return t("common.console_engine", { name });
}
