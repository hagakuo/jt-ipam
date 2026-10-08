import { apiClient } from "@/api/client";
import { LONG_OP_TIMEOUT_MS } from "@/api/integrations";

// 裝置匯入（issue #46）：預覽（dry_run）同步回每一列的結果；實際匯入走背景作業。

export type DeviceImportAction = "create" | "update" | "skip" | "error";
export interface DeviceImportMessage { code: string; params: Record<string, string | number> }
export interface DeviceImportRow { line: number; name: string | null; action: DeviceImportAction; messages: DeviceImportMessage[] }
export interface DeviceImportPreview {
  dry_run: true;
  total: number; created: number; updated: number; skipped: number; errored: number; warnings: number;
  ignored_columns: string[];
  fatal: { code: string; params?: Record<string, string | number> } | null;
  rows: DeviceImportRow[];
}

function form(file: File, dryRun: boolean, onExisting: "skip" | "update"): FormData {
  const f = new FormData();
  f.append("file", file, file.name);
  f.append("dry_run", String(dryRun));
  f.append("on_existing", onExisting);
  return f;
}

export async function previewDeviceImport(file: File, onExisting: "skip" | "update"): Promise<DeviceImportPreview> {
  const { data } = await apiClient.post<DeviceImportPreview>("/api/v1/devices/import", form(file, true, onExisting),
    { headers: { "Content-Type": "multipart/form-data" }, timeout: LONG_OP_TIMEOUT_MS });
  return data;
}

export async function runDeviceImport(file: File, onExisting: "skip" | "update"): Promise<{ task_id: string }> {
  const { data } = await apiClient.post("/api/v1/devices/import", form(file, false, onExisting),
    { headers: { "Content-Type": "multipart/form-data" }, timeout: LONG_OP_TIMEOUT_MS });
  return data;
}

/** 匯入範本（CSV）；includeDevices 時帶出全部現有裝置 */
export async function downloadDeviceTemplate(includeDevices: boolean): Promise<void> {
  const resp = await apiClient.get("/api/v1/devices/import-template", {
    params: { include_devices: includeDevices }, responseType: "blob", timeout: LONG_OP_TIMEOUT_MS,
  });
  const url = URL.createObjectURL(resp.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = includeDevices ? "devices-import.csv" : "devices-import-template.csv";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
