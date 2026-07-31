import { apiClient } from "@/api/client";

export interface EnrollResponse {
  secret: string;
  otpauth_uri: string;
}

export async function enroll(): Promise<EnrollResponse> {
  const { data } = await apiClient.post<EnrollResponse>("/api/v1/auth/totp/enroll");
  return data;
}

export async function confirm(secret: string, code: string): Promise<void> {
  await apiClient.post("/api/v1/auth/totp/confirm", { secret, code });
}

/** 停用 TOTP 需要升級驗證：本機帳號給密碼，外部認證帳號給當前 6 位數驗證碼。 */
export async function disable(payload: { password?: string; code?: string }): Promise<void> {
  await apiClient.post("/api/v1/auth/totp/disable", payload);
}
