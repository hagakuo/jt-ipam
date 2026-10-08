/**
 * 給「會改到帳號自己設定」的 spec 用的臨時管理員帳號（語言、儀表板偏好…）。
 *
 * 平行跑 e2e 時大家共用同一個 admin：一支 spec 把 admin 的語言改成日文，同時間別的 spec 打開的畫面就變日文，
 * 用中文字串找元素全部失敗 —— 看起來像功能壞了（2026-10-02 發版時踩到）。改用自己的帳號就不會影響別人。
 */
import crypto from "node:crypto";
import { expect, type APIRequestContext } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

async function adminToken(request: APIRequestContext): Promise<string> {
  const r = await request.post("/api/v1/auth/login",
    { data: { username: ADMIN_USER, password: ADMIN_PASS, realm: "local" } });
  expect(r.ok(), "admin API 登入要成功").toBeTruthy();
  return (await r.json()).access_token;
}

export interface TempUser { id: string; username: string; password: string }

export async function createTempAdmin(request: APIRequestContext, prefix: string): Promise<TempUser> {
  const username = `e2e-${prefix}-${Date.now().toString(36)}`;
  const password = `Tmp-${crypto.randomBytes(9).toString("base64url")}`;
  const r = await request.post("/api/v1/users", {
    headers: { Authorization: `Bearer ${await adminToken(request)}` },
    data: { username, email: `${username}@example.com`, password, is_admin: true },
  });
  expect(r.status(), await r.text()).toBe(201);
  return { id: (await r.json()).id, username, password };
}

export async function deleteTempUser(request: APIRequestContext, user: TempUser | null): Promise<void> {
  if (!user) return;
  await request.delete(`/api/v1/users/${user.id}`,
    { headers: { Authorization: `Bearer ${await adminToken(request)}` } });
}
