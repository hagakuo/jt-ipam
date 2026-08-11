"""新增 VMware 主機的表單欄位，後端必須收得下。

客戶回報（0.5.149）：新增 VMware 主機一律失敗，`POST /api/v1/esxi` 回 422
`extra_forbidden`，指向 `extra_api_urls`。

成因：備援位址欄位加在 model、migration 與前端表單上，卻**沒有加進任何一個
schema**。`StrictModel` 是 extra=forbid，所以每一次新增都被擋下 —— 整個整合從發布
起就完全不能用，而且連續兩版都帶著這個問題出去。

服務層的測試（SOAP 解析、同步）全都是綠的，因為它們根本沒有經過 schema。
**端點的欄位契約要自己測**：能不能建、建完存不存在、改得動嗎。
"""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient


def _payload(**over):
    body = {
        "name": f"esxi-{uuid.uuid4().hex[:6]}",
        "api_url": "https://esxi.example.test",
        "username": "ro@vsphere.local",
        "password": "s3cret-pw",
    }
    body.update(over)
    return body


@pytest.mark.anyio
async def test_creating_a_host_with_failover_addresses_works(client: AsyncClient, auth_headers):
    """備援位址是這個欄位存在的理由 —— 送出去必須收得下。"""
    body = _payload(extra_api_urls="https://esxi-b.example.test\nhttps://esxi-c.example.test")
    r = await client.post("/api/v1/esxi", json=body, headers=auth_headers)
    assert r.status_code in (200, 201), r.text
    assert "esxi-b.example.test" in (r.json().get("extra_api_urls") or "")


@pytest.mark.anyio
async def test_an_empty_failover_field_is_accepted(client: AsyncClient, auth_headers):
    """表單沒填時前端送的是 null —— 客戶踩到的正是這一個。"""
    r = await client.post("/api/v1/esxi", json=_payload(extra_api_urls=None),
                          headers=auth_headers)
    assert r.status_code in (200, 201), r.text


@pytest.mark.anyio
async def test_the_field_can_be_edited_afterwards(client: AsyncClient, auth_headers):
    r = await client.post("/api/v1/esxi", json=_payload(), headers=auth_headers)
    assert r.status_code in (200, 201), r.text
    rid = r.json()["id"]
    r2 = await client.patch(f"/api/v1/esxi/{rid}",
                            json={"extra_api_urls": "https://vc2.example.test"},
                            headers=auth_headers)
    assert r2.status_code == 200, r2.text
    assert "vc2.example.test" in (r2.json().get("extra_api_urls") or "")


@pytest.mark.anyio
async def test_every_field_the_form_sends_is_accepted(client: AsyncClient, auth_headers):
    """一字不差照抄前端表單送出的 payload（ESXiAdmin.vue 的 submit()）。

    少收任何一個鍵都是同一種 422，而使用者只會看到「新增不了」。這裡刻意連
    `description: null`、`scope_subnet_ids: null`、`extra_api_urls: null` 都照送 ——
    客戶踩到的就是全部留空的那一版。
    """
    body = {
        "name": f"esxi-{uuid.uuid4().hex[:6]}",
        "api_url": "https://esxi.example.test",
        "username": "ro@vsphere.local",
        "password": "s3cret-pw",
        "enabled": True,
        "verify_tls": True,
        "sync_interval_seconds": 300,
        "description": None,
        "extra_api_urls": None,
        "scope_subnet_ids": None,
    }
    r = await client.post("/api/v1/esxi", json=body, headers=auth_headers)
    assert r.status_code in (200, 201), r.text

    # 再送一次填了備援位址的版本，確認值真的存進去
    body2 = dict(body, name=f"esxi-{uuid.uuid4().hex[:6]}",
                 extra_api_urls="https://esxi-b.example.test\nhttps://esxi-c.example.test")
    r2 = await client.post("/api/v1/esxi", json=body2, headers=auth_headers)
    assert r2.status_code in (200, 201), r2.text
    assert "esxi-c.example.test" in (r2.json().get("extra_api_urls") or "")


def test_no_model_field_is_unreachable_through_the_schema():
    """守住「欄位加在 model 與表單、卻漏了 schema」這一類缺陷。

    這正是客戶踩到的形狀：`StrictModel` 是 extra=forbid，schema 少一個鍵，整張表單
    就 422，而服務層的測試全都是綠的（它們不經過 schema）。新增欄位時若刻意不對外
    開放，把它加進 INTERNAL 即可 —— 重點是要「刻意」，不是忘記。
    """
    from sqlalchemy import inspect as sa_inspect
    from app.models.esxi import ESXiInstance
    from app.schemas.esxi import ESXiCreate, ESXiUpdate

    INTERNAL = {
        "id", "created_at", "updated_at",       # 系統維護
        "cluster_id", "last_sync_at", "last_error",  # 同步結果，非設定
        "password_enc", "password_nonce",       # 密文不對外，明文走 password 欄位
    }
    cols = {c.key for c in sa_inspect(ESXiInstance).columns} - INTERNAL
    for schema in (ESXiCreate, ESXiUpdate):
        missing = sorted(cols - set(schema.model_fields))
        assert not missing, f"{schema.__name__} 收不到 model 的欄位：{missing}"


@pytest.mark.anyio
async def test_connection_test_fails_readably_not_with_a_500(client: AsyncClient, auth_headers):
    """新增之後客戶會按的下一顆按鈕就是「測試連線」。

    連不上是正常情況（打錯位址、防火牆擋住、憑證不對），必須回可讀訊息 ——
    回 500 的話畫面只會顯示「伺服器發生錯誤」，使用者完全不知道要調什麼。
    """
    r = await client.post("/api/v1/esxi", json=_payload(), headers=auth_headers)
    rid = r.json()["id"]
    t = await client.post(f"/api/v1/esxi/{rid}/test", headers=auth_headers)
    assert t.status_code != 500, t.text
    body = t.json()
    # 不論成功與否，都要有可讀的內容（ok 旗標或訊息），不能是空的
    assert body and (("ok" in body) or ("detail" in body) or ("steps" in body))


@pytest.mark.anyio
async def test_sync_now_fails_readably_not_with_a_500(client: AsyncClient, auth_headers):
    r = await client.post("/api/v1/esxi", json=_payload(), headers=auth_headers)
    rid = r.json()["id"]
    s = await client.post(f"/api/v1/esxi/{rid}/sync", headers=auth_headers)
    assert s.status_code != 500, s.text


@pytest.mark.anyio
async def test_clearing_the_failover_field_stores_null_not_an_empty_string(
    client: AsyncClient, auth_headers,
):
    """把備援位址清空，存的應該是「沒有」，不是一個空字串。

    兩者行為目前一樣，但空字串會讓「有沒有設過」這件事在資料層變得模稜兩可。
    """
    r = await client.post("/api/v1/esxi", json=_payload(extra_api_urls="https://b.example.test"),
                          headers=auth_headers)
    rid = r.json()["id"]
    r2 = await client.patch(f"/api/v1/esxi/{rid}", json={"extra_api_urls": ""},
                            headers=auth_headers)
    assert r2.status_code == 200, r2.text
    assert r2.json().get("extra_api_urls") is None
