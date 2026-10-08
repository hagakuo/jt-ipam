"""PVE 主控台登入失敗要分得出原因（使用者回報，2026-09-24）。

用已存的 PVE 帳密連 noVNC，一律只看到「PVE 認證失敗（帳號或密碼錯誤）」。PVE 的
/access/ticket 對密碼錯、帳號不存在、帳號停用、realm 不對全都回 401、不給原因，但還是有
幾件事分得出來、或至少講得出關鍵線索：

- realm 打錯：/access/domains 不用登入就查得到有哪些 realm，直接講出來。
- 帳密被拒：講出是哪一台 PVE、用哪個 user@realm —— 並提醒要的是 **PVE 的帳密，不是這台
  VM 自己的**（連 VM 的 IP 開主控台時最常見的誤會）。
- 用的是已存帳密：講出是哪一組（存的時候密碼可能就打錯了）。
- 連不上：講出底層原因（連線被拒／名稱解析不到／TLS 驗不過），不是只有類別名稱。
"""
from __future__ import annotations

import httpx
import pytest
from app.services import pve_console as pc

BASE = "https://pve.example.com:8006"


class _Resp:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._p = payload
        self.status_code = status

    def json(self) -> dict:
        return self._p


def _patch(monkeypatch, *, ticket_status: int = 401, realms: list[str] | None = ("pam", "pve"),
           domains_error: Exception | None = None) -> list[str]:
    calls: list[str] = []

    async def fake(method, url, *, json=None, timeout=None, verify=None, **_kw):
        calls.append(f"{method} {url}")
        if url.endswith("/access/domains"):
            if domains_error is not None:
                raise domains_error
            return _Resp({"data": [{"realm": r, "type": r} for r in (realms or [])]})
        return _Resp({"data": None}, status=ticket_status)

    monkeypatch.setattr(pc, "safe_request", fake)
    return calls


@pytest.mark.anyio
async def test_rejected_credentials_name_the_host_and_the_account(monkeypatch) -> None:
    _patch(monkeypatch)
    with pytest.raises(pc.PveConsoleError) as exc:
        await pc.pve_login(BASE, "root@pam", "wrong", False)
    e = exc.value
    assert e.code == "pve_auth_failed"
    assert e.http_status == 401
    assert e.params["user"] == "root@pam"
    assert e.params["host"] == "pve.example.com:8006"
    assert "不是這台 VM" in str(e), "連 VM 的 IP 開主控台，最常見的誤會是填了 VM 自己的帳密"


@pytest.mark.anyio
async def test_unknown_realm_is_named_with_the_ones_that_exist(monkeypatch) -> None:
    calls = _patch(monkeypatch, realms=["pam", "pve", "corp-ad"])
    with pytest.raises(pc.PveConsoleError) as exc:
        await pc.pve_login(BASE, "root@pem", "pw", False)
    e = exc.value
    assert e.code == "pve_unknown_realm"
    assert e.params["realm"] == "pem"
    assert e.params["available"] == "pam, pve, corp-ad"
    assert any(c.startswith("GET ") and c.endswith("/api2/json/access/domains") for c in calls)


@pytest.mark.anyio
async def test_realm_lookup_failing_does_not_hide_the_real_answer(monkeypatch) -> None:
    """查 realm 只是補充線索；它自己失敗時，照樣回「帳密被拒」而不是別的錯。"""
    _patch(monkeypatch, domains_error=httpx.ConnectError("boom"))
    with pytest.raises(pc.PveConsoleError) as exc:
        await pc.pve_login(BASE, "root@pam", "pw", False)
    assert exc.value.code == "pve_auth_failed"


@pytest.mark.anyio
async def test_unreachable_names_the_underlying_cause(monkeypatch) -> None:
    async def fake(method, url, **_kw):
        try:
            raise ConnectionRefusedError(111, "Connection refused")
        except ConnectionRefusedError as inner:
            raise httpx.ConnectError("All connection attempts failed") from inner

    monkeypatch.setattr(pc, "safe_request", fake)
    with pytest.raises(pc.PveConsoleError) as exc:
        await pc.pve_login(BASE, "root@pam", "pw", False)
    assert exc.value.code == "pve_unreachable"
    assert "Connection refused" in exc.value.params["reason"], \
        "只有「ConnectError」分不出是連線被拒、名稱解析不到還是憑證驗不過"


@pytest.mark.anyio
async def test_saved_credential_rejection_names_which_one(
    db_session, client, auth_headers, admin_user, monkeypatch,
) -> None:
    """用已存帳密被 PVE 拒絕 → 講出是哪一組（使用者回報的情境：存的時候密碼可能就打錯了）。"""
    import uuid

    from app.api.v1.endpoints import novnc_console as ep
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet

    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.79", novnc_enabled=True)
    db_session.add(ip)
    await db_session.commit()

    target = pc.PveTarget(kind="vm", node="pve1", vmid=101, cluster_name=None,
                          base_url=BASE, verify_tls=False)

    async def fake_target(_s, _ip):
        return target

    async def fake_login(base_url, username, password, verify_tls, *, tfa_code=None):
        raise pc.PveConsoleError("rejected", code="pve_auth_failed", status=401,
                                 user=username, host="pve.example.com:8006")

    monkeypatch.setattr(pc, "resolve_pve_target", fake_target)
    monkeypatch.setattr(pc, "pve_login", fake_login)
    monkeypatch.setattr(ep, "NOVNC_AVAILABLE", True)

    r = await client.post("/api/v1/ssh-credentials", headers=auth_headers, json={
        "label": "pve@198.51.100.79", "username": "root@pam", "password": "typo",
        "auth_type": "password", "protocol": "pve", "target_ip_id": str(ip.id)})
    assert r.status_code == 201, r.text
    cred_id = r.json()["id"]

    r = await client.post(f"/api/v1/addresses/{ip.id}/novnc/ticket", headers=auth_headers,
                          json={"credential_id": cred_id})
    assert r.status_code == 401, r.text
    d = r.json()["detail"]
    assert d["code"] == "pve_auth_failed_saved"
    assert d["params"]["label"] == "pve@198.51.100.79"
    assert d["params"]["user"] == "root@pam"
