"""SFTP 的權限閘門：獨立的開關，但與 SSH 同等強度的授權。

`sftp_enabled` 與 `ssh_enabled` 各自獨立 —— 可以只開放傳檔、不開放終端機（反之亦然）。
但**授權模型必須一樣嚴**：SFTP 是遠端檔案讀寫，若它比 SSH 鬆一級，等於在 SSH 旁邊開了
一道沒鎖的門。
"""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient


async def _user(db_session, *, can_ssh: bool, admin: bool = False):
    from app.core.security import hash_password
    from app.models.user import User
    u = User(username=f"sftp-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@e.test",
             password_hash=hash_password("Xx!12345678xX"), is_admin=admin, is_active=True,
             can_ssh=can_ssh)
    db_session.add(u)
    await db_session.flush()
    return u


async def _ip(db_session, *, ssh: bool = True, sftp: bool = True):
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="198.51.100.5", ssh_enabled=ssh, sftp_enabled=sftp)
    db_session.add(ipa)
    await db_session.flush()
    return ipa


@pytest.mark.anyio
async def test_a_user_without_ssh_rights_cannot_get_an_sftp_ticket(client: AsyncClient, db_session):
    from app.services.auth import issue_access_token
    u = await _user(db_session, can_ssh=False)
    ipa = await _ip(db_session)
    await db_session.commit()
    r = await client.post(f"/api/v1/addresses/{ipa.id}/sftp/ticket",
                          headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 403


@pytest.mark.anyio
async def test_both_open_means_the_same_verdict_for_the_same_user(client: AsyncClient, db_session):
    """兩個開關都開時，同一個帳號在 SSH 與 SFTP 上的判斷結果必須一致。

    兩邊各自實作一套授權判斷，遲早會有一邊被改鬆 —— 這條測試守的是那個。
    """
    from app.services.auth import issue_access_token
    u = await _user(db_session, can_ssh=False)
    ipa = await _ip(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {issue_access_token(u)}"}
    ssh = await client.post(f"/api/v1/addresses/{ipa.id}/ssh/ticket", headers=h)
    sftp = await client.post(f"/api/v1/addresses/{ipa.id}/sftp/ticket", headers=h)
    assert ssh.status_code == sftp.status_code


@pytest.mark.anyio
async def test_sftp_off_blocks_sftp_even_when_ssh_is_on(client: AsyncClient, db_session, fake_redis):
    """只開 SSH 不開 SFTP：admin 也拿不到 SFTP ticket，但 SSH 照常。

    這是「獨立開關」的重點 —— 若 SFTP 還是看 ssh_enabled，這條會過不了。
    """
    from app.services.auth import issue_access_token
    u = await _user(db_session, can_ssh=True, admin=True)
    ipa = await _ip(db_session, ssh=True, sftp=False)
    await db_session.commit()
    h = {"Authorization": f"Bearer {issue_access_token(u)}"}
    assert (await client.post(f"/api/v1/addresses/{ipa.id}/sftp/ticket", headers=h)).status_code == 403
    assert (await client.post(f"/api/v1/addresses/{ipa.id}/ssh/ticket", headers=h)).status_code == 200


@pytest.mark.anyio
async def test_ssh_off_still_allows_sftp_when_sftp_is_on(client: AsyncClient, db_session, fake_redis):
    """只開 SFTP 不開 SSH：傳得了檔，但開不了終端機 —— 這正是這個開關存在的理由。"""
    from app.services.auth import issue_access_token
    u = await _user(db_session, can_ssh=True, admin=True)
    ipa = await _ip(db_session, ssh=False, sftp=True)
    await db_session.commit()
    h = {"Authorization": f"Bearer {issue_access_token(u)}"}
    assert (await client.post(f"/api/v1/addresses/{ipa.id}/sftp/ticket", headers=h)).status_code == 200
    assert (await client.post(f"/api/v1/addresses/{ipa.id}/ssh/ticket", headers=h)).status_code == 403


@pytest.mark.anyio
async def test_a_missing_address_is_404_not_a_ticket(client: AsyncClient, db_session):
    from app.services.auth import issue_access_token
    u = await _user(db_session, can_ssh=True, admin=True)
    await db_session.commit()
    r = await client.post(f"/api/v1/addresses/{uuid.uuid4()}/sftp/ticket",
                          headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 404


class _FakeRedis:
    """夠用的假 Redis：set 與「取出即刪」。

    用假的而不是 skip —— ticket 的「單次有效」與「綁定該位址」正是這道門的全部，
    跳過等於這兩件事沒有被測到。取出走 `eval`：正式碼用 Lua 而非 `GETDEL`（後者
    要 Redis 6.2+），見 `app/core/tickets.py`；這裡照同一個介面實作。
    """

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value.encode() if isinstance(value, str) else value

    async def eval(self, _script: str, _numkeys: int, key: str) -> bytes | None:
        return self.store.pop(key, None)


@pytest.fixture
def fake_redis(monkeypatch):
    fake = _FakeRedis()
    # 兩個端點都要換掉：它們各自 `from ... import _redis_client`，只改來源模組沒有用
    monkeypatch.setattr("app.api.v1.endpoints.sftp_console._redis_client", lambda: fake)
    monkeypatch.setattr("app.api.v1.endpoints.ssh_console._redis_client", lambda: fake)
    monkeypatch.setattr("app.core.rate_limit._redis_client", lambda: fake)
    return fake


@pytest.mark.anyio
async def test_a_ticket_works_once_and_only_for_its_own_address(db_session, fake_redis):
    """單次有效、而且只對換發時那個位址有效。"""
    import json as _json

    from app.api.v1.endpoints.sftp_console import _redeem, _ticket_key
    u = await _user(db_session, can_ssh=True, admin=True)
    ipa = await _ip(db_session)
    await db_session.commit()

    await fake_redis.set(_ticket_key("tk1"),
                         _json.dumps({"user_id": str(u.id), "ip_id": str(ipa.id)}))
    # 換給別的位址 → 不接受
    assert await _redeem("tk1", uuid.uuid4()) is None
    # 正確的位址 → 通過
    await fake_redis.set(_ticket_key("tk2"),
                         _json.dumps({"user_id": str(u.id), "ip_id": str(ipa.id)}))
    assert await _redeem("tk2", ipa.id) == u.id
    # 用過就沒了
    assert await _redeem("tk2", ipa.id) is None


@pytest.mark.anyio
async def test_the_websocket_rejects_a_bogus_ticket(fake_redis):
    """沒有有效 ticket 就不該開得起來 —— WS 帶不了 Authorization，這是唯一的門。"""
    from app.api.v1.endpoints.sftp_console import _redeem
    assert await _redeem("", uuid.uuid4()) is None
    assert await _redeem("not-a-real-ticket", uuid.uuid4()) is None
