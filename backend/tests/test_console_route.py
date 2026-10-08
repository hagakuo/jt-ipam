"""主控台的連線出口解析與跳板通道（issue #24 階段一）。

這一組測試守的是**「連到別人」**這個後果，不只是「連不上」。會用跳板的站台，多半正是
多個客戶共用相同私網網段的站台；一旦出口解析錯了、或某條路徑安靜地退回直連，
後端就會拿同一個私網位址去連 —— 然後打到另一個客戶的機器上。這種錯誤不會有紅字。
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.models.address import IPAddress
from app.models.jump_host import JumpHost
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import console_route


async def _mk_jump(session: Any, name: str, **kw: Any) -> JumpHost:
    jump = JumpHost(name=name, host=kw.pop("host", "198.51.100.9"),
                    username="jump", auth_kind="key", **kw)
    session.add(jump)
    await session.flush()
    jump.private_key_enc, jump.private_key_nonce = console_route.encrypt_secret_for(
        jump.id, "private_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n")
    await session.flush()
    return jump


async def _mk_ip(session: Any, *, subnet_jump: JumpHost | None = None,
                 ip_jump: JumpHost | None = None) -> IPAddress:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    session.add(sec)
    await session.flush()
    subnet = Subnet(section_id=sec.id, cidr="192.0.2.0/24",
                    jump_host_id=subnet_jump.id if subnet_jump else None)
    session.add(subnet)
    await session.flush()
    ipa = IPAddress(subnet_id=subnet.id, ip="192.0.2.50",
                    jump_host_id=ip_jump.id if ip_jump else None)
    session.add(ipa)
    await session.flush()
    return ipa


@pytest.mark.anyio
async def test_no_assignment_means_direct(db_session: Any) -> None:
    ipa = await _mk_ip(db_session)
    route = await console_route.resolve_route(db_session, ipa)
    assert isinstance(route, console_route.Direct)
    assert console_route.route_label(route) is None


@pytest.mark.anyio
async def test_subnet_assignment_is_inherited(db_session: Any) -> None:
    jump = await _mk_jump(db_session, f"j-sub-{uuid.uuid4().hex[:6]}")
    ipa = await _mk_ip(db_session, subnet_jump=jump)
    route = await console_route.resolve_route(db_session, ipa)
    assert isinstance(route, console_route.ViaJumpHost)
    assert route.id == jump.id


@pytest.mark.anyio
async def test_ip_overrides_subnet(db_session: Any) -> None:
    """IP 上的設定要蓋過子網路的 —— 順序反了會把單一台機器的例外整批帶錯路。"""
    sub_jump = await _mk_jump(db_session, f"j-sub-{uuid.uuid4().hex[:6]}")
    ip_jump = await _mk_jump(db_session, f"j-ip-{uuid.uuid4().hex[:6]}")
    ipa = await _mk_ip(db_session, subnet_jump=sub_jump, ip_jump=ip_jump)
    route = await console_route.resolve_route(db_session, ipa)
    assert isinstance(route, console_route.ViaJumpHost)
    assert route.id == ip_jump.id, "IP 覆寫沒有優先於子網路"


@pytest.mark.anyio
async def test_disabled_jump_host_refuses_instead_of_going_direct(db_session: Any) -> None:
    """停用的跳板要拒絕連線，不可以退回直連（issue #24，2026-10-02 使用者決定）。

    以前停用＝直連：在重疊網段的站台，後端會拿同一個私網位址連到**自己網路上**那台，
    也就是連錯主機，而且畫面上看起來一切正常。要直連就把子網路／IP 的跳板指派拿掉，那是明確的動作。
    """
    jump = await _mk_jump(db_session, f"j-off-{uuid.uuid4().hex[:6]}", enabled=False)
    for ipa in (await _mk_ip(db_session, subnet_jump=jump), await _mk_ip(db_session, ip_jump=jump)):
        with pytest.raises(console_route.JumpHostError) as exc:
            await console_route.resolve_route(db_session, ipa)
        assert exc.value.code == "jump_host_disabled"
        assert exc.value.params["name"] == jump.name


@pytest.mark.anyio
async def test_secret_round_trips_and_is_bound_to_the_row(db_session: Any) -> None:
    """機密以 AES-GCM 加密，AAD 綁這一列的 id —— 換到別列就解不開。"""
    from app.core.security import decrypt_secret
    jump = await _mk_jump(db_session, f"j-sec-{uuid.uuid4().hex[:6]}")
    route = await console_route.resolve_route(
        db_session, await _mk_ip(db_session, subnet_jump=jump))
    assert isinstance(route, console_route.ViaJumpHost)
    assert "OPENSSH PRIVATE KEY" in route.secret

    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        decrypt_secret(jump.private_key_enc, jump.private_key_nonce,
                       aad=b"jump_host:00000000-0000-0000-0000-000000000000:private_key")


@pytest.mark.anyio
async def test_missing_secret_says_so_instead_of_failing_at_connect(db_session: Any) -> None:
    jump = JumpHost(name=f"j-nokey-{uuid.uuid4().hex[:6]}", host="198.51.100.9",
                    username="jump", auth_kind="key")
    db_session.add(jump)
    await db_session.flush()
    ipa = await _mk_ip(db_session, subnet_jump=jump)
    with pytest.raises(console_route.JumpHostError, match="金鑰"):
        await console_route.resolve_route(db_session, ipa)


# ─────────────────── 通道 ───────────────────

@pytest.mark.anyio
async def test_direct_route_costs_nothing() -> None:
    """直連時 `open_route` 不可以建立任何連線 —— 它在每一條主控台的熱路徑上。"""
    tunnel = await console_route.open_route(console_route.Direct(), "203.0.113.7", 22)
    assert (tunnel.host, tunnel.port) == ("203.0.113.7", 22)
    assert tunnel.via is None
    await tunnel.aclose()
    await tunnel.aclose()          # 可以關兩次（finally 疊 finally）


@pytest.mark.anyio
async def test_unpinned_host_key_refuses_to_connect() -> None:
    """跳板是整條路徑的中間人：沒釘選指紋就不連，而不是「先連再說」。"""
    route = console_route.ViaJumpHost(
        id=uuid.uuid4(), name="j", host="198.51.100.9", port=22, username="u",
        auth_kind="key", secret="x", host_key_fingerprint=None, max_sessions=10)
    with pytest.raises(console_route.JumpHostError, match="尚未信任主機金鑰"):
        await console_route.open_route(route, "192.0.2.50", 22)


@pytest.mark.anyio
async def test_session_limit_is_enforced_per_jump_host(monkeypatch: Any) -> None:
    """同時連線上限要真的擋 —— 客戶的跳板往往是台小機器。"""

    class _FakeListener:
        def get_port(self) -> int:
            return 40000

        def close(self) -> None:
            pass

    class _FakeConn:
        def __init__(self) -> None:
            self.closed = False

        async def forward_local_port(self, *_a: Any) -> _FakeListener:
            return _FakeListener()

        def close(self) -> None:
            self.closed = True

    conn = _FakeConn()

    async def fake_connect(_route: Any) -> Any:
        return conn

    monkeypatch.setattr(console_route, "_connect", fake_connect)
    route = console_route.ViaJumpHost(
        id=uuid.uuid4(), name="j", host="198.51.100.9", port=22, username="u",
        auth_kind="key", secret="x", host_key_fingerprint="SHA256:x", max_sessions=2)

    a = await console_route.open_route(route, "192.0.2.50", 22)
    b = await console_route.open_route(route, "192.0.2.51", 22)
    assert (a.host, a.port) == ("127.0.0.1", 40000)
    with pytest.raises(console_route.JumpHostError, match="上限"):
        await console_route.open_route(route, "192.0.2.52", 22)

    # 共用同一條 SSH 連線：最後一個 session 離開才關
    await a.aclose()
    assert conn.closed is False, "還有 session 在用就把連線關掉了"
    await b.aclose()
    assert conn.closed is True, "最後一個 session 離開後沒有關閉連線"


@pytest.mark.anyio
async def test_a_failed_forward_returns_the_reference(monkeypatch: Any) -> None:
    """轉發失敗也要把 refs 還回去，否則幾次失敗就把上限用光、之後全部連不上。"""
    import asyncssh

    class _FakeConn:
        def __init__(self) -> None:
            self.closed = False

        async def forward_local_port(self, *_a: Any) -> Any:
            raise asyncssh.ChannelOpenError(1, "connect failed")

        def close(self) -> None:
            self.closed = True

    async def fake_connect(_route: Any) -> Any:
        return _FakeConn()

    monkeypatch.setattr(console_route, "_connect", fake_connect)
    route = console_route.ViaJumpHost(
        id=uuid.uuid4(), name="j", host="198.51.100.9", port=22, username="u",
        auth_kind="key", secret="x", host_key_fingerprint="SHA256:x", max_sessions=1)

    for _ in range(3):
        with pytest.raises(console_route.JumpHostError, match="無法轉發"):
            await console_route.open_route(route, "192.0.2.50", 22)
    assert console_route._pool == {}, "失敗的嘗試把連線池卡住了"


@pytest.mark.anyio
async def test_unreachable_jump_host_error_carries_the_reason(monkeypatch: Any) -> None:
    """「連不上」要說得出是哪一種：名稱解析、拒絕連線、路由不通長得完全不一樣。"""
    import asyncssh

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise OSError(113, "No route to host")

    monkeypatch.setattr("asyncssh.connect", boom)
    route = console_route.ViaJumpHost(
        id=uuid.uuid4(), name="邊界跳板", host="198.51.100.9", port=22, username="u",
        auth_kind="key",
        # 要用真的能解析的金鑰：金鑰解析失敗會在連線之前就擋下來，
        # 那樣這個測試就驗不到「連線錯誤有沒有帶原文」了（第一版就踩到）
        secret=asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode(),
        host_key_fingerprint="SHA256:x", max_sessions=10)
    with pytest.raises(console_route.JumpHostError) as exc:
        await console_route._connect(route)
    msg = str(exc.value)
    assert "邊界跳板" in msg
    assert "No route to host" in msg, "少了底層原文就只能猜"
