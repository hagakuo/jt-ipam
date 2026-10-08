"""issue #44：Proxmox 所有節點都驗證失敗時，同步仍回報「成功、0 筆」。

使用者看到「成功、新增 0／更新 0」會以為環境裡真的沒有 VM，而不是整合連不上。
連不上／認證失敗是硬失敗：寫 last_error、往上拋，讓作業顯示「失敗」並帶最後一個錯誤。
DNS 同步早就這樣做；同一個寫法（接住錯誤、塞進 summary、照樣回傳）在 LibreNMS 與 AdGuard 也有，一起修。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.adguard import AdGuardInstance
from app.models.background_task import BackgroundTask
from app.models.librenms import LibreNMSInstance
from app.models.virt import ProxmoxInstance
from app.services import adguard as adguard_svc
from app.services import background_tasks as bt
from app.services import librenms as lnms
from app.services import proxmox as px


async def _pve(session) -> ProxmoxInstance:
    inst = ProxmoxInstance(api_url="https://pve-a.example.com:8006", auth_username="root@pam",
                           auth_token_id="jtipam",
                           extra_api_urls="https://pve-b.example.com:8006\nhttps://pve-c.example.com:8006")
    session.add(inst)
    await session.flush()
    return inst


def _all_401(monkeypatch, tried: list[str]):
    async def fake(_s, _inst, path, *, base_url=None, timeout=None):
        tried.append(base_url or "")
        raise px.ProxmoxError(f"Proxmox {path}: 401 Authentication failed!")
    monkeypatch.setattr(px, "_api_get", fake)


@pytest.mark.anyio
async def test_proxmox_all_nodes_failing_is_a_failure_not_success_zero(db_session, monkeypatch) -> None:
    tried: list[str] = []
    _all_401(monkeypatch, tried)
    inst = await _pve(db_session)
    with pytest.raises(px.ProxmoxError) as ei:
        await px.sync_instance(db_session, inst)
    assert "401" in str(ei.value), "要帶最後一個錯誤，使用者才知道是認證問題"
    assert len(set(tried)) == 3, "三個候選節點都要試過"
    await db_session.refresh(inst)
    assert inst.last_error and "401" in inst.last_error, "last_error 要寫進去（整合頁看得到）"


@pytest.mark.anyio
async def test_proxmox_pull_task_ends_failed_with_the_error(db_session, monkeypatch) -> None:
    """「拉取」走背景作業：作業要是「失敗」並帶錯誤，而不是「成功、0 筆」。"""
    tried: list[str] = []
    _all_401(monkeypatch, tried)
    inst = await _pve(db_session)
    await db_session.commit()
    task = BackgroundTask(kind="proxmox.sync", status="pending", trigger="manual", progress=0)
    db_session.add(task)
    await db_session.commit()

    async def runner(sess, _t):
        i = await sess.get(ProxmoxInstance, inst.id)
        return (await px.sync_instance(sess, i)).to_dict()

    await bt._run(task.id, runner)
    await db_session.refresh(task)
    assert task.status == "failed"
    assert "401" in (task.error or "")


@pytest.mark.anyio
async def test_librenms_unreachable_is_a_failure(db_session, monkeypatch) -> None:
    inst = LibreNMSInstance(name=f"lnms-{uuid.uuid4().hex[:6]}", api_url="http://192.0.2.63",
                            api_token_enc=b"x", api_token_nonce=b"x", enabled=True, sync_devices=True)
    db_session.add(inst)
    await db_session.flush()

    async def fake(_inst, path, *, timeout=30.0):
        raise lnms.LibreNMSError(f"LibreNMS {path}: 401 Unauthenticated")
    monkeypatch.setattr(lnms, "_api_get", fake)
    with pytest.raises(lnms.LibreNMSError):
        await lnms.sync_instance(db_session, inst)
    await db_session.refresh(inst)
    assert inst.last_error and "401" in inst.last_error


@pytest.mark.anyio
async def test_adguard_unreachable_is_a_failure(db_session, monkeypatch) -> None:
    inst = AdGuardInstance(name=f"ag-{uuid.uuid4().hex[:6]}", api_url="https://adguard.local",
                           api_user="admin", api_password_enc=b"x", api_password_nonce=b"x",
                           enabled=True, sync_clients=True)
    db_session.add(inst)
    await db_session.flush()

    async def fake(_inst, path, *, timeout=15.0):
        raise adguard_svc.AdGuardError(f"AdGuard {path}: 401")
    monkeypatch.setattr(adguard_svc, "_api_get", fake)
    with pytest.raises(adguard_svc.AdGuardError):
        await adguard_svc.sync_instance(db_session, inst)
    await db_session.refresh(inst)
    assert inst.last_error and "401" in inst.last_error
