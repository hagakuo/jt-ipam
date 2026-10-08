"""從掃描代理執行探測：安全邊界與工作生命週期。

這個功能讓後端可以指使代理對客戶內網發包，因此**驗證比功能本身重要**。
被守住的性質：

- 只接受允許清單探測種類（絕不執行任意指令）
- 目標必須是 IP 或合法主機名稱（不讓奇怪字串進到子行程 argv）
- 埠與數量都有上限，待辦數也有上限（代理離線時使用者連按不會堆積）
- 代理只能結束**自己領到**的工作
- 沒人領的工作會過期作廢（避免代理上線後補跑一堆遲來的探測）
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.agent_probe_job import (
    STATUS_DONE,
    STATUS_EXPIRED,
    STATUS_PENDING,
    STATUS_RUNNING,
    AgentProbeJob,
)
from app.models.scan_agent import ScanAgent
from app.services.agent_probe import (
    MAX_PENDING_PER_AGENT,
    ProbeJobError,
    claim_jobs,
    create_job,
    expire_stale,
    finish_job,
    validate_params,
)


# ─────────── 參數驗證（安全核心）───────────
@pytest.mark.parametrize("kind", ["exec", "shell", "os", "", "PING; rm -rf /"])
def test_only_allowlisted_probe_kinds(kind) -> None:
    """允許清單之外一律拒絕 —— 這個端點絕不能變成遠端執行任意指令的入口。"""
    with pytest.raises(ProbeJobError):
        validate_params(kind, {"targets": "198.51.100.1"})


@pytest.mark.parametrize("target", [
    "198.51.100.1; rm -rf /",       # 命令串接
    "$(whoami)",                    # 命令替換
    "`id`",
    "-oProxyCommand=curl evil",     # 參數注入（被當成 ping 的旗標）
    "a" * 300,                      # 超長
    "../../etc/passwd",
])
def test_hostile_targets_are_rejected(target) -> None:
    """即使代理端一律用陣列傳參數、不經過 shell，也不讓這種字串進到 argv。"""
    with pytest.raises(ProbeJobError):
        validate_params("ping", {"targets": target})


def test_valid_targets_pass() -> None:
    out = validate_params("ping", {"targets": "198.51.100.1, host.example.net\n203.0.113.9"})
    assert out["targets"] == ["198.51.100.1", "host.example.net", "203.0.113.9"]


def test_counts_and_timeouts_are_clamped() -> None:
    """使用者給的數值一律夾在合理範圍，避免一次請求把代理綁住幾分鐘。"""
    out = validate_params("ping", {"targets": "198.51.100.1", "count": 9999, "timeout": 9999})
    assert out["count"] == 10
    assert out["timeout"] == 10.0


def test_port_validation() -> None:
    assert validate_params("tcp", {"targets": "198.51.100.1", "ports": "22,443"})["ports"] \
        == [22, 443]
    for bad in ("0", "65536", "abc", ""):
        with pytest.raises(ProbeJobError):
            validate_params("tcp", {"targets": "198.51.100.1", "ports": bad})
    with pytest.raises(ProbeJobError):
        validate_params("tcp", {"targets": "198.51.100.1",
                                "ports": ",".join(str(p) for p in range(1, 100))})


def test_too_many_targets_rejected() -> None:
    with pytest.raises(ProbeJobError):
        validate_params("ping", {"targets": " ".join(f"198.51.100.{i}" for i in range(1, 100))})


def test_traceroute_takes_single_target() -> None:
    with pytest.raises(ProbeJobError):
        validate_params("traceroute", {"targets": "198.51.100.1 198.51.100.2"})


# ─────────── 工作生命週期 ───────────
async def _agent(session) -> ScanAgent:
    a = ScanAgent(name=f"agent-{uuid.uuid4().hex[:6]}",
                  enroll_key_hash=uuid.uuid4().hex * 2, enabled=True)
    session.add(a)
    await session.flush()
    return a


@pytest.mark.anyio
async def test_job_lifecycle(db_session) -> None:
    agent = await _agent(db_session)
    job = await create_job(db_session, agent_id=agent.id, kind="ping",
                           params={"targets": "198.51.100.1"}, requested_by=None)
    assert job.status == STATUS_PENDING

    claimed = await claim_jobs(db_session, agent_id=agent.id)
    assert [c.id for c in claimed] == [job.id]
    assert job.status == STATUS_RUNNING

    ok = await finish_job(db_session, agent_id=agent.id, job_id=job.id,
                          result={"items": [{"target": "198.51.100.1", "alive": True}]})
    assert ok is True
    assert job.status == STATUS_DONE


@pytest.mark.anyio
async def test_agent_cannot_finish_another_agents_job(db_session) -> None:
    """代理只能結束自己領到的工作 —— 否則一台被入侵的代理可以偽造別站台的結果。"""
    a1, a2 = await _agent(db_session), await _agent(db_session)
    job = await create_job(db_session, agent_id=a1.id, kind="ping",
                           params={"targets": "198.51.100.1"}, requested_by=None)
    await claim_jobs(db_session, agent_id=a1.id)
    assert await finish_job(db_session, agent_id=a2.id, job_id=job.id,
                            result={"items": []}) is False
    assert job.status == STATUS_RUNNING


@pytest.mark.anyio
async def test_claim_does_not_hand_out_other_agents_jobs(db_session) -> None:
    a1, a2 = await _agent(db_session), await _agent(db_session)
    await create_job(db_session, agent_id=a1.id, kind="ping",
                     params={"targets": "198.51.100.1"}, requested_by=None)
    assert await claim_jobs(db_session, agent_id=a2.id) == []


@pytest.mark.anyio
async def test_stale_pending_job_expires(db_session) -> None:
    """代理離線時工作要作廢，否則它上線後會補跑一堆早就沒意義的探測。"""
    agent = await _agent(db_session)
    job = await create_job(db_session, agent_id=agent.id, kind="ping",
                           params={"targets": "198.51.100.1"}, requested_by=None)
    job.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.flush()

    await expire_stale(db_session)
    await db_session.refresh(job)
    assert job.status == STATUS_EXPIRED
    assert await claim_jobs(db_session, agent_id=agent.id) == []


@pytest.mark.anyio
async def test_pending_jobs_are_capped(db_session) -> None:
    """代理離線時使用者連按，不該無限堆積。"""
    agent = await _agent(db_session)
    for _ in range(MAX_PENDING_PER_AGENT):
        await create_job(db_session, agent_id=agent.id, kind="ping",
                         params={"targets": "198.51.100.1"}, requested_by=None)
    with pytest.raises(ProbeJobError):
        await create_job(db_session, agent_id=agent.id, kind="ping",
                         params={"targets": "198.51.100.1"}, requested_by=None)


@pytest.mark.anyio
async def test_endpoint_requires_auth(client, db_session) -> None:
    """從代理探測等於能對客戶內網發包 —— 未認證一律拒絕（端點另掛 require_admin）。"""
    agent = await _agent(db_session)
    await db_session.commit()
    r = await client.post("/api/v1/tools/net/agent-probe",
                          json={"agent_id": str(agent.id), "kind": "ping",
                                "targets": "198.51.100.1"})
    assert r.status_code in (401, 403)


@pytest.mark.anyio
async def test_endpoint_rejects_bad_params(client, auth_headers, db_session) -> None:
    agent = await _agent(db_session)
    await db_session.commit()
    r = await client.post("/api/v1/tools/net/agent-probe",
                          json={"agent_id": str(agent.id), "kind": "ping",
                                "targets": "1.2.3.4; id"},
                          headers=auth_headers)
    assert r.status_code == 400

    r2 = await client.post("/api/v1/tools/net/agent-probe",
                           json={"agent_id": str(agent.id), "kind": "exec",
                                 "targets": "198.51.100.1"},
                           headers=auth_headers)
    assert r2.status_code == 400


@pytest.mark.anyio
async def test_full_round_trip_through_endpoints(client, auth_headers, db_session) -> None:
    """建立 → 代理領取 → 回報 → 查結果，全程走真正的端點。"""
    from app.api.v1.endpoints.scan_agents import _key_hash   # noqa: PLC0415

    raw_key = "k" * 40
    agent = ScanAgent(name=f"agent-{uuid.uuid4().hex[:6]}",
                      enroll_key_hash=_key_hash(raw_key), enabled=True)
    db_session.add(agent)
    await db_session.commit()

    r = await client.post("/api/v1/tools/net/agent-probe",
                          json={"agent_id": str(agent.id), "kind": "tcp",
                                "targets": "198.51.100.7", "ports": "443"},
                          headers=auth_headers)
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    got = await client.get("/api/v1/scan-agents/jobs", headers={"X-Agent-Key": raw_key})
    assert got.status_code == 200
    jobs = got.json()["jobs"]
    assert [j["id"] for j in jobs] == [job_id]
    assert jobs[0]["params"]["ports"] == [443]

    done = await client.post(f"/api/v1/scan-agents/jobs/{job_id}/result",
                             json={"result": {"items": [{"target": "198.51.100.7",
                                                         "open": [443], "closed": []}]}},
                             headers={"X-Agent-Key": raw_key})
    assert done.status_code == 200

    final = await client.get(f"/api/v1/tools/net/agent-probe/{job_id}", headers=auth_headers)
    assert final.json()["status"] == STATUS_DONE
    assert final.json()["result"]["items"][0]["open"] == [443]

    rows = list((await db_session.execute(select(AgentProbeJob))).scalars().all())
    assert len(rows) == 1


# ─────────── 代理端自我驗證（後端被入侵時的最後一道閘）───────────
def _agent_module():
    """直接載入代理程式檔（它不是套件的一部分，用檔案路徑載）。"""
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_agent.py"
    spec = importlib.util.spec_from_file_location("jt_agent_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("kind", ["exec", "shell", "rm", ""])
def test_agent_refuses_non_allowlisted_kind(kind) -> None:
    """代理**自己**要擋 —— 後端被入侵時，這是唯一還站著的檢查。"""
    mod = _agent_module()
    result, error = mod._job_execute(kind, {"targets": ["198.51.100.1"]})
    assert result is None
    assert error and "unsupported" in error


@pytest.mark.parametrize("target", ["1.2.3.4; id", "$(whoami)", "-oProxyCommand=x", "a" * 300])
def test_agent_refuses_hostile_targets(target) -> None:
    mod = _agent_module()
    result, error = mod._job_execute("ping", {"targets": [target]})
    assert result is None
    assert error == "no valid target"


def test_agent_caps_targets_and_ports() -> None:
    mod = _agent_module()
    many = [f"198.51.100.{i}" for i in range(1, 100)]
    _, err = mod._job_execute("ping", {"targets": many})
    assert err and "too many targets" in err
    _, err2 = mod._job_execute("tcp", {"targets": ["198.51.100.1"],
                                       "ports": list(range(1, 100))})
    assert err2 and "too many ports" in err2


def test_agent_accepts_valid_job_shape() -> None:
    """合法工作要能通過驗證（不能因為擋太兇而把正常用法也擋掉）。"""
    mod = _agent_module()
    assert mod._job_valid_target("198.51.100.1") == "198.51.100.1"
    assert mod._job_valid_target("host.example.net") == "host.example.net"
    assert mod._job_valid_target("bad host") is None
