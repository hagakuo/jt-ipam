"""AI 巡檢：模型輸出的防禦性解析、排程判斷，以及 RBAC 與權限分級。

這裡守的三件事，每一件都是「做錯了不會報錯、但會安靜地出問題」：
1. 模型輸出是不可信輸入 —— 解析不出來寧可什麼都不存
2. 餵給模型的資料要先過可見範圍
3. 看發現要 global_read、執行/忽略要 admin
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
from app.mcp.tools import ADMIN_TOOLS, TOOLS
from app.services import ai_audit as aa


def test_valid_output_is_parsed():
    out = aa.parse_findings(
        '{"findings":[{"severity":"high","category":"exposure","title":"t",'
        '"detail":"d","recommendation":"r","evidence":{"ips":["10.0.0.1"]}}]}')
    assert len(out) == 1
    assert out[0]["severity"] == "high"
    assert out[0]["category"] == "exposure"
    assert out[0]["evidence"] == {"ips": ["10.0.0.1"]}


def test_markdown_fenced_json_is_accepted():
    """模型很常把 JSON 包在 ``` 裡，即使被要求只回 JSON。"""
    assert len(aa.parse_findings('```json\n{"findings":[{"title":"a"}]}\n```')) == 1


def test_invented_severity_and_category_are_downgraded():
    """模型會自創等級（CRITICAL、P1…）。照單全收會讓嚴重度失去意義。"""
    out = aa.parse_findings(
        '{"findings":[{"title":"x","severity":"CRITICAL!!","category":"made-up"}]}')
    assert out[0]["severity"] == "low"
    assert out[0]["category"] == "other"


@pytest.mark.parametrize("raw", [
    "抱歉，我無法完成這個要求", "", "   ", "not json at all",
    '{"findings":"not-a-list"}', '{"nope":[]}', "[]",
])
def test_unparseable_output_yields_nothing(raw):
    """解析不出來就什麼都不存 —— 塞半截資料進資料庫比什麼都不給更糟。"""
    assert aa.parse_findings(raw) == []


def test_empty_findings_list_is_success_not_failure():
    """「這次沒發現問題」是合法答案，不是解析失敗。

    兩者混在一起的話必定有一邊出錯：不是把模型故障當成一切平安，就是每次乾淨的巡檢
    都回報成錯誤。所以 `_parse` 用 `None`／`[]` 區分，`parse_findings` 才把兩者攤平。
    """
    assert aa._parse('{"findings":[]}') == []          # 解析成功、沒有發現
    assert aa._parse("模型今天壞了") is None             # 解析失敗
    assert aa._parse("") is None


def test_findings_without_a_title_are_dropped():
    assert aa.parse_findings('{"findings":[{"detail":"d","severity":"high"}]}') == []


def test_long_fields_are_truncated():
    long_t, long_d = "t" * 900, "d" * 9000
    out = aa.parse_findings(f'{{"findings":[{{"title":"{long_t}","detail":"{long_d}"}}]}}')
    assert len(out[0]["title"]) == 300
    assert len(out[0]["detail"]) == 4000


def test_finding_count_is_capped():
    items = ",".join(f'{{"title":"t{i}"}}' for i in range(200))
    assert len(aa.parse_findings(f'{{"findings":[{items}]}}')) == aa.MAX_FINDINGS


_TZ = timezone(timedelta(hours=8))          # 排程照伺服器本地時區算


def _at(day: int, hh: int, mm: int) -> datetime:
    return datetime(2026, 8, day, hh, mm, tzinfo=_TZ)


@pytest.mark.parametrize(("last", "times", "now", "expected"), [
    # 從沒跑過 → 下一輪就跑（打開開關卻整天沒動靜，看起來像壞掉）
    (None, ["03:30"], _at(2, 14, 0), True),
    # 今天 03:30 已過、上次是昨天 → 該跑
    (_at(1, 3, 30), ["03:30"], _at(2, 14, 0), True),
    # 今天 03:30 已跑過 → 不再跑
    (_at(2, 3, 31), ["03:30"], _at(2, 14, 0), False),
    # 還沒到今天的時刻，而上次是昨天那一輪 → 不跑
    (_at(1, 3, 31), ["03:30"], _at(2, 2, 0), False),
    # 多個時刻：上次 03:30 跑過，現在過了 15:00 → 該跑
    (_at(2, 3, 31), ["03:30", "15:00"], _at(2, 15, 1), True),
    (_at(2, 15, 1), ["03:30", "15:00"], _at(2, 15, 30), False),
    # 一個時刻都沒有 → 永不觸發（不能因為沒設定就變成每輪都跑）
    (None, [], _at(2, 14, 0), False),
    (_at(1, 1, 0), ["bogus", "99:99"], _at(2, 14, 0), False),
])
def test_schedule_due(last, times, now, expected):
    assert aa.due(last, times, now) is expected


def test_due_handles_a_last_run_in_another_timezone():
    """last_run 從 DB 讀出來是 UTC；跟本地時刻比較前必須換算，否則會差 8 小時。"""
    from datetime import UTC
    # 台北時間 8/2 04:00 跑過 ＝ UTC 8/1 20:00
    last_utc = datetime(2026, 8, 1, 20, 0, tzinfo=UTC)
    assert aa.due(last_utc, ["03:30"], _at(2, 14, 0)) is False


def test_mcp_tool_is_registered_and_admin_gated():
    """巡檢結論限管理員 —— 要和 REST 端的 require_admin 同一級。

    工具原本掛在「全域讀取」那一級，於是有萬用讀取權限的唯讀檢視者，選單裡看不到巡檢，
    卻能在 AI 對話裡把結論問出來。同一份資料兩道門、兩把鎖，等於沒鎖
    （這個專案在 get_topology 踩過一次）。
    """
    assert "list_ai_findings" in TOOLS
    assert "list_ai_findings" in ADMIN_TOOLS


def test_mcp_tool_labels_output_as_inference():
    """回傳必須自帶「這是推測」的標示，否則對話端會把它當成查核過的事實轉述。"""
    import inspect
    src = inspect.getsource(TOOLS["list_ai_findings"]["fn"])
    assert "not verified facts" in src
    assert "evidence" in src


async def test_collect_respects_visibility(db_session):
    """零權限帳號取樣結果必須是空的 —— 不能把整庫倒給模型。"""
    from app.core.security import hash_password
    from app.models.user import User

    u = User(username=f"aiaudit-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@e.test",
             password_hash=hash_password("Xx!12345678xX"), is_admin=False, is_active=True)
    db_session.add(u)
    await db_session.flush()

    snap = await aa._collect(db_session, u)
    assert snap["ips"] == []
    assert snap["subnets"] == []
    assert snap["empty"] is True


def _route_deps(path: str, method: str) -> set[str]:
    """該路由實際掛了哪些權限 dependency。

    用 FastAPI 解析後的 dependant 樹，而不是讀原始碼字串 —— `from __future__ import
    annotations` 會讓型別註記變成字串，靠文字比對會誤判（這個專案的 RBAC 稽核踩過）。
    """
    from app.main import app
    for r in app.routes:
        if getattr(r, "path", None) == path and method in getattr(r, "methods", set()):
            out: set[str] = set()
            stack = [r.dependant]
            while stack:
                d = stack.pop()
                if d.call is not None:
                    out.add(getattr(d.call, "__name__", ""))
                stack.extend(d.dependencies)
            return out
    raise AssertionError(f"找不到路由 {method} {path}")


def test_run_and_dismiss_require_admin():
    """執行會把資料送給 LLM 並消耗資源；忽略會改變別人也看得到的狀態。兩者都限管理員。"""
    assert "require_admin" in _route_deps("/api/v1/ai-audit/run", "POST")
    assert "require_admin" in _route_deps("/api/v1/ai-audit/dismiss", "POST")


def test_every_endpoint_requires_admin():
    """整支限管理員 —— 包含只是「看發現」的那幾支。

    功能放在管理區，權限就要跟位置對得起來。只把選單藏起來、網址照樣進得去的話，
    那是最糟的一種：看起來有管控，實際上沒有。

    另外，巡檢結論本身就是一份跨部門的弱點清單（哪些網段沒監測、哪些管理介面放在
    一般網段），不該給只被指派特定物件的帳號看。
    """
    for path, method in (
        ("/api/v1/ai-audit/findings", "GET"),
        ("/api/v1/ai-audit/summary", "GET"),
        ("/api/v1/ai-audit/status", "GET"),
        ("/api/v1/ai-audit/run", "POST"),
        ("/api/v1/ai-audit/dismiss", "POST"),
        ("/api/v1/ai-audit/restore", "POST"),
    ):
        assert "require_admin" in _route_deps(path, method), f"{method} {path} 沒限管理員"


class _FakeUser:
    id = uuid.uuid4()


async def _coro(v):
    return v


async def _run_with_model_reply(monkeypatch, reply, db_session):
    """跑一次 run_audit，但把 LLM 換成固定回應（不打真的模型）。"""
    from app.services import ai as ai_mod
    snapshot = {"subnets": [{"id": "x", "cidr": "10.0.0.0/24"}],
                "ips": [], "devices": [], "empty": False}
    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(snapshot))
    monkeypatch.setattr(ai_mod, "raw_chat", lambda s, p, **kw: _coro(reply))
    return await aa.run_audit(db_session, _FakeUser())


async def test_clean_run_with_no_findings_is_not_an_error(monkeypatch, db_session):
    """模型看完覺得沒問題 → 0 筆發現、**不帶錯誤**（端點才會回 200 而不是 502）。"""
    r = await _run_with_model_reply(monkeypatch, '{"findings":[]}', db_session)
    assert r.findings == 0
    assert r.error is None


async def test_broken_model_reply_is_reported_as_an_error(monkeypatch, db_session):
    """模型講了別的東西 → 必須報錯，不能假裝「沒發現問題」。"""
    r = await _run_with_model_reply(monkeypatch, "抱歉，我無法完成這個要求", db_session)
    assert r.findings == 0
    assert r.error


async def test_empty_model_reply_is_reported_as_an_error(monkeypatch, db_session):
    r = await _run_with_model_reply(monkeypatch, "   ", db_session)
    assert r.error


async def test_prompt_asks_for_the_users_language(monkeypatch, db_session):
    """發現存的是文字、不是 i18n key，所以語言要在產生時就決定。

    順帶守住一件會安靜出錯的事：提示詞裡有 JSON 範例的大括號，語言只能用 `replace`
    代入。改用 `str.format` 會炸在那些大括號上（或更糟：靜靜代出壞掉的提示詞）。
    """
    seen = {}

    from app.services import ai as ai_mod
    snapshot = {"subnets": [{"id": "x", "cidr": "10.0.0.0/24"}],
                "ips": [], "devices": [], "empty": False}
    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(snapshot))

    def _capture(s, p, **kw):
        seen["prompt"] = p
        seen["kw"] = kw
        return _coro('{"findings":[]}')

    monkeypatch.setattr(ai_mod, "raw_chat", _capture)
    await aa.run_audit(db_session, _FakeUser())

    assert "繁體中文" in seen["prompt"]          # 沒有偏好時的預設
    assert "{language}" not in seen["prompt"]    # 佔位符確實被代掉
    assert '{"findings":[{"severity"' in seen["prompt"]   # JSON 範例沒被破壞

    # 巡檢要用自己的逾時，不能沿用互動對話那個（預設 90 秒，一批資料常常不夠跑）
    assert seen["kw"].get("timeout") == aa.AUDIT_TIMEOUT
    assert aa.AUDIT_TIMEOUT >= 180


async def test_audit_uses_its_own_model_when_set(monkeypatch, db_session):
    """巡檢可以指定自己的模型；沒指定就沿用對話模型。

    這個設定如果沒真的傳到 LLM 呼叫，畫面上看起來完全正常（選了、存了、跑得動），
    只是永遠用對話模型 —— 一個安靜失效的設定比沒有這個設定更糟。
    """
    from app.services import ai as ai_mod
    from app.services import system_config

    snapshot = {"subnets": [{"id": "x", "cidr": "10.0.0.0/24"}],
                "ips": [], "devices": [], "empty": False}
    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(snapshot))
    seen = {}

    def _capture(s, p, **kw):
        seen["model"] = kw.get("model")
        return _coro('{"findings":[]}')

    monkeypatch.setattr(ai_mod, "raw_chat", _capture)

    class _Cfg:
        provider = "ollama"
        api_key = None
        ai_audit_model = "review-model:7b"
        chat_model = "chat-model:8b"
        num_ctx = 16384
        ai_audit_num_ctx = None

    monkeypatch.setattr(system_config, "get_llm_config", lambda s: _coro(_Cfg()))
    monkeypatch.setattr(aa, "get_llm_config", lambda s: _coro(_Cfg()))
    await aa.run_audit(db_session, _FakeUser())
    assert seen["model"] == "review-model:7b"

    # 沒設 → 傳 None，由 raw_chat 沿用對話模型
    _Cfg.ai_audit_model = None
    await aa.run_audit(db_session, _FakeUser())
    assert seen["model"] is None


async def test_raw_chat_falls_back_to_chat_model(monkeypatch, db_session):
    """`model=None` 時 raw_chat 必須送出設定的對話模型（而不是空的 model 欄位）。"""
    from app.services import ai as ai_mod

    sent = {}

    class _Resp:
        status_code = 200
        @staticmethod
        def json():
            return {"message": {"content": "ok"}}

    async def _fake_request(method, url, **kw):
        sent["model"] = kw["json"]["model"]
        return _Resp()

    monkeypatch.setattr(ai_mod, "safe_request", _fake_request)

    class _Cfg:
        provider = "ollama"
        api_key = None
        enabled = True
        url = "http://ollama.invalid:11434"
        chat_model = "chat-model:8b"
        timeout = 30.0
        num_ctx = None
        ai_audit_num_ctx = None

    from app.services import system_config
    monkeypatch.setattr(system_config, "get_llm_config", lambda s: _coro(_Cfg()))

    await ai_mod.raw_chat(db_session, "hi")
    assert sent["model"] == "chat-model:8b"

    await ai_mod.raw_chat(db_session, "hi", model="other:3b")
    assert sent["model"] == "other:3b"


# ── 切批：這是 v0.5.134 在正式環境實際踩到的坑 ──────────────────────────────
# 360 筆 IP 一次送出（約 75,000 字元）超過 num_ctx=16384，Ollama 把提示詞前段截掉，
# 模型收到的是半截輸入 → 回了一篇「網路環境總覽」散文，一個發現都沒有。
# 畫面上看起來像「跑完了，沒問題」。這一組測試守的就是「不要再一次全部送出去」。

def _snapshot(n_ips: int, desc_len: int = 40) -> dict:
    return {
        "subnets": [{"id": "s", "cidr": "10.0.0.0/24", "description": "網段" * 5}],
        "devices": [{"id": "d", "name": "sw1", "type": "switch"}],
        "ips": [{"id": f"i{i}", "ip": f"10.0.{i // 256}.{i % 256}",
                 "hostname": f"host-{i}.corp.local", "description": "描述" * (desc_len // 2),
                 "state": "active", "status": "online (scanner)"} for i in range(n_ips)],
        "empty": False,
    }


def test_large_inventory_is_split_into_batches():
    batches = aa._batches(_snapshot(360), budget_tokens=16384 - aa.RESERVED_TOKENS)
    assert len(batches) > 1, "360 筆一次送就是正式環境炸掉的那個情況"
    assert sum(len(b["ips"]) for b in batches) == 360, "切批不能弄丟資料"


def test_every_batch_fits_the_context_budget():
    budget = 16384 - aa.RESERVED_TOKENS
    for b in aa._batches(_snapshot(360), budget_tokens=budget):
        got = aa.estimate_tokens(json.dumps(b, ensure_ascii=False))
        assert got <= budget, f"這一批估計 {got} tokens，超過預算 {budget}"


def test_every_batch_carries_the_subnet_and_device_context():
    """少了網段／裝置，模型就無法判斷「這個網段有沒有監測」這類跨物件的問題。"""
    for b in aa._batches(_snapshot(300), budget_tokens=4000):
        assert b["subnets"] and b["devices"]


def test_small_inventory_stays_in_one_batch():
    assert len(aa._batches(_snapshot(5), budget_tokens=16384)) == 1


def test_token_estimate_counts_cjk_as_full_tokens():
    """中文不能用「4 字元 1 token」去估 —— 那會低估到讓提示詞被截掉。"""
    assert aa.estimate_tokens("網段描述" * 100) >= 400


def test_findings_are_deduped_across_batches():
    """每批都附網段資訊，同一件事很容易被講兩次。"""
    out = aa._dedupe([
        {"title": "重複的主機名稱", "detail": "a"},
        {"title": "重複的主機名稱 ", "detail": "b"},
        {"title": "另一件事", "detail": "c"},
    ])
    assert [f["title"] for f in out] == ["重複的主機名稱", "另一件事"]


async def test_partial_batch_failure_still_reports_what_was_found(monkeypatch, db_session):
    """一批失敗不該把整次巡檢丟掉，但也不能安靜地當作全部成功。"""
    from app.services import ai as ai_mod
    from app.services.ai import AIError

    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(_snapshot(300)))
    calls = {"n": 0}

    def _flaky(s, p, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise AIError("模型忙碌中")
        return _coro('{"findings":[{"title":"某個發現","severity":"low"}]}')

    monkeypatch.setattr(ai_mod, "raw_chat", _flaky)

    class _Cfg:
        provider = "ollama"
        api_key = None
        ai_audit_model = None
        chat_model = "m:1b"
        num_ctx = 8192
        ai_audit_num_ctx = None

    monkeypatch.setattr(aa, "get_llm_config", lambda s: _coro(_Cfg()))
    r = await aa.run_audit(db_session, _FakeUser())
    assert calls["n"] > 1, "第一批失敗後必須繼續跑其餘批次"
    assert r.findings >= 1          # 拿到的發現要留著
    assert r.error                  # 但失敗也要講出來


async def test_progress_is_reported_for_each_batch(monkeypatch, db_session):
    """UI 要能顯示現在跑到哪 —— 沒有回報的話，長時間執行跟卡死看起來一模一樣。"""
    from app.services import ai as ai_mod

    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(_snapshot(300)))
    monkeypatch.setattr(ai_mod, "raw_chat",
                        lambda s, p, **kw: _coro('{"findings":[]}'))

    class _Cfg:
        provider = "ollama"
        api_key = None
        ai_audit_model = None
        chat_model = "m:1b"
        num_ctx = 8192
        ai_audit_num_ctx = None

    monkeypatch.setattr(aa, "get_llm_config", lambda s: _coro(_Cfg()))
    events: list[dict] = []

    async def _prog(ev):
        events.append(ev)

    await aa.run_audit(db_session, _FakeUser(), progress=_prog)
    stages = [e["stage"] for e in events]
    assert stages[0] == "collecting"
    assert "analyzing" in stages
    assert stages[-1] == "done"
    # 進度要能算出百分比：current/total 必須單調前進到 total
    analyzing = [e for e in events if e["stage"] == "analyzing"]
    assert analyzing[-1]["current"] == analyzing[-1]["total"] > 1


async def test_audit_forces_json_output(monkeypatch, db_session):
    """光靠提示詞說「只回 JSON」不夠 —— 正式環境就是這樣拿到一篇散文的。

    看實際送出去的參數，不是看原始碼字串：原始碼比對會在重構時假性失敗，
    也會在「參數存在但沒被傳下去」時假性通過。
    """
    from app.services import ai as ai_mod

    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(_snapshot(10)))
    seen = {}

    def _capture(s, p, **kw):
        seen.update(kw)
        return _coro('{"findings":[]}')

    monkeypatch.setattr(ai_mod, "raw_chat", _capture)

    class _Cfg:
        provider = "ollama"
        api_key = None
        ai_audit_model = None
        chat_model = "m:1b"
        num_ctx = 8192
        ai_audit_num_ctx = None

    monkeypatch.setattr(aa, "get_llm_config", lambda s: _coro(_Cfg()))
    await aa.run_audit(db_session, _FakeUser())
    assert seen.get("force_json") is True


def test_batches_are_capped_by_row_count_too():
    """上下文放得下不代表跑得動。

    實測：一批塞滿 13k token 給 gemma4:26b，900 秒還沒回完 —— 整次巡檢就卡在那裡，
    使用者只看到進度條停在第一批。所以除了 token 預算，還要限制每批的筆數。
    """
    batches = aa._batches(_snapshot(300), budget_tokens=100_000)   # 預算大到不會成為限制
    assert all(len(b["ips"]) <= aa.MAX_IPS_PER_BATCH for b in batches)
    assert len(batches) >= 300 // aa.MAX_IPS_PER_BATCH


async def test_collect_only_includes_subnets_marked_for_audit(db_session):
    """沒勾「納入 AI 巡檢」的子網路，連同其 IP 都不該被送給模型。

    只過濾子網路、忘了過濾 IP 的話最糟：清單看起來被縮小了，實際上整段 IP 還是送出去。
    """
    import uuid as _u

    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet

    sec = Section(name=f"aiaudit-sec-{_u.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()

    inc = Subnet(section_id=sec.id, cidr="10.90.1.0/24", ai_audit_enabled=True)
    exc = Subnet(section_id=sec.id, cidr="10.90.2.0/24", ai_audit_enabled=False)
    db_session.add_all([inc, exc])
    await db_session.flush()
    db_session.add_all([
        IPAddress(subnet_id=inc.id, ip="10.90.1.5", hostname="included"),
        IPAddress(subnet_id=exc.id, ip="10.90.2.5", hostname="excluded"),
    ])
    await db_session.flush()

    from app.core.security import hash_password
    from app.models.user import User
    admin = User(username=f"aa-{_u.uuid4().hex[:6]}", email=f"{_u.uuid4().hex[:6]}@e.test",
                 password_hash=hash_password("Xx!12345678xX"), is_admin=True, is_active=True)
    db_session.add(admin)
    await db_session.flush()

    snap = await aa._collect(db_session, admin)
    cidrs = {s["cidr"] for s in snap["subnets"]}
    assert "10.90.1.0/24" in cidrs
    assert "10.90.2.0/24" not in cidrs
    hostnames = {i["hostname"] for i in snap["ips"]}
    assert "included" in hostnames
    assert "excluded" not in hostnames, "子網路排除了，但它的 IP 還是被送出去"


# ── 背景執行：進度必須跟「人有沒有開著那一頁」無關 ─────────────────────────────
# 原本是把整段巡檢綁在 HTTP 請求上（SSE），使用者切到別頁 → 連線中斷 → 整個作業
# 被取消，跑了十幾分鐘的東西一點都拿不回來，畫面上還顯示成「沒有發現」。

def test_run_endpoint_does_not_block_on_the_llm():
    """`/run` 只負責把作業排出去，不能自己 await 整段巡檢。

    用 AST 看「處理函式自己的層級」有沒有 await run_audit —— 巢狀的 runner 裡當然會有，
    單純比對字串會把那個也算進去。
    """
    import ast
    import inspect
    import textwrap

    from app.api.v1.endpoints import ai_audit as ep
    fn = ast.parse(textwrap.dedent(inspect.getsource(ep.run_now))).body[0]

    nested = {n for f in ast.walk(fn)
              if isinstance(f, (ast.AsyncFunctionDef, ast.FunctionDef)) and f is not fn
              for n in ast.walk(f)}
    top_level_awaits = [
        n.value.func for n in ast.walk(fn)
        if isinstance(n, ast.Await) and n not in nested
        and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
    ]
    names = {f.id for f in top_level_awaits}
    assert "spawn_task" in names, "要用背景作業，不能在請求裡跑完"
    assert "run_audit" not in names, "請求裡直接 await 巡檢＝離開頁面就前功盡棄"


async def test_second_run_is_rejected_while_one_is_active(db_session):
    """連按兩次不能變成兩個作業。

    這裡故意不用程序內的鎖判斷：作業是非同步啟動的，第二次點下去時第一個往往還沒
    拿到鎖 —— 用鎖判斷會漏掉，於是多一筆立刻失敗的作業，狀態查詢還會顯示那筆失敗的、
    把真正在跑的蓋掉。
    """
    from app.api.v1.endpoints.ai_audit import _active_run
    from app.models.background_task import BackgroundTask

    assert await _active_run(db_session) is None
    for status in ("pending", "running"):
        task = BackgroundTask(kind="ai_audit.run", status=status)
        db_session.add(task)
        await db_session.flush()
        assert await _active_run(db_session) is not None, f"{status} 應該算「還在跑」"
        await db_session.delete(task)
        await db_session.flush()

    # 跑完的不算
    done = BackgroundTask(kind="ai_audit.run", status="succeeded")
    db_session.add(done)
    await db_session.flush()
    assert await _active_run(db_session) is None


def test_progress_percent_is_monotonic_and_bounded():
    from app.api.v1.endpoints.ai_audit import _percent
    assert _percent({"stage": "collecting"}) == 2
    seq = [_percent({"stage": "analyzing", "current": i, "total": 6}) for i in range(7)]
    assert seq == sorted(seq), "百分比不能倒退"
    assert max(seq) <= 99, "分析階段不該顯示 100%（還沒存檔）"
    assert _percent({"stage": "done"}) == 100


async def test_output_length_is_capped(monkeypatch, db_session):
    """限制單批產出長度。

    實測看過模型卡在重複輸出的迴圈裡，一批寫到 34,000 字還沒停 —— 沒有上限的話，
    它會把整個逾時燒完才失敗，而那段時間裡進度條就停在同一個百分比。
    """
    from app.services import ai as ai_mod

    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(_snapshot(10)))
    seen = {}

    def _capture(s, p, **kw):
        seen.update(kw)
        return _coro('{"findings":[]}')

    monkeypatch.setattr(ai_mod, "raw_chat", _capture)

    class _Cfg:
        provider = "ollama"
        api_key = None
        ai_audit_model = None
        chat_model = "m:1b"
        num_ctx = 8192
        ai_audit_num_ctx = None

    monkeypatch.setattr(aa, "get_llm_config", lambda s: _coro(_Cfg()))
    await aa.run_audit(db_session, _FakeUser())
    assert seen.get("max_output_tokens") == aa.MAX_OUTPUT_TOKENS
    assert 0 < aa.MAX_OUTPUT_TOKENS <= 8000


async def test_raw_chat_passes_num_predict_to_ollama(monkeypatch, db_session):
    """上限要真的送到 Ollama（options.num_predict），不是只存在參數裡。"""
    from app.services import ai as ai_mod

    sent = {}

    class _Resp:
        status_code = 200
        @staticmethod
        def json():
            return {"message": {"content": "ok"}}

    async def _fake_request(method, url, **kw):
        sent.update(kw["json"])
        return _Resp()

    monkeypatch.setattr(ai_mod, "safe_request", _fake_request)

    class _Cfg:
        provider = "ollama"
        api_key = None
        enabled = True
        url = "http://ollama.invalid:11434"
        chat_model = "m:1b"
        timeout = 30.0
        num_ctx = 4096
        ai_audit_num_ctx = None

    from app.services import system_config
    monkeypatch.setattr(system_config, "get_llm_config", lambda s: _coro(_Cfg()))

    await ai_mod.raw_chat(db_session, "hi", max_output_tokens=1234)
    assert sent["options"]["num_predict"] == 1234
    assert sent["options"]["num_ctx"] == 4096, "帶了 num_predict 不能把 num_ctx 蓋掉"


# ── 被切斷的 JSON：實際發生過 ─────────────────────────────────────────────────
# 產出長度上限會把最後一筆發現切成半截，整份 JSON 因此無法解析。前面那幾筆是完整的，
# 整批丟掉等於把已經算出來（也已經花掉算力）的結果浪費掉，畫面上還顯示成「執行失敗」。

def test_truncated_json_keeps_the_complete_findings():
    raw = ('{"findings":[{"severity":"medium","category":"conflict","title":"重複的紀錄",'
           '"detail":"a"},{"severity":"high","category":"exposure","title":"管理介面外露",'
           '"detail":"b"},{"severity":"low","title":"被切一半的第三筆","det')
    out = aa.parse_findings(raw)
    assert [f["title"] for f in out] == ["重複的紀錄", "管理介面外露"]
    assert out[1]["severity"] == "high"


def test_truncated_json_with_no_complete_item_is_still_an_error():
    """只切出半筆＝什麼都沒拿到，那就該照實回報失敗，不能當成「沒發現問題」。"""
    raw = '{"findings":[{"severity":"low","title":"只寫到一半'
    assert aa._parse(raw) is None


def test_salvage_ignores_braces_inside_strings():
    """字串裡的大括號不能被當成物件邊界 —— 否則會切錯位置、撿出壞掉的東西。"""
    raw = ('{"findings":[{"title":"含有 { 與 } 的說明","detail":"a\\"b"},'
           '{"title":"第二筆"},{"title":"半截')
    out = aa.parse_findings(raw)
    assert [f["title"] for f in out] == ["含有 { 與 } 的說明", "第二筆"]


def test_salvage_only_applies_to_findings_shaped_output():
    """不是我們要的格式（例如模型寫了一篇散文）仍然要判定為失敗。"""
    assert aa._parse("這是一段關於網路環境的說明，完全不是 JSON。") is None


# ── 思考模式會吃掉產出額度 ────────────────────────────────────────────────────
# 實測：gemma4:26b 一批寫了 10,401 字的思考過程，真正的答案因此被 num_predict 切斷，
# 三批全部解析失敗、一筆發現都沒存下來。巡檢不需要看模型的思考過程。

async def test_audit_turns_thinking_off(monkeypatch, db_session):
    from app.services import ai as ai_mod

    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(_snapshot(10)))
    seen = {}

    def _capture(s, p, **kw):
        seen.update(kw)
        return _coro('{"findings":[]}')

    monkeypatch.setattr(ai_mod, "raw_chat", _capture)

    class _Cfg:
        provider = "ollama"
        api_key = None
        ai_audit_model = None
        chat_model = "m:1b"
        num_ctx = 8192
        ai_audit_num_ctx = None

    monkeypatch.setattr(aa, "get_llm_config", lambda s: _coro(_Cfg()))
    await aa.run_audit(db_session, _FakeUser())
    assert seen.get("no_thinking") is True


async def test_raw_chat_sends_think_false(monkeypatch, db_session):
    from app.services import ai as ai_mod

    sent = {}

    class _Resp:
        status_code = 200
        text = ""
        @staticmethod
        def json():
            return {"message": {"content": "ok"}}

    async def _fake_request(method, url, **kw):
        sent.clear()
        sent.update(kw["json"])
        return _Resp()

    monkeypatch.setattr(ai_mod, "safe_request", _fake_request)

    class _Cfg:
        provider = "ollama"
        api_key = None
        enabled = True
        url = "http://ollama.invalid:11434"
        chat_model = "m:1b"
        timeout = 30.0
        num_ctx = 4096
        ai_audit_num_ctx = None

    from app.services import system_config
    monkeypatch.setattr(system_config, "get_llm_config", lambda s: _coro(_Cfg()))

    await ai_mod.raw_chat(db_session, "hi", no_thinking=True)
    assert sent.get("think") is False
    await ai_mod.raw_chat(db_session, "hi")
    assert "think" not in sent, "沒要求時不該多送這個欄位"


async def test_old_ollama_rejecting_think_is_retried_without_it(monkeypatch, db_session):
    """舊版 Ollama 不認 `think` —— 要退回不帶它重送，而不是讓整批巡檢失敗。"""
    from app.services import ai as ai_mod

    calls: list[dict] = []

    class _Resp:
        def __init__(self, code, text=""):
            self.status_code = code
            self.text = text
        @staticmethod
        def json():
            return {"message": {"content": "ok"}}

    async def _fake_request(method, url, **kw):
        calls.append(dict(kw["json"]))
        if "think" in kw["json"]:
            return _Resp(400, 'unknown field "think"')
        return _Resp(200)

    monkeypatch.setattr(ai_mod, "safe_request", _fake_request)

    class _Cfg:
        provider = "ollama"
        api_key = None
        enabled = True
        url = "http://ollama.invalid:11434"
        chat_model = "m:1b"
        timeout = 30.0
        num_ctx = 4096
        ai_audit_num_ctx = None

    from app.services import system_config
    monkeypatch.setattr(system_config, "get_llm_config", lambda s: _coro(_Cfg()))

    out = await ai_mod.raw_chat(db_session, "hi", no_thinking=True)
    assert out == "ok"
    assert len(calls) == 2, "第一次被拒後要再送一次"
    assert "think" in calls[0] and "think" not in calls[1]


# ── 巡檢的上下文長度可以跟對話模型分開設 ──────────────────────────────────────
# 這個值決定一批塞得下多少筆資料。巡檢是一次送大量結構化資料的批次工作，跟互動對話
# 的取捨不同 —— 開大一點批次變少、整體快很多，代價是記憶體／VRAM。

class _CtxCfg:
    ai_audit_model = None
    chat_model = "m:1b"
    num_ctx = 8192
    ai_audit_num_ctx = None


def test_audit_num_ctx_falls_back_to_the_chat_setting():
    cfg = _CtxCfg()
    assert aa.audit_num_ctx(cfg) == 8192
    cfg.ai_audit_num_ctx = 32768
    assert aa.audit_num_ctx(cfg) == 32768


def test_bigger_context_means_fewer_batches():
    """設定要真的影響切批，不然它只是個沒有作用的欄位。"""
    small = aa._batches(_snapshot(300), budget_tokens=aa._budget_tokens(_CtxCfg()))
    big_cfg = _CtxCfg()
    big_cfg.ai_audit_num_ctx = 65536
    big = aa._batches(_snapshot(300), budget_tokens=aa._budget_tokens(big_cfg))
    assert len(big) <= len(small)
    # 但每批的筆數上限仍然守著（上下文放得下不代表跑得動）
    assert all(len(b["ips"]) <= aa.MAX_IPS_PER_BATCH for b in big)


async def test_audit_passes_its_own_num_ctx_to_the_model(monkeypatch, db_session):
    from app.services import ai as ai_mod

    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(_snapshot(10)))
    seen = {}

    def _capture(s, p, **kw):
        seen.update(kw)
        return _coro('{"findings":[]}')

    monkeypatch.setattr(ai_mod, "raw_chat", _capture)
    cfg = _CtxCfg()
    cfg.ai_audit_num_ctx = 24576
    monkeypatch.setattr(aa, "get_llm_config", lambda s: _coro(cfg))
    await aa.run_audit(db_session, _FakeUser())
    assert seen.get("num_ctx") == 24576


async def test_raw_chat_num_ctx_override_reaches_ollama(monkeypatch, db_session):
    from app.services import ai as ai_mod

    sent = {}

    class _Resp:
        status_code = 200
        text = ""
        @staticmethod
        def json():
            return {"message": {"content": "ok"}}

    async def _fake_request(method, url, **kw):
        sent.clear()
        sent.update(kw["json"])
        return _Resp()

    monkeypatch.setattr(ai_mod, "safe_request", _fake_request)

    class _Cfg:
        provider = "ollama"
        api_key = None
        enabled = True
        url = "http://ollama.invalid:11434"
        chat_model = "m:1b"
        timeout = 30.0
        num_ctx = 4096
        ai_audit_num_ctx = None

    from app.services import system_config
    monkeypatch.setattr(system_config, "get_llm_config", lambda s: _coro(_Cfg()))

    await ai_mod.raw_chat(db_session, "hi", num_ctx=16384)
    assert sent["options"]["num_ctx"] == 16384
    await ai_mod.raw_chat(db_session, "hi")
    assert sent["options"]["num_ctx"] == 4096, "沒指定時要用設定裡的值"


# ── 忽略要真的有效：下次巡檢不能又跳回來 ──────────────────────────────────────
# 使用者判斷過是誤報而按了忽略，隔天整排又跳回未處理的話，「忽略」等於沒有用，
# 最後大家乾脆不看這一頁。

def test_fingerprint_survives_the_model_rewording_the_title():
    """指紋用分類＋IP 清單，不用標題 —— 模型每次都會重新措辭。"""
    a = {"category": "conflict", "title": "重複的紀錄",
         "evidence": {"ips": ["10.0.0.2", "10.0.0.1"]}}
    b = {"category": "conflict", "title": "重複的 IP 位址紀錄（第二次講法）",
         "evidence": {"ips": ["10.0.0.1", "10.0.0.2"]}}     # 順序不同也要一樣
    assert aa.fingerprint(a) == aa.fingerprint(b)


def test_fingerprint_differs_across_categories_and_ips():
    base = {"category": "conflict", "title": "x", "evidence": {"ips": ["10.0.0.1"]}}
    other_cat = {**base, "category": "stale"}
    other_ip = {"category": "conflict", "title": "x", "evidence": {"ips": ["10.0.0.9"]}}
    assert aa.fingerprint(base) != aa.fingerprint(other_cat)
    assert aa.fingerprint(base) != aa.fingerprint(other_ip)


def test_fingerprint_falls_back_to_title_without_ips():
    """沒有 IP 可指的發現也要有指紋，否則它永遠忽略不掉。"""
    a = {"category": "policy", "title": "命名規範不一致", "evidence": {"note": "n"}}
    b = {"category": "policy", "title": "  命名規範不一致 ", "evidence": None}
    assert aa.fingerprint(a) == aa.fingerprint(b)


async def test_previously_dismissed_findings_do_not_come_back(monkeypatch, db_session):
    from app.models.ai_finding import AIFinding
    from app.services import ai as ai_mod
    from sqlalchemy import select as _select

    reply = ('{"findings":[{"severity":"high","category":"conflict","title":"重複的紀錄",'
             '"evidence":{"ips":["10.0.0.1"]}},'
             '{"severity":"low","category":"stale","title":"另一件事",'
             '"evidence":{"ips":["10.0.0.5"]}}]}')
    snapshot = {"subnets": [{"id": "x", "cidr": "10.0.0.0/24"}], "ips": [],
                "devices": [], "empty": False}
    monkeypatch.setattr(aa, "_collect", lambda s, u: _coro(snapshot))
    monkeypatch.setattr(ai_mod, "raw_chat", lambda s, p, **kw: _coro(reply))

    class _Cfg:
        provider = "ollama"
        api_key = None
        ai_audit_model = None
        chat_model = "m:1b"
        num_ctx = 8192
        ai_audit_num_ctx = None

    monkeypatch.setattr(aa, "get_llm_config", lambda s: _coro(_Cfg()))

    first = await aa.run_audit(db_session, _FakeUser())
    assert first.findings == 2

    # 使用者把其中一筆判定為誤報
    row = (await db_session.execute(
        _select(AIFinding).where(AIFinding.run_id == first.run_id,
                                 AIFinding.title == "重複的紀錄").limit(1)
    )).scalar_one()
    row.status = "dismissed"
    await db_session.flush()

    second = await aa.run_audit(db_session, _FakeUser())
    # 同一件事不再算成未處理的新發現；另一件事照常
    assert second.findings == 1, "已忽略的發現又跳回未處理了"

    # 已忽略的那一筆維持一列就好，不要每跑一次就再存一份。
    # （原本每輪都補一列「已忽略」的紀錄，跑久了「已忽略」分頁會塞滿同一件事的複本 ——
    #   跟未處理清單累積成 62 筆是同一個毛病。）
    rows = (await db_session.execute(
        _select(AIFinding).where(AIFinding.title == "重複的紀錄")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].status == "dismissed"


# ── 台灣用詞：提示詞是盡力而為，存檔前再做一次確定性替換 ────────────────────────
# 實際發生：提示詞已經寫了「相關」不用「涉及」，模型下一輪還是寫了「涉及裝置」。
# 使用者一看就知道不是自家的東西。

@pytest.mark.parametrize(("bad", "good"), [
    ("主機名稱缺失", "主機名稱缺少"),
    ("涉及裝置：sw1", "相關裝置：sw1"),
    ("IP 地址 10.0.0.1", "IP 位址 10.0.0.1"),
    ("這台服務器的網絡信息", "這台伺服器的網路資訊"),
    ("默認端口", "預設連接埠"),
    ("交換機在線", "交換器上線"),
])
def test_mainland_terms_are_rewritten(bad, good):
    assert aa.zh_tw_fixup(bad) == good


def test_ambiguous_words_are_left_alone():
    """一詞兩義的不能替換 —— 改了會把句意改掉，比用錯詞更糟。"""
    for text in ("通過測試", "支持這個做法", "法律程序", "配置檔"):
        assert aa.zh_tw_fixup(text) == text


def test_fixup_is_applied_to_narrative_but_not_evidence():
    out = aa.parse_findings(
        '{"findings":[{"title":"主機名稱缺失","detail":"IP 地址不一致",'
        '"recommendation":"補上信息","category":"other",'
        '"evidence":{"note":"涉及 host-1","ips":["10.0.0.1"]}}]}')
    f = out[0]
    assert f["title"] == "主機名稱缺少"
    assert f["detail"] == "IP 位址不一致"
    assert f["recommendation"] == "補上資訊"
    # evidence 一個字都不能動 —— 裡面是主機名稱與位址，改了就對不上實際資料
    assert f["evidence"]["note"] == "涉及 host-1"
    assert f["evidence"]["ips"] == ["10.0.0.1"]


def test_snapshot_gives_the_model_names_not_uuids():
    """快照不給 UUID，模型才不會把 UUID 寫進發現裡（人看著一串 UUID 不知道是哪台）。"""
    import inspect
    src = inspect.getsource(aa._collect)
    assert '"id": str(i)' not in src, "裝置/子網路不應該再把 UUID 送給模型"
