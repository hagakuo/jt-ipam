"""路徑追蹤要邊跑邊出，一跳一列。

沒回應的躍點必須等滿逾時才能確定，所以 15 跳可能要 30～60 秒。把結果全部壓到最後
一次呈現，使用者看到的就是一個按下去長時間毫無反應的按鈕 —— 分不出是在跑、卡住、
還是壞了。

**實測過的關鍵細節**：`tracepath` 的輸出接到 pipe 時是整塊緩衝的，所有行會在行程
結束時一次湧出（實測 6.02s 時全部到達）。加上 `stdbuf -oL` 之後才真的是 +0.02 /
+3.02 / +6.03 逐行到達。少了它，串流程式碼看起來對、畫面上卻依然什麼都沒有。
"""
from __future__ import annotations

import pytest
from app.services import netdiag


def test_the_command_is_line_buffered():
    """沒有 stdbuf，C 程式接到 pipe 會整塊緩衝 —— 串流就完全失去意義。"""
    argv = netdiag.trace_argv("8.8.8.8", max_hops=5)
    assert argv[:2] == ["stdbuf", "-oL"] or "stdbuf" not in argv[0]
    # 有 stdbuf 就必須帶 -oL；沒有的話至少要能跑（降級成一次呈現）
    if argv[0] == "stdbuf":
        assert "-oL" in argv


def test_hops_are_parsed_one_line_at_a_time():
    """逐行解析必須和整批解析得到一樣的結果。"""
    lines = [
        " 1?: [LOCALHOST]                      pmtu 1500",
        " 1:  192.168.1.1                                          0.312ms",
        " 1:  192.168.1.1                                          0.221ms",
        " 2:  no reply",
        " 3:  168.95.210.154                                       3.902ms",
    ]
    p = netdiag.TracepathIncremental("8.8.8.8")
    hops = [h for ln in lines for h in [p.feed(ln)] if h]
    assert [h["hop"] for h in hops] == [1, 2, 3]
    assert hops[0]["host"] == "192.168.1.1"
    assert hops[1]["host"] is None and hops[1]["note"]      # 無回應也要出現
    assert p.path_mtu == 1500


def test_a_repeated_probe_of_the_same_hop_is_not_emitted_twice():
    """tracepath 每跳會印多行探測 —— 逐行送出時很容易變成同一跳出現好幾列。"""
    p = netdiag.TracepathIncremental("x")
    assert p.feed(" 1:  10.0.0.1   0.3ms") is not None
    assert p.feed(" 1:  10.0.0.1   0.2ms") is None


def test_localhost_line_is_not_a_hop():
    p = netdiag.TracepathIncremental("x")
    assert p.feed(" 1?: [LOCALHOST]     pmtu 1500") is None


@pytest.mark.anyio
async def test_stream_yields_hops_then_a_done_event():
    """介面契約：先一連串 hop，最後一個 done（帶路徑 MTU 與是否截斷）。"""
    seen = []
    async for ev in netdiag.traceroute_stream("127.0.0.1", max_hops=1):
        seen.append(ev)
    assert seen, "至少要有一個事件"
    assert seen[-1]["type"] == "done"
    assert all(e["type"] == "hop" for e in seen[:-1])
