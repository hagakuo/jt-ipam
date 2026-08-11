"""ping 的封包之間要有間隔，而且兩條路徑要一致。

實機發現：介面上選「次數 10」，按下去**立刻**就出數字。它確實送了 10 個、也收了 10 個
（不是假的），但整批在 53 毫秒內打完 —— 封包之間完全沒有間隔。

兩個問題，第二個比較嚴重：

1. 一個 50 毫秒的連發量到的東西，和「10 次」給人的印象不一樣：它看不到抖動、看不到
   間歇性掉包，而且對 ICMP 有速率限制的裝置反而會回報出不存在的遺失。
2. **兩條路徑的行為天差地遠**：能開 ICMP socket 的機器走自己送（53 毫秒），不能的
   走外部 `ping -c 10`（預設每秒一個，約 9 秒）。同一個畫面、同一組設定，量到的卻是
   兩件事，而且取決於這台機器能不能開 socket。
"""
from __future__ import annotations

import time

import pytest
from app.services import netdiag


def test_the_external_command_spaces_its_packets():
    """外部 ping 要明確帶 -i，不要靠它的預設值（那是每秒一個，10 次要 9 秒）。"""
    argv = netdiag.ping_argv("127.0.0.1", count=5, timeout=2.0)
    assert "-i" in argv
    i = argv.index("-i")
    assert float(argv[i + 1]) == pytest.approx(netdiag.PING_INTERVAL)


def test_the_interval_is_within_what_an_unprivileged_ping_allows():
    """iputils 的 ping 在 -i < 0.2 時需要 root —— 選太小會變成整個功能不能用。"""
    assert netdiag.PING_INTERVAL >= 0.2


@pytest.mark.anyio
async def test_the_native_path_takes_at_least_the_spacing():
    """自己送的那條也要間隔，否則兩條路徑量到的不是同一件事。"""
    t0 = time.monotonic()
    res = await netdiag.ping_many(["127.0.0.1"], count=3, timeout=1.0)
    elapsed = time.monotonic() - t0
    assert res[0].sent == 3
    # 3 個封包之間有 2 段間隔
    assert elapsed >= 2 * netdiag.PING_INTERVAL * 0.9


@pytest.mark.anyio
async def test_a_single_ping_does_not_wait_for_nothing(anyio_backend):
    """次數 1 沒有「之間」，不該為了間隔多等一輪。"""
    t0 = time.monotonic()
    await netdiag.ping_many(["127.0.0.1"], count=1, timeout=1.0)
    assert time.monotonic() - t0 < netdiag.PING_INTERVAL + 0.5
