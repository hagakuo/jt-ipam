"""代理自我更新（os.execv，PID 不變）之後，舊程式留下的子行程結束了沒有人收 → 殭屍行程。

2026-10-02 在正式環境看到 8 個 nmap 殭屍，都是 9/28 那次自動更新時正在跑的背景探測。
新程式啟動時記下「已經存在的子行程」（只有 exec 前留下的才會是），之後每輪只收那幾個 ——
不可以用 waitpid(-1)：會搶走 subprocess 正在等的子行程，讓它拿到錯的結束碼。
"""
from __future__ import annotations

import os
import subprocess
import time

from tests.test_agent_scan_split import _agent_module


def test_children_of_reads_the_parent_from_proc(tmp_path) -> None:
    mod = _agent_module()
    for pid, ppid, comm in ((101, 7, "nmap"), (102, 7, "nmap (x) y"), (103, 9, "other")):
        d = tmp_path / str(pid)
        d.mkdir()
        (d / "stat").write_text(f"{pid} ({comm}) Z {ppid} 1 1 0 -1 0\n")
    (tmp_path / "self").mkdir()
    assert sorted(mod._children_of(7, proc=str(tmp_path))) == [101, 102]   # 名稱裡有括號也要解得對


def test_inherited_children_are_reaped_and_forgotten() -> None:
    mod = _agent_module()
    child = subprocess.Popen(["true"])            # 結束後沒有人 wait ＝ 殭屍
    deadline = time.time() + 5
    while time.time() < deadline:
        with open(f"/proc/{child.pid}/stat") as f:
            if f.read().rsplit(")", 1)[1].split()[0] == "Z":
                break
        time.sleep(0.05)
    mod._INHERITED[:] = [child.pid]
    mod._reap_inherited()
    assert mod._INHERITED == []
    assert not os.path.exists(f"/proc/{child.pid}")
    child.returncode = 0                           # 已經收過了，別讓 Popen 再等


def test_reaping_is_called_every_round() -> None:
    src = open(_agent_module().__file__, encoding="utf-8").read()
    body = src[src.index("def scan_once() -> None:"):]
    assert "_reap_inherited()" in body[:600]
    assert "_INHERITED = _children_of(os.getpid())" in src or "_INHERITED: list = _children_of(os.getpid())" in src
