"""小機器（2 vCPU／4 GB）跑得動、升級時不會被 OOM 砍掉（2026-10-02 檢視最低需求時實測）。

量到的數字：平常整台約 1.8 GB，其中後端主行程＋4 個 worker（每個約 250 MB）是大宗；升級時前端 build 峰值
約 1.6 GB。4 GB 又沒有 swap 的機器，以前固定開 4 個 worker，build 時剛好碰到背景同步就可能被砍。

- `run-backend.sh`：沒指定 UVICORN_WORKERS 時依機器決定 worker 數（2 核或記憶體 ≤ 4.5 GB 開 2 個）
- `jt-ipam.sh` 的 build_frontend：build 前看可用記憶體，不夠就先暫停後端騰出空間，build 失敗也要把後端開回來

這裡實際用 bash 跑那兩個函式（餵假的 /proc/meminfo 與 cgroup 檔），不是只看字串。
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_BACKEND = ROOT / "scripts" / "run-backend.sh"
INSTALLER = ROOT / "scripts" / "jt-ipam.sh"


def _func(path: Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", src, re.S | re.M)
    assert m, f"{path.name} 裡找不到 {name}()"
    return m.group(0)


def _meminfo(tmp_path: Path, total_mb: int, avail_mb: int = 0, swap_mb: int = 0) -> Path:
    p = tmp_path / "meminfo"
    p.write_text(f"MemTotal:       {total_mb * 1024} kB\nMemFree:        1 kB\n"
                 f"MemAvailable:   {avail_mb * 1024} kB\nSwapTotal:      {swap_mb * 1024} kB\n"
                 f"SwapFree:       {swap_mb * 1024} kB\n")
    return p


def _run(func_src: str, call: str, env: dict[str, str]) -> str:
    out = subprocess.run(["bash", "-c", f"set -euo pipefail\n{func_src}\n{call}"],
                         capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", **env}, timeout=10)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def _workers(tmp_path: Path, cpus: int, total_mb: int, cg_max: str | None = None) -> int:
    env = {"JT_IPAM_NPROC": str(cpus), "JT_IPAM_MEMINFO": str(_meminfo(tmp_path, total_mb))}
    cg = tmp_path / "memory.max"
    cg.write_text((cg_max or "max") + "\n")
    env["JT_IPAM_CGROUP_DIR"] = str(tmp_path)
    return int(_run(_func(RUN_BACKEND, "default_workers"), "default_workers", env))


def test_small_machines_get_two_workers(tmp_path) -> None:
    assert _workers(tmp_path, 2, 8192) == 2              # 2 核
    assert _workers(tmp_path, 4, 3900) == 2              # 「4 GB」的機器回報的 MemTotal 比 4096 小
    assert _workers(tmp_path, 4, 4096) == 2
    assert _workers(tmp_path, 4, 8192) == 4
    assert _workers(tmp_path, 8, 16384) == 4             # 不因為機器大就無限加


def test_a_container_memory_limit_counts(tmp_path) -> None:
    """容器沒有 lxcfs 時 /proc/meminfo 是宿主的記憶體 —— 要看 cgroup 的上限。"""
    assert _workers(tmp_path, 8, 65536, cg_max=str(4096 * 1024 * 1024)) == 2
    assert _workers(tmp_path, 8, 65536, cg_max="max") == 4


def test_an_explicit_worker_count_still_wins() -> None:
    src = RUN_BACKEND.read_text(encoding="utf-8")
    assert 'workers="${UVICORN_WORKERS:-$(default_workers)}"' in src


def _avail(tmp_path: Path, avail_mb: int, swap_mb: int = 0, cg: tuple[int, int] | None = None) -> int:
    env = {"JT_IPAM_MEMINFO": str(_meminfo(tmp_path, 8192, avail_mb, swap_mb)), "JT_IPAM_CGROUP_DIR": str(tmp_path)}
    (tmp_path / "memory.max").write_text(f"{cg[0] * 1048576}\n" if cg else "max\n")
    (tmp_path / "memory.current").write_text(f"{cg[1] * 1048576}\n" if cg else "0\n")
    return int(_run(_func(INSTALLER, "mem_available_mb"), "mem_available_mb", env))


def test_available_memory_counts_swap_and_the_container_limit(tmp_path) -> None:
    assert _avail(tmp_path, 1500) == 1500
    assert _avail(tmp_path, 1500, swap_mb=1024) == 2524
    assert _avail(tmp_path, 6000, cg=(4096, 3000)) == 1096     # 容器只剩 1 GB，別信宿主的 6 GB


def test_build_checks_memory_and_brings_the_backend_back_if_it_paused_it() -> None:
    body = _func(INSTALLER, "build_frontend")
    check = body.find("ensure_build_memory")
    build = body.find('"$pnpm_bin" run build')
    assert 0 <= check < build, "build 前要先檢查可用記憶體"
    guard = _func(INSTALLER, "ensure_build_memory")
    assert "systemctl stop" in guard and "BUILD_PAUSED_BACKEND=1" in guard, "記憶體不夠時要暫停後端騰出空間"
    assert re.search(r'BUILD_PAUSED_BACKEND.*\n.*systemctl start', body), \
        "build 失敗時要把暫停的後端開回來，否則升級失敗＝整個站台停擺"


def _guard_run(tmp_path: Path, avail_mb: int) -> tuple[str, str]:
    """跑 ensure_build_memory：systemctl 換成記錄呼叫的假指令，記憶體用假的 /proc/meminfo。"""
    log = tmp_path / "calls.log"
    env = {"JT_IPAM_MEMINFO": str(_meminfo(tmp_path, 4096, avail_mb)), "JT_IPAM_CGROUP_DIR": str(tmp_path / "none")}
    stubs = (f'systemctl() {{ echo "$*" >> {log}; [[ "$1" == is-active ]]; }}\n'
             'warn() { echo "WARN $*" >&2; }\nsleep() { :; }\nFRONTEND_BUILD_MIN_MB=2048\nBUILD_PAUSED_BACKEND=0\n')
    src = stubs + _func(INSTALLER, "mem_available_mb") + _func(INSTALLER, "ensure_build_memory")
    out = _run(src, 'ensure_build_memory; echo "paused=$BUILD_PAUSED_BACKEND"', env)
    return out, (log.read_text() if log.exists() else "")


def test_short_memory_pauses_the_backend_for_the_build(tmp_path) -> None:
    out, calls = _guard_run(tmp_path, avail_mb=1200)
    assert "paused=1" in out
    assert "stop jt-ipam-backend.service" in calls


def test_enough_memory_leaves_the_backend_alone(tmp_path) -> None:
    out, calls = _guard_run(tmp_path, avail_mb=3000)
    assert "paused=0" in out
    assert "stop" not in calls
