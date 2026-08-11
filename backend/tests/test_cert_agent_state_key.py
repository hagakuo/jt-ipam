"""回歸測試：派送代理的狀態鍵必須包含「部署目標」，不能只有 憑證+profile。

2026-08-01 在 Windows 實機測出來的：同一張憑證用在兩個不同繫結（例如 443 上兩個 SNI
站台）時，第二筆會被當成「already up to date」直接跳過 —— **靜默不做事，還回報 ok**，
續簽後第二個站台會默默過期。Linux 代理的手動模式（同憑證寫到不同路徑，profile 都是
generic）有一模一樣的缺陷。

這裡直接把 `agent/jt_ipam_cert_agent.sh` 裡真正在用的 `state_fp` / `set_state` 抽出來跑，
不重寫一份邏輯 —— 重寫的話測的是我寫的第二份實作，不是實際會執行的那份。
"""

from __future__ import annotations

import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

AGENT_SH = Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_cert_agent.sh"
AGENT_PS1 = Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_cert_agent.ps1"
INSTALLER_PS1 = Path(__file__).resolve().parents[2] / "agent" / "jt-ipam-cert-agent-installer.ps1"
INSTALLER_SH = Path(__file__).resolve().parents[2] / "agent" / "jt-ipam-cert-agent-installer.sh"


def _extract_bash_function(src: str, name: str) -> str:
    """抓出 `name() { ... }`，以大括號配對找結尾（函式內有巢狀大括號也正確）。"""
    m = re.search(rf"^{re.escape(name)}\(\)\s*\{{", src, re.M)
    assert m, f"找不到 bash 函式 {name}()"
    depth, i = 0, m.end() - 1
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start(): i + 1]
        i += 1
    raise AssertionError(f"{name}() 的大括號沒有配對")


@pytest.mark.skipif(shutil.which("bash") is None, reason="需要 bash")
def test_bash_state_key_separates_deployments_with_same_cert_and_profile(tmp_path):
    src = AGENT_SH.read_text()
    funcs = "\n".join(_extract_bash_function(src, n) for n in ("state_fp", "set_state"))
    state = tmp_path / "state"
    state.write_text("")

    script = textwrap.dedent(f"""
        set -u
        STATE_FILE="{state}"
        {funcs}

        set_state web generic "/a/x.pem||||" FP1
        echo "other_target=[$(state_fp web generic "/b/y.pem||||")]"
        echo "same_target=[$(state_fp web generic "/a/x.pem||||")]"

        set_state web generic "/b/y.pem||||" FP2
        echo "first_still=[$(state_fp web generic "/a/x.pem||||")]"
        echo "second=[$(state_fp web generic "/b/y.pem||||")]"
        echo "rows=[$(wc -l < "$STATE_FILE" | tr -d ' ')]"

        printf 'old\\tnginx\\tFPOLD\\n' >> "$STATE_FILE"
        echo "legacy_no_target=[$(state_fp old nginx "")]"
        echo "legacy_with_target=[$(state_fp old nginx "/z.pem||||")]"
    """)
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout
    got = dict(re.findall(r"^(\w+)=\[(.*)\]$", out, re.M))

    # 核心性質：換了部署目標就**不可以**被認為已完成 —— 這正是原本會靜默跳過的那一步
    assert got["other_target"] == "", f"不同目標卻被當成已完成（原 bug）: {out}"
    assert got["same_target"] == "FP1"

    # 兩筆各自獨立保存，不會互相覆蓋
    assert got["first_still"] == "FP1"
    assert got["second"] == "FP2"
    assert got["rows"] == "2"

    # 舊版寫下的 3 欄列沒有目標欄：只有同樣沒有目標的部署才能沿用，否則寧可重做一次
    assert got["legacy_no_target"] == "FPOLD"
    assert got["legacy_with_target"] == ""


def _extract_ps_function(src: str, name: str) -> str:
    """抓出 PowerShell 函式本體（大括號配對），讓斷言能限縮到單一函式。"""
    i = src.index(f"function {name} ")
    depth, j, started = 0, i, False
    while j < len(src):
        if src[j] == "{":
            depth += 1
            started = True
        elif src[j] == "}":
            depth -= 1
            if started and depth == 0:
                return src[i:j + 1]
        j += 1
    raise AssertionError(f"{name} 的大括號沒有配對")


def test_windows_agent_keys_state_by_target():
    """PowerShell 版沒有本機可執行的環境，至少守住「目標有被算進狀態鍵」這件事。

    只斷言呼叫端有把 -Target 傳進去；行為本身已於 2026-08-01 在 Windows 11 + IIS 實機
    驗證（同憑證換繫結不再被跳過、續簽會換、驗證失敗會還原）。
    """
    src = AGENT_PS1.read_text()
    assert "function Get-DeploymentTarget" in src
    assert re.search(r"Get-StateFingerprint\s+-Cert\s+\$cert\s+-Profile\s+\$prof\s+-Target\s+\$target", src)
    assert re.search(r"Set-StateFingerprint\s+-Cert\s+\$cert\s+-Profile\s+\$prof\s+-Target\s+\$target", src)
    # iis 的目標是繫結、files 的目標是輸出路徑；store 沒有可區分的目標
    assert re.search(r'"iis"\s*\{\s*return \(Get-Cfg \$D "BINDING"', src)

def test_windows_agent_reads_the_binding_not_the_probe():
    """「這個繫結已經綁好了嗎」必須問 http.sys，不能靠 TLS 探測。

    2026-08-01 實機（Windows 11 + 兩個 SNI 站台）測出來的：SNI 繫結還沒註冊時，探測會被
    同一個埠上的非 SNI 萬用繫結回應。若那張剛好就是要部署的憑證，代理就會判定「已綁好」
    直接返回 —— 回報成功、狀態記成完成，實際上 SNI 繫結什麼都沒註冊。
    """
    src = AGENT_PS1.read_text()
    assert "function Get-HttpSysCertificate" in src

    # 只針對 IIS 那支函式斷言。WinRM 與 RDP 用探測是**對的**：WinRM 每個位址/埠只有一個
    # 接聽器、RDP 只有一組憑證，探測回來的就是要換掉的那個，沒有「被別的繫結回應」的問題。
    # IIS 的 SNI 繫結才有那個陷阱，所以禁令要限縮在這裡，而不是全檔一律禁止。
    iis = _extract_ps_function(src, "Invoke-DeployIis")
    assert re.search(r"\$old = Get-HttpSysCertificate -Parts \$parts", iis)
    assert not re.search(r"\$old = Get-ServedThumbprint", iis), \
        "IIS 不可再用探測結果決定是否已綁好（SNI 繫結會被萬用繫結回應）"
    # 探測仍要留著，但只用於「換完之後真的送出了嗎」
    assert re.search(r"\$now = Get-ServedThumbprint", iis)
    # 比對的是 40 位十六進位指紋值,不是會被在地化的 netsh 標籤
    assert "[0-9a-fA-F]{40}" in src


def test_windows_schedule_matches_the_linux_timer():
    """Windows 排程要有 Linux systemd timer 的等價設定，外加 Windows 才有的兩個陷阱。

    Linux 端是 `Type=oneshot` 的 service 由 timer 叫起來（不是常駐服務），timer 設了
    `RandomizedDelaySec=600`（抖動）與 `Persistent=true`（錯過的補跑）。Windows 工作排程器
    是對應物，但它的預設值會**拒絕在電池供電時啟動、且切到電池就停掉** —— 筆電或有回報
    電池的 VM 會默默跳過續簽。
    """
    sh = INSTALLER_SH.read_text()
    assert "RandomizedDelaySec=600" in sh and "Persistent=true" in sh, "Linux 端的基準變了，這裡要跟著調"

    ps = INSTALLER_PS1.read_text()
    assert "-RandomDelay" in ps, "缺抖動：所有主機會在同一秒打伺服器"
    assert "-StartWhenAvailable" in ps, "缺補跑：關機錯過的那次就永遠不會補"
    assert "-AllowStartIfOnBatteries" in ps and "-DontStopIfGoingOnBatteries" in ps, \
        "Task Scheduler 預設會因電池而不跑／中途停止"
    assert "-ExecutionTimeLimit" in ps, "預設 3 天，卡住的執行會擋住後續每一次"
    # 服務 vs 排程：Windows 這邊刻意用排程（對應 oneshot+timer），不是常駐服務
    assert "New-Service" not in ps and "sc.exe" not in ps
