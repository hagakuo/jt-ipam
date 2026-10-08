"""RustDesk 代理安裝腳本的 systemd unit 與設定檔（「刪除舊註冊」的主機端開關）。

最小權限、兩邊都同意：
- 沒帶 --allow-delete：hbbs 目錄唯讀掛載（ReadOnlyPaths），跟以前完全一樣
- 帶 --allow-delete（或 JT_RD_ALLOW_DELETE=1）：hbbs 目錄可寫（SQLite 要在旁邊建日誌檔），私鑰檔 id_ed25519
  對代理完全不可見（InaccessiblePaths），其餘加固照舊；設定檔多一行 JT_RD_ALLOW_DELETE=1
- 重跑時沒給的 JT_IPAM_URL／金鑰沿用既有設定檔（只為了打開刪除而重跑，不必再貼一次金鑰）；
  每次重跑都重新決定：沒帶旗標就變回唯讀

在暫存目錄裡跑真正的腳本：把固定路徑換到暫存目錄、systemctl／curl／sleep 換成假的。
"""
from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = _ROOT / "agent" / "jt-ipam-rustdesk-agent-installer.sh"
AGENT = _ROOT / "agent" / "jt_ipam_rustdesk_agent.py"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("python3") is None,
                                reason="needs bash and python3")


def _stub(path: pathlib.Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def box(tmp_path):  # type: ignore[no-untyped-def]
    """暫存目錄裡的安裝環境 → (執行函式, 路徑)。"""
    src = INSTALLER.read_text()
    for old, new in (("DEST=/opt/jt-ipam-rustdesk-agent", f"DEST={tmp_path}/opt"),
                     ("ENVFILE=/etc/jt-ipam-rustdesk-agent.env", f"ENVFILE={tmp_path}/agent.env"),
                     ('UNIT="/etc/systemd/system/${SVC}.service"', f'UNIT="{tmp_path}/agent.service"'),
                     ("[[ $EUID -eq 0 ]] ||", "true ||"),
                     ('chown root:root "$ENVFILE"', "true")):
        assert old in src, f"安裝腳本改了，測試要跟著改：{old}"
        src = src.replace(old, new)
    script = tmp_path / "installer.sh"
    script.write_text(src)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _stub(bin_dir / "systemctl", "exit 0")
    _stub(bin_dir / "sleep", "exit 0")
    # curl ... <url> -o <file>：把這份代理程式複製過去
    _stub(bin_dir / "curl", f'while [[ $# -gt 0 ]]; do if [[ "$1" == "-o" ]]; then cp "{AGENT}" "$2"; fi; shift; done')
    data = tmp_path / "rustdesk-server"
    data.mkdir()
    (data / "db_v2.sqlite3").write_bytes(b"")

    def run(*args: str, **env: str) -> subprocess.CompletedProcess:
        e = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(tmp_path),
             "JT_IPAM_RUSTDESK_DIR": str(data), **env}
        return subprocess.run(["bash", str(script), *args], env=e, capture_output=True, text=True, timeout=60,
                              check=False)

    return run, tmp_path, data


def _unit(tmp_path: pathlib.Path) -> str:
    return (tmp_path / "agent.service").read_text()


def _env(tmp_path: pathlib.Path) -> dict[str, str]:
    out = {}
    for line in (tmp_path / "agent.env").read_text().splitlines():
        k, _, v = line.partition("=")
        out[k] = v
    return out


def test_default_install_keeps_the_hbbs_directory_read_only(box) -> None:  # type: ignore[no-untyped-def]
    run, tmp, data = box
    r = run(JT_IPAM_URL="https://ipam.example.com", JT_IPAM_AGENT_KEY="k" * 43 + "=", JT_IPAM_INSECURE="1")
    assert r.returncode == 0, r.stderr
    unit = _unit(tmp)
    assert f"ReadWritePaths={tmp}/opt\n" in unit
    assert f"ReadOnlyPaths={data}\n" in unit
    assert "InaccessiblePaths" not in unit and "--allow-delete" not in unit
    for hard in ("NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "ProtectSystem=strict", "ProtectHome=yes"):
        assert hard in unit
    env = _env(tmp)
    assert env["JT_IPAM_AGENT_KEY"] == "k" * 43 + "=" and "JT_RD_ALLOW_DELETE" not in env
    assert "not allowed on this host" in r.stdout


def test_allow_delete_makes_it_writable_but_hides_the_private_key(box) -> None:  # type: ignore[no-untyped-def]
    run, tmp, data = box
    r = run("--allow-delete", JT_IPAM_URL="https://ipam.example.com", JT_IPAM_AGENT_KEY="key-1")
    assert r.returncode == 0, r.stderr
    unit = _unit(tmp)
    assert f"ReadWritePaths={tmp}/opt {data}\n" in unit
    assert f"InaccessiblePaths=-{data}/id_ed25519\n" in unit
    assert "ReadOnlyPaths" not in unit
    for hard in ("NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "ProtectSystem=strict", "UMask=0077"):
        assert hard in unit, "其餘加固照舊"
    assert _env(tmp)["JT_RD_ALLOW_DELETE"] == "1"
    assert "allowed on this host" in r.stdout


def test_rerun_keeps_the_config_and_decides_delete_again(box) -> None:  # type: ignore[no-untyped-def]
    run, tmp, data = box
    assert run(JT_IPAM_URL="https://ipam.example.com", JT_IPAM_AGENT_KEY="key=with=equals",
               JT_IPAM_INSECURE="1").returncode == 0
    r = run(JT_RD_ALLOW_DELETE="1")                         # 只為了打開刪除而重跑：不給網址與金鑰
    assert r.returncode == 0, r.stderr
    env = _env(tmp)
    assert env["JT_IPAM_URL"] == "https://ipam.example.com" and env["JT_IPAM_AGENT_KEY"] == "key=with=equals"
    assert env["JT_IPAM_INSECURE"] == "1" and env["JT_RD_ALLOW_DELETE"] == "1"
    assert f"InaccessiblePaths=-{data}/id_ed25519" in _unit(tmp)
    first = (_unit(tmp), (tmp / "agent.env").read_text())
    assert run("--allow-delete").returncode == 0
    assert (_unit(tmp), (tmp / "agent.env").read_text()) == first, "同一個指令跑兩次結果一樣"
    assert run().returncode == 0                            # 沒帶旗標 → 變回唯讀
    assert f"ReadOnlyPaths={data}" in _unit(tmp) and "InaccessiblePaths" not in _unit(tmp)
    assert "JT_RD_ALLOW_DELETE" not in _env(tmp)
    assert _env(tmp)["JT_IPAM_AGENT_KEY"] == "key=with=equals"


def test_missing_values_without_a_config_still_fail(box) -> None:  # type: ignore[no-untyped-def]
    run, _tmp, _data = box
    r = run("--allow-delete")
    assert r.returncode != 0 and "JT_IPAM_URL is required" in r.stderr
    r = run("--bogus", JT_IPAM_URL="https://ipam.example.com", JT_IPAM_AGENT_KEY="k")
    assert r.returncode != 0 and "Unknown option" in r.stderr
