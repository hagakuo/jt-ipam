"""起一台真的 SFTP 伺服器當 e2e 的目標主機。

用 asyncssh 的行程內伺服器：不必動系統 sshd、不必開真的帳號，但走的是完整 SSH/SFTP
協定 —— 瀏覽器那一端看到的行為與真實環境一致。

用法（在 backend 的 venv 裡跑，asyncssh 已是既有相依）：

    JT_E2E_SFTP_ROOT=/tmp/jt-ipam-e2e-sftproot \\
      backend/.venv/bin/python frontend/e2e/fixtures/sftp-target.py

再讓 e2e 指向它（IP 記錄要指到這台的位址、且已開啟 SSH）：

    E2E_SFTP_ROOT=/tmp/jt-ipam-e2e-sftproot E2E_SFTP_IP_ID=<ip uuid> \\
      E2E_ADMIN_PASS=... npx playwright test e2e/sftp.spec.ts
"""
import asyncio
import os
from pathlib import Path

import asyncssh

ROOT = Path(os.environ.get("JT_E2E_SFTP_ROOT", "/tmp/jt-ipam-e2e-sftproot"))
PORT = int(os.environ.get("JT_E2E_SFTP_PORT", "2222"))
USER = os.environ.get("JT_E2E_SFTP_USER", "tester")
PASSWORD = os.environ.get("JT_E2E_SFTP_PASS", "TestPass!2026")


class Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True                      # 要密碼

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == USER and password == PASSWORD


async def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "etc").mkdir(exist_ok=True)
    (ROOT / "etc" / "nginx.conf").write_text("server { listen 80; }\n", encoding="utf-8")
    # 含中文的檔名與內容：編碼壞掉時要看得出來
    (ROOT / "readme-中文.txt").write_text("這是一份含中文檔名與內容的測試檔\n", encoding="utf-8")
    (ROOT / "app.log").write_text("log line\n" * 200, encoding="utf-8")

    key = asyncssh.generate_private_key("ssh-rsa")
    server = await asyncssh.create_server(
        Server, "127.0.0.1", PORT, server_host_keys=[key],
        # chroot：測試只該看到這個目錄，不該碰到跑測試那台機器的檔案系統
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(ROOT)),
    )
    print(f"SFTP test target listening on 127.0.0.1:{PORT}, root {ROOT}", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        server.close()


asyncio.run(main())
