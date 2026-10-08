"""取主機金鑰的逾時不可以比真正連線的逾時還短。

實機（2026-08-31）：某台 OpenSSH 8.9 從 prod 連過去，第一次要 8 秒以上、
第二次 1.08 秒、第三次 0.05 秒。而 `fetch_host_key` 的預設逾時是 **8 秒** ——
比 `open_tunnel` 的 15 秒還短。於是「連得上、只是第一次慢」被報成「連不上」，
使用者從自己的電腦 ssh 又完全正常，只會覺得是我們壞掉。

這一步是整條路徑上**第一個**連出去的動作。第一個動作給最短的耐心，先後本身就不對。
"""

from __future__ import annotations

import inspect

from app.services import ssh_tunnel


def test_host_key_timeout_is_not_shorter_than_the_connect_timeout():
    sig = inspect.signature(ssh_tunnel.fetch_host_key)
    got = sig.parameters["timeout"].default
    assert got >= ssh_tunnel.TunnelConfig.timeout, (
        f"取主機金鑰只給 {got}s，但真正連線給 {ssh_tunnel.TunnelConfig.timeout}s —— "
        "先跑的那一步反而比較沒耐心，會把「第一次比較慢」報成連不上"
    )


def test_timeout_message_says_what_to_do():
    """逾時訊息要講得出「可能是什麼、該怎麼辦」，不要只丟一句 timeout。"""
    src = inspect.getsource(ssh_tunnel.fetch_host_key)
    assert "再試一次" in src or "retry" in src.lower(), "沒有告訴使用者可以重試"
    assert "DNS" in src, "沒有提到最常見的原因（伺服器對來源做反解 DNS）"
