"""ENCRYPTION_KEY 格式錯誤時要講清楚（2026-09-26）。

CI 設的測試用金鑰既不是 base64 也不是 hex，程式載入時只丟出 fromhex 的
「non-hexadecimal number found」—— 89 個測試檔在收集階段全數失敗，CI 紅了三週沒人看得出原因。
客戶手動改壞 backend.env 也會看到同一句看不懂的話。
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from app.core import security
from pydantic import SecretStr


def _with_key(monkeypatch, raw: str) -> None:
    monkeypatch.setattr(security, "_settings", SimpleNamespace(encryption_key=SecretStr(raw)))


def test_a_key_that_is_neither_base64_nor_hex_says_how_to_make_one(monkeypatch) -> None:
    _with_key(monkeypatch, "ci-not-a-real-key-ci-not-a-real-key-0000")
    with pytest.raises(ValueError, match="ENCRYPTION_KEY") as exc:
        security._derive_key()
    assert "openssl rand -base64 32" in str(exc.value)


def test_existing_key_formats_derive_the_same_key_as_before(monkeypatch) -> None:
    """既有站台的金鑰不可以因為這次修改而換掉，否則已加密的資料全部解不開。"""
    import hashlib
    _with_key(monkeypatch, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")      # 安裝腳本產的格式
    assert security._derive_key() == bytes(32)
    # 64 個 hex 字元同時也是合法的 base64（解出 48 bytes），一直以來都走 SHA-256 派生
    _with_key(monkeypatch, "00" * 32)
    assert security._derive_key() == hashlib.sha256(("00" * 32).encode()).digest()
