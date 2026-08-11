"""BIND 9 整合的設定必須真的到得了 adapter。

客戶回報（v0.5.129）：接了 BIND9、狀態顯示啟用中、同步也不報錯，但 DNS 記錄永遠是 0。
原因是兩件「存了卻沒生效」的事：

1. **zone 清單根本沒有輸入欄位**。BIND 沒有列舉 zone 的協定，adapter 只認設定裡明列的
   zone；UI 從來不寫這個值，於是 `list_zones()` 永遠回空、AXFR 一次都不會發生。
2. **TSIG 金鑰沒有被拆解**。UI 提示輸入 `algorithm:keyname:base64key`，但後端把整串
   當成密鑰、keyname 另外去 extra 讀（UI 也沒寫），結果 keyname 永遠是空的 →
   等於沒有 TSIG → BIND 拒絕 AXFR。

兩者都不會產生錯誤訊息，畫面上看起來一切正常。
"""

from __future__ import annotations

import pytest
from app.services.dns.base import DNSAdapterError
from app.services.dns.factory import parse_tsig


@pytest.mark.parametrize(("raw", "expected"), [
    ("hmac-sha256:jt-ipam-key:c2VjcmV0", ("hmac-sha256", "jt-ipam-key", "c2VjcmV0")),
    ("HMAC-SHA512:Key1:AAAA", ("hmac-sha512", "Key1", "AAAA")),
    # 沒寫演算法 → 用預設，但 keyname 一定要拆出來
    ("jt-ipam-key:c2VjcmV0", ("", "jt-ipam-key", "c2VjcmV0")),
    # 只有一段：整串都是密鑰（維持舊行為，不要讓既有設定突然壞掉）
    ("c2VjcmV0", ("", "", "c2VjcmV0")),
    (None, ("", "", "")),
    ("", ("", "", "")),
])
def test_parse_tsig(raw, expected):
    assert parse_tsig(raw) == expected


def test_base64_secret_with_padding_is_not_split_further():
    """base64 可能含 '=' 但不含 ':'；密鑰本身不可以被再切一刀。"""
    algo, name, secret = parse_tsig("hmac-sha256:k:YWJjZGVmZ2hpams=")
    assert (algo, name, secret) == ("hmac-sha256", "k", "YWJjZGVmZ2hpams=")


async def test_missing_zones_is_a_clear_error_not_a_silent_empty_sync(db_session):
    """沒設 zone 要明講，不能安靜地同步出 0 筆 —— 那讓人以為是 BIND 沒資料。"""
    import json as _json
    import uuid as _uuid

    from app.models.dns import DNSServer
    from app.services.dns.factory import get_adapter

    srv = DNSServer(name=f"bind-{_uuid.uuid4().hex[:6]}", type="bind9",
                    server_address="10.42.9.99", enabled=True,
                    extra_config=_json.dumps({}))
    db_session.add(srv)
    await db_session.flush()

    with pytest.raises(DNSAdapterError, match="zone"):
        await get_adapter(db_session, srv)
