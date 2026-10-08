"""憑證到期通知的天數：全域預設 + 逐張覆寫。

由來（使用者要求）：「憑證到期多久前通知要可以設定，不同憑證可以設不同。」
不同憑證的更新流程長短差很多 —— 手動申請的商業憑證要提前一個月準備，自動續簽的
提前七天就夠。用同一個門檻，不是太吵就是太晚。

這裡守兩件容易做錯的事：
1. **取用順序**：該張憑證自己的設定優先，沒設才用全域預設。
2. **「沒設定」不等於「不通知」**：`None` 代表沿用預設；要能從自訂改回沿用預設，
   所以 PATCH 需要一個明確的旗標（`None` 在 PATCH 語意是「不修改」）。
"""

from __future__ import annotations

import inspect

from app.api.v1.endpoints import certificates as cert_ep
from app.models.certificate import Certificate
from app.schemas.certificate import CertificateUpdate
from app.services import cert_alert


def test_model_has_a_per_certificate_override():
    col = Certificate.__table__.c.get("expiry_warn_days")
    assert col is not None, "憑證沒有逐張的通知天數欄位"
    assert col.nullable, "必須可以是 NULL —— 那代表『沿用全域預設』，不是『不通知』"


def test_alert_prefers_the_certificate_setting():
    src = inspect.getsource(cert_alert.check_cert_alerts)
    assert "cert.expiry_warn_days" in src, "沒有讀取該張憑證自己的設定"
    assert "default_days" in src, "沒有全域預設可以退回"
    i = src.index("cert.expiry_warn_days")
    assert "if cert.expiry_warn_days is not None" in src[i - 60:i + 80], (
        "沒有『有設就用、沒設才退回預設』的判斷"
    )


def test_update_schema_can_clear_back_to_default():
    fields = CertificateUpdate.model_fields
    assert "expiry_warn_days" in fields
    assert "clear_expiry_warn_days" in fields, (
        "沒有辦法把憑證改回『沿用全域預設』—— PATCH 的 None 是『不修改』，"
        "少了明確旗標，使用者設過一次就再也回不去"
    )


def test_endpoint_honours_the_clear_flag():
    src = inspect.getsource(cert_ep.update_certificate)
    assert "clear_expiry_warn_days" in src, "端點沒有處理『改回沿用預設』"
    assert "obj.expiry_warn_days = None" in src, "旗標沒有真的把值清掉"


def test_global_default_is_bounded():
    """天數要有上下限：0 或負數等於永遠不通知，而那不該是靜靜發生的設定值。"""
    from app.services.system_config import set_cert_expiry_days
    src = inspect.getsource(set_cert_expiry_days)
    assert "max(1" in src and "min(365" in src, "全域預設沒有夾在合理範圍內"
