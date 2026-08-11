"""所有時間欄位都必須是 timezone-aware。

這條規則守的是一個「寫的時候完全看不出來」的錯：`Mapped[datetime | None] =
mapped_column()` 不帶型別時，SQLAlchemy 推出的是 **naive** `DateTime`，但 migration
建出來的欄位是 `timestamptz`。兩邊型別不合，讀取沒事、寫入帶時區的值才炸 —— 於是
問題會躲過測試，直到某個使用者送出帶時區的時間才在正式環境變成 500。

實際發生過兩次：`ai_findings.dismissed_at`（忽略發現整個壞掉）與
`circuits.install_date` / `contract_end_date`（帶時區的開通日 API 回 500）。
"""

from __future__ import annotations

from sqlalchemy import DateTime

import app.models  # noqa: F401  —— 要 import 才會把所有 model 註冊進 metadata
from app.models.base import Base


def test_all_datetime_columns_are_timezone_aware():
    naive = [
        f"{table.name}.{col.name}"
        for table in Base.metadata.tables.values()
        for col in table.columns
        if isinstance(col.type, DateTime) and not col.type.timezone
    ]
    assert not naive, (
        "這些欄位是 naive DateTime，但 migration 建的是 timestamptz："
        f"{naive}。請改成 mapped_column(DateTime(timezone=True))"
    )
