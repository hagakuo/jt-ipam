"""每個外鍵欄位都要有索引（GitHub issue #47、超大規模環境）。

沒有索引時，刪除被參照的那一列要把子表整個掃一遍（ON DELETE SET NULL／CASCADE 的外鍵檢查），
每刪一列掃一遍：issue #47 那台裝置清理三萬多個埠要將近兩分鐘；刪掉一個 /16 子網路時六萬多個
IP 各自把好幾張表掃一遍。migration 0167 一次補齊；新增外鍵時要一起建索引（可為 NULL 的用
`postgresql_where=<col> IS NOT NULL` 的部分索引）。
"""
from __future__ import annotations

from sqlalchemy import text

_MISSING = text("""
SELECT c.conrelid::regclass::text || '.' || a.attname
FROM pg_constraint c
JOIN LATERAL unnest(c.conkey) WITH ORDINALITY k(attnum, ord) ON true
JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
WHERE c.contype = 'f' AND array_length(c.conkey, 1) = 1
  AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.conrelid AND i.indkey[0] = k.attnum)
ORDER BY 1
""")


async def test_every_foreign_key_column_has_an_index(db_session) -> None:
    fks = (await db_session.execute(text("SELECT count(*) FROM pg_constraint WHERE contype = 'f'"))).scalar()
    assert fks > 50, "查不到外鍵 —— 測試資料庫可能不是最新結構（先跑 alembic upgrade head）"
    missing = (await db_session.execute(_MISSING)).scalars().all()
    assert missing == [], f"這些外鍵欄位沒有索引（大量刪除時會整表掃描）：{missing}"
