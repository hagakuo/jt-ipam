"""大量值的 IN 條件：一個陣列參數，而不是一個值一個參數。

asyncpg（PostgreSQL 的協定）一個語句最多 32767 個參數，`col.in_(python_list)` 每個值佔一個。
清單來自客戶資料時 —— 某台裝置的全部連接埠、整個 /16 的 IP、幾萬筆 DHCP 租約 —— 超大規模的
站台就會整支失敗（GitHub issue #47：LibreNMS 同步清理連接埠時
`InterfaceError: the number of query arguments cannot exceed 32767`）。

`col = ANY($1::type[])` 不論多少個值都只佔一個參數，PostgreSQL 一樣會用索引。

規則：**清單的長度會隨網路規模成長時（IP、MAC、埠、租約、主機名稱、裝置…），一律用
`in_values()`**；只有天然有上限的（一頁的筆數、使用者勾選的項目、固定的常數）才用 `.in_()`。
tests/test_many_values_in.py 有守門測試。
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import all_, any_, bindparam
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.sql.elements import ClauseElement, ColumnElement
from sqlalchemy.types import NullType, TypeEngine


def _array(col: ColumnElement[Any], values: Iterable[Any], type_: TypeEngine[Any] | None) -> Any:
    if isinstance(values, ClauseElement):
        # 子查詢沒有參數上限的問題，本來就該用 .in_(select(...))／.not_in(select(...))
        raise TypeError("in_values()/not_in_values() take Python values; use .in_() for a subquery")
    elem = type_ if type_ is not None else col.type
    if isinstance(elem, NullType):
        raise TypeError("in_values()/not_in_values() need type_= for an expression without a type")
    return bindparam(None, list(values), type_=ARRAY(elem), unique=True)


def in_values(col: ColumnElement[Any], values: Iterable[Any], *,
              type_: TypeEngine[Any] | None = None) -> ColumnElement[bool]:
    """`col IN (values)`，但只用一個陣列參數。

    `type_`：元素型別，預設取欄位的型別；`func.host(...)` 這類沒有型別的運算式要自己指定。
    空清單＝沒有任何一列符合（與 `.in_([])` 相同）。
    """
    return col == any_(_array(col, values, type_))


def not_in_values(col: ColumnElement[Any], values: Iterable[Any], *,
                  type_: TypeEngine[Any] | None = None) -> ColumnElement[bool]:
    """`col NOT IN (values)`，只用一個陣列參數（`col <> ALL(...)`）。空清單＝每一列都符合。"""
    return col != all_(_array(col, values, type_))
