"""子網路內的位址範圍（集區）—— GitHub issue #40。"""
from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import Field

from app.schemas.base import StrictModel

IPRangePurpose = Literal["dhcp", "reserved", "other"]


class IPRangeCreate(StrictModel):
    start_ip: Annotated[str, Field(min_length=2, max_length=64)]
    end_ip: Annotated[str, Field(min_length=2, max_length=64)]
    purpose: IPRangePurpose = "dhcp"
    name: Annotated[str | None, Field(max_length=64)] = None
    description: Annotated[str | None, Field(max_length=1024)] = None


class IPRangeUpdate(StrictModel):
    start_ip: Annotated[str | None, Field(min_length=2, max_length=64)] = None
    end_ip: Annotated[str | None, Field(min_length=2, max_length=64)] = None
    purpose: IPRangePurpose | None = None
    name: Annotated[str | None, Field(max_length=64)] = None
    description: Annotated[str | None, Field(max_length=1024)] = None


class IPRangeRead(StrictModel):
    id: uuid.UUID
    subnet_id: uuid.UUID
    start_ip: str
    end_ip: str
    purpose: IPRangePurpose
    name: str | None = None
    description: str | None = None
    #: 範圍內有幾個位址、其中幾個已有 IP 記錄、下一個還沒有記錄的位址
    size: int = 0
    used: int = 0
    first_free: str | None = None
    #: 由偵測到的 DHCP 發放範圍自動建立（跟著上游走，不能手動改／刪）與它的來源（firewall-a · KEA）
    auto: bool = False
    source_label: str | None = None
