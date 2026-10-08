"""忽略過的 AI 巡檢發現，不可以下次又跳回來（2026-09-05 使用者回報）。

使用者的原話是「我已經按忽略了後又出現，我又按忽略，這樣忽略沒有用」。

實機資料說明了原因：同一件「IPMI 管理介面在服務網段」被拆成五筆，
每一筆引用的位址是**不同的子集**：

    {192.0.2.60}
    {192.0.2.46}
    {192.0.2.60, 192.0.2.46}
    {192.0.2.74, 192.0.2.60, 192.0.2.54}
    {198.51.100.74}          ← 模型把位址打錯的那一筆

指紋是「分類＋位址集合」，集合每次都不一樣 → 指紋每次都不一樣 → 忽略永遠帶不過去。

修法：忽略記在**對象**上。使用者按忽略的意思是「這幾台機器的這件事我知道了」，
不是「這串措辭我看過了」。因此：

- 一條發現講的對象**全部**都被忽略過 → 不再開啟
- 只要出現**新的對象** → 照樣要跳出來（那是新資訊，不是重複）
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.models.ai_finding import AIFinding
from app.services import ai_audit


def _item(category: str, ips: list[str], title: str = "管理介面位於一般用途子網路") -> dict[str, Any]:
    return {"severity": "high", "category": category, "title": title,
            "detail": "d", "recommendation": "r", "evidence": {"ips": ips}}


def test_subjects_keeps_addresses_and_drops_the_rest() -> None:
    """依據資料裡會混進主機名稱與網段 —— 那些每次措辭都不同，不能當識別。"""
    got = ai_audit.subjects(_item("exposure",
                                  ["192.0.2.60", "ipmi-host-a", "192.0.2.0/24", " 192.0.2.46 "]))
    assert got == {"192.0.2.60", "192.0.2.46"}


def test_fingerprint_ignores_wording_but_follows_the_subjects() -> None:
    a = ai_audit.fingerprint(_item("exposure", ["192.0.2.60"], title="管理介面位於一般用途子網路"))
    b = ai_audit.fingerprint(_item("exposure", ["192.0.2.60"], title="管理介面暴露於一般用途子網路"))
    c = ai_audit.fingerprint(_item("exposure", ["192.0.2.99"], title="管理介面位於一般用途子網路"))
    assert a == b, "換個講法就變成另一件事 —— 忽略會帶不過去"
    assert a != c


@pytest.mark.anyio
async def test_dismissed_subjects_are_not_reopened(db_session: Any) -> None:
    """實機那一串子集：忽略過之後，任何子集組合都不該再開一筆。"""
    run = uuid.uuid4()
    for ips in (["192.0.2.60"], ["192.0.2.46"], ["192.0.2.74", "192.0.2.54"]):
        db_session.add(AIFinding(
            run_id=run, severity="high", category="exposure", title="t", detail="d",
            evidence={"ips": ips}, status="dismissed",
            fingerprint=ai_audit.fingerprint(_item("exposure", ips))))
    await db_session.flush()

    # 下一輪：模型換了措辭、引用了這些位址的各種組合
    items = [
        _item("exposure", ["192.0.2.60", "192.0.2.46"], title="管理介面暴露於一般用途子網路"),
        _item("exposure", ["192.0.2.46"]),
        _item("exposure", ["192.0.2.74", "192.0.2.60", "192.0.2.54"]),
    ]
    kept = await ai_audit.reconcile_findings(
        db_session, uuid.uuid4(), items, model_name="m", partial=False)
    await db_session.flush()

    from sqlalchemy import select
    opened = (await db_session.execute(
        select(AIFinding).where(AIFinding.status == "open"))).scalars().all()
    assert kept == 0, "忽略過的對象又被開出來了"
    assert opened == [], [o.title for o in opened]


@pytest.mark.anyio
async def test_a_new_subject_still_surfaces(db_session: Any) -> None:
    """只要有新的機器牽涉進來，就該再講一次 —— 那是新資訊，不是重複。"""
    db_session.add(AIFinding(
        run_id=uuid.uuid4(), severity="high", category="exposure", title="t", detail="d",
        evidence={"ips": ["192.0.2.60"]}, status="dismissed",
        fingerprint=ai_audit.fingerprint(_item("exposure", ["192.0.2.60"]))))
    await db_session.flush()

    kept = await ai_audit.reconcile_findings(
        db_session, uuid.uuid4(),
        items=[_item("exposure", ["192.0.2.60", "192.0.2.99"])],
        model_name="m", partial=False)
    await db_session.flush()
    assert kept == 1, "多了一台沒被忽略過的機器，應該要跳出來"


@pytest.mark.anyio
async def test_dismissal_is_scoped_to_its_category(db_session: Any) -> None:
    """同一台機器在別的分類下被忽略，不代表這個分類也不用講。"""
    db_session.add(AIFinding(
        run_id=uuid.uuid4(), severity="low", category="naming", title="t", detail="d",
        evidence={"ips": ["192.0.2.60"]}, status="dismissed",
        fingerprint=ai_audit.fingerprint(_item("naming", ["192.0.2.60"]))))
    await db_session.flush()

    kept = await ai_audit.reconcile_findings(
        db_session, uuid.uuid4(), [_item("exposure", ["192.0.2.60"])],
        model_name="m", partial=False)
    await db_session.flush()
    assert kept == 1, "忽略跨分類外溢了"
