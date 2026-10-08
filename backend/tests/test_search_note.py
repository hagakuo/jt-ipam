"""全域搜尋也要找得到「備註」。

備註是使用者自己寫的欄位 —— 機器名稱、工單號、「這台是誰的」—— 但它原本不在搜尋
範圍內，所以寫進去的字查不到，等於那個欄位只能用眼睛找。

同時守「優先權放最後」：備註是自由文字，命中的理由最弱。它出現在主機名稱、描述、
IP、MAC 的後面，不能把真正的目標擠下去。
"""

from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.search import search


async def _seed(session, *, note: str | None = None, hostname: str | None = None,
                ip: str = "192.0.2.10", cidr: str = "192.0.2.0/24") -> IPAddress:
    sec = Section(name=f"note-sec-{uuid.uuid4().hex[:6]}")
    session.add(sec)
    await session.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr)
    session.add(sub)
    await session.flush()
    addr = IPAddress(subnet_id=sub.id, ip=ip, hostname=hostname, note=note)
    session.add(addr)
    await session.flush()
    return addr


async def test_note_is_searchable(db_session, admin_user):
    tag = f"ud24-{uuid.uuid4().hex[:6]}"
    addr = await _seed(db_session, note=f"dev2-{tag}")

    res = await search(db_session, user=admin_user, q=tag)
    ids = [h["id"] for h in res["results"] if h["type"] == "ip_address"]
    assert str(addr.id) in ids, "備註裡的字查不到 —— 那個欄位等於只能用眼睛找"


async def test_note_match_shows_the_note_so_the_row_explains_itself(db_session, admin_user):
    """只憑備註命中的那一列，要把備註顯示出來。

    否則畫面上是一個跟查詢字毫無關係的 IP，使用者看不出它為什麼在結果裡。
    """
    tag = f"ticket-{uuid.uuid4().hex[:6]}"
    await _seed(db_session, note=f"工單 {tag}", hostname="unrelated-host", ip="192.0.2.11")

    res = await search(db_session, user=admin_user, q=tag)
    hit = next(h for h in res["results"] if h["type"] == "ip_address")
    assert tag in (hit["sublabel"] or ""), "看不出這一列為什麼會被搜出來"


async def test_note_ranks_below_hostname(db_session, admin_user):
    """同一個字，一台寫在主機名稱、一台寫在備註 —— 主機名稱那台要排前面。"""
    tag = f"nas{uuid.uuid4().hex[:4]}"
    by_host = await _seed(db_session, hostname=tag, ip="192.0.2.20", cidr="192.0.2.0/24")
    by_note = await _seed(db_session, note=f"備用機 {tag}", hostname="other-box",
                          ip="198.51.100.20", cidr="198.51.100.0/24")

    res = await search(db_session, user=admin_user, q=tag)
    order = [h["id"] for h in res["results"] if h["type"] == "ip_address"]
    assert str(by_host.id) in order and str(by_note.id) in order
    assert order.index(str(by_host.id)) < order.index(str(by_note.id)), \
        "備註的命中把主機名稱的命中擠到後面了"


async def test_note_does_not_outrank_an_exact_ip(db_session, admin_user):
    """有人把 IP 寫進別台的備註時，真正的那個 IP 還是要排第一。"""
    await _seed(db_session, note="備援指向 203.0.113.9", ip="192.0.2.30")
    target = await _seed(db_session, ip="203.0.113.9", cidr="203.0.113.0/24")

    res = await search(db_session, user=admin_user, q="203.0.113.9")
    assert res["results"], "什麼都沒搜到"
    assert res["results"][0]["id"] == str(target.id), "備註把真正的 IP 擠下去了"


async def test_description_is_searchable_even_when_something_else_also_matches(
    db_session, admin_user,
):
    """說明命中的那一列不能被「子字串優先」那道篩選吃掉。

    `description` 本來就在 WHERE 裡，看起來有搜；但命中的字只在說明欄，label 與
    sublabel 都看不到它，於是只要畫面上另有一筆真的含查詢字的結果，這一列就會被
    整批濾掉 —— 表面上是「說明搜不到」。
    """
    tag = f"svcdesc{uuid.uuid4().hex[:5]}"
    by_desc = await _seed(db_session, ip="192.0.2.40")
    by_desc.description = f"這台跑 {tag} 服務"
    # 同時有一筆主機名稱直接含查詢字 → 觸發子字串優先的篩選
    await _seed(db_session, hostname=f"{tag}-box", ip="198.51.100.40", cidr="198.51.100.0/24")
    await db_session.flush()

    res = await search(db_session, user=admin_user, q=tag)
    ids = [h["id"] for h in res["results"] if h["type"] == "ip_address"]
    assert str(by_desc.id) in ids, "說明命中的那一列被濾掉了"


async def test_owner_is_searchable(db_session, admin_user):
    """擁有者原本完全不在搜尋範圍內。"""
    tag = f"owner{uuid.uuid4().hex[:5]}"
    addr = await _seed(db_session, ip="192.0.2.50")
    addr.owner = f"{tag} 資訊室"
    await db_session.flush()

    res = await search(db_session, user=admin_user, q=tag)
    ids = [h["id"] for h in res["results"] if h["type"] == "ip_address"]
    assert str(addr.id) in ids, "擁有者裡的字查不到"


async def test_the_row_says_which_field_matched(db_session, admin_user):
    """靠說明／擁有者命中時，副標要指出是哪一欄命中 —— 否則看不出為什麼會搜出來。"""
    tag = f"why{uuid.uuid4().hex[:5]}"
    a = await _seed(db_session, hostname="plain-host", ip="192.0.2.60")
    a.owner = f"{tag} 網路組"
    await db_session.flush()

    res = await search(db_session, user=admin_user, q=tag)
    hit = next(h for h in res["results"] if h["id"] == str(a.id))
    assert tag in (hit["sublabel"] or ""), "看不出這一列為什麼會被搜出來"


async def test_hostname_hit_does_not_get_cluttered(db_session, admin_user):
    """主機名稱自己就含查詢字時，副標不要再塞一堆命中欄位 —— 理由已經看得見了。"""
    tag = f"clean{uuid.uuid4().hex[:5]}"
    a = await _seed(db_session, hostname=f"{tag}-01", ip="192.0.2.70")
    a.description = f"{tag} 說明"
    a.owner = f"{tag} 擁有者"
    a.note = f"{tag} 備註"
    await db_session.flush()

    res = await search(db_session, user=admin_user, q=tag)
    hit = next(h for h in res["results"] if h["id"] == str(a.id))
    assert "說明" not in (hit["sublabel"] or "")
    assert "備註" not in (hit["sublabel"] or "")


async def test_hostname_substring_beats_owner_and_description(db_session, admin_user):
    """主機名稱含查詢字的那台要排在說明／擁有者命中的前面。

    主機名稱是這個物件的身分：打「kappa5」的人要的就是那台叫 kappa5 的機器。
    純看 trigram 相似度會反過來 —— 「kappa5 小組」比「kappa5-web」短，分數反而高，
    於是「某某組負責的機器」排在「那台機器」前面。
    """
    tag = f"kappa{uuid.uuid4().hex[:4]}"
    by_host = await _seed(db_session, hostname=f"{tag}-web", ip="192.0.2.80")
    by_owner = await _seed(db_session, hostname="plain-a", ip="192.0.2.81")
    by_owner.owner = f"{tag} 小組"
    by_desc = await _seed(db_session, hostname="plain-b", ip="192.0.2.82")
    by_desc.description = f"{tag} 的測試機"
    await db_session.flush()

    res = await search(db_session, user=admin_user, q=tag)
    order = [h["id"] for h in res["results"] if h["type"] == "ip_address"]
    assert order[0] == str(by_host.id), "主機名稱命中的那台沒有排第一"
    assert str(by_owner.id) in order and str(by_desc.id) in order
