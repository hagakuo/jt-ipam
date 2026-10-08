"""探測結果解析的正規表示式不可以是二次方（CodeQL #39／#40，2026-10-01）。

nmap 的腳本輸出是代理回報的、內容由被掃的主機決定；解析在 async 處理裡同步執行，慢一次就卡住整個
工作程序。舊的兩條在惡意輸入上要十秒以上（40 KB 的未結束 telnet 子協商、「OS: a ( ( ( …」）。
官方代理會截短腳本輸出，但伺服器不能假設送來的一定是官方代理。
"""
from __future__ import annotations

import time

from app.services.ip_identify import _unescape, recog_observations


def _smb(text: str) -> list[tuple[str, str | None, str]]:
    obs = recog_observations({"host_scripts": {"smb-os-discovery": text}})
    return [(k, v) for k, _w, v in obs if k.startswith("smb.")]


def test_telnet_negotiation_is_still_removed() -> None:
    raw = r"\xff\xfb\x01\xff\xfd\x03\xff\xfa\x18\x01\xff\xf0login:"
    assert _unescape(raw, telnet=True) == "login:"


def test_telnet_cleanup_is_linear() -> None:
    raw = r"\xff\xfa" * 20000 + "login:"
    t0 = time.monotonic()
    _unescape(raw, telnet=True)
    assert time.monotonic() - t0 < 1.0


def test_smb_os_line_parses_the_same() -> None:
    assert _smb("\n  OS: Windows 10 Pro 19045 (Windows 10 Pro 6.3)\n  OS CPE: cpe:/o:microsoft:windows_10::-\n") == [
        ("smb.native_os", "Windows 10 Pro 19045"), ("smb.native_lm", "Windows 10 Pro 6.3")]
    assert _smb("  OS: Unix  ") == [("smb.native_os", "Unix")]
    assert _smb("OS: A (B) (C)") == [("smb.native_os", "A"), ("smb.native_lm", "B) (C")]
    assert _smb("OS: X ()") == [("smb.native_os", "X ()")]
    assert _smb("no os line here") == []


def test_smb_os_line_is_linear() -> None:
    t0 = time.monotonic()
    _smb("OS: a" + " (" * 20000)
    _smb("\n" * 20000 + "OS:")
    assert time.monotonic() - t0 < 1.0


# ─────────────────── 設備類型的知識表（services/device_kind_knowledge.py，2026-10-05） ───────────────────
# 產品字樣、網頁標題、Server 標頭、主機名稱都是被掃的主機（或 DHCP 用戶端）給的。每條正規表示式都要：
# ① 沒有「群組裡一個可重複的東西、群組本身又重複」的寫法（與 Recog 指紋同一個檢查）；
# ② 在惡意的長字串上維持線性時間 —— 比對前會截短，帶 `(?!.*…)` 的幾條也只到二次方的上限。

def _knowledge_patterns() -> list[tuple[str, str]]:
    from app.services import device_kind_knowledge as kk
    out = [(f"service:{p.pattern[:40]}", p.pattern) for p in kk.SERVICE_PRODUCT_PATTERNS]
    out += [(f"hostname:{h.pattern[:40]}", h.pattern) for h in kk.HOSTNAME_HINTS]
    out.append(("hostname-veto", kk.HOSTNAME_ROLE_VETO))
    for o in kk.NMAP_CLASS_OVERRIDES:
        out += [(f"nmap:{o.reason[:30]}", rx) for rx in (o.vendor, o.osfamily, o.name) if rx]
    out += [(f"recog:{o.reason[:30]}", o.pattern) for o in kk.RECOG_OVERRIDES]
    return out


def test_knowledge_regexes_have_no_nested_quantifiers() -> None:
    from app.services.recog import _NESTED_QUANT
    bad = [name for name, rx in _knowledge_patterns() if _NESTED_QUANT.search(rx)]
    assert not bad, bad


# 長度在比對上限附近的惡意字串：重複的單字、數字、空白、連字號，以及各樣式裡常見的字首
_HOSTILE = [s * (400 // len(s) + 1) for s in (
    "a", "1", " ", "-", "a ", "a1", "x-", "axis ", "camera ", "printer ", "ups ", "nas ", "ap ", "cam1 ",
    "proxmox ", "sonicwall ", "vigor ", "kasa ", "esp_", "hp", "sw1 ", "galaxy ", "(", "a(", "server ")]


def test_every_knowledge_regex_is_fast_on_hostile_text() -> None:
    import re
    slow = []
    for name, rx in _knowledge_patterns():
        c = re.compile(rx, re.I)
        t0 = time.monotonic()
        for s in _HOSTILE:
            c.search(s[:400])
        if time.monotonic() - t0 > 0.25:
            slow.append(name)
    assert not slow, slow


def test_knowledge_helpers_cap_their_input() -> None:
    from app.services import device_kind_knowledge as kk
    huge = "axis " * 40000 + "camera"
    t0 = time.monotonic()
    kk.classify_service_text(huge)
    kk.classify_service_text("a(" * 100000)
    kk.hostname_kind("a-" * 100000)
    kk.nmap_kind("WAP", "x" * 100000, "y" * 100000, "Linux (" * 50000)
    kk.recog_kind("Device", "v" * 100000, "p" * 100000, "d" * 100000)
    kk.oui_hint("v" * 100000, "0" * 100000)
    assert time.monotonic() - t0 < 1.0


def test_first_alternative_keeps_its_meaning_and_is_linear(monkeypatch) -> None:
    """CodeQL #45：分隔符改成單一空白後，結果要跟以前一樣，而且不靠長度上限也是線性。"""
    from app.services import device_kind_knowledge as kk
    assert kk.first_alternative("A  or  B") == "A"
    assert kk.first_alternative("A,\tB") == "A"
    assert kk.first_alternative("A; B") == "A"
    assert kk.first_alternative("Linux 4.15 - 5.6 or Linux 3.2") == "Linux 4.15 - 5.6"
    assert kk.first_alternative("Microsoft Windows 10 (1903) or Windows 11") == "Microsoft Windows 10"
    assert kk.first_alternative("Motorola camera") == "Motorola camera"
    monkeypatch.setattr(kk, "MAX_TEXT", 10_000_000)
    t0 = time.monotonic()
    kk.first_alternative("a" + " " * 50000 + "b")
    assert time.monotonic() - t0 < 0.1
