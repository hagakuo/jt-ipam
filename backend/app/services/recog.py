"""Recog 指紋資料庫（rapid7/recog，BSD-2-Clause）：由 banner、網頁標題、憑證等文字認出產品、OS、設備類型。

用在 IP「探測」的結果摘要（services/ip_identify.py）：nmap 認得協定與多數產品，但認不出
「這個網頁標題是 Synology NAS」「這張預設憑證是 FortiGate」「OpenSSH 的註解寫著 Ubuntu」。
Recog 正是整理這些文字特徵的社群資料庫，約每 1～6 週發佈一次。

**選用元件**：沒有安裝時探測照常運作，只是少了這一層判斷。安裝／升級時下載，之後每週由
jt-ipam-recog-refresh.timer 檢查一次新版（`python -m app.cli.recog update`）。

資料放在 `recog_databases`（一個指紋檔一列）。存的是 Recog 原本的 Ruby 正規式，載入時才轉成
Python —— 轉換規則改進時不必重新下載，只要把 TRANSLATOR_VERSION 加一，下次檢查就會重新匯入。

安全（下載的檔案與被掃主機回的文字都不可信任）：
- XML 走 defusedxml；zip 只取 xml/*.xml，壓縮前後大小、檔數都有上限；GitHub 有提供 SHA-256 就驗
- 每條指紋要能通過自己附的範例才收（轉換出錯的規則會被剔除，而不是默默比錯）
- 可能被惡意 banner 拖成指數時間的寫法（`(.+)*` 這類）匯入時就剔除；比對的輸入限制長度
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import logging
import re
import time
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from defusedxml import ElementTree as DefusedET
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.safe_http import safe_request, transport_detail
from app.models.recog import RecogDatabase
from app.models.system_setting import SystemSetting

logger = logging.getLogger(__name__)

PROJECT_URL = "https://github.com/rapid7/recog"
LICENSE = "BSD-2-Clause"
_API_LATEST = "https://api.github.com/repos/rapid7/recog/releases/latest"
_WEB_LATEST = "https://github.com/rapid7/recog/releases/latest"
_ASSET_URL = "https://github.com/rapid7/recog/releases/download/v{v}/recog-content-{v}.zip"
_ASSET_RE = re.compile(r"^recog-content-(\d+(?:\.\d+){1,3})\.zip$")
_TAG_RE = re.compile(r"/releases/tag/v?(\d+(?:\.\d+){1,3})\b")

STATE_KEY = "recog"
# 轉換規則（Ruby → Python）或匯入檢查改了就加一：已安裝的站台下次檢查會重新匯入同一版
TRANSLATOR_VERSION = 1

MAX_ZIP_BYTES = 20 * 1024 * 1024
MAX_XML_BYTES = 8 * 1024 * 1024
MAX_TOTAL_XML_BYTES = 48 * 1024 * 1024
MAX_FILES = 200
# 正常的一版有四千多條；少到這個數字代表下載或解析出了問題，不可以拿它蓋掉現有的
MIN_FINGERPRINTS = 1000
# 比對的輸入上限（banner、標題、憑證名稱都不會這麼長；限制長度讓最壞情況有上限）
MAX_INPUT = 512
# 同一時間只能有一個程序在更新（安裝腳本、每週排程、畫面上的「立即檢查」可能同時跑）
_UPDATE_LOCK = 0x7265636F67  # "recog"


class RecogError(RuntimeError):
    pass


# ───────────────────────── Ruby 正規式 → Python ─────────────────────────

_POSIX = {
    "alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9", "upper": "A-Z", "lower": "a-z",
    "space": r"\s", "xdigit": "0-9a-fA-F", "punct": r"!-/:-@\[-`{-~", "print": r"\x20-\x7e",
    "graph": r"\x21-\x7e", "word": r"\w", "blank": r" \t", "cntrl": r"\x00-\x1f\x7f",
}
_INLINE_FLAGS = re.compile(r"\(\?([imx]*)(?:-([imx]+))?([:)])")
_NAMED_GROUP = re.compile(r"\(\?<([A-Za-z_]\w*)>")


def _map_flags(on: str, off: str | None) -> str:
    """Ruby 的 m＝「. 也比對換行」＝ Python 的 s（Ruby 的 ^ $ 本來就是逐行）。"""
    on = on.replace("m", "s")
    return on + (f"-{off.replace('m', 's')}" if off else "")


def translate(pattern: str) -> str:
    """把 Recog 的 Ruby 正規式轉成 Python `re` 認得的寫法。不支援的構造直接 raise ValueError。

    差異：\\z → \\Z、\\Z → (?=\\n?\\Z)、\\h → 十六進位、[[:alpha:]] 這類 POSIX 類別、
    (?<name>…) → (?P<name>…)、\\k<name> → (?P=name)、(?m) → (?s)；
    寫在中間的 (?i) 在 Ruby 管到所屬群組結束，Python 3.11 起不允許 → 改成 (?i:…) 包到同一個位置。
    """
    out: list[str] = []
    pending: list[int] = [0]          # 每一層群組結束前要補上的 ")"（中途的 inline flag 造成）
    i, n = 0, len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 >= n:
                raise ValueError("trailing backslash")
            d = pattern[i + 1]
            if d == "z":
                out.append(r"\Z")
            elif d == "Z":
                out.append("Z" if in_class else r"(?=\n?\Z)")
            elif d == "h":
                out.append("0-9a-fA-F" if in_class else "[0-9a-fA-F]")
            elif d == "H":
                if in_class:
                    raise ValueError(r"\H inside a class")
                out.append("[^0-9a-fA-F]")
            elif d == "k" and pattern.startswith("<", i + 2):
                j = pattern.index(">", i + 3)
                out.append(f"(?P={pattern[i + 3:j]})")
                i = j + 1
                continue
            elif d in "GKpPRXg":
                raise ValueError(f"unsupported escape \\{d}")
            else:
                out.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            if c == "[":
                if pattern.startswith("[:", i):
                    j = pattern.find(":]", i + 2)
                    name = pattern[i + 2:j] if j > 0 else ""
                    if name in _POSIX:
                        out.append(_POSIX[name])
                        i = j + 2
                        continue
                raise ValueError("nested character class")
            if c == "]":
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            if i < n and pattern[i] == "^":
                out.append("^")
                i += 1
            if i < n and pattern[i] == "]":
                out.append(r"\]")
                i += 1
            continue
        if c == "(":
            m = _NAMED_GROUP.match(pattern, i)
            if m:
                out.append(f"(?P<{m.group(1)}>")
                pending.append(0)
                i = m.end()
                continue
            m = _INLINE_FLAGS.match(pattern, i)
            if m and (m.group(1) or m.group(2)):
                flags = _map_flags(m.group(1), m.group(2))
                if m.group(3) == ":":
                    out.append(f"(?{flags}:")
                    pending.append(0)
                elif not out and len(pending) == 1 and not m.group(2):
                    out.append(f"(?{flags})")          # 開頭的全域旗標：Python 也接受
                else:
                    out.append(f"(?{flags}:")          # 中途切換：包到所屬群組結束
                    pending[-1] += 1
                i = m.end()
                continue
            out.append("(")
            pending.append(0)
            i += 1
            continue
        if c == ")":
            if len(pending) == 1:
                raise ValueError("unbalanced parenthesis")
            out.append(")" * pending.pop())
            out.append(")")
            i += 1
            continue
        out.append(c)
        i += 1
    if in_class or len(pending) != 1:
        raise ValueError("unterminated group or class")
    out.append(")" * pending[0])
    return "".join(out)


# 群組裡只有一個可重複的東西、群組本身又重複：(.+)*、(\d+)+、([a-z]*)*、(?:\S+)+
# 這種寫法遇到「差一點比中」的長字串會回溯到指數時間 —— banner 是被掃的主機給的，不可信任
_NESTED_QUANT = re.compile(
    r"\((?:\?:|\?P<\w+>)?(?:\\.|\[(?:\\.|[^\]\\])*\]|\.|[^()\\|?*+{])[+*]\??\)(?:[+*]|\{\d*,\d*\})")

_FLAG_NAMES = {"REG_ICASE": re.I, "REG_DOT_NEWLINE": re.S, "REG_MULTILINE": re.S}


def compile_pattern(pattern: str, flags: str | None) -> re.Pattern[str]:
    """Recog 的 pattern + flags 屬性 → 編好的 Python 正規式（Ruby 的 ^ $ 一律逐行 → re.M）。"""
    py = translate(pattern)
    if _NESTED_QUANT.search(py):
        raise ValueError("nested quantifier (catastrophic backtracking risk)")
    f = re.M
    for name in (flags or "").split(","):
        name = name.strip()
        if name:
            f |= _FLAG_NAMES.get(name, 0)
    return re.compile(py, f)


_INTERP = re.compile(r"\{([a-z0-9_.]+)\}")


def apply_params(params: list[list[Any]], m: re.Match[str]) -> dict[str, str]:
    """比中之後的欄位：pos 0＝固定值、pos N＝第 N 個擷取群組；值裡的 {service.version} 代入其他欄位。"""
    out: dict[str, str] = {}
    for pos, name, value in params:
        if pos == 0:
            out[name] = value
        else:
            try:
                g = m.group(pos)
            except IndexError:
                g = None
            if g is not None and g != "":
                out[name] = g
    for k, v in list(out.items()):
        if "{" in v:
            out[k] = _INTERP.sub(lambda mm: out.get(mm.group(1), ""), v)
    return out


# ───────────────────────── 解析發佈檔 ─────────────────────────

@dataclass
class ParsedDatabase:
    key: str
    filename: str
    protocol: str | None
    database_type: str | None
    preference: float | None
    fingerprints: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    skipped: int = 0


def _example_text(ex: Any) -> str | None:
    if ex.get("_filename"):
        return None                                  # 範例放在另一個檔案（發佈檔沒帶）
    txt = ex.text or ""
    if ex.get("_encoding") == "base64":
        try:
            return base64.b64decode(txt).decode("utf-8", errors="replace")
        except ValueError:
            return None
    return txt


def parse_database(data: bytes, filename: str) -> ParsedDatabase:
    """一個指紋檔 → 可以存進資料庫的形狀。轉不過去、或比不中自己範例的指紋會被剔除（算進 skipped）。"""
    root = DefusedET.fromstring(data)
    if root.tag != "fingerprints":
        raise RecogError(f"{filename}: not a Recog fingerprint file")
    stem = filename.rsplit("/", 1)[-1].removesuffix(".xml")
    pref = root.get("preference")
    try:
        preference = float(pref) if pref else None
    except ValueError:
        preference = None
    db = ParsedDatabase(key=(root.get("matches") or stem)[:96], filename=stem,
                        protocol=root.get("protocol"), database_type=root.get("database_type"),
                        preference=preference)
    for el in root.findall("fingerprint"):
        db.total += 1
        pattern = el.get("pattern") or ""
        flags = el.get("flags")
        params = []
        for p in el.findall("param"):
            try:
                params.append([int(p.get("pos") or 0), p.get("name") or "", p.get("value") or ""])
            except ValueError:
                continue
        try:
            rx = compile_pattern(pattern, flags)
        except (ValueError, re.error):
            db.skipped += 1
            continue
        ok = True
        for ex in el.findall("example"):
            txt = _example_text(ex)
            if txt is None:
                continue
            m = rx.search(txt[:MAX_INPUT * 8])
            if not m:
                ok = False
                break
            got = apply_params(params, m)
            if any(got.get(k) != v for k, v in ex.attrib.items() if not k.startswith("_")):
                ok = False
                break
        if not ok:
            db.skipped += 1
            continue
        fp: dict[str, Any] = {"p": pattern, "d": (el.findtext("description") or "").strip()[:300], "a": params}
        if flags:
            fp["f"] = flags
        if el.get("certainty"):
            fp["c"] = el.get("certainty")
        db.fingerprints.append(fp)
    return db


def parse_bundle(data: bytes) -> list[ParsedDatabase]:
    """recog-content-*.zip → 每個指紋檔一份。只讀 xml/*.xml，其他一律略過。"""
    if len(data) > MAX_ZIP_BYTES:
        raise RecogError("the Recog bundle is too large")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise RecogError(f"not a valid zip file ({exc})") from exc
    infos = [i for i in zf.infolist()
             if not i.is_dir() and re.fullmatch(r"(?:[^/]+/)?xml/[A-Za-z0-9_.\-]+\.xml", i.filename)]
    if not infos:
        raise RecogError("no fingerprint files (xml/*.xml) in the bundle")
    if len(infos) > MAX_FILES:
        raise RecogError("too many files in the Recog bundle")
    if sum(i.file_size for i in infos) > MAX_TOTAL_XML_BYTES:
        raise RecogError("the Recog bundle is too large once uncompressed")
    out: list[ParsedDatabase] = []
    seen: set[str] = set()
    for info in infos:
        if info.file_size > MAX_XML_BYTES:
            raise RecogError(f"{info.filename} is too large")
        with zf.open(info) as fh:
            raw = fh.read(MAX_XML_BYTES + 1)
        if len(raw) > MAX_XML_BYTES:
            raise RecogError(f"{info.filename} is too large")
        try:
            db = parse_database(raw, info.filename)
        except (DefusedET.ParseError, ValueError) as exc:
            raise RecogError(f"{info.filename}: {exc}") from exc
        if db.key in seen:                      # 同一個 matches 出現兩次：以檔名區分
            db.key = f"{db.key}#{db.filename}"[:96]
        seen.add(db.key)
        out.append(db)
    return out


# ───────────────────────── 比對 ─────────────────────────

@dataclass
class _Compiled:
    preference: float
    items: list[tuple[re.Pattern[str], list[list[Any]], str, str | None]]


class Matcher:
    """某一版指紋庫的比對器。指紋檔用到才編譯（大多數探測只用到其中幾個）。"""

    def __init__(self, release: str, raw: dict[str, tuple[float | None, list[dict[str, Any]]]]):
        self.release = release
        self._raw = raw
        self._compiled: dict[str, _Compiled] = {}
        self._match = lru_cache(maxsize=4096)(self._match_uncached)

    @property
    def keys(self) -> list[str]:
        return list(self._raw)

    def _db(self, key: str) -> _Compiled | None:
        c = self._compiled.get(key)
        if c is None and key in self._raw:
            pref, fps = self._raw[key]
            items = []
            for fp in fps:
                try:
                    rx = compile_pattern(fp["p"], fp.get("f"))
                except (ValueError, re.error, KeyError):
                    continue
                items.append((rx, fp.get("a") or [], fp.get("d") or "", fp.get("c")))
            c = self._compiled[key] = _Compiled(preference=pref if pref is not None else 0.5, items=items)
        return c

    def preference(self, key: str) -> float:
        c = self._db(key)
        return c.preference if c else 0.0

    def match(self, key: str, text: str) -> dict[str, Any] | None:
        """第一個比中的指紋（Recog 的語意：檔案內依序、先中先贏）。沒比中回 None。"""
        text = (text or "").strip()[:MAX_INPUT]
        if not text:
            return None
        return self._match(key, text)

    def _match_uncached(self, key: str, text: str) -> dict[str, Any] | None:
        db = self._db(key)
        if db is None:
            return None
        for rx, params, desc, certainty in db.items:
            m = rx.search(text)
            if m:
                out = {"db": key, "description": desc, "params": apply_params(params, m)}
                if certainty:
                    out["certainty"] = certainty
                return out
        return None


_cache: dict[str, Any] = {"stamp": None, "matcher": None, "checked": 0.0}
_CACHE_TTL = 60.0


async def get_matcher(session: AsyncSession) -> Matcher | None:
    """目前安裝的指紋庫（沒安裝回 None）。每個行程快取一份，每分鐘看一次有沒有換版。"""
    now = time.monotonic()
    if _cache["checked"] and now - _cache["checked"] < _CACHE_TTL:
        return _cache["matcher"]
    row = (await session.execute(select(func.max(RecogDatabase.updated_at), func.max(RecogDatabase.release),
                                        func.count()))).one()
    stamp = (row[0], row[1], row[2])
    if stamp != _cache["stamp"]:
        matcher = None
        if row[2]:
            rows = (await session.execute(select(RecogDatabase.key, RecogDatabase.preference,
                                                 RecogDatabase.fingerprints))).all()
            matcher = Matcher(str(row[1]), {k: (p, fps or []) for k, p, fps in rows})
        _cache["matcher"] = matcher
        _cache["stamp"] = stamp
    _cache["checked"] = now
    return _cache["matcher"]


def reset_cache() -> None:
    _cache.update(stamp=None, matcher=None, checked=0.0)


# ───────────────────────── 下載與更新 ─────────────────────────

@dataclass
class Release:
    version: str
    url: str
    sha256: str | None = None
    size: int | None = None


async def latest_release() -> Release:
    """GitHub 上最新一版。API 被限流（未登入每小時 60 次）或擋掉時，改看 releases/latest 轉到哪個 tag。"""
    api_err = ""
    try:
        resp = await safe_request("GET", _API_LATEST, timeout=20.0, max_bytes=2 * 1024 * 1024,
                                  headers={"Accept": "application/vnd.github+json",
                                           "User-Agent": "jt-ipam-recog"})
        if resp.status_code == 200:
            body = resp.json()
            for a in body.get("assets") or []:
                m = _ASSET_RE.match(str(a.get("name") or ""))
                if m and a.get("browser_download_url"):
                    digest = str(a.get("digest") or "")
                    return Release(version=m.group(1), url=str(a["browser_download_url"]),
                                   sha256=digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else None,
                                   size=int(a["size"]) if isinstance(a.get("size"), int) else None)
            api_err = "the latest release has no recog-content zip"
        else:
            api_err = f"HTTP {resp.status_code}"
    except Exception as exc:  # 任何失敗都改走備援；兩條都失敗才回報（附兩邊原因）
        api_err = transport_detail(exc)
    try:
        resp = await safe_request("GET", _WEB_LATEST, timeout=20.0, max_bytes=4 * 1024 * 1024,
                                  headers={"User-Agent": "jt-ipam-recog"})
        m = _TAG_RE.search(str(resp.url))
        if m:
            return Release(version=m.group(1), url=_ASSET_URL.format(v=m.group(1)))
        web_err = f"HTTP {resp.status_code}, no release tag in {resp.url}"
    except Exception as exc:
        web_err = transport_detail(exc)
    raise RecogError(f"cannot reach GitHub to check the latest Recog release (API: {api_err}; web: {web_err})")


async def download(rel: Release) -> bytes:
    resp = await safe_request("GET", rel.url, timeout=120.0, max_bytes=MAX_ZIP_BYTES,
                              headers={"User-Agent": "jt-ipam-recog"})
    if resp.status_code != 200:
        raise RecogError(f"download failed: HTTP {resp.status_code} ({rel.url})")
    data = resp.content
    if rel.sha256 and hashlib.sha256(data).hexdigest() != rel.sha256:
        raise RecogError("the downloaded Recog bundle does not match the SHA-256 published on GitHub")
    return data


async def _get_state(session: AsyncSession) -> dict[str, Any]:
    row = await session.get(SystemSetting, STATE_KEY)
    return dict(row.value) if row and isinstance(row.value, dict) else {}


async def _put_state(session: AsyncSession, **changes: Any) -> None:
    row = await session.get(SystemSetting, STATE_KEY)
    if row is None:
        row = SystemSetting(key=STATE_KEY, value={})
        session.add(row)
    row.value = {**(row.value or {}), **changes}
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(row, "value")


async def installed(session: AsyncSession) -> dict[str, Any] | None:
    """已安裝的版本（以資料表為準，不看設定：系統匯出／匯入只搬設定時，不可以讓對方以為裝好了）。"""
    row = (await session.execute(select(
        func.max(RecogDatabase.release), func.min(RecogDatabase.translator_version),
        func.count(), func.sum(RecogDatabase.total), func.sum(RecogDatabase.skipped),
        func.max(RecogDatabase.updated_at),
        func.sum(func.jsonb_array_length(RecogDatabase.fingerprints))))).one()
    if not row[2]:
        return None
    return {"release": row[0], "translator_version": row[1], "databases": int(row[2]),
            "total": int(row[3] or 0), "skipped": int(row[4] or 0), "updated_at": row[5],
            "fingerprints": int(row[6] or 0)}


def version_from_filename(name: str | None) -> str | None:
    m = _ASSET_RE.match((name or "").rsplit("/", 1)[-1])
    return m.group(1) if m else None


async def _lock(session: AsyncSession) -> None:
    """交易層級的 advisory lock：commit／rollback 時自動放掉，同一個交易重複取不會卡住自己。

    2026-09-29 全新安裝關卡抓到：安裝腳本的下載與排程同時跑，兩邊一起整批寫入 → 主鍵撞鍵。"""
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _UPDATE_LOCK})


async def install_bundle(session: AsyncSession, data: bytes, *, version: str, source: str) -> dict[str, Any]:
    """解析並整批換掉資料表內容（同一個交易：失敗時舊的一版原封不動）。"""
    dbs = await asyncio.to_thread(parse_bundle, data)
    await _lock(session)
    kept = sum(len(d.fingerprints) for d in dbs)
    if kept < MIN_FINGERPRINTS:
        raise RecogError(f"only {kept} usable fingerprints in the bundle — refusing to replace the installed database")
    now = datetime.now(UTC)
    await session.execute(delete(RecogDatabase))
    for d in dbs:
        session.add(RecogDatabase(
            key=d.key, filename=d.filename, release=version, translator_version=TRANSLATOR_VERSION,
            protocol=d.protocol, database_type=d.database_type, preference=d.preference,
            fingerprints=d.fingerprints, total=d.total, skipped=d.skipped, updated_at=now))
    await _put_state(session, installed_at=now.isoformat(), source=source,
                     sha256=hashlib.sha256(data).hexdigest(), error=None)
    await session.flush()
    reset_cache()
    return {"release": version, "databases": len(dbs), "fingerprints": kept,
            "skipped": sum(d.skipped for d in dbs)}


async def check_and_update(session: AsyncSession, *, force: bool = False) -> dict[str, Any]:
    """檢查 GitHub 上有沒有新版，有就下載安裝。任何失敗只記錄、回報，不影響現有的一版。

    回傳 {status: up_to_date|updated|error, release, latest, ...}；呼叫端負責 commit。
    """
    now = datetime.now(UTC).isoformat()
    # 先排隊再看裝了哪一版：後到的程序要看到前一個剛裝好的結果，而不是也去下載、也去寫
    await _lock(session)
    cur = await installed(session)
    try:
        rel = await latest_release()
        if (not force and cur and cur["release"] == rel.version
                and cur["translator_version"] == TRANSLATOR_VERSION):
            await _put_state(session, checked_at=now, latest=rel.version, error=None, last_ok_at=now)
            return {"status": "up_to_date", "release": cur["release"], "latest": rel.version}
        data = await download(rel)
        result = await install_bundle(session, data, version=rel.version, source=rel.url)
    except RecogError as exc:
        await _put_state(session, checked_at=now, error=str(exc)[:500])
        return {"status": "error", "error": str(exc)[:500], "release": cur["release"] if cur else None}
    await _put_state(session, checked_at=now, latest=rel.version, last_ok_at=now)
    return {"status": "updated", "previous": cur["release"] if cur else None, "latest": rel.version, **result}


async def status(session: AsyncSession) -> dict[str, Any]:
    cur = await installed(session)
    st = await _get_state(session)
    return {
        "installed": cur is not None,
        "release": cur["release"] if cur else None,
        "databases": cur["databases"] if cur else 0,
        "fingerprints": cur["fingerprints"] if cur else 0,
        "skipped": cur["skipped"] if cur else 0,
        "updated_at": cur["updated_at"].isoformat() if cur and cur["updated_at"] else None,
        "checked_at": st.get("checked_at"),
        "last_ok_at": st.get("last_ok_at"),
        "latest": st.get("latest"),
        "error": st.get("error"),
        "project_url": PROJECT_URL,
        "license": LICENSE,
    }
