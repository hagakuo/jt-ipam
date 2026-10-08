"""讀 .xlsx 的第一張工作表 → 每列一個字串清單（零相依：zipfile ＋ defusedxml）。

給「匯出改完再匯回來」用（issue #46 裝置匯入）：使用者最常做的是從清單匯出成 Excel、在 Excel 裡改、
存檔再匯入。匯出端本來就是零相依產生 xlsx，這裡對應地只讀需要的部分：共用字串、行內字串、數字、布林。

安全（上傳的檔案是不可信任的輸入）：
- XML 一律走 defusedxml（擋 XXE／實體展開）
- 解壓後總大小、列數、欄數都有上限（擋壓縮炸彈與超大檔拖垮後端）
"""
from __future__ import annotations

import io
import posixpath
import re
import zipfile

from defusedxml import ElementTree as DefusedET

MAX_UNCOMPRESSED = 64 * 1024 * 1024
_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
_R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_CELL_REF = re.compile(r"^([A-Z]+)(\d+)$")


class XlsxError(ValueError):
    pass


def is_xlsx(data: bytes) -> bool:
    return data[:4] == b"PK\x03\x04"


def _col_index(letters: str) -> int:
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _text(el) -> str:
    """<si>／<is>：純文字 <t>，或 rich text 的多段 <r><t>。"""
    parts = [t.text or "" for t in el.iter(f"{{{_NS['m']}}}t")]
    return "".join(parts)


def read_first_sheet(data: bytes, *, max_rows: int = 10_000, max_cols: int = 64) -> list[list[str]]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise XlsxError(f"not a valid .xlsx file ({exc})") from exc
    if sum(i.file_size for i in zf.infolist()) > MAX_UNCOMPRESSED:
        raise XlsxError("the .xlsx file is too large once uncompressed")

    def xml(name: str):
        try:
            return DefusedET.fromstring(zf.read(name))
        except KeyError as exc:
            raise XlsxError(f"missing part {name}") from exc

    # 第一張工作表的路徑：workbook.xml 的第一個 <sheet> → 關聯檔裡的 Target
    wb = xml("xl/workbook.xml")
    first = wb.find("m:sheets/m:sheet", _NS)
    if first is None:
        raise XlsxError("the workbook has no sheet")
    rid = first.get(f"{{{_R_NS}}}id")
    target = "worksheets/sheet1.xml"
    try:
        rels = DefusedET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
        for rel in rels.iter(f"{{{_PKG_REL}}}Relationship"):
            if rel.get("Id") == rid and rel.get("Target"):
                target = rel.get("Target").lstrip("/")
                break
    except KeyError:
        pass
    sheet_path = target if target.startswith("xl/") else posixpath.normpath(posixpath.join("xl", target))

    shared: list[str] = []
    if "xl/sharedStrings.xml" in zf.namelist():
        shared = [_text(si) for si in xml("xl/sharedStrings.xml").findall("m:si", _NS)]

    rows: list[list[str]] = []
    for row in xml(sheet_path).iterfind("m:sheetData/m:row", _NS):
        if len(rows) >= max_rows:
            break
        cells: dict[int, str] = {}
        for i, c in enumerate(row.findall("m:c", _NS)):
            m = _CELL_REF.match(c.get("r") or "")
            idx = _col_index(m.group(1)) if m else i
            if idx >= max_cols:
                continue
            kind = c.get("t")
            v = c.find("m:v", _NS)
            if kind == "inlineStr":
                is_ = c.find("m:is", _NS)
                val = _text(is_) if is_ is not None else ""
            elif kind == "s":
                try:
                    val = shared[int(v.text)] if v is not None and v.text else ""
                except (ValueError, IndexError):
                    val = ""
            elif kind == "b":
                val = "TRUE" if v is not None and v.text == "1" else "FALSE"
            else:
                val = (v.text or "") if v is not None else ""
                # 整數存成數字時 Excel 會寫 "12" 或 "12.0"
                if re.fullmatch(r"-?\d+\.0+", val):
                    val = val.split(".")[0]
            cells[idx] = val
        if cells:
            width = max(cells) + 1
            rows.append([cells.get(j, "") for j in range(width)])
        else:
            rows.append([])
    return rows
