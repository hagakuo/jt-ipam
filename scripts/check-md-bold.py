#!/usr/bin/env python3
"""Find bold markers that will NOT render, which happens easily in Chinese text.

CommonMark: a `**` run can open (left-flanking) only if it is not followed by
whitespace AND (not followed by punctuation OR preceded by whitespace/punctuation).
The trap in Chinese prose is a bold run that starts right at a full-width bracket:

    ...是**「文字」**）      the opening ** is preceded by a Han character and followed
                            by 「 → not left-flanking → the asterisks are printed as-is

Write it as 「**文字**」 instead. Bold that spans a line break is fine and is skipped
here (this check is line-based, so it cannot see across the break).

Usage: python3 scripts/check-md-bold.py FILE...   (exit 1 if anything would not render)
"""
import re, sys, unicodedata
from pathlib import Path

def is_punct(ch: str) -> bool:
    return bool(ch) and (unicodedata.category(ch).startswith("P") or ch in "＋－＝｜～")

def is_space(ch: str) -> bool:
    return ch == "" or ch.isspace()

def flanking(text: str, i: int, n: int):
    before = text[i - 1] if i > 0 else ""
    after = text[i + n] if i + n < len(text) else ""
    left = (not is_space(after)) and ((not is_punct(after)) or is_space(before) or is_punct(before))
    right = (not is_space(before)) and ((not is_punct(before)) or is_space(after) or is_punct(after))
    return left, right

def paragraphs(text: str):
    """把連續的非空行併成一段（附上起始行號）。粗體可以跨行，逐行看會誤判。"""
    buf: list[str] = []
    start = 1
    in_code = False
    for lineno, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        if in_code or line.lstrip().startswith("    "):
            continue
        if line.strip():
            if not buf:
                start = lineno
            buf.append(line)
        elif buf:
            yield start, " ".join(buf)
            buf = []
    if buf:
        yield start, " ".join(buf)


bad = 0
for f in sys.argv[1:]:
    for lineno, line in paragraphs(Path(f).read_text(encoding="utf-8")):
        if False:
            continue
        runs = [(m.start(), len(m.group())) for m in re.finditer(r"\*{2,}", line)]
        if not runs or len(runs) % 2:
            continue      # 奇數＝這段粗體跨行，line-based 檢查看不到另一半
        # 行首或行尾就是 ** 的情形多半是跨行粗體的後半/前半，同樣略過
        if line.strip().startswith("**") and line.rstrip().endswith("**") and len(runs) == 2 \
                and runs[0][0] == len(line) - len(line.lstrip()):
            pass
        for idx, (pos, n) in enumerate(runs):
            left, right = flanking(line, pos, n)
            opening = idx % 2 == 0
            if opening and not left:
                print(f"{f}:{lineno}: 開頭 ** 不會生效 → {line[max(0,pos-12):pos+22]}")
                bad += 1
            if not opening and not right:
                print(f"{f}:{lineno}: 結尾 ** 不會生效 → {line[max(0,pos-22):pos+12]}")
                bad += 1
print(f"--- {bad} problem(s) ---")
sys.exit(1 if bad else 0)
