#!/bin/bash
# 發版關卡（TEST_CHECKLIST 5h）：上網查 Debian／Ubuntu 目前「還在支援期」的版本，跟 targets.txt 比對。
#   - 有支援中的版本不在 targets.txt → 列出來、回傳 1：要加進去、編好、驗好、隨版提供。
#   - targets.txt 裡有已經停止支援的 → 只提醒，可以退場。
# 「支援中」＝已發佈且 eol（一般支援結束日）還沒到；非 LTS 的 Ubuntu 在支援期內也算。
# 只看安裝腳本支援的範圍：Debian 12 以上、Ubuntu 22.04 以上。
# 資料來源：endoflife.date（公開 API，不需金鑰）。用法：check-new-os.sh [targets 檔]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
python3 - "${1:-$HERE/targets.txt}" <<'PY'
import datetime, json, sys, urllib.request
targets = {l.strip() for l in open(sys.argv[1]) if l.strip() and not l.lstrip().startswith("#")}
today = datetime.date.today().isoformat()
MIN = {"debian": (12,), "ubuntu": (22, 4)}
missing, retired, current = [], [], []
for product in ("debian", "ubuntu"):
    with urllib.request.urlopen(f"https://endoflife.date/api/{product}.json", timeout=30) as r:
        cycles = json.load(r)
    for c in cycles:
        ver = str(c["cycle"])
        if tuple(int(x) for x in ver.split(".")) < MIN[product]:
            continue
        image = f"{product}:{ver}"
        released = c.get("releaseDate") and c["releaseDate"] <= today
        eol = c.get("eol")
        supported = released and (eol is False or (isinstance(eol, str) and eol > today))
        if supported:
            current.append(f"{image}（支援到 {eol}）")
            if image not in targets:
                missing.append(f"{image} {c.get('codename', '')}（{c['releaseDate']} 發佈，支援到 {eol}）")
        elif image in targets:
            retired.append(f"{image}（{eol} 已停止支援）")
print("支援中：" + "、".join(current))
for r in retired:
    print(f"可以退場：{r}")
if missing:
    for m in missing:
        print(f"缺少預編目標：{m}")
    print("→ 加進 scripts/guacd/targets.txt，跑 scripts/guacd/build.sh 與 verify.sh，驗過隨版提供。")
    sys.exit(1)
print("guacd 預編目標涵蓋所有支援中的版本。")
PY
