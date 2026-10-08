#!/usr/bin/env python3
"""建立一份「可以拿去截圖」的示範資料集 —— 純虛構、可重跑。

為什麼需要這個：官網與文件站的畫面截圖，過去是對著某一台實際跑著的系統拍的。
那有兩個問題：

1. **會把真實環境洩出去**。主機名稱、網段、機房名稱、裝置型號，全部都是別人家的
   資產清單。一張截圖就是一份偵察報告。
2. **拍不出第二次**。資料會變，下一版要補拍時畫面已經不一樣了；本機開發用的資料
   又太稀疏（一個機房、一座機櫃、三台裝置），拍起來像個空系統。

所以這裡把「畫面上該有什麼」寫成程式：位址一律用 RFC 5737／RFC 3849 的**文件保留
網段**（198.51.100.0/24、203.0.113.0/24、192.0.2.0/24、2001:db8::/32），名稱一律是
虛構的通用名（`core-sw-01`、`Tokyo DC`），不含任何真實組織或人的資訊。

用法（**只對可丟棄的資料庫跑**）：

    python3 scripts/demo_dataset.py --base http://127.0.0.1:8010/api/v1 \\
        --user admin --password '...'

重複執行是安全的：同名的物件會被跳過而不是重複建立，所以補資料、改資料都可以
直接再跑一次。

`--consoles`（要搭配 `--db-url`）另外建立瀏覽器連線管理的示範目標（SSH／RDP／VNC／
PVE／BMC／RustDesk），拍 `ssh-rdp` 那張圖用。它會多出幾筆 IP、讓其他畫面也出現連線按鈕，
所以預設不做；其他截圖照舊在沒有加這個參數的資料上拍。
"""
from __future__ import annotations

import argparse
import json
import pathlib
import secrets
import sys
import urllib.error
import urllib.request
from typing import Any

# ── 這份資料集的內容（改這裡就會改畫面上的樣子）─────────────────────────

#: 名稱一律用中性的英數站台代號，不用中文。理由：**同一份資料要配三種語言的截圖**，
#: 資料本身不會跟著語言變 —— 中文的機房名稱出現在英文與日文的畫面上會很突兀，
#: 而現實中的站台代號本來就多半是這種寫法。
LOCATIONS = [
    # name, address, lat, lon —— 座標是給世界地圖用的；城市中心點即可
    ("Tokyo DC", "Minato, Tokyo", 35.6586, 139.7454),
    ("Osaka Site", "Kita, Osaka", 34.7055, 135.4983),
    ("Taipei HQ", "Xinyi, Taipei", 25.0330, 121.5654),
    ("Singapore Edge", "Downtown Core, Singapore", 1.2897, 103.8501),
    # 只放層架的實驗室：拍層架那張圖時，旁邊不要有一座幾乎全空的 24U 機櫃佔掉一半寬度
    ("Taipei Lab", "Neihu, Taipei", 25.0797, 121.5745),
    # 三種新型態（角鋼層架、KALLAX、LackRack）各一座，拍 rack-more-kinds 那張圖用
    ("Taichung Office", "Xitun, Taichung", 24.1631, 120.6408),
]

#: 機櫃：(名稱, 機房, U 數, 寬 mm, 深 mm, 平面圖 x, 平面圖 y)
RACKS = [
    # 平面圖座標拉開一點：擠在一起的話三個機櫃名稱會互相疊住，看不出是哪一櫃
    ("TYO-R01", "Tokyo DC", 42, 600, 1200, 0.22, 0.30),
    ("TYO-R02", "Tokyo DC", 42, 600, 1200, 0.45, 0.30),
    ("TYO-R03", "Tokyo DC", 42, 600, 1200, 0.68, 0.30),
    ("OSA-R01", "Osaka Site", 42, 600, 1000, 0.30, 0.55),
    ("TPE-R01", "Taipei HQ", 24, 600, 800, 0.55, 0.40),
    ("SIN-R01", "Singapore Edge", 24, 600, 800, 0.45, 0.60),
]

SECTIONS = [
    ("Production", "Public services and core network"),
    ("Staging", "Integration tests and pre-production"),
    ("Management", "BMC and switch management interfaces"),
]

#: 子網路：(區段, CIDR, 說明, VLAN)
SUBNETS = [
    ("Production", "198.51.100.0/24", "Server segment", 100),
    ("Production", "203.0.113.0/24", "DMZ", 113),
    ("Production", "2001:db8:100::/64", "Server segment (IPv6)", 100),
    ("Staging", "192.0.2.0/25", "Test segment", 200),
    # RFC 5737 只有三段可用，管理網段就從測試網段後半切一個 /25（不能與既有網段重疊）
    ("Management", "192.0.2.128/25", "BMC / management", 900),
]

#: 層架：台灣中小企業與實驗室最常見的兩種「機櫃」。規格照正式環境實際在用的兩座抄過來
#: （IKEA IVAR 179 公分側架＋18mm 層板、90×60×150 公分五層電鍍波浪鐵架），
#: 所以截圖裡的層高、層板與調整孔都是真實比例，不是示意。
#: (名稱, 機房, 型態, 層數, 寬, 深, 編號方向, 單一層高, 逐層高度, 層板厚, 最下層板離地, 平面圖 x, y)
SHELVES = [
    ("LAB-S01", "Taipei Lab", "wood_shelf", 9, 420, 300, "top-down", 298,
     [210, 210, 110, 140, 140, 140, 140, 45, 90], 18, 10, 0.35, 0.45),
    ("LAB-S02", "Taipei Lab", "wire_shelf", 5, 900, 600, "bottom-up", 300,
     None, None, None, 0.60, 0.45),
    # 台灣最常見的角鋼層架：90×45×180 公分四層（4 片板＝3 層之間＋頂板上面；
    # 層高 (1800 − 59×4 − 10) ÷ 3 ≈ 518mm）、KALLAX 2×4、兩張疊起來的 LackRack（16U）
    ("TC-A01", "Taichung Office", "angle_shelf", 3, 900, 450, "top-down", 518,
     None, 59, 10, 0.25, 0.45),
    ("TC-K01", "Taichung Office", "kallax", 4, 765, 390, "top-down", 335,
     None, 15, 0, 0.50, 0.45),
    ("TC-L01", "Taichung Office", "lackrack", 16, 550, 550, "top-down", None,
     None, None, None, 0.72, 0.45),
]

#: 表面顏色（只有這三種新型態有）
SHELF_FINISH = {"TC-A01": "black", "TC-K01": "white", "TC-L01": "black"}

#: 層架上的裝置：(名稱, 型別, 層架, 層, 橫向起點, 橫向格數, 層內起點, 層內格數)
#: 一層橫向與垂直各 60 格；「層數＋1」＝頂板上方（層架沒有天花板，上面也放得了東西）。
SHELF_DEVICES = [
    ("ai-box-01",  "server",  "LAB-S01", 10, 0, 30, 0, 30),
    ("mini-pc-01", "server",  "LAB-S01", 10, 30, 30, 0, 30),
    ("sw-10g-01",  "switch",  "LAB-S01", 9, 0, 60, 0, 30),
    ("sw-ib-01",   "switch",  "LAB-S01", 8, 0, 60, 0, 60),
    ("pve-01",     "server",  "LAB-S01", 7, 0, 60, 0, 60),
    ("pve-02",     "server",  "LAB-S01", 6, 0, 60, 0, 60),
    ("pve-03",     "server",  "LAB-S01", 5, 0, 60, 0, 60),
    ("pve-04",     "server",  "LAB-S01", 4, 0, 60, 0, 60),
    ("pve-05",     "server",  "LAB-S01", 3, 0, 60, 0, 60),
    ("das-01",     "storage", "LAB-S01", 2, 0, 30, 0, 60),
    ("nas-01",     "storage", "LAB-S01", 2, 30, 30, 0, 60),
    ("ws-01",      "other",   "LAB-S01", 1, 0, 60, 0, 60),
    ("gpu-srv-01", "server",  "LAB-S02", 1, 0, 30, 0, 60),
    ("nas-11",     "storage", "LAB-S02", 2, 0, 20, 0, 60),
    ("nas-12",     "storage", "LAB-S02", 2, 20, 20, 0, 60),
    ("nas-13",     "storage", "LAB-S02", 2, 40, 20, 0, 60),
    ("nas-14",     "storage", "LAB-S02", 3, 0, 20, 0, 60),
    ("nas-15",     "storage", "LAB-S02", 3, 20, 20, 0, 60),
    ("backup-01",  "server",  "LAB-S02", 4, 0, 60, 0, 60),
    ("ups-01",     "ups",     "LAB-S02", 5, 0, 30, 0, 60),
    # 角鋼層架（90 公分寬 → 一格 15mm；層高 518mm → 一格 8.6mm），尺寸照實物：
    # 4-bay NAS 200×230、直立式 UPS 160×240、19 吋 1U 交換器 440×44、迷你主機 180×60（疊在交換器上）
    ("nas-21",     "storage", "TC-A01", 1, 0, 14, 0, 27),
    ("ups-21",     "ups",     "TC-A01", 1, 16, 11, 0, 28),
    ("sw-21",      "switch",  "TC-A01", 2, 0, 29, 0, 5),
    ("mini-pc-21", "server",  "TC-A01", 2, 0, 12, 5, 7),
    ("nvr-21",     "storage", "TC-A01", 3, 0, 25, 0, 7),
    ("ap-ctl-21",  "other",   "TC-A01", 4, 0, 13, 0, 5),
    # KALLAX（格內寬 685mm → 一格 11.4mm，左格 0–29、右格 30–59；格高 335mm → 一格 5.6mm）
    ("nas-31",     "storage", "TC-K01", 3, 0, 18, 0, 41),
    ("rt-31",      "router",  "TC-K01", 4, 30, 22, 0, 8),
    ("sw-31",      "switch",  "TC-K01", 2, 30, 14, 0, 5),
    ("ups-31",     "ups",     "TC-K01", 1, 0, 13, 0, 43),
    # LackRack：19 吋設備鎖在桌腳上（最後一欄是 U 數）
    ("sw-41",      "switch",  "TC-L01", 16, 0, 60, 0, 60),
    ("patch-41",   "patch_panel", "TC-L01", 15, 0, 60, 0, 60),
    ("fw-41",      "firewall", "TC-L01", 13, 0, 60, 0, 60),
    ("srv-41",     "server",  "TC-L01", 6, 0, 60, 0, 60, 2),
    ("nas-41",     "storage", "TC-L01", 3, 0, 60, 0, 60, 2),
    ("ap-41",      "other",   "TC-L01", 17, 0, 20, 0, 60),     # 桌面上方（LACK 桌面也放得了東西）
]

#: 裝置：(名稱, 型別, 廠牌, 型號, 機櫃, U 位, U 數, 主要 IP)
DEVICES = [
    # TYO-R01 是「拿來拍照」的那一座：裝置集中在 U24 以上，機櫃圖一打開就看得到東西
    ("edge-fw-01",  "firewall", "Generic", "FW-2200",     "TYO-R01", 42, 1, "198.51.100.1"),
    ("edge-rt-01",  "router",   "Generic", "RT-1100",     "TYO-R01", 41, 1, "198.51.100.4"),
    ("core-sw-01",  "switch",   "Generic", "GS-4800-48T", "TYO-R01", 40, 1, "198.51.100.2"),
    ("core-sw-02",  "switch",   "Generic", "GS-4800-48T", "TYO-R01", 39, 1, "198.51.100.3"),
    ("patch-01",    "patch_panel", "Generic", "PP-24",    "TYO-R01", 38, 1, None),
    ("tor-sw-01",   "switch",   "Generic", "GS-2400-24T", "TYO-R01", 37, 1, "198.51.100.5"),
    ("app-srv-01",  "server",   "Generic", "SR-2U",       "TYO-R01", 34, 2, "198.51.100.11"),
    ("app-srv-02",  "server",   "Generic", "SR-2U",       "TYO-R01", 32, 2, "198.51.100.12"),
    ("app-srv-03",  "server",   "Generic", "SR-2U",       "TYO-R01", 30, 2, "198.51.100.13"),
    ("db-srv-01",   "server",   "Generic", "SR-2U",       "TYO-R01", 27, 2, "198.51.100.21"),
    ("db-srv-02",   "server",   "Generic", "SR-2U",       "TYO-R01", 25, 2, "198.51.100.22"),
    ("nas-01",      "storage",  "Generic", "ST-4U",       "TYO-R02", 38, 4, "198.51.100.31"),
    ("nas-02",      "storage",  "Generic", "ST-4U",       "TYO-R02", 34, 4, "198.51.100.32"),
    ("bkp-srv-01",  "server",   "Generic", "SR-2U",       "TYO-R02", 31, 2, "198.51.100.81"),
    ("pdu-a-01",    "pdu",      "Generic", "PDU-16A",     "TYO-R03", 42, 1, "198.51.100.201"),
    ("ups-01",      "ups",      "Generic", "UPS-6K",      "TYO-R03", 39, 3, "198.51.100.202"),
    ("osa-sw-01",   "switch",   "Generic", "GS-2400-24T", "OSA-R01", 42, 1, "203.0.113.2"),
    ("osa-srv-01",  "server",   "Generic", "SR-1U",       "OSA-R01", 40, 1, "203.0.113.11"),
    ("osa-srv-02",  "server",   "Generic", "SR-1U",       "OSA-R01", 39, 1, "203.0.113.12"),
    ("tpe-sw-01",   "switch",   "Generic", "GS-2400-24T", "TPE-R01", 24, 1, "192.0.2.2"),
    ("tpe-ap-01",   "ap",       "Generic", "AP-6",        "TPE-R01", 22, 1, "192.0.2.21"),
    ("sin-sw-01",   "switch",   "Generic", "GS-2400-24T", "SIN-R01", 24, 1, "192.0.2.3"),
    ("sin-srv-01",  "server",   "Generic", "SR-1U",       "SIN-R01", 22, 1, "192.0.2.11"),
]


#: 額外的 IP（不是裝置的主要位址，用來讓子網路頁看起來有實際使用率）
EXTRA_IPS: list[tuple[str, str, str]] = [
    ("198.51.100.41", "web-01", "Web frontend"),
    ("198.51.100.42", "web-02", "Web frontend"),
    ("198.51.100.43", "web-03", "Web frontend"),
    ("198.51.100.51", "cache-01", "Redis"),
    ("198.51.100.52", "cache-02", "Redis"),
    ("198.51.100.61", "queue-01", "Message queue"),
    ("198.51.100.71", "log-01", "Log collector"),
    ("198.51.100.72", "log-02", "Log collector"),
    ("198.51.100.101", "mon-01", "Monitoring"),
    ("198.51.100.102", "mon-02", "Monitoring"),
    ("203.0.113.21", "mail-relay-01", "Mail relay"),
    ("203.0.113.22", "mail-relay-02", "Mail relay"),
    ("203.0.113.31", "proxy-01", "Reverse proxy"),
    ("203.0.113.32", "proxy-02", "Reverse proxy"),
    ("192.0.2.31", "test-runner-01", "CI runner"),
    ("192.0.2.32", "test-runner-02", "CI runner"),
    ("192.0.2.41", "staging-web-01", "Staging"),
]

#: 額外的連接埠：只有被佈線用到的埠，裝置明細的「連接埠／佈線」那一區只會有一兩列，
#: 看不出那個畫面是拿來做什麼的。這裡補出一台交換器該有的樣子。
EXTRA_PORTS = [
    ("core-sw-01", [f"Te1/0/{i}" for i in range(2, 13)]),
    ("tor-sw-01", [f"Gi1/0/{i}" for i in range(3, 25)]),
    ("patch-01", [f"P{i:02d}" for i in range(3, 13)]),
    ("app-srv-01", ["eth1", "ipmi"]),
    ("app-srv-02", ["eth1", "ipmi"]),
    ("edge-fw-01", ["port3", "port4", "mgmt"]),
]

#: 憑證：(名稱, CN, SAN, 效期天數)。效期刻意有長有短，憑證清單的「剩餘天數」
#: 才看得出它在提醒什麼 —— 全部都是 365 天的話那一欄等於沒有資訊。
CERTS = [
    ("wildcard-example-net", "*.example.net", ["*.example.net", "example.net"], 365),
    ("portal-example-net", "portal.example.net", ["portal.example.net"], 96),
    ("api-example-net", "api.example.net", ["api.example.net", "api-v2.example.net"], 24),
    ("mail-example-org", "mail.example.org", ["mail.example.org"], 730),
]

#: 連接埠與佈線：讓「纜線多跳追蹤」畫面有東西可追
#: (裝置, 埠名) → (裝置, 埠名)，中間會自動穿過 patch panel
CABLES = [
    (("app-srv-01", "eth0"), ("patch-01", "P01"), "blue", 3.0),
    (("patch-01", "P01-R"), ("tor-sw-01", "Gi1/0/1"), "yellow", 1.5),
    (("app-srv-02", "eth0"), ("patch-01", "P02"), "blue", 3.0),
    (("patch-01", "P02-R"), ("tor-sw-01", "Gi1/0/2"), "yellow", 1.5),
    (("tor-sw-01", "Te1/0/49"), ("core-sw-01", "Te1/0/1"), "orange", 10.0),
    (("core-sw-01", "Te1/0/47"), ("edge-fw-01", "port1"), "orange", 2.0),
    (("edge-fw-01", "port2"), ("edge-rt-01", "eth0"), "orange", 1.0),
]


# ── HTTP 小工具（刻意零相依：安裝環境裡不一定有 requests）────────────────

class Api:
    def __init__(self, base: str, token: str | None = None) -> None:
        self.base = base.rstrip("/")
        self.token = token

    def call(self, method: str, path: str, body: Any = None,
             headers: dict[str, str] | None = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        # 網址由執行者自己在命令列上給（這是個開發用的灌資料腳本），不是從資料
        # 或使用者輸入來的，所以 S310 在這裡不適用
        req = urllib.request.Request(self.base + path, data=data, method=method)  # noqa: S310
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:   # noqa: S310  # nosec B310
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read() or b""
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw[:300].decode(errors="replace")

    def upload(self, path: str, filename: str, data: bytes) -> tuple[int, Any]:
        """multipart/form-data 上傳。自己組 boundary —— 為了不相依 requests。"""
        boundary = "----jtipam" + secrets.token_hex(8)
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: image/png\r\n\r\n"
        ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(self.base + path, data=body, method="POST")  # noqa: S310
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:   # noqa: S310
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, (e.read() or b"")[:300].decode(errors="replace")

    def login(self, user: str, password: str) -> None:
        st, body = self.call("POST", "/auth/login",
                             {"username": user, "password": password})
        if st != 200:
            sys.exit(f"登入失敗（{st}）：{body}")
        self.token = body["access_token"]


def _existing(api: Api, path: str, key: str = "name") -> dict[str, str]:
    """回「名稱 → id」；重跑時用來跳過已經存在的東西。"""
    sep = "&" if "?" in path else "?"
    st, body = api.call("GET", f"{path}{sep}page_size=500")
    if st != 200:
        return {}
    items = body.get("items", body) if isinstance(body, dict) else body
    return {str(i[key]): str(i["id"]) for i in items or [] if i.get(key)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:8010/api/v1")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", required=True)
    ap.add_argument("--db-url", help="給定時直接寫資料庫，補上示範用的上線／離線狀態"
                                     "（IP 指示計需要）。只對可丟棄的資料庫使用。")
    ap.add_argument("--consoles", action="store_true",
                    help="另外建立瀏覽器連線管理的示範目標（SSH/RDP/VNC/PVE/BMC/RustDesk，"
                         "拍 ssh-rdp 那張圖用；需要 --db-url）。會多出幾筆 IP、改變其他畫面，所以預設不做。")
    args = ap.parse_args()

    api = Api(args.base)
    api.login(args.user, args.password)

    # ── 機房與機櫃 ──
    loc_ids = _existing(api, "/locations")
    for name, address, lat, lon in LOCATIONS:
        if name in loc_ids:
            continue
        st, body = api.call("POST", "/locations", {
            "name": name, "address": address, "latitude": lat, "longitude": lon})
        if st >= 400:
            print(f"  ! location {name}: {st} {body}")
        else:
            loc_ids[name] = body["id"]
    print(f"機房 {len(loc_ids)}")

    rack_ids = _existing(api, "/racks")
    for name, loc, u, w, d, x, y in RACKS:
        if name in rack_ids or loc not in loc_ids:
            continue
        st, body = api.call("POST", "/racks", {
            "name": name, "location_id": loc_ids[loc], "u_height": u,
            "width_mm": w, "depth_mm": d})
        if st >= 400:
            print(f"  ! rack {name}: {st} {body}")
            continue
        rack_ids[name] = body["id"]
        # 平面圖座標只有 PATCH 收（建立時是 extra_forbidden），所以分兩步
        st, body = api.call("PATCH", f"/racks/{rack_ids[name]}", {"pos_x": x, "pos_y": y})
        if st >= 400:
            print(f"  ! rack {name} 平面圖座標: {st} {body}")
    # 層架：型態與層板規格只有 PATCH 收得齊，所以跟平面圖座標一樣分兩步
    for (name, loc, kind, levels, w, d, numbering, row_h, heights, board, floor,
         x, y) in SHELVES:
        if name in rack_ids or loc not in loc_ids:
            continue
        st, body = api.call("POST", "/racks", {
            "name": name, "location_id": loc_ids[loc], "u_height": levels,
            "width_mm": w, "depth_mm": d})
        if st >= 400:
            print(f"  ! shelf {name}: {st} {body}")
            continue
        rack_ids[name] = body["id"]
        patch = {"kind": kind, "numbering": numbering, "row_height_mm": row_h,
                 "pos_x": x, "pos_y": y}
        if heights:
            patch["level_heights"] = heights
        if board is not None:
            patch["board_mm"] = board
        if floor is not None:
            patch["floor_mm"] = floor
        if name in SHELF_FINISH:
            patch["finish"] = SHELF_FINISH[name]
        st, body = api.call("PATCH", f"/racks/{rack_ids[name]}", patch)
        if st >= 400:
            print(f"  ! shelf {name} 規格: {st} {body}")
    print(f"機櫃 {len(rack_ids)}")

    # ── 區段與子網路 ──
    sec_ids = _existing(api, "/sections")
    for name, desc in SECTIONS:
        if name in sec_ids:
            continue
        st, body = api.call("POST", "/sections", {"name": name, "description": desc})
        if st >= 400:
            print(f"  ! section {name}: {st} {body}")
        else:
            sec_ids[name] = body["id"]
    print(f"區段 {len(sec_ids)}")

    subnet_ids = _existing(api, "/subnets", key="cidr")
    for sec, cidr, desc, vlan in SUBNETS:
        if cidr in subnet_ids or sec not in sec_ids:
            continue
        payload: dict[str, Any] = {"section_id": sec_ids[sec], "cidr": cidr,
                                   "description": desc}
        st, body = api.call("POST", "/subnets", payload)
        if st >= 400:
            print(f"  ! subnet {cidr}: {st} {body}")
        else:
            subnet_ids[cidr] = body["id"]
    print(f"子網路 {len(subnet_ids)}")

    def subnet_for(ip: str) -> str | None:
        """挑最合適的子網路 —— /25 要贏過 /24，所以從長前綴開始找。"""
        import ipaddress
        addr = ipaddress.ip_address(ip)
        best, best_len = None, -1
        for cidr, sid in subnet_ids.items():
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if addr.version == net.version and addr in net and net.prefixlen > best_len:
                best, best_len = sid, net.prefixlen
        return best

    # ── IP ──
    ip_ids = _existing(api, "/addresses", key="ip")
    wanted: list[tuple[str, str, str]] = [
        (ip, host, desc) for ip, host, desc in EXTRA_IPS
    ] + [
        (ip, name, f"{vendor} {model}")
        for name, _t, vendor, model, _r, _u, _s, ip in DEVICES if ip
    ]
    for ip, host, desc in wanted:
        if ip in ip_ids:
            continue
        sid = subnet_for(ip)
        if not sid:
            continue
        st, body = api.call("POST", "/addresses", {
            "subnet_id": sid, "ip": ip, "hostname": host, "description": desc})
        if st >= 400:
            print(f"  ! ip {ip}: {st} {body}")
        else:
            ip_ids[ip] = body["id"]
    print(f"IP {len(ip_ids)}")

    # ── 裝置（含機櫃 U 位與主要 IP）──
    dev_ids = _existing(api, "/devices")
    for name, dtype, vendor, model, rack, u_pos, u_size, ip in DEVICES:
        if name in dev_ids:
            continue
        payload = {
            "name": name, "type": dtype, "vendor": vendor, "model": model,
            "u_position": u_pos, "u_size": u_size, "rack_face": "front",
        }
        if rack in rack_ids:
            payload["rack_id"] = rack_ids[rack]
            # 機房清單的「裝置數」是看 location_id 的；只設 rack_id 會讓那一欄永遠是 0
            room = next((loc for rn, loc, *_ in RACKS if rn == rack), None)
            if room in loc_ids:
                payload["location_id"] = loc_ids[room]
        if ip and ip in ip_ids:
            payload["primary_ip_id"] = ip_ids[ip]
        st, body = api.call("POST", "/devices", payload)
        if st >= 400:
            print(f"  ! device {name}: {st} {body}")
        else:
            dev_ids[name] = body["id"]
    for name, dtype, shelf, level, slot, span, vslot, vspan, *more in SHELF_DEVICES:
        if name in dev_ids or shelf not in rack_ids:
            continue
        room = next(loc for sn, loc, *_ in SHELVES if sn == shelf)
        st, body = api.call("POST", "/devices", {
            "name": name, "type": dtype, "rack_id": rack_ids[shelf],
            "location_id": loc_ids.get(room), "u_position": level, "u_size": more[0] if more else 1,
            "rack_face": "front", "rack_slot": slot, "rack_slot_span": span,
            "rack_vslot": vslot, "rack_vslot_span": vspan})
        if st >= 400:
            print(f"  ! device {name}: {st} {body}")
        else:
            dev_ids[name] = body["id"]
    print(f"裝置 {len(dev_ids)}")

    # ── 連接埠與佈線（纜線追蹤畫面要有多跳才看得出價值）──
    # device-ports 一定要指定 device_id（沒有「全部的埠」這支查詢），所以逐台問
    have_ports: dict[tuple[str, str], str] = {}
    for dev_name in ({side[0] for a, b, _c, _l in CABLES for side in (a, b)}
                     | {d for d, _ in EXTRA_PORTS}):
        if dev_name not in dev_ids:
            continue
        st, ports = api.call("GET", f"/device-ports?device_id={dev_ids[dev_name]}")
        if st == 200 and isinstance(ports, list):
            for p in ports:
                have_ports[(dev_name, p["name"])] = str(p["id"])

    def port_id(dev: str, port: str) -> str | None:
        if (dev, port) in have_ports:
            return have_ports[(dev, port)]
        if dev not in dev_ids:
            return None
        st_, body_ = api.call("POST", "/device-ports", {
            "device_id": dev_ids[dev], "name": port, "type": "network"})
        if st_ >= 400:
            print(f"  ! port {dev}/{port}: {st_} {body_}")
            return None
        have_ports[(dev, port)] = str(body_["id"])
        return have_ports[(dev, port)]

    # 跳接面板的前後埠要互指（peer_port_id），否則纜線追蹤到面板就停住 ——
    # 畫面上只會看到兩跳，看起來像「沒有接下去」，而不是「穿過面板繼續走」
    for front, rear in (("P01", "P01-R"), ("P02", "P02-R")):
        f_id, r_id = port_id("patch-01", front), port_id("patch-01", rear)
        if f_id and r_id:
            for a, b in ((f_id, r_id), (r_id, f_id)):
                st, body = api.call("PATCH", f"/device-ports/{a}", {"peer_port_id": b})
                if st >= 400:
                    print(f"  ! pass-through {front}/{rear}: {st} {body}")

    for dev, names in EXTRA_PORTS:
        for nm in names:
            port_id(dev, nm)

    st, cables = api.call("GET", "/cables?page_size=500")
    have_labels = {c.get("label") for c in (cables or {}).get("items", [])} if st == 200 else set()
    for (a_dev, a_port), (b_dev, b_port), color, length in CABLES:
        label = f"{a_dev}:{a_port}→{b_dev}:{b_port}"
        if label in have_labels:
            continue
        a_id, b_id = port_id(a_dev, a_port), port_id(b_dev, b_port)
        if not a_id or not b_id:
            continue
        st, cable = api.call("POST", "/cables", {
            "label": label, "type": "cat6", "color": color, "length_m": length})
        if st >= 400:
            print(f"  ! cable {label}: {st} {cable}")
            continue
        for side, pid in (("A", a_id), ("B", b_id)):
            st_, body_ = api.call("POST", "/cable-terminations", {
                "cable_id": cable["id"], "side": side,
                "object_type": "device_port", "object_id": pid})
            if st_ >= 400:
                print(f"  ! termination {label}/{side}: {st_} {body_}")
    print(f"佈線 {len(CABLES)}")

    # IP 掛回裝置：主要 IP 只是裝置指向位址的單向關係，裝置明細的「IP 清單」
    # 看的是位址上的 device_id。少了這一步那一區永遠是 0。
    linked = 0
    for name, _t, _v, _m, _r, _u, _s, ip in DEVICES:
        if not ip or ip not in ip_ids or name not in dev_ids:
            continue
        st, body = api.call("PATCH", f"/addresses/{ip_ids[ip]}",
                            {"device_id": dev_ids[name]})
        if st >= 400:
            print(f"  ! link {ip} → {name}: {st} {body}")
        else:
            linked += 1
    print(f"IP 掛裝置 {linked}")

    # 憑證：自簽即可 —— 這一頁要展示的是「集中保管＋效期一眼可見」，不是憑證本身
    cert_ids = _existing(api, "/certificates")
    for name, cn, sans, days in CERTS:
        if name in cert_ids:
            continue
        st, body = api.call("POST", "/certificates", {"name": name})
        if st >= 400:
            print(f"  ! cert {name}: {st} {body}")
            continue
        cert_ids[name] = body["id"]
        st, body = api.call("POST", f"/certificates/{cert_ids[name]}/self-signed",
                            {"common_name": cn, "sans": sans, "days": days})
        if st >= 400:
            print(f"  ! cert {name} 自簽: {st} {body}")
    print(f"憑證 {len(cert_ids)}")

    _upload_floorplans(api, loc_ids)

    # 儀表板的「稼働狀況」清單是逐帳號釘選的（user_preferences.pinned）；不釘的話
    # 那張卡片永遠是空的，而它正是首頁最顯眼的一塊
    watch = [ip_ids[ip] for ip in ("198.51.100.1", "198.51.100.2", "198.51.100.11",
                                   "198.51.100.21", "203.0.113.2", "203.0.113.31")
             if ip in ip_ids]
    if watch:
        st, body = api.call("PATCH", "/me/preferences", {"pinned": {"uptime_ips": watch}})
        if st >= 400:
            print(f"  ! 儀表板釘選: {st} {body}")
        else:
            print(f"儀表板釘選 {len(watch)}")

    if args.db_url:
        _fake_liveness(args.db_url)

    if args.consoles:
        _console_targets(api, args.db_url, subnet_for, ip_ids, dev_ids)

    print("\n完成。這份資料是虛構的：位址都在 RFC 5737／RFC 3849 的文件保留網段內，"
          "名稱不對應任何真實組織。")
    return 0


def _upload_floorplans(api: Api, loc_ids: dict[str, str]) -> None:
    """每個機房都放一張平面圖 —— 沒有圖的話，機櫃頁最上面是一張空卡片，
    而機房平面圖本身就是要展示的功能之一。圖用 `scripts/gen_floorplan.py` 現畫。"""
    import subprocess
    import tempfile
    here = pathlib.Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory() as tmp:
        png = pathlib.Path(tmp) / "floorplan.png"
        try:
            cmd = [sys.executable, str(here / "gen_floorplan.py"), "-o", str(png)]  # noqa: S607
            subprocess.run(cmd, check=True, capture_output=True)  # noqa: S603
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"  ! 產生平面圖失敗（需要 Pillow）：{exc}")
            return
        data = png.read_bytes()
        for name, loc_id in loc_ids.items():
            st, body = api.upload(f"/locations/{loc_id}/floorplan", "floorplan.png", data)
            if st >= 400:
                print(f"  ! floorplan {name}: {st} {body}")
    print(f"平面圖 {len(loc_ids)}")


#: 「IP 指示計」的紅／綠／灰是掃描寫進 `effective_status` 的，沒有 API 可以設 ——
#: 而一片灰的截圖等於沒有展示到這個功能。這一步直接寫資料庫，所以**只給示範用的
#: 可丟棄資料庫**（要自己把 --db-url 指過去，預設不做）。
_LIVENESS_SQL = """
UPDATE ip_addresses SET effective_status = NULL, last_seen_scanner = NULL;
-- 先全部標成上線，再挑幾台標離線、留幾台未知：畫面上要同時看得到三種顏色，
-- 全綠或全灰都等於沒有展示到這個功能
UPDATE ip_addresses SET effective_status = 'online',
       last_seen_scanner = now() - (random() * interval '20 minutes');
UPDATE ip_addresses SET effective_status = 'offline',
       last_seen_scanner = now() - interval '3 days'
 WHERE hostname IN ('web-03', 'cache-02', 'log-02', 'osa-srv-02', 'test-runner-02');
UPDATE ip_addresses SET effective_status = NULL, last_seen_scanner = NULL
 WHERE hostname IN ('backup-01', 'mon-02', 'proxy-02', 'staging-web-01',
                    'tpe-ap-01', 'sin-srv-01');
"""


def _fake_liveness(db_url: str) -> None:
    import subprocess
    try:
        # psql 走 PATH（開發環境本來就這樣用）；SQL 是上面的常數、db_url 由執行者給
        cmd = ["psql", db_url, "-v", "ON_ERROR_STOP=1", "-q", "-c", _LIVENESS_SQL]  # noqa: S607
        subprocess.run(cmd, check=True)  # noqa: S603
        print("上線／離線狀態 已寫入（示範用）")
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"  ! 寫入上線狀態失敗（需要 psql）：{exc}")


# ── 瀏覽器連線管理的示範目標（--consoles；拍 ssh-rdp 那張圖用）──────────────
#
# 只有加 --consoles 才建立：會多出幾筆 IP、子網路與 IP 明細也會出現連線按鈕，
# 其他截圖的內容就不一樣了。所以這一段跟上面完全分開，預設不跑。
#
# 連線管理頁每一種連線都要看得到：SSH、RDP、VNC、PVE 主控台（VM 的 noVNC、CT 的 xterm）、
# BMC 序列主控台，以及相容 RustDesk 的網頁連線。排序是照 IP 字串排的，所以位址挑成
# 「字串序＝數值序」（同一段都是兩位數或都是三位數），畫面上才不會出現 .141 排在 .31 前面。
# 列數也要收斂：日文的欄位名稱長、裝置名稱會折成兩行，超過 11 列整張表就超出 1600×900 的畫面。

#: 新增的位址：(IP, 主機名稱, 說明, 掛到哪台裝置)。BMC 是伺服器的頻外管理介面，掛回那台伺服器
CONSOLE_IPS: list[tuple[str, str, str, str | None]] = [
    ("192.0.2.101", "ws-01", "Office desktop", None),
    ("192.0.2.102", "ws-02", "Office desktop", None),
    ("192.0.2.103", "ws-03", "Design workstation", None),
    ("192.0.2.141", "app-srv-01-bmc", "BMC", "app-srv-01"),
]

#: 每個位址開哪幾種連線（＝IP 編輯表單裡的開關）
CONSOLE_FLAGS: dict[str, tuple[str, ...]] = {
    "192.0.2.101": ("rdp", "rustdesk"),
    "192.0.2.102": ("rustdesk",),
    "192.0.2.103": ("vnc", "rustdesk"),
    "192.0.2.141": ("bmc",),
    "198.51.100.12": ("ssh", "sftp"),
    "198.51.100.21": ("ssh", "sftp"),
    "198.51.100.41": ("ssh", "novnc"),
    "198.51.100.51": ("ssh", "novnc"),
    "198.51.100.81": ("rdp",),
    "203.0.113.2": ("ssh",),
    "203.0.113.31": ("ssh", "sftp"),
}

#: 掃描代理會寫的 OS 與設備類型（沒有 API，要 --db-url）：IP → (OS 原始字串, OS 家族, 設備類型)
CONSOLE_OS: dict[str, tuple[str | None, str | None, str]] = {
    "192.0.2.101": ("Microsoft Windows 11 Pro", "windows", "windows"),
    "192.0.2.102": ("Microsoft Windows 11 Pro", "windows", "windows"),
    "192.0.2.103": ("Apple macOS 14", "macos", "server"),
    "192.0.2.141": (None, None, "specialized"),
    "198.51.100.12": ("Linux 6.8 (Ubuntu 24.04)", "linux", "server"),
    "198.51.100.21": ("Linux 6.1 (Debian 12)", "linux", "server"),
    "198.51.100.41": ("Linux 6.8 (Ubuntu 24.04)", "linux", "server"),
    "198.51.100.51": ("Linux 6.1 (Debian 12)", "linux", "server"),
    "198.51.100.81": ("Microsoft Windows Server 2022", "windows", "windows"),
    "203.0.113.2": ("Embedded switch OS 9.3", "network", "switch"),
    "203.0.113.31": ("Linux 6.8 (Ubuntu 24.04)", "linux", "server"),
}

#: PVE 的 VM／CT：(IP, VMID, 名稱, 種類)。VM 開 noVNC、CT 開 xterm（PVE 主控台按鈕會依種類換）
CONSOLE_PVE = [
    ("198.51.100.41", 101, "web-01", "vm"),
    ("198.51.100.51", 201, "cache-01", "ct"),
]

#: RustDesk 伺服器與已註冊的裝置：(RustDesk ID, 登記 IP)。ID 是隨手編的 9 位數
CONSOLE_RUSTDESK_SERVER = "rd-hub-01"
CONSOLE_RUSTDESK_PEERS = [
    ("318204557", "192.0.2.101"),
    ("462097183", "192.0.2.102"),
    ("705316942", "192.0.2.103"),
]


def _console_targets(api: Api, db_url: str | None, subnet_for: Any,
                     ip_ids: dict[str, str], dev_ids: dict[str, str]) -> None:
    """建立連線管理頁的示範目標。RustDesk 走真正的代理協定（/rustdesk/agent/report），
    讓「哪個 ID 對應到哪筆 IP」由正式的比對邏輯決定，而不是直接塞資料表。"""
    import base64

    # 位址
    for ip, host, desc, _dev in CONSOLE_IPS:
        if ip in ip_ids:
            continue
        sid = subnet_for(ip)
        if not sid:
            print(f"  ! console ip {ip}: 找不到子網路")
            continue
        st, body = api.call("POST", "/addresses", {
            "subnet_id": sid, "ip": ip, "hostname": host, "description": desc})
        if st >= 400:
            print(f"  ! console ip {ip}: {st} {body}")
        else:
            ip_ids[ip] = body["id"]
    for ip, _host, _desc, dev in CONSOLE_IPS:
        if dev and ip in ip_ids and dev in dev_ids:
            st, body = api.call("PATCH", f"/addresses/{ip_ids[ip]}", {"device_id": dev_ids[dev]})
            if st >= 400:
                print(f"  ! link {ip} → {dev}: {st} {body}")

    # 逐 IP 的連線開關
    enabled = 0
    for ip, kinds in CONSOLE_FLAGS.items():
        if ip not in ip_ids:
            print(f"  ! console flags {ip}: 沒有這筆 IP")
            continue
        st, body = api.call("PATCH", f"/addresses/{ip_ids[ip]}",
                            {f"{k}_enabled": True for k in kinds})
        if st >= 400:
            print(f"  ! console flags {ip}: {st} {body}")
        else:
            enabled += 1
    print(f"連線目標 {enabled}")

    # RustDesk：建伺服器（開網頁連線），再以它的代理金鑰送一份 hbbs 回報
    st, body = api.call("GET", "/rustdesk/servers?page_size=100")
    srv = next((s for s in (body or {}).get("items", []) if s.get("name") == CONSOLE_RUSTDESK_SERVER),
               None) if st == 200 else None
    key = None
    if srv is None:
        st, srv = api.call("POST", "/rustdesk/servers", {
            "name": CONSOLE_RUSTDESK_SERVER, "client_address": "rd.example.net",
            "hbbs_host": "rd.example.net", "web_enabled": True, "web_file_transfer": True})
        if st >= 400:
            print(f"  ! rustdesk server: {st} {srv}")
            srv = None
        else:
            key = srv.get("agent_key")
    elif srv.get("id"):
        st, kb = api.call("GET", f"/rustdesk/servers/{srv['id']}/agent-key")
        key = kb.get("agent_key") if st == 200 and isinstance(kb, dict) else None
    if srv and key:
        report = {
            "source_id": srv["id"], "version": "1.1.14",
            # 隨機產生的公鑰（格式對就好；示範環境不會真的連到 hbbs）
            "public_key": base64.b64encode(secrets.token_bytes(32)).decode(),
            "files": {"db": {"path": "/var/lib/rustdesk-server/db_v2.sqlite3", "ok": True}},
            "online_ok": True,
            "peers": [{"id": rid, "ip": ip, "online": True} for rid, ip in CONSOLE_RUSTDESK_PEERS],
        }
        # 代理端點認的是 X-Agent-Key，不是登入的 token
        agent = Api(api.base)
        st, body = agent.call("POST", "/rustdesk/agent/report", report, headers={"X-Agent-Key": key})
        if st >= 400:
            print(f"  ! rustdesk report: {st} {body}")
        else:
            print(f"RustDesk 裝置 {body.get('peers')}（對應到 IP {body.get('matched')}）")

    if not db_url:
        print("  ! 沒給 --db-url：PVE 主控台、OS 與上線狀態要直接寫資料庫，這幾項會缺")
        return
    _console_db(db_url)


def _sql_str(v: str | None) -> str:
    """常數表裡的字串轉 SQL 字面值（只用在上面那幾張寫死的表，不是外來輸入）。"""
    return "NULL" if v is None else "'" + v.replace("'", "''") + "'"


def _console_db(db_url: str) -> None:
    """PVE 的 VM／CT 只會從同步進來（沒有新增的 API）；OS 與設備類型是掃描代理寫的。
    跟 _fake_liveness 一樣只給可丟棄的示範資料庫。"""
    import subprocess
    os_rows = ", ".join(f"({_sql_str(ip)}, {_sql_str(raw)}, {_sql_str(fam)}, {_sql_str(kind)})"
                        for ip, (raw, fam, kind) in CONSOLE_OS.items())
    vm_sql = "\n".join(
        "INSERT INTO virtual_machines (cluster_id, legacy_vmid, name, node, kind, status, primary_ip_id)\n"
        f"SELECT c.id, {vmid}, {_sql_str(name)}, 'pve-01', {_sql_str(kind)}, 'running', a.id\n"
        f"  FROM virt_clusters c JOIN ip_addresses a ON host(a.ip) = {_sql_str(ip)}\n"
        " WHERE c.name = 'pve-lab'\n"
        "ON CONFLICT (cluster_id, legacy_vmid) DO NOTHING;"
        for ip, vmid, name, kind in CONSOLE_PVE)
    new_ips = ", ".join(_sql_str(ip) for ip, *_ in CONSOLE_IPS)
    sql = f"""
INSERT INTO virt_clusters (name, type) VALUES ('pve-lab', 'proxmox') ON CONFLICT (name) DO NOTHING;
-- 網址用 example.net（RFC 2606）：PVE 主控台按鈕只看「對應到啟用中的 PVE 整合」，不會真的連過去
INSERT INTO proxmox_instances (cluster_id, api_url, auth_username, auth_token_id, enabled)
SELECT c.id, 'https://pve-01.example.net:8006', 'jtipam@pve', 'docs', true FROM virt_clusters c
 WHERE c.name = 'pve-lab' AND NOT EXISTS (SELECT 1 FROM proxmox_instances p WHERE p.cluster_id = c.id);
{vm_sql}
UPDATE ip_addresses SET os_guess = v.raw, os_family = v.fam, device_kind = v.kind
  FROM (VALUES {os_rows}) AS v(ip, raw, fam, kind)
 WHERE host(ip_addresses.ip) = v.ip;
UPDATE ip_addresses SET effective_status = 'online',
       last_seen_scanner = now() - (random() * interval '20 minutes')
 WHERE host(ip) IN ({new_ips});
"""  # noqa: S608  # 只由上面寫死的常數表組成（_sql_str 跳脫），沒有外來輸入
    try:
        cmd = ["psql", db_url, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql]  # noqa: S607
        subprocess.run(cmd, check=True)  # noqa: S603
        print("PVE 主控台／OS／上線狀態 已寫入（示範用）")
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"  ! 寫入連線示範資料失敗（需要 psql）：{exc}")


if __name__ == "__main__":
    raise SystemExit(main())
