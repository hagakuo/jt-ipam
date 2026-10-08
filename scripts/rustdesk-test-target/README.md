# RustDesk 測試靶（相容 RustDesk 的網頁連線用）

可丟棄的測試環境，給「相容 RustDesk 的網頁連線」做端到端驗證：官方的 hbbs/hbbr（1.1.16）加上官方的 Linux 受控端
（1.4.1）。受控端跑在 Xvfb 上，桌面只有一個大字級的 xterm，打什麼字畫面上就看得到，鍵盤、滑鼠、滾輪都能肉眼驗。

全部是官方發佈的執行檔，只當黑箱執行；我們沒有閱讀它們的原始碼或文件。

## 安全

- 發布的埠只綁 `127.0.0.1`。
- 受控端只接在 docker 的 internal 網路（`rdtest-int`）上，連不到網際網路，所以不會向公用或正式的 RustDesk 伺服器註冊。
  不要拿正式環境的 RustDesk 伺服器當靶。
- 受控端的永久密碼寫在 `run.sh` 裡（`Rd-Test-2026`），用完就 `down`。

## 用法

```bash
scripts/rustdesk-test-target/run.sh up      # 第一次會下載官方受控端 deb（約 20 MB）並建置映像
scripts/rustdesk-test-target/run.sh info    # RustDesk ID、永久密碼、伺服器公鑰、hbbs/hbbr 位址
scripts/rustdesk-test-target/run.sh shot /tmp/remote.png   # 受控端螢幕的截圖（對照網頁裡看到的）
scripts/rustdesk-test-target/run.sh down    # 全部移除（容器與兩個 docker 網路）
```

`info` 會建議 jt-ipam 的設定：hbbs 位址填容器在 `rdtest-net` 上的位址（私網，出站規則預設允許）、中繼位址留空。
`127.0.0.1:31116` 這類發布出來的位址會被 jt-ipam 的出站規則擋下（迴路位址一律擋），除非另外設定 `OUTBOUND_ALLOW_CIDRS`。

## 接到開發用的 jt-ipam

正式環境由 RustDesk 代理回報裝置、jt-ipam 自己對應到 IP 記錄。測試靶沒有代理，用 `seed_jtipam.py` 直接寫進
**拋棄式**資料庫（名稱要以 `_e2e` 或 `_test` 結尾）。不可以用發版 e2e 共用的 `jt_ipam_e2e`：這裡建的子網路會跟它的種子資料
重複，好幾個 e2e 跟著失敗（腳本會拒絕）。


```bash
cd backend
set -a; . ../.dev.env; set +a
PEER=$(docker logs rdtest-client 2>&1 | sed -n 's/^rustdesk id: //p' | tail -1)
KEY=$(docker exec rdtest-server cat /data/id_ed25519.pub)
SRV=$(docker inspect rdtest-server --format '{{(index .NetworkSettings.Networks "rdtest-net").IPAddress}}')
POSTGRES_DB=jt_ipam_rd_e2e .venv/bin/python ../scripts/rustdesk-test-target/seed_jtipam.py \
    --peer-id "$PEER" --key "$KEY" --hbbs "$SRV"          # 加 --transport ws 改用 WebSocket
```

之後開 IP `198.51.100.77` 的詳細資料頁，按 RustDesk，輸入 `Rd-Test-2026`。

## 驗證時的小工具

- 受控端游標的實際位置（驗座標四個角落）：`docker exec rdtest-client sh -c 'DISPLAY=:0 xdotool getmouselocation'`
- 受控端視窗的位置（驗拖曳）：`docker exec rdtest-client sh -c 'DISPLAY=:0 xdotool search --name rdtest-xterm getwindowgeometry'`
- 受控端自己的執行記錄：容器裡的 `/root/.local/share/logs/RustDesk/server/`
- hbbs/hbbr 的記錄：`docker logs rdtest-server`

## 已知限制

- hbbs 要用它自己的金鑰對啟動（不帶 `-k`）：用 `-k <公鑰字串>` 啟動時 hbbs 不會簽受控端身分，網頁連線依規格拒絕連線
  （`rd_insecure_refused`）。hbbr 照樣帶 `-k` 檢查公鑰。
- 受控端沒有「連線管理」視窗，所以「不填密碼、請對方按同意」只看得到網頁這邊在等待，對方畫面不會跳出同意視窗；這一項要用真的桌面驗。
- 受控端沒有 H.264 硬體編碼器，畫面一律是 VP9。
