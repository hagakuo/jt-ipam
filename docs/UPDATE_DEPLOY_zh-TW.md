# jt-ipam 更新與正式站部署 SOP

本文記錄 NKUST `jt-ipam` fork 的標準更新流程。目的有三個：

1. 將原作者 `jasoncheng7115/jt-ipam` 的最新 `main` 合併到校內 fork。
2. 保留校內已做過的本地修補，不覆蓋正式站已套用的 migration。
3. 安全部署到 `ipam.nkust.edu.tw`，並用可重複的檢查確認服務正常。

## 環境摘要

- 本機工作目錄：`C:\Users\haga.kuo\專案\nkust_IPAM\jt-ipam`
- 本機 fork remote：`origin = https://github.com/hagakuo/jt-ipam.git`
- 原作者 remote：`upstream = https://github.com/jasoncheng7115/jt-ipam.git`
- 正式站：`ipam.nkust.edu.tw`
- 正式站 IP：`120.119.140.8`
- 正式站 repo：`/opt/jt-ipam`
- 正式站部署帳號：`kenboy`
- 正式站服務：`jt-ipam-backend`、`nginx`、`redis-server`、`postgresql`；1.0.1 另需 `jt-ipam-guacd`

不要把正式站密碼、API token、`.env`、TLS key 或初始 admin password 寫進 repo。

## 1. 本機更新前檢查

先進入真正的 git repo。外層 `nkust_IPAM` 可能只是規劃資料夾，不要在外層跑 git 更新。

```powershell
cd "C:\Users\haga.kuo\專案\nkust_IPAM\jt-ipam"
git rev-parse --show-toplevel
git status --short --branch
git remote -v
```

預期：

- `git rev-parse --show-toplevel` 應該指向 `...\nkust_IPAM\jt-ipam`。
- `git status` 最好是乾淨的。
- remote 應該同時有 `origin` 和 `upstream`。

若沒有 `upstream`：

```powershell
git remote add upstream https://github.com/jasoncheng7115/jt-ipam.git
```

若工作樹不是乾淨的，先確認那些修改是否要保留。要保留但還不能 commit 時，可先 stash：

```powershell
git stash push -u -m "pre-upstream-update-YYYYMMDD"
```

PowerShell 取回 stash 時要加引號：

```powershell
git stash apply 'stash@{0}'
```

## 2. 抓取 upstream 與比對

```powershell
git fetch origin main
git fetch upstream main
git log --oneline --decorate --graph --max-count=30 --all
git rev-parse HEAD origin/main upstream/main
git merge-base HEAD upstream/main
```

看上游新增哪些檔案：

```powershell
git diff --name-status HEAD..upstream/main
git diff --stat HEAD..upstream/main
```

若本機 fork 有校內 commit，通常不是 fast-forward，而是要 merge。

## 3. 合併 upstream

```powershell
git merge --no-edit upstream/main
```

若出現 conflict：

1. 用 `git status --short` 看衝突檔。
2. 優先保留校內安全修補、NKUST branding、正式站已套用的 Alembic migration。
3. 解完衝突後跑：

```powershell
rg -n "^(<<<<<<<|=======|>>>>>>>)" .
git diff --check
```

確認沒有衝突標記與空白錯誤後再 commit。

## 4. Alembic migration 特別注意

正式站已套用過的 revision 不能任意改名或刪除。若正式 DB 的 `alembic_version` 已是某個本地 revision，即使上游後來新增同號 migration，也要保留已套用的本地 migration。

檢查 migration heads：

```powershell
cd "C:\Users\haga.kuo\專案\nkust_IPAM\jt-ipam\backend"
python -m alembic -c alembic.ini heads
```

若 Windows 的 `cp950` 無法讀取含中文註解的 `alembic.ini`，不要修改 migration
或設定檔編碼。可直接用 Alembic API 載入 revision graph：

```powershell
python -X utf8 -c "from alembic.config import Config; from alembic.script import ScriptDirectory; c=Config(); c.set_main_option('script_location','alembic'); print(ScriptDirectory.from_config(c).get_heads())"
```

若出現多個 heads，且原因是「校內已套用 migration」和「上游新 migration」分支，做法是新增 merge migration，不要改舊 revision。範例：

```powershell
python -m alembic -c alembic.ini merge -m "merge local and upstream heads" HEAD_1 HEAD_2
```

merge migration 內容通常只需要 `pass`，因為它只是合併 migration graph，不改資料表。

本次案例：

- 正式站已套用：`0086_refresh_token_revocation`
- 上游新增鏈：`0086_scan_agent_tools -> 0087_pfsense_firewall -> 0088_pfsense_rules_dsv`
- 因此新增 merge revision：`0089_merge_refresh_pfsense`
- 注意：`alembic_version.version_num` 欄位長度是 32，revision id 必須控制在 32 字元以內。

2026-07-31 從 `0.5.13` 更新到 `0.5.122` 時，上游 migration 已延伸至
`0101_librenms_links`，而正式站仍帶有先前的本地 merge head。處理方式仍是不改動任何
已套用 revision，新增第二個 graph-only merge：

- 既有本地 head：`0089_merge_refresh_pfsense`
- 最新上游 head：`0101_librenms_links`
- 新的單一 head：`0102_merge_local_refresh`

2026-08-11 從 `0.5.122` 更新到 `0.5.161` 時，上游從同一個
`0101_librenms_links` 分出 `0102_ai_findings`，並一路延伸到
`0114_scan_agent_is_local`。正式站已套用的 `0102_merge_local_refresh` 不能改名或刪除，
因此保留兩條分支並新增第三個 graph-only merge：

- 既有校內 head：`0102_merge_local_refresh`
- 最新上游 head：`0114_scan_agent_is_local`
- 新的單一 head：`0115_merge_local_refresh`
- `0115_merge_local_refresh.down_revision = ("0102_merge_local_refresh", "0114_scan_agent_is_local")`

驗證結果必須只有：

```text
0188_merge_local_refresh
```

2026-10-08 更新至 `1.0.1`：上游固定提交為
`868635952f87548dfe8caac36fce8da04b35cabc`，最新上游 head 為
`0187_change_impact`。保留正式站已套用的 `0115_merge_local_refresh`，新增
`0188_merge_local_refresh` 合併兩條鏈。不要刪除或改名舊 migration。

未來更新時，這個 head 可能再往前推進；每次都以當次 Alembic graph 為準。

## 5. 本機驗證

至少跑這些檢查：

```powershell
cd "C:\Users\haga.kuo\專案\nkust_IPAM\jt-ipam"
git diff --check
python -m compileall -q backend\app backend\tests agent
```

若本機 `python` launcher 有問題，可用 Codex bundled Python：

```powershell
& "C:\Users\haga.kuo\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -m compileall -q backend\app backend\tests agent
```

若有測試環境，建議跑：

```powershell
cd backend
python -m pytest
python -m ruff check app tests
```

後端的 PTY／FreeRDP 使用 `termios`／`fcntl`，完整測試要在 Linux 執行。
測試 fixture 會清空資料表，**不得指向正式資料庫**。先將備份還原至獨立的
`*_test` 資料庫，使用獨立測試角色與 Redis，執行 `alembic upgrade head`，
再設 `JTIPAM_TEST_DATABASE_URL` 跑回歸。不要為測試關閉正式 PostgreSQL 的持久化設定。

至少驗證登入／refresh／logout、OIDC 驗簽、API scope、RBAC、MCP、SSRF、
LibreNMS ARP、同步排程與新功能；再跑 `python -m pip_audit` 及
`corepack pnpm audit --prod`。工具警告必須逐項判讀，不等於已確認漏洞。
安裝工具 `pip` 本次需升至 `26.2.1`，之後依當期公告重新稽核，不要永久照抄版本。

工作樹裡未追蹤的 NM_tools 匯入程式屬使用者既有工作，不能為了 inclusiveTerms
測試改名或刪除。可用 `git archive` 匯出已追蹤的正式候選版本，在副本重跑該測試。

前端驗證：

```powershell
cd "C:\Users\haga.kuo\專案\nkust_IPAM\jt-ipam\frontend"
corepack pnpm --version
corepack pnpm install --frozen-lockfile
corepack pnpm lint
corepack pnpm test:unit
corepack pnpm build
```

`package.json` 目前指定 `pnpm@9.15.9`。若系統預設 pnpm 11 顯示
`ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`，不要用 `--no-frozen-lockfile` 重寫上游 lockfile；改用
`corepack pnpm` 讓 Corepack 依 `packageManager` 欄位選用正確版本。非互動環境若要求確認刪除
`node_modules`，先設定 `CI=true`。

## 6. Commit 與 push

確認檔案只包含這次更新需要的內容：

```powershell
cd "C:\Users\haga.kuo\專案\nkust_IPAM\jt-ipam"
git status --short --branch
git diff --stat
```

提交：

```powershell
git add <changed-files>
git commit -m "chore: sync upstream release"
```

推送到 fork：

```powershell
git push origin main
```

推送後確認 GitHub fork 已到本機 commit：

```powershell
git rev-parse HEAD
git ls-remote origin refs/heads/main
```

兩個 hash 應一致。

## 7. 正式站部署

先確認 DNS：

```powershell
Resolve-DnsName ipam.nkust.edu.tw
```

目前正式站應指向 `120.119.140.8`。

連線：

```powershell
ssh kenboy@120.119.140.8
```

部署前檢查：

```bash
hostname
id
cd /opt/jt-ipam
git rev-parse HEAD
git status --short --branch
git remote -v
systemctl is-active jt-ipam-backend nginx redis-server postgresql
```

部署前先暫停同步，避免新版程式與舊 schema 同時執行，並另外建立可核對的完整備份：

```bash
sudo systemctl stop jt-ipam-sync.timer jt-ipam-sync.service
sudo bash
set -euo pipefail
umask 077
BACKUP="/var/backups/jt-ipam/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP"
sudo -u postgres pg_dump -Fc jt_ipam > "$BACKUP/jt-ipam.dump"
cp /etc/jt-ipam/backend.env "$BACKUP/backend.env"
git -c safe.directory=/opt/jt-ipam -C /opt/jt-ipam bundle create "$BACKUP/repo.bundle" --all
tar -czf "$BACKUP/uploads.tar.gz" -C /var/lib/jt-ipam uploads
tar -czf "$BACKUP/frontend-dist.tar.gz" -C /opt/jt-ipam/frontend dist
# 另備份實際 TLS 憑證目錄及掃描代理設定；不要輸出密鑰內容。
cd "$BACKUP"
sha256sum jt-ipam.dump backend.env repo.bundle uploads.tar.gz frontend-dist.tar.gz > SHA256SUMS
sha256sum -c SHA256SUMS
pg_restore --list jt-ipam.dump >/dev/null
exit
```

記錄備份絕對路徑、舊 commit 與舊 DB head。此備份含密鑰，目錄權限應為 `0700`，
檔案 `0600`；不要上傳 GitHub。備份是否可還原須用隔離副本驗證。

部署：

```bash
sudo git -c safe.directory=/opt/jt-ipam -C /opt/jt-ipam pull --ff-only origin main
cd /opt/jt-ipam
sudo bash /opt/jt-ipam/scripts/jt-ipam.sh upgrade --no-pull
```

重點：

- 先由外部 `git pull --ff-only` 同步到 fork 最新 commit。
- `upgrade` 一定加 `--no-pull`，避免 script 內部再 pull 一次造成版本不明。
- upgrade script 會自動做 DB backup、backend dependency update、Alembic migration、frontend build、nginx reload、backend restart。
- 本次升級另會安裝 guacd、更新必要的 nginx 主控台中繼規則。不要自行開放 guacd 的外網埠。
- 升級失敗時先檢查服務與 migration，不要立即恢復同步或反覆重跑。

## 8. 部署後驗證

在正式站跑：

```bash
cd /opt/jt-ipam
git rev-parse HEAD
git status --short --branch
grep __version__ backend/app/version.py
sudo -u postgres psql -d jt_ipam -tAc "select version_num from alembic_version"
systemctl is-active jt-ipam-backend nginx redis-server postgresql jt-ipam-guacd
curl -k -fsS https://ipam.nkust.edu.tw/healthz
curl -k -fsS https://ipam.nkust.edu.tw/readyz
curl -k -fsS https://ipam.nkust.edu.tw/api/v1/system/version
curl -k -sS -o /dev/null -w '%{http_code} %{content_type}\n' https://ipam.nkust.edu.tw/
journalctl -u jt-ipam-backend --since '10 minutes ago' --no-pager -p warning..alert
```

預期：

- Git commit 等於 `origin/main` 最新 commit。
- `git status` 乾淨。
- Alembic revision 是最新 head。
- 四個服務都回 `active`。
- `/healthz` 回 `ok`。
- 首頁回 `200 text/html`。
- 最近 10 分鐘 backend warning/error 沒有異常。

核對新版登入頁與靜態檔實際可載入，再恢復並驗證同步：

```bash
sudo systemctl start jt-ipam-sync.timer
sudo systemctl start jt-ipam-sync.service
systemctl show jt-ipam-sync.service -p Result -p ExecMainStatus
systemctl is-active jt-ipam-sync.timer jt-ipam-backup.timer
```

正式站 `nz` 掃描代理原本由管理員停用，升級必須保持停用；代理不是為了通過 health
檢查就可以重新啟用。`curl -k` 只驗證 HTTP 功能，不代表憑證鏈受信任，現有自簽 TLS
需要另案處理。新增整合與外部 MCP 也不應在升級時擅自開啟。

## 9. 常見問題

### SSH 連錯主機

`ipam.nkust.edu.tw` 是 `120.119.140.8`。不要部署到 `120.119.140.10`，那是其他系統主機。

### `detected dubious ownership`

在正式站執行：

```bash
sudo git -C /opt/jt-ipam config --global --add safe.directory /opt/jt-ipam
```

### Alembic 有多個 heads

不要直接刪掉正式站已套用的本地 migration。先確認每個 head 的來源，再用 Alembic merge revision 合併。

### `aardwolf==0.2.13` 找不到 wheel

這是 optional RDP dependency。upgrade script 會警告並跳過；核心 IPAM、一般 API、SSH/VNC、前端仍可繼續部署。若需要 RDP console，再另外處理 Python/平台 wheel 相容性。

### Windows 顯示遠端 build 輸出失敗

若本機 PowerShell 因 cp950 無法顯示 Vite 的 Unicode 符號而中斷，不要直接判定部署失敗。重新 SSH 到主機檢查：

```bash
pgrep -af 'jt-ipam.sh|vite build|vue-tsc|pnpm|node' || true
systemctl is-active jt-ipam-backend nginx redis-server postgresql
curl -k -fsS https://ipam.nkust.edu.tw/healthz
```

必要時可重新跑：

```bash
cd /opt/jt-ipam
sudo bash /opt/jt-ipam/scripts/jt-ipam.sh upgrade --no-pull
```

## 10. 最小回滾方向

upgrade script 會先備份 DB，備份通常位於：

```bash
/var/backups/jt-ipam/YYYY-MM-DD/
```

若部署後必須回滾，先不要反覆重跑 upgrade。保留現場狀態，記錄：

```bash
git -C /opt/jt-ipam rev-parse HEAD
sudo -u postgres psql -d jt_ipam -tAc "select version_num from alembic_version"
systemctl status jt-ipam-backend --no-pager
journalctl -u jt-ipam-backend -n 200 --no-pager
ls -lh /var/backups/jt-ipam/
```

再決定是回退 git commit、還原 DB backup，或只修 forward patch。

不能只回退程式卻留下不相容的新 schema。若需完整還原，停止 backend 與同步，
以舊 repo bundle 建立獨立舊版 checkout，重新建立相符環境，將備份還原至新資料庫
並核對資料；保留故障資料庫作證據。確認舊版與還原庫可以服務後才切換設定。
不確定 migration 是否可降版時，不要在正式庫直接執行 `alembic downgrade`。
