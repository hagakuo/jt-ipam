# jt-ipam を 0.4 から最新版へアップグレードする

> English: [UPGRADE_FROM_0.4.md](UPGRADE_FROM_0.4.md) · 繁體中文版：[UPGRADE_FROM_0.4_zh-TW.md](UPGRADE_FROM_0.4_zh-TW.md)

古い **0.4.x** の環境を現行リリースまで引き上げるための手順書です。**複数のバージョンを
またいで一度に**アップグレードできます。Alembic が途中のマイグレーションをすべて順に
実行するため、間のリリースを踏む必要はありません。

以下のパスは既定の構成を前提にしています。ソースは `/opt/jt-ipam`、設定は
`/etc/jt-ipam/backend.env`、システムアカウントは `jtipam` です。すべて `root` / `sudo` で
実行してください。

> アップグレードの近道として `install` を再実行しないでください。`install` は `git pull` を
> しないため、単体では*古い*コードに対して Alembic とビルドをやり直すだけで、バージョンは
> 変わりません。既存の環境に対して安全ではあります（DB を保持し、`ENCRYPTION_KEY` を
> 作り直すこともありません）が、役に立つのはコードを更新した**後**（手順 2 のあと）の
> 「修復」としてだけです。

---

## 前提の確認

```bash
test -d /opt/jt-ipam/backend/.venv && echo "venv OK"
test -r /etc/jt-ipam/backend.env && echo "env OK"
stat -c '%U' /opt/jt-ipam          # jtipam であること
```

---

## 手順 0：まずバックアップ（必ず行ってください）

```bash
# データベース（custom 形式。pg_restore で戻せます）
sudo -u postgres pg_dump -Fc jt_ipam > /root/jt_ipam_$(date +%F_%H%M).dump

# 設定とアップロード。backend.env には ENCRYPTION_KEY が入っており、失うと保存済みの機密情報を一切復号できなくなります。
cp -a /etc/jt-ipam /root/etc-jt-ipam.bak
tar czf /root/jt-ipam-uploads_$(date +%F).tgz -C /var/lib/jt-ipam uploads 2>/dev/null || true
```

> `backend.env` の `ENCRYPTION_KEY` / `SECRET_KEY` は絶対に変更しないでください。変更すると、
> 連携の資格情報、TOTP のシード、証明書の秘密鍵がすべて使えなくなります。アップグレード自体が
> これらに触れることはありません。

---

## 手順 1：まずは通常の方法を試す

```bash
sudo /opt/jt-ipam/scripts/jt-ipam.sh upgrade 2>&1 | tee /root/upgrade.log
```

- **成功した場合** → 手順 6（確認）へ進んでください。これで完了です。
- **失敗した場合** → `upgrade.log` の最後の 20 行ほどを見て、どの段階で止まったか
  （`git pull` / `alembic` / `pip` / `build`）を確認し、対応する下の手動手順へ進みます。

手順 2〜5 は、`upgrade` の流れ（`git pull --ff-only` → バックアップ → pip → `alembic upgrade head`
→ ビルド → 再起動）を分解したものです。詰まった段階を越えるために使います。

---

## 手順 2：コードを最新にする（git の履歴が食い違っている場合の対処）

`upgrade` は `git pull --ff-only` を使うため、古い 0.4 のクローンの履歴が公開リポジトリと
食い違っていると中止されます。手作業で揃えます。

```bash
sudo -u jtipam git -C /opt/jt-ipam config --global --add safe.directory /opt/jt-ipam
sudo -u jtipam git -C /opt/jt-ipam fetch origin
sudo -u jtipam git -C /opt/jt-ipam reset --hard origin/main   # 顧客の設定は /etc/jt-ipam にあり、リポジトリ内には無いので安全です
sudo -u jtipam git -C /opt/jt-ipam log --oneline -1           # 最新のコミットにいることを確認します
```

`origin` が古い URL を指している、あるいは fetch が失敗する場合は、リモートを設定し直します。

```bash
sudo -u jtipam git -C /opt/jt-ipam remote set-url origin https://github.com/jasoncheng7115/jt-ipam.git
sudo -u jtipam git -C /opt/jt-ipam fetch origin && sudo -u jtipam git -C /opt/jt-ipam reset --hard origin/main
```

---

## 手順 3：バックエンドの依存関係を更新する

```bash
sudo -u jtipam bash -c 'cd /opt/jt-ipam/backend && .venv/bin/pip install -e .'
```

`requires a different Python` と表示されたり、依存パッケージの wheel が無い場合は、OS や
Python が古すぎる可能性が高いです。先へ進む前に、エラーの全文を控えてください。

---

## 手順 4：データベースのマイグレーション（0.4 から最新への大きな跳躍。最も重要です）

```bash
# 現在の位置を確認します
sudo -u jtipam bash -c 'cd /opt/jt-ipam/backend; set -a; source /etc/jt-ipam/backend.env; set +a; .venv/bin/alembic current'
# head まですべてのマイグレーションを実行します
sudo -u jtipam bash -c 'cd /opt/jt-ipam/backend; set -a; source /etc/jt-ipam/backend.env; set +a; .venv/bin/alembic upgrade head'
```

よくある失敗：

- **`Can't locate revision <xxxx>`**：`alembic_version` が、もう存在しないリビジョンを指しています。
  連なりを確認し、実態に合うものを stamp してから `upgrade head` をやり直します。
  ```bash
  sudo -u jtipam bash -c 'cd /opt/jt-ipam/backend; .venv/bin/alembic history | head -40'
  # 実際の DB 構造に合致するリビジョンを確認してからにしてください：
  # sudo -u jtipam bash -c 'cd /opt/jt-ipam/backend; set -a; source /etc/jt-ipam/backend.env; set +a; .venv/bin/alembic stamp <revision>'
  ```
  `stamp` は記録上のバージョンを書き換えるだけで、スキーマは変更しません。リビジョンは慎重に選んでください。
- **手元のデータでマイグレーションが失敗する**（一意制約の衝突、型の不一致）：失敗したリビジョンと
  エラーを控え、その 1 件を直します。手順 0 のバックアップがあるので、安全にやり直せます。
- **古い `SQL_ASCII` のデータベース**で文字コードのエラーが出る場合：先に DB を UTF-8 へ変換し
  （別の手順になります）、それから続けてください。

---

## 手順 5：フロントエンドを再ビルドして再起動する

コードはすでに最新なので、残りのアップグレードは `--no-pull` で実行します（pip → alembic →
**フロントエンドのビルド** → 再起動、加えて nginx の WebSocket 設定の補正）。

```bash
sudo /opt/jt-ipam/scripts/jt-ipam.sh upgrade --no-pull
```

手作業で再ビルドする場合は次のとおりです。

```bash
cd /opt/jt-ipam/frontend && sudo npm run build
sudo systemctl restart jt-ipam-backend
```

---

## 手順 6：確認

```bash
# バージョンと、Alembic が head にあること
grep '"version"' /opt/jt-ipam/frontend/package.json
sudo -u jtipam bash -c 'cd /opt/jt-ipam/backend; set -a; source /etc/jt-ipam/backend.env; set +a; .venv/bin/alembic current'

# サービスが動いていること
systemctl is-active jt-ipam-backend
journalctl -u jt-ipam-backend -n 30 --no-pager    # トレースバックが無いこと

# API が応答すること
curl -sk https://localhost/api/v1/health || curl -sk https://127.0.0.1:8443/api/v1/health
```

続いてブラウザからログインし（古い JS を捨てるため**スーパーリロード**してください）、
サブネット / IP / 機器が存在すること、連携が引き続き接続できること（`ENCRYPTION_KEY` が
保持され、機密情報が復号できている証拠になります）、ログイン（TOTP を含む）が動作することを
確認します。

---

## 元に戻す

```bash
# コードを以前のコミットへ戻します
sudo -u jtipam git -C /opt/jt-ipam reset --hard <old-commit>
# データベースを戻します
sudo -u postgres pg_restore --clean --no-owner -d jt_ipam /root/jt_ipam_YYYY-MM-DD_HHMM.dump
# 再起動します
sudo systemctl restart jt-ipam-backend
```

---

## 補足

- 通常は手順 1（`jt-ipam.sh upgrade`）だけで済みます。手順 2〜5 は、詰まったときのための分解です。
- バージョンをまたぐアップグレードに対応しています。途中のリリースを踏む必要はありません。
- `install.sh` の再実行はアップグレードの手段ではありません。`git pull` をしないため、
  コードを更新した後（手順 2 のあと）の修復としてしか機能しません。既存の環境や DB を
  壊すことはありません（鍵を作り直したり、データベースを消したりはしません）。
