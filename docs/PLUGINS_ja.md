# jt-ipam プラグイン開発ガイド

> English: [PLUGINS.md](PLUGINS.md) · 繁體中文：[PLUGINS_zh-TW.md](PLUGINS_zh-TW.md)

サードパーティのパッケージは、本体のリポジトリをフォークすることなく、`entry_points` を
使って jt-ipam を拡張できます。

---

## 最小限の動くプラグイン

`my_plugin/__init__.py`:

```python
from fastapi import APIRouter, Depends

from app.api.v1.dependencies import CurrentUser
from app.plugins import JtIpamPlugin

router = APIRouter(prefix="/api/v1/my-plugin", tags=["my-plugin"])


@router.get("/hello")
async def hello(_user: CurrentUser) -> dict:
    return {"hello": "from my plugin"}


def _on_load(app):
    app.include_router(router)


plugin = JtIpamPlugin(
    name="my-plugin",
    version="1.0.0",
    description="Example plugin",
    on_load=_on_load,
)
```

`pyproject.toml`:

```toml
[project]
name = "my-jt-ipam-plugin"
version = "1.0.0"

[project.entry-points."jt_ipam.plugins"]
my_plugin = "my_plugin:plugin"
```

導入すると、jt-ipam は起動時にこれを読み込みます。

```bash
cd /opt/jt-ipam/backend
.venv/bin/pip install /path/to/my-jt-ipam-plugin
sudo systemctl restart jt-ipam-backend
```

確認：

```bash
curl -fsS https://ipam.example.com/api/v1/plugins -H "Authorization: Bearer ..."
# {"count": 1, "plugins": [{"name": "my-plugin", "version": "1.0.0", ...}]}
```

---

## 登録できるもの

`on_load(app)` は FastAPI のアプリオブジェクトを受け取ります。ここで次のことができます。

- `app.include_router(...)` で REST のエンドポイントを追加する
- `app.middleware(...)` でミドルウェアを追加する
- バックグラウンドのタスクを開始する（`asyncio.create_task`）

後片付け用のフックは `on_shutdown(app)` です。

---

## セキュリティ上の注意（OWASP）

- **A01**：プラグインのエンドポイントでは `Depends(get_current_user)` または
  `Depends(require_admin)` を**必ず**使ってください。RBAC を迂回しないこと。
- **A02**：プラグインが持つ機密情報は、環境変数や素の DB 列ではなく
  `app.models.encrypted_secret.EncryptedSecret` を通してください。
- **A09**：書き込みを伴う操作では `app.core.audit.append_audit()` を呼び、監査チェーンに追記してください。
- **A10**：外向きの通信は `app.core.safe_http.safe_request` を使い、`httpx.get()` を直接呼ばないでください。
- **A06**：依存関係のバージョンはプラグインの pyproject で固定してください。リリースは SBOM の流れに従います。

---

## 現時点（フェーズ 4）の制限

- データベースのマイグレーションは管理されません。プラグイン自身のテーブルは、自前の
  alembic で管理してください（jt-ipam 本体の alembic とは分けた、別の alembic env を推奨します）。
- プラグインのエンドポイントは `/openapi.json` に自動的に現れます。
- プラグインのホットアンインストールはありません。現時点で無効化するには
  `pip uninstall && systemctl restart` です。

これらの制限はフェーズ 4.x で改善していく予定です。
