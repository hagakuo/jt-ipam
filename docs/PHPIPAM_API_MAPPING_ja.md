# phpIPAM v1.7 API 互換レイヤ：対応表

> English: [PHPIPAM_API_MAPPING.md](PHPIPAM_API_MAPPING.md) · 繁體中文版：[PHPIPAM_API_MAPPING_zh-TW.md](PHPIPAM_API_MAPPING_zh-TW.md)

> 目的：既存の phpIPAM 用スクリプトを一切変更せずに移行できるようにすること。パスの接頭辞は `/api/phpipam/<app_id>/` です。
>
> フェーズ 1 では主要な 8 分類（Sections / Subnets / Addresses / VLANs / VRFs / Devices / Tools / User）を扱います。残り（Folder / Locations / L2Domains / Circuits / Tags）はフェーズ 2 です。
>
> セキュリティ上の考慮：
> - 認証トークンは phpIPAM の仕組み（`POST /user/`）を使いますが、jt-ipam の内部では `api_tokens` としてハッシュを暗号化して保管します（A02 / A07）
> - すべてのエンドポイントで RBAC の判定を行います。Section / Subnet の権限は現行の API と共通です（A01）
> - 出力は phpIPAM 形式の `{success, data, message, time}` で包みますが、内部では引き続き Pydantic の検証を通します（A03）

---

## 1. 認証

| phpIPAM のエンドポイント | jt-ipam のエンドポイント | 備考 |
|---|---|---|
| `POST /api/<app_id>/user/` | `POST /api/phpipam/<app_id>/user/` | トークンの取得 |
| `DELETE /api/<app_id>/user/` | `DELETE /api/phpipam/<app_id>/user/` | トークンの失効 |
| `PATCH /api/<app_id>/user/` | `PATCH /api/phpipam/<app_id>/user/` | トークンの期限延長 |
| `GET /api/<app_id>/user/` | `GET /api/phpipam/<app_id>/user/` | トークンの情報 |

**セキュリティ上の強化**：トークンの有効期限は必須で、最長 1 年です。作成時に平文をどこにも書き出しません。

---

## 2. セクション

| phpIPAM | jt-ipam |
|---|---|
| `GET    /sections/` | `GET /api/phpipam/<app>/sections/` |
| `GET    /sections/{id}/` | 同じ |
| `GET    /sections/{name}/` | 同じ（名前で指定） |
| `GET    /sections/{id}/subnets/` | 同じ |
| `POST   /sections/` | 同じ |
| `PATCH  /sections/{id}/` | 同じ |
| `DELETE /sections/{id}/` | 同じ |

**内部モデルとの対応**：`Section`。フェーズ 1 で必須です。

---

## 3. サブネット

| phpIPAM | jt-ipam |
|---|---|
| `GET /subnets/{id}/` | 同じ |
| `GET /subnets/cidr/{subnet}/` | 同じ |
| `GET /subnets/{id}/usage/` | 使用率を算出 |
| `GET /subnets/{id}/first_free/` | 最初の空き IP |
| `GET /subnets/{id}/slaves/` | 子サブネット |
| `GET /subnets/{id}/slaves_recursive/` | 再帰的に取得 |
| `GET /subnets/{id}/addresses/` | そのサブネット内のすべての IP |
| `GET /subnets/{id}/first_subnet/{mask}/` | 最初の空き子サブネット |
| `GET /subnets/{id}/all_subnets/{mask}/` | 分割候補の一覧 |
| `GET /subnets/{id}/search/{ip}/` | サブネット内を検索 |
| `POST /subnets/` | 作成 |
| `POST /subnets/{id}/first_subnet/{mask}/` | 次のブロックを自動で切り出す |
| `POST /subnets/{id}/resize/` | サイズ変更 |
| `POST /subnets/{id}/split/` | 分割 |
| `PATCH /subnets/{id}/` | 更新 |
| `PATCH /subnets/{id}/resize/` | 上と同じ |
| `PATCH /subnets/{id}/split/` | 上と同じ |
| `DELETE /subnets/{id}/` | 削除 |
| `DELETE /subnets/{id}/truncate/` | 配下の IP を消去 |
| `DELETE /subnets/{id}/permissions/` | 権限をリセット |

**内部モデルとの対応**：`Subnet`。

---

## 4. アドレス（IP）

| phpIPAM | jt-ipam |
|---|---|
| `GET /addresses/{id}/` | 同じ |
| `GET /addresses/{ip}/{subnetId}/` | IP とサブネットで指定 |
| `GET /addresses/search/{ip}/` | 全体を検索 |
| `GET /addresses/search_hostname/{hostname}/` | ホスト名で検索 |
| `GET /addresses/first_free/{subnetId}/` | 最初の空き |
| `GET /addresses/custom_fields/` | カスタム項目の定義 |
| `GET /addresses/tags/` | 状態のタグ |
| `GET /addresses/tags/{id}/addresses/` | その状態を持つすべての IP |
| `POST /addresses/` | 作成 |
| `POST /addresses/first_free/` | 最初の空きを確保 |
| `PATCH /addresses/{id}/` | 更新 |
| `DELETE /addresses/{id}/` | 削除 |
| `DELETE /addresses/{ip}/{subnetId}/` | IP とサブネットで削除 |

**内部モデルとの対応**：`IPAddress`。phpIPAM では「状態」をタグと呼ぶ点に注意してください。

---

## 5. VLAN

| phpIPAM | jt-ipam |
|---|---|
| `GET /vlans/` | 同じ |
| `GET /vlans/{id}/` | 同じ |
| `GET /vlans/{id}/subnets/` | 同じ |
| `GET /vlans/{id}/subnets/{section}/` | 同じ |
| `GET /vlans/search/{number}/` | 番号で検索 |
| `POST /vlans/` | 同じ |
| `PATCH /vlans/{id}/` | 同じ |
| `DELETE /vlans/{id}/` | 同じ |

**内部モデルとの対応**：`VLAN` と `VLANDomain`。

---

## 6. VRF

| phpIPAM | jt-ipam |
|---|---|
| `GET /vrf/` | 同じ |
| `GET /vrf/{id}/` | 同じ |
| `GET /vrf/{id}/subnets/` | 同じ |
| `POST /vrf/` | 同じ |
| `PATCH /vrf/{id}/` | 同じ |
| `DELETE /vrf/{id}/` | 同じ |

**内部モデルとの対応**：`VRF`。

---

## 7. 機器

| phpIPAM | jt-ipam |
|---|---|
| `GET /devices/` | 同じ |
| `GET /devices/{id}/` | 同じ |
| `GET /devices/{id}/subnets/` | 同じ |
| `GET /devices/{id}/addresses/` | 同じ |
| `POST /devices/` | 同じ |
| `PATCH /devices/{id}/` | 同じ |
| `DELETE /devices/{id}/` | 同じ |

**内部モデルとの対応**：`Device`。

### 機器の種別

| phpIPAM | jt-ipam |
|---|---|
| `GET /tools/device_types/` | 同じ |
| `POST /tools/device_types/` | 同じ |
| `PATCH /tools/device_types/{id}/` | 同じ |
| `DELETE /tools/device_types/{id}/` | 同じ |

---

## 8. Tools（その他）

対象：tags、nameservers、scan_agents、locations、racks、custom_fields、users、groups。

| phpIPAM のエンドポイント | 内部での対応先 |
|---|---|
| `/tools/tags/` | IPAddress.state の列挙 |
| `/tools/locations/` | Location |
| `/tools/racks/` | Rack |
| `/tools/nameservers/` | DNSServer（フェーズ 2） |
| `/tools/scanagents/` | ScanAgent（フェーズ 1） |
| `/tools/custom_fields/{object}/` | CustomFieldDefinition |
| `/tools/users/` | User |
| `/tools/groups/` | Group |

---

## 9. 応答の形式

phpIPAM の標準的な形式：

```json
{
  "code": 200,
  "success": true,
  "data": [...] or {...},
  "message": "...",
  "time": 0.012
}
```

jt-ipam は `/api/phpipam/` 配下の応答をこの形式で統一して包みます。`/api/v1/` は標準的な OpenAPI の形式です。

---

## 10. 非互換な点と注意

| phpIPAM の挙動 | jt-ipam での扱い |
|---|---|
| 数値の ID（自動採番） | jt-ipam は内部では UUID を使い、phpIPAM 向けには互換のため数値の `legacy_id`（単調増加の bigint）を別途発行します |
| 一部の項目が真偽値に `0/1` を使う | ラッパーが自動的に変換します |
| `null` と `""` が混在する | jt-ipam は内部で厳密に区別し、出力時に phpIPAM 形式へ正規化します |
| サブネットの CIDR が `subnet` と `mask` の 2 列 | jt-ipam は単一の `cidr` を使い、出力時に分けます |
| `permissions` が base64 でシリアライズされた文字列 | jt-ipam は解析し、出力時に再度符号化します |

---

## 11. フェーズの区分

| フェーズ | 対象 |
|---|---|
| **フェーズ 1** | user、sections、subnets、addresses、vlans、vrf、devices、tools（基本） |
| **フェーズ 2** | folder、l2domains、circuits、locations、prefixes、scanagents の全体 |
| **フェーズ 3** | 応用：複数種別のカスタム項目、一括処理のエンドポイント |
