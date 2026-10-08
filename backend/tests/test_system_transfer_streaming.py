"""系統匯入改成串流（2026-10-01）：不再把整份匯出檔讀進記憶體。

27.5 MB 的匯出檔（42.7 萬列）以前匯入尖峰 1.36 GB。改成兩趟逐段讀檔：第一趟驗證密碼與完整性、
取出各表筆數；第二趟逐列解析、邊讀邊寫。這裡驗的是「讀出來的東西跟整份載入一模一樣」，
以及壞檔、錯密碼、竄改、段落邊界、表的順序與本機不同等情況。
"""
from __future__ import annotations

import io
import json
import secrets as _rng
import uuid

import pytest
from app.services.system_transfer import crypto, importer, streaming

from tests.test_system_transfer import _seed
from tests.test_system_transfer_forward_refs import _seed_forward_refs

PW = "stream-pass-2026"

# 故意塞進會跨段落邊界、又會干擾簡陋解析器的字元
TRICKY = 'a "quoted" {brace} [bracket] \\ back, slash / 中文 日本語 🌏   end'


def _inner(n_rows: int = 37) -> dict:
    rows = [{"id": str(uuid.UUID(int=i + 1)), "name": f"{TRICKY} {i}", "n": i, "f": 1.5,
             "flags": [True, False, None], "nested": {"k": [1, {"x": TRICKY}]}} for i in range(n_rows)]
    return {"tables": {"customers": rows, "sections": [], "zz_unknown": [{"id": "1"}]},
            "central_secrets": [{"object_type": "x", "plain": TRICKY}],
            "counts": {"customers": n_rows, "sections": 0, "zz_unknown": 1, "encrypted_secrets": 1}}


def _write_sealed(tmp_path, inner: dict, name: str = "x.json", **meta) -> str:
    env = crypto.seal(inner, PW, metadata={"app_version": "9.9.9", "scope": ["core"], **meta}, rng=_rng)
    path = tmp_path / name
    path.write_text(json.dumps(env), encoding="utf-8")
    return str(path)


def _rebuild(path: str, *, chunk: int, batch: int) -> dict:
    """把事件組回 inner dict，用來跟整份載入的結果比對。"""
    tables: dict[str, list] = {}
    other: dict = {}
    for ev in streaming.iter_events(path, PW, batch=batch, chunk=chunk):
        if ev[0] == "table":
            tables[ev[1]] = []
        elif ev[0] == "rows":
            assert len(ev[2]) <= batch
            tables[ev[1]].extend(ev[2])
        elif ev[0] == "key":
            other[ev[1]] = ev[2]
    return {"tables": tables, **other}


@pytest.mark.parametrize("chunk", [7, 64, 4096, 1 << 20])
def test_streamed_events_equal_the_whole_file(tmp_path, chunk) -> None:
    inner = _inner()
    path = _write_sealed(tmp_path, inner)
    assert _rebuild(path, chunk=chunk, batch=5) == inner


def test_scan_returns_metadata_and_counts(tmp_path) -> None:
    inner = _inner()
    path = _write_sealed(tmp_path, inner)
    r = streaming.scan(path, PW)
    assert r.metadata["app_version"] == "9.9.9"
    assert r.metadata["scope"] == ["core"]
    assert r.counts == inner["counts"]


def test_streamed_export_file_is_read_too(tmp_path) -> None:
    """匯出端的 write_sealed（串流寫出的檔案）也要能串流讀回。"""
    import gzip
    inner = _inner(500)
    raw = gzip.compress(json.dumps(inner, ensure_ascii=False).encode())
    path = tmp_path / "w.json"
    with open(path, "wb") as f:
        crypto.write_sealed(f, raw, PW, metadata={"app_version": "1.0.0", "scope": ["core"]}, rng=_rng)
    assert _rebuild(str(path), chunk=999, batch=64) == inner
    assert streaming.scan(str(path), PW).counts == inner["counts"]


def test_wrong_passphrase_says_so(tmp_path) -> None:
    """密碼錯時解出來的是亂碼 —— 要報「密碼錯誤」，不是「無法解壓」。"""
    path = _write_sealed(tmp_path, _inner())
    with pytest.raises(crypto.TransferCryptoError) as exc:
        streaming.scan(path, "wrong-pass")
    assert exc.value.code == "xfer_bad_passphrase"


def test_tampered_payload_is_rejected(tmp_path) -> None:
    path = _write_sealed(tmp_path, _inner())
    env = json.loads(open(path, encoding="utf-8").read())
    ct = bytearray(__import__("base64").b64decode(env["payload"]))
    ct[len(ct) // 2] ^= 0x01
    env["payload"] = __import__("base64").b64encode(bytes(ct)).decode()
    open(path, "w", encoding="utf-8").write(json.dumps(env))
    with pytest.raises(crypto.TransferCryptoError) as exc:
        streaming.scan(path, PW)
    assert exc.value.code == "xfer_bad_passphrase"


def test_truncated_and_foreign_files(tmp_path) -> None:
    path = _write_sealed(tmp_path, _inner())
    data = open(path, "rb").read()
    cut = tmp_path / "cut.json"
    cut.write_bytes(data[: len(data) // 2])
    with pytest.raises(crypto.TransferCryptoError) as exc:
        streaming.scan(str(cut), PW)
    assert exc.value.code == "xfer_envelope_broken"

    junk = tmp_path / "junk.json"
    junk.write_bytes(b"PK\x03\x04 not json")
    with pytest.raises(crypto.TransferCryptoError) as exc:
        streaming.scan(str(junk), PW)
    assert exc.value.code == "xfer_not_json"

    other = tmp_path / "other.json"
    other.write_text(json.dumps({"format": "something-else", "payload": "AAAA"}))
    with pytest.raises(crypto.TransferCryptoError) as exc:
        streaming.scan(str(other), PW)
    assert exc.value.code == "xfer_not_export_file"


def test_pretty_printed_envelope_with_fields_after_payload(tmp_path) -> None:
    """有人把匯出檔用排版工具整理過（縮排、payload 後面還有欄位）也要讀得動。"""
    env = crypto.seal(_inner(), PW, metadata={}, rng=_rng)
    env["scope"] = ["core", "settings"]                      # 加在 payload 之後
    env["app_version"] = "8.8.8"
    path = tmp_path / "pretty.json"
    path.write_text(json.dumps(env, indent=2), encoding="utf-8")
    r = streaming.scan(str(path), PW)
    assert r.metadata["scope"] == ["core", "settings"]
    assert r.metadata["app_version"] == "8.8.8"
    assert _rebuild(str(path), chunk=33, batch=4) == _inner()


async def test_streamed_import_matches_whole_file_import(db_session, tmp_path) -> None:
    from app.core.security import decrypt_secret
    from app.models.address import IPAddress
    from app.models.librenms import LibreNMSInstance
    from app.services.librenms import _aad
    from app.services.system_transfer import exporter
    from sqlalchemy import func, select
    ids, token = await _seed(db_session)
    raw, _counts = await exporter.export_compressed(db_session, ["core", "integrations"])
    path = tmp_path / "real.json"
    buf = io.BytesIO()
    crypto.write_sealed(buf, raw, PW, metadata={"app_version": "9.9.9", "scope": ["core", "integrations"]},
                        rng=_rng)
    path.write_bytes(buf.getvalue())
    report = await importer.import_file(db_session, str(path), PW, mode="replace")
    assert report["tables"]["customers"] == {"inserted": 1, "updated": 0, "skipped": 0, "errored": 0, "errors": []}
    assert report["tables"]["ip_addresses"]["inserted"] == 1
    assert all(t["errored"] == 0 for t in report["tables"].values())
    got = (await db_session.execute(select(IPAddress).where(IPAddress.id == ids["ip"]))).scalar_one()
    assert str(got.ip) == "10.9.8.5"
    inst = (await db_session.execute(
        select(LibreNMSInstance).where(LibreNMSInstance.id == ids["librenms"]))).scalar_one()
    assert decrypt_secret(inst.api_token_enc, inst.api_token_nonce, aad=_aad(ids["librenms"])).decode() == token
    assert (await db_session.execute(select(func.count()).select_from(IPAddress))).scalar_one() == 1

    # 第二次 merge：全部是更新
    r2 = await importer.import_file(db_session, str(path), PW, mode="merge")
    assert r2["tables"]["customers"]["updated"] == 1
    assert r2["tables"]["customers"]["inserted"] == 0


async def test_tables_out_of_local_order_are_held_and_still_correct(db_session, tmp_path) -> None:
    """檔案裡的表順序跟本機的外鍵相依序不同（例如舊版匯出）：先暫存、輪到時再寫，資料不可少。"""
    from app.models.device import Device
    from app.models.physical import DevicePort
    from app.services.system_transfer import exporter
    from sqlalchemy import select

    ids = await _seed_forward_refs(db_session)
    inner = await exporter.build_export(db_session, ["core"])
    inner["tables"] = dict(reversed(list(inner["tables"].items())))     # 子表全部排在父表前面
    path = _write_sealed(tmp_path, inner, name="rev.json")
    report = await importer.import_file(db_session, path, PW, mode="replace")
    assert all(t["errored"] == 0 for t in report["tables"].values()), report["tables"]
    dev = (await db_session.execute(select(Device).where(Device.id == ids["device"]))).scalar_one()
    assert dev.primary_ip_id == ids["ip"]                                # 往後指的外鍵也補回來了
    port = (await db_session.execute(select(DevicePort).where(DevicePort.id == ids["port"]))).scalar_one()
    assert port.peer_port_id == ids["peer"]


async def test_replace_never_wipes_when_the_file_is_bad(db_session, tmp_path) -> None:
    """密碼錯的檔案在第一趟就被擋下 —— 取代模式的清空一定不能先發生。"""
    from app.models.customer import Customer
    from sqlalchemy import func, select
    await _seed(db_session)
    path = _write_sealed(tmp_path, _inner())
    with pytest.raises(crypto.TransferCryptoError):
        await importer.import_file(db_session, path, "wrong-pass", mode="replace")
    await db_session.rollback()
    assert (await db_session.execute(select(func.count()).select_from(Customer))).scalar_one() == 1


async def test_analyze_and_dry_run_endpoints_stream_the_upload(client, auth_headers, db_session, tmp_path) -> None:
    from app.services.system_transfer import exporter
    await _seed(db_session)
    raw, _counts = await exporter.export_compressed(db_session, ["core"])
    buf = io.BytesIO()
    crypto.write_sealed(buf, raw, PW, metadata={"app_version": "9.9.9", "scope": ["core"]}, rng=_rng)
    files = {"file": ("export.json", buf.getvalue(), "application/json")}
    r = await client.post("/api/v1/system/transfer/import/analyze", headers=auth_headers,
                          files=files, data={"passphrase": PW})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["counts"]["customers"] == 1
    assert body["metadata"]["app_version"] == "9.9.9"
    d = await client.post("/api/v1/system/transfer/import/apply", headers=auth_headers,
                          json={"token": body["token"], "passphrase": PW, "mode": "merge", "dry_run": True})
    assert d.status_code == 200, d.text
    assert d.json()["report"]["tables"]["customers"]["updated"] == 1

    bad = await client.post("/api/v1/system/transfer/import/analyze", headers=auth_headers,
                            files=files, data={"passphrase": "nope"})
    assert bad.status_code == 400
    assert bad.json()["detail"]["code"] == "xfer_bad_passphrase"
