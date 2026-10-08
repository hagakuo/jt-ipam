"""憑證自動抓取來源(URL / SFTP)。

定期(sync timer)或手動向來源拉 cert/key/chain → 驗證 → **fingerprint 與目前版本相同就跳過
(不是新檔、不處理)**;不同才存成新版本。來源未提供私鑰時沿用目前版本的 key(多數商業續約
不換 key)。帳密 / SSH key 走 encrypted_secret(object_type='certificate'),不回明文。

安全:URL 走 safe_http(SSRF 允許清單);SFTP host 先過 SSRF 檢查(擋 metadata/loopback)。
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import UTC, datetime
from typing import Any

import asyncssh
import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import append_audit
from app.core.config import get_settings
from app.core.safe_http import (
    _BLOCKED_CIDRS,
    _PRIVATE_CIDRS,
    UnsafeOutboundURL,
    _ip_in,
    safe_request,
)
from app.core.security import decrypt_secret, encrypt_secret
from app.core.ui_error import UiError
from app.models.certificate import Certificate, CertVersion
from app.models.encrypted_secret import EncryptedSecret
from app.services.cert_service import (
    CertError,
    _split_pem_certs,
    analyze_chain,
    validate_bundle,
)


class FetchError(UiError):
    """憑證來源抓取失敗。訊息會顯示給使用者，所以帶代碼讓前端翻譯（見 core/ui_error）。"""


def _aad(cert_id: Any, field: str) -> bytes:
    return f"certificate:{cert_id}:{field}".encode()


def _key_aad(cert_id: Any, fingerprint: str) -> bytes:
    return f"cert_version:{cert_id}:{fingerprint}".encode()


async def load_cert_secret(session: AsyncSession, cert_id: Any, field: str) -> str | None:
    row = (await session.execute(select(EncryptedSecret).where(
        EncryptedSecret.object_type == "certificate",
        EncryptedSecret.object_id == cert_id,
        EncryptedSecret.field == field,
    ))).scalar_one_or_none()
    if row is None:
        return None
    return decrypt_secret(row.ciphertext, row.nonce, aad=_aad(cert_id, field)).decode("utf-8")


async def save_cert_secret(session: AsyncSession, cert_id: Any, field: str, value: str) -> None:
    enc, nonce = encrypt_secret(value, aad=_aad(cert_id, field))
    existing = (await session.execute(select(EncryptedSecret).where(
        EncryptedSecret.object_type == "certificate",
        EncryptedSecret.object_id == cert_id,
        EncryptedSecret.field == field,
    ))).scalar_one_or_none()
    if existing is None:
        session.add(EncryptedSecret(object_type="certificate", object_id=cert_id,
                                    field=field, ciphertext=enc, nonce=nonce))
    else:
        existing.ciphertext = enc
        existing.nonce = nonce


def _check_host_safe(host: str) -> None:
    settings = get_settings()
    try:
        addrs = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise FetchError(f"無法解析主機 {host}", code="cert_src_dns", host=host) from exc
        addrs = [ipaddress.ip_address(i[4][0]) for i in infos]
    for ip in addrs:
        if _ip_in(ip, _BLOCKED_CIDRS):
            raise FetchError(f"封鎖的 IP(SSRF):{ip}", code="cert_src_blocked_ip", ip=str(ip))
        if _ip_in(ip, _PRIVATE_CIDRS) and not settings.outbound_allow_private:
            raise FetchError(f"私網 IP {ip} 未允許(需 OUTBOUND_ALLOW_PRIVATE)", code="cert_src_private_ip", ip=str(ip))


async def _get_url(url: str) -> str:
    try:
        resp = await safe_request("GET", url, timeout=20.0)
    except UnsafeOutboundURL as exc:
        raise FetchError(f"SSRF 守門擋下:{exc}", code="cert_src_ssrf", reason=str(exc)[:200]) from exc
    except httpx.HTTPError as exc:
        raise FetchError(f"連線失敗:{exc.__class__.__name__}", code="cert_src_connect", reason=exc.__class__.__name__) from exc
    if resp.status_code != 200:
        raise FetchError(f"{url} 回 HTTP {resp.status_code}", code="cert_src_http", url=url, status=resp.status_code)
    return resp.text


async def _fetch_url(cfg: dict[str, Any]) -> tuple[str, str | None, str | None]:
    cert_url = cfg.get("cert_url")
    if not cert_url:
        raise FetchError("URL 來源需要 cert_url", code="cert_src_need_url")
    cert_pem = await _get_url(cert_url)
    key_pem = await _get_url(cfg["key_url"]) if cfg.get("key_url") else None
    chain_pem = await _get_url(cfg["chain_url"]) if cfg.get("chain_url") else None
    return cert_pem, key_pem, chain_pem


# ── SFTP 主機金鑰釘選（TOFU）─────────────────────────────────────────────────────
# 以前每次都是 known_hosts=None：完全不驗主機金鑰、又用密碼登入 —— 中間的人冒充 SFTP 主機就拿得到密碼
# （2026-10-06 CodeQL 判讀時發現）。現在第一次連線記下主機金鑰（存在 source_config），之後每次都要相同；
# 改了主機或埠就作廢、重新記；主機真的換了金鑰時，管理員確認後按「重新信任」（forget-host-key）。
PIN_FIELDS = ("host_key", "host_key_fingerprint", "host_key_for", "host_key_pinned_at")


def pin_target(cfg: dict[str, Any]) -> str:
    return f"{cfg.get('host')}:{int(cfg.get('port') or 22)}"


def merge_pin(saved: dict[str, Any] | None, form: dict[str, Any] | None) -> dict[str, Any]:
    """表單送來的設定＋伺服器記住的釘選：表單裡的釘選欄位一律丟掉（不信任客戶端），
    主機與埠沒變才帶上已記住的釘選。"""
    out = {k: v for k, v in (form or {}).items() if k not in PIN_FIELDS}
    saved = saved or {}
    if saved.get("host_key") and saved.get("host_key_for") == pin_target(out):
        out.update({k: saved[k] for k in PIN_FIELDS if k in saved})
    return out


async def _trust(cfg: dict[str, Any]) -> tuple[Any, dict[str, Any] | None, str]:
    """(asyncssh 的 known_hosts 參數, 這次新記住的釘選或 None, 主機金鑰指紋)。"""
    from app.services.ssh_tunnel import (
        SSHTunnelError,
        fetch_host_key,
        server_key_fingerprint_sha256,
    )
    if cfg.get("host_key") and cfg.get("host_key_for") == pin_target(cfg):
        line = str(cfg["host_key"])
        fp = str(cfg.get("host_key_fingerprint") or "")
        if not fp:
            import base64
            fp = server_key_fingerprint_sha256(base64.b64decode(line.split()[1]))
        new_pin = None
    else:
        try:
            hk = await fetch_host_key(str(cfg["host"]), int(cfg.get("port") or 22))
        except SSHTunnelError as exc:
            raise FetchError(f"SFTP 連線失敗:{exc}", code="cert_src_sftp_connect",
                             reason=str(exc)[:200]) from exc
        line, fp = hk["known_host"], hk["fingerprint"]
        new_pin = {"host_key": line, "host_key_fingerprint": fp, "host_key_for": pin_target(cfg),
                   "host_key_pinned_at": datetime.now(UTC).isoformat()}
    try:
        key = asyncssh.import_public_key(line)
    except Exception as exc:
        raise FetchError("記住的主機金鑰無法解析，請重新信任主機金鑰", code="cert_src_host_key_bad") from exc
    return ([key], [], []), new_pin, fp


async def _host_key_mismatch(cfg: dict[str, Any], expected: str, exc: Exception) -> FetchError:
    """連線時主機金鑰跟記住的不同：可能有人冒充，也可能主機重灌。列出兩個指紋給管理員比對。"""
    from app.services.ssh_tunnel import SSHTunnelError, fetch_host_key
    actual = "?"
    try:
        actual = (await fetch_host_key(str(cfg["host"]), int(cfg.get("port") or 22)))["fingerprint"]
    except (SSHTunnelError, OSError):
        pass
    return FetchError(
        f"SFTP 主機金鑰跟記住的不同（記住的 {expected}，現在的 {actual}）：可能有人冒充這台主機，"
        "也可能主機重灌換了金鑰。確認後再按「重新信任主機金鑰」。",
        code="cert_src_host_key_mismatch", expected=expected, actual=actual)


async def _fetch_sftp(session: AsyncSession, cert: Certificate,
                      cfg: dict[str, Any]) -> tuple[str, str | None, str | None]:
    host = cfg.get("host")
    username = cfg.get("username")
    cert_path = cfg.get("cert_path")
    if not host or not username or not cert_path:
        raise FetchError("SFTP 來源需要 host + username + cert_path", code="cert_src_need_sftp_all")
    _check_host_safe(host)
    password = await load_cert_secret(session, cert.id, "source_password")
    private_key = await load_cert_secret(session, cert.id, "source_private_key")
    known_hosts, new_pin, expected_fp = await _trust(cfg)
    kw: dict[str, Any] = {"host": host, "port": int(cfg.get("port", 22)),
                          "username": username, "known_hosts": known_hosts}
    if private_key:
        kw["client_keys"] = [asyncssh.import_private_key(private_key)]
    elif password:
        kw["password"] = password
    else:
        raise FetchError("SFTP 來源需要密碼或私鑰", code="cert_src_need_sftp_auth")

    async def _read() -> tuple[str, str | None, str | None]:
        async with asyncssh.connect(**kw) as conn, conn.start_sftp_client() as sftp:
            async def rf(p: str) -> str:
                async with sftp.open(p, "r") as f:
                    return await f.read()
            c = await rf(cert_path)
            k = await rf(cfg["key_path"]) if cfg.get("key_path") else None
            ch = await rf(cfg["chain_path"]) if cfg.get("chain_path") else None
            return c, k, ch

    try:
        out = await asyncio.wait_for(_read(), timeout=30)
    except FetchError:
        raise
    except asyncssh.HostKeyNotVerifiable as exc:
        raise await _host_key_mismatch(cfg, expected_fp, exc) from exc
    except Exception as exc:
        raise FetchError(f"SFTP 失敗:{exc.__class__.__name__}: {exc}", code="cert_src_sftp_failed",
                         reason=f"{exc.__class__.__name__}: {exc}"[:200]) from exc
    if new_pin:
        # 第一次連上：記住主機金鑰（之後每次都要相同）；記一筆稽核，事後查得到是何時、記住哪一把
        cert.source_config = {**(cert.source_config or {}), **new_pin}
        await append_audit(session, actor_user_id=None, actor_ip=None, actor_user_agent=None,
                           object_type="certificate", object_id=str(cert.id), action="cert_source_pin_host_key",
                           diff={"fingerprint": new_pin["host_key_fingerprint"], "host": new_pin["host_key_for"]},
                           request_id=None)
    return out


def generate_source_ssh_keypair(comment: str = "jt-ipam-cert-source") -> tuple[str, str]:
    """產生 jt-ipam 端用來登入 SFTP 來源的 SSH 金鑰對。

    回 (private_openssh_pem, public_openssh)。私鑰由呼叫端加密存成 source_private_key,
    公鑰回給使用者貼到 SFTP 主機的 authorized_keys。
    """
    key = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
    priv = key.export_private_key().decode("utf-8")
    pub = key.export_public_key().decode("utf-8").strip()
    return priv, pub


async def install_public_key_sftp(cfg: dict[str, Any], *, password: str,
                                  public_key: str) -> tuple[str, dict[str, Any] | None]:
    """用密碼登入 SFTP 主機,把 public_key 加進 ~/.ssh/authorized_keys(冪等)。回成功訊息。

    僅在使用者已提供登入密碼時可用(否則無法登入安裝)。失敗 raise FetchError。
    """
    host = cfg.get("host")
    username = cfg.get("username")
    if not host or not username:
        raise FetchError("安裝公鑰需要 host + username", code="cert_src_need_host_user")
    if not password:
        raise FetchError("自動安裝公鑰需要登入密碼(請填密碼,或自行把公鑰貼到主機)", code="cert_src_need_password")
    _check_host_safe(host)
    pub = public_key.strip()
    known_hosts, new_pin, expected_fp = await _trust(cfg)

    async def _install() -> str:
        async with asyncssh.connect(
            host=host, port=int(cfg.get("port", 22)), username=username,
            password=password, known_hosts=known_hosts,
        ) as conn, conn.start_sftp_client() as sftp:
            try:
                await sftp.mkdir(".ssh")
            except Exception:  # 目錄已存在等
                pass
            try:
                await sftp.chmod(".ssh", 0o700)
            except Exception:
                pass
            path = ".ssh/authorized_keys"
            existing = ""
            if await sftp.exists(path):
                async with sftp.open(path, "r") as f:
                    existing = await f.read()
            if pub in existing:
                return "公鑰已存在於主機 authorized_keys（未重複加入）"
            sep = "" if (not existing or existing.endswith("\n")) else "\n"
            async with sftp.open(path, "a") as f:
                await f.write(f"{sep}{pub}\n")
            await sftp.chmod(path, 0o600)
            return "已將公鑰安裝到主機 ~/.ssh/authorized_keys"

    try:
        return await asyncio.wait_for(_install(), timeout=30), new_pin
    except FetchError:
        raise
    except asyncssh.HostKeyNotVerifiable as exc:
        raise await _host_key_mismatch(cfg, expected_fp, exc) from exc
    except Exception as exc:
        raise FetchError(f"安裝公鑰失敗:{exc.__class__.__name__}: {exc}", code="cert_src_install_key_failed",
                         reason=f"{exc.__class__.__name__}: {exc}"[:200]) from exc


async def probe_source_connection(
    cfg: dict[str, Any], *, source_type: str,
    password: str | None = None, private_key: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """嘗試連線來源(不存檔、不抓整包)。成功回 (可讀訊息, {host_key_fingerprint, new_pin}),失敗 raise FetchError。

    secrets 由呼叫端決定:表單有填就用填的,沒填就帶入已存的(沿用)。
    """
    if source_type == "url":
        cert_url = cfg.get("cert_url")
        if not cert_url:
            raise FetchError("URL 來源需要 cert_url", code="cert_src_need_url")
        text = await _get_url(cert_url)
        if "BEGIN CERTIFICATE" not in text:
            raise FetchError("cert_url 取得的內容不是 PEM 憑證", code="cert_src_not_pem")
        if cfg.get("chain_url"):
            await _get_url(cfg["chain_url"])
        if cfg.get("key_url"):
            await _get_url(cfg["key_url"])
        return "URL 連線成功,cert_url 可取得 PEM 憑證", {}
    if source_type == "sftp":
        host = cfg.get("host")
        username = cfg.get("username")
        if not host or not username:
            raise FetchError("SFTP 來源需要 host + username", code="cert_src_need_host_user")
        _check_host_safe(host)
        known_hosts, new_pin, expected_fp = await _trust(cfg)
        kw: dict[str, Any] = {"host": host, "port": int(cfg.get("port", 22)),
                              "username": username, "known_hosts": known_hosts}
        try:
            if private_key:
                kw["client_keys"] = [asyncssh.import_private_key(private_key)]
            elif password:
                kw["password"] = password
            else:
                raise FetchError("SFTP 來源需要密碼或私鑰", code="cert_src_need_sftp_auth")
        except FetchError:
            raise
        except Exception as exc:
            raise FetchError(f"私鑰格式無法解析:{exc.__class__.__name__}", code="cert_src_bad_key",
                             reason=exc.__class__.__name__) from exc
        cert_path = cfg.get("cert_path")

        async def _probe() -> str:
            async with asyncssh.connect(**kw) as conn, conn.start_sftp_client() as sftp:
                if cert_path and not await sftp.exists(cert_path):
                    raise FetchError(f"登入成功,但找不到 cert_path:{cert_path}", code="cert_src_path_missing",
                                     path=str(cert_path))
            return "SFTP 登入成功" + (f",cert_path 存在:{cert_path}" if cert_path else "")
        try:
            msg = await asyncio.wait_for(_probe(), timeout=30)
            return msg, {"host_key_fingerprint": expected_fp, "new_pin": new_pin}
        except FetchError:
            raise
        except asyncssh.HostKeyNotVerifiable as exc:
            raise await _host_key_mismatch(cfg, expected_fp, exc) from exc
        except Exception as exc:
            raise FetchError(f"SFTP 連線失敗:{exc.__class__.__name__}: {exc}", code="cert_src_sftp_connect",
                             reason=f"{exc.__class__.__name__}: {exc}"[:200]) from exc
    raise FetchError("此來源類型不需測試連線", code="cert_src_no_test")


async def _current_version(session: AsyncSession, cert_id: Any) -> CertVersion | None:
    return (await session.execute(select(CertVersion).where(
        CertVersion.certificate_id == cert_id, CertVersion.is_current.is_(True),
    ).limit(1))).scalar_one_or_none()


async def store_cert_version(
    session: AsyncSession, *, cert: Certificate, cert_pem: str, key_pem: str,
    chain_pem: str | None, info: Any, actor_user_id: Any, request_id: str | None, action: str,
) -> CertVersion:
    """存成新版本(加密私鑰、設為目前版本、寫稽核)。同 fingerprint 已存在 → FetchError。"""
    if (await session.execute(select(CertVersion).where(
        CertVersion.certificate_id == cert.id,
        CertVersion.fingerprint_sha256 == info.fingerprint_sha256,
    ).limit(1))).scalar_one_or_none() is not None:
        raise FetchError("這張憑證(相同 fingerprint)已存在", code="cert_src_duplicate")
    enc, nonce = encrypt_secret(key_pem, aad=_key_aad(cert.id, info.fingerprint_sha256))
    await session.execute(update(CertVersion).where(
        CertVersion.certificate_id == cert.id).values(is_current=False))
    v = CertVersion(
        certificate_id=cert.id, fingerprint_sha256=info.fingerprint_sha256, serial=info.serial,
        subject=info.subject, issuer=info.issuer, not_before=info.not_before,
        not_after=info.not_after, domains=info.domains, cert_pem=cert_pem, chain_pem=chain_pem,
        key_enc=enc, key_nonce=nonce, is_current=True, uploaded_by=actor_user_id,
    )
    session.add(v)
    cert.domains = info.domains
    await session.flush()
    await append_audit(
        session, actor_user_id=str(actor_user_id) if actor_user_id else None,
        actor_ip=None, actor_user_agent="cert-fetch",
        object_type="certificate", object_id=str(cert.id), action=action,
        diff={"fingerprint": info.fingerprint_sha256, "not_after": info.not_after.isoformat(),
              "domains": info.domains},
        request_id=request_id,
    )
    return v


async def fetch_certificate(session: AsyncSession, cert: Certificate, *,
                            actor_user_id: Any = None) -> dict[str, Any]:
    """抓取來源 → fingerprint 不同才存新版。回 {status: none/skipped/updated/error}。自行 commit。"""
    now = datetime.now(UTC)
    if cert.source_type not in ("url", "sftp"):
        return {"status": "none"}
    cfg = cert.source_config or {}
    cur: CertVersion | None = None
    try:
        if cert.source_type == "url":
            cert_pem, key_pem, chain_pem = await _fetch_url(cfg)
        else:
            cert_pem, key_pem, chain_pem = await _fetch_sftp(session, cert, cfg)
        cur = await _current_version(session, cert.id)
        if not key_pem:  # 來源沒給 key → 沿用目前版本(續約不換 key 的常見情況)
            if cur is None:
                raise FetchError("來源未提供私鑰,且此憑證尚無既有版本可沿用 key", code="cert_src_no_key")
            key_pem = decrypt_secret(cur.key_enc, cur.key_nonce,
                                     aad=_key_aad(cert.id, cur.fingerprint_sha256)).decode("utf-8")
        info = validate_bundle(cert_pem, key_pem, chain_pem)
    except (FetchError, CertError) as exc:
        cert.last_fetch_at = now
        cert.last_fetch_error = str(exc)
        await session.commit()
        return {"status": "error", "error": str(exc), "code": getattr(exc, "code", None),
                "params": getattr(exc, "params", None) or {}}

    if cur is not None and cur.fingerprint_sha256 == info.fingerprint_sha256:
        cert.last_fetch_at = now
        cert.last_fetch_error = None
        await session.commit()
        return {"status": "skipped", "fingerprint": info.fingerprint_sha256}

    # Auto-complete the chain before storing: sources (SFTP/URL) usually provide only leaf+intermediate.
    # If the chain can reach the root (from the fetched files or the server's trust store), build the full
    # intermediate+root chain now — so strict services (Zimbra/PDM) verify without a manual "build full chain".
    chain_analysis = analyze_chain(cert_pem, chain_pem)
    if chain_analysis["can_rebuild"]:
        leaf = _split_pem_certs(cert_pem)[0]
        cert_pem = leaf if leaf.endswith("\n") else leaf + "\n"
        chain_pem = chain_analysis["built_chain_pem"]

    try:
        await store_cert_version(session, cert=cert, cert_pem=cert_pem, key_pem=key_pem,
                                 chain_pem=chain_pem, info=info, actor_user_id=actor_user_id,
                                 request_id=None, action="cert_fetch")
    except FetchError as exc:
        cert.last_fetch_at = now
        cert.last_fetch_error = str(exc)
        await session.commit()
        return {"status": "error", "error": str(exc)}
    cert.last_fetch_at = now
    cert.last_fetch_error = None
    await session.commit()
    return {"status": "updated", "fingerprint": info.fingerprint_sha256,
            "not_after": info.not_after.isoformat()}
