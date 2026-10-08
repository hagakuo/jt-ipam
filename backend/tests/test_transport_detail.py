"""出站錯誤訊息要說得出原因。

客戶的 LibreNMS 整合顯示 `transport: ConnectError` —— 這個字串沒有任何資訊量：
名稱解析不到、連線被拒、路由不通、TLS 憑證驗不過，四種完全不同的問題長得一模一樣，
處理的人只能一個一個猜。原因其實在例外底下（`__cause__` 常是 socket.gaierror 或
ssl.SSLCertVerificationError），只是被丟掉了。

同 FortiGate 那次的教訓：解析／連線類的錯誤一定要帶底層原文。
"""

from __future__ import annotations

import socket
import ssl

import httpx

from app.core.safe_http import transport_detail


def _raise_from(outer: Exception, inner: Exception) -> Exception:
    try:
        try:
            raise inner
        except Exception as i:
            raise outer from i
    except Exception as e:
        return e


def test_dns_failure_names_the_cause():
    exc = _raise_from(httpx.ConnectError("[Errno -2] Name or service not known"),
                      socket.gaierror(-2, "Name or service not known"))
    out = transport_detail(exc)
    assert "ConnectError" in out
    assert "Name or service not known" in out


def test_tls_verification_failure_is_visible_even_with_empty_outer_message():
    """httpx 把握手期的 SSL 錯誤包成 ConnectError，外層訊息可能是空的。"""
    exc = _raise_from(
        httpx.ConnectError(""),
        ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"),
    )
    out = transport_detail(exc)
    assert "CERTIFICATE_VERIFY_FAILED" in out, "憑證問題必須看得出來，否則會被當成網路不通"


def test_connection_refused_differs_from_dns_failure():
    dns = transport_detail(_raise_from(httpx.ConnectError("[Errno -2] Name or service not known"),
                                       socket.gaierror(-2, "Name or service not known")))
    refused = transport_detail(_raise_from(httpx.ConnectError("[Errno 111] Connection refused"),
                                           ConnectionRefusedError(111, "Connection refused")))
    assert dns != refused


def test_message_is_bounded():
    exc = httpx.ConnectError("x" * 5000)
    assert len(transport_detail(exc)) <= 200, "這串會存進 last_error 並顯示在表格裡"


def test_no_cause_still_returns_something_useful():
    assert transport_detail(httpx.ConnectTimeout("timed out")) == "ConnectTimeout: timed out"
    assert transport_detail(httpx.ConnectError("")) == "ConnectError"
