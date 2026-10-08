"""沒有分割 VDOM 的 FortiGate 也要能用（GitHub issue #26）。

使用者回報：「工具是否只支援有分割 VDOM 的 FortiGate？沒有分割會不會異常？」

檢查程式後的結論是**不需要 VDOM**，但我們原本有一個「用猜的」環節：問不到 VDOM 清單時
退回 `["root"]`，等於把一個猜來的名字塞進**每一支請求**。沒開 VDOM 的機器上 root 通常是
對的，但那是巧合不是保證 —— 一旦某個韌體版本不吃這個參數，壞掉的會是全部端點，
而畫面上只有一排看不出共同原因的錯誤。

改成：先問裝置自己的 `vdom-mode`，`no-vdom` 或問不到就**不帶 vdom 參數**。
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from app.services import fortigate as svc


def _fw(**kw: Any) -> Any:
    base = {"id": uuid.uuid4(), "name": "fgt", "api_url": "https://192.0.2.9",
            "verify_tls": False, "vdoms": None, "scope_subnet_ids": None}
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.mark.anyio
async def test_no_vdom_device_gets_no_vdom_parameter(monkeypatch: Any) -> None:
    """裝置說 `no-vdom` → 一支請求都不要帶 vdom。"""
    async def fake_get(fw: Any, path: str, **kw: Any) -> Any:
        assert path == svc.EP_GLOBAL, f"問過 vdom-mode 就不該再去列 VDOM（{path}）"
        return [{"vdom-mode": "no-vdom"}]

    monkeypatch.setattr(svc, "_api_get", fake_get)
    assert await svc.list_vdoms(_fw()) == [svc.NO_VDOM]


@pytest.mark.anyio
async def test_an_unreadable_vdom_list_does_not_become_a_guess(monkeypatch: Any) -> None:
    """權限不足／韌體沒有這支端點 → 不指定範圍，而不是猜 `root`。"""
    async def fake_get(fw: Any, path: str, **kw: Any) -> Any:
        raise svc.FortiGateError("403 拒絕存取")

    monkeypatch.setattr(svc, "_api_get", fake_get)
    assert await svc.list_vdoms(_fw()) == [svc.NO_VDOM]


@pytest.mark.anyio
async def test_multi_vdom_device_still_enumerates(monkeypatch: Any) -> None:
    async def fake_get(fw: Any, path: str, **kw: Any) -> Any:
        if path == svc.EP_GLOBAL:
            return [{"vdom-mode": "multi-vdom"}]
        return [{"name": "root"}, {"name": "guest"}]

    monkeypatch.setattr(svc, "_api_get", fake_get)
    assert await svc.list_vdoms(_fw()) == ["root", "guest"]


@pytest.mark.anyio
async def test_explicitly_configured_vdoms_win(monkeypatch: Any) -> None:
    """使用者填了就照填的來，連問都不用問。"""
    async def fake_get(fw: Any, path: str, **kw: Any) -> Any:
        raise AssertionError("不該打 API")

    monkeypatch.setattr(svc, "_api_get", fake_get)
    assert await svc.list_vdoms(_fw(vdoms=["vd1", "vd2"])) == ["vd1", "vd2"]


@pytest.mark.anyio
async def test_empty_vdom_is_omitted_from_the_request(monkeypatch: Any) -> None:
    """保留值要真的讓 `_api_get` 省略參數，不是送出 `vdom=`。"""
    import inspect
    src = inspect.getsource(svc._api_get)
    assert 'params = {"vdom": vdom} if vdom else None' in src
    assert svc.NO_VDOM == ""


def test_places_that_write_the_vdom_into_data_use_a_label() -> None:
    """空字串可以當「不指定範圍」，但不能變成資料裡的空白欄位。

    通道名會變成 `fw/ipsec//tunnel`、NAT 的 external_id 會變成 `:name`、
    唯讀檢視的 VDOM 篩選會多一個空白選項 —— 都是看得到卻說不出原因的怪狀。
    """
    import inspect
    assert svc.vdom_label("") == "root"
    assert svc.vdom_label("guest") == "guest"
    for fn in (svc.sync_vpn, svc.sync_nat, svc.sync_policies, svc.sync_addresses,
               svc.sync_dhcp_ranges):
        src = inspect.getsource(fn)
        assert "vdom_label(vdom)" in src, f"{fn.__name__} 仍直接把 vdom 寫進資料"


@pytest.mark.anyio
async def test_diagnosis_retries_without_vdom_and_says_so(monkeypatch: Any) -> None:
    """帶 VDOM 失敗、不帶就成功 → 診斷要講出這件事，這才是可行動的資訊。"""
    calls: list[Any] = []

    async def fake_get(fw: Any, path: str, *, vdom: Any = None, **kw: Any) -> Any:
        calls.append((path, vdom))
        if path == svc.EP_GLOBAL:
            return [{"vdom-mode": "multi-vdom"}]
        if path == svc.EP_VDOMS:
            return [{"name": "vd1"}]
        if vdom:
            raise svc.FortiGateError("400 bad vdom")
        return [{"x": 1}]

    monkeypatch.setattr(svc, "_api_get", fake_get)
    out = await svc.diagnose(_fw())
    assert out["vdom_scoped"] is True
    assert all(c["ok"] for c in out["checks"])
    assert all(c.get("without_vdom") for c in out["checks"])
    assert "400 bad vdom" in out["checks"][0]["vdom_error"]
