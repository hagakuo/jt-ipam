"""測試只能有一個 event loop 的主人（2026-09-26）。

anyio 與 pytest-asyncio 兩個外掛同時在的時候，`@pytest.mark.anyio` 的測試由誰接手取決於外掛的
載入順序（site-packages 在檔案系統上的列舉順序，每台機器不同）。anyio 接手就用它自己的 loop，
共用連線池裡的 asyncpg 連線被帶到別的 loop，整套測試卡到逾時 —— 開發機綠、CI 紅，而且原因看不出來。
"""
from __future__ import annotations


def test_the_anyio_pytest_plugin_stays_off(pytestconfig) -> None:
    assert not pytestconfig.pluginmanager.has_plugin("anyio"), (
        "anyio 的 pytest 外掛被打開了：非同步測試會依外掛載入順序跑在不同的 event loop（見 pyproject 的 addopts）")
    assert pytestconfig.pluginmanager.has_plugin("asyncio")
