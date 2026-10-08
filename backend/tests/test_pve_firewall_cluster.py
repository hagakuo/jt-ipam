"""PVE 防火牆的每一列都要說得出「這是哪一座叢集」。

由來（2026-09-03 使用者回報「這頁少了叢集欄位」）：防火牆分頁只顯示 VMID／節點，
多叢集時看不出 212 是哪一台的 212。

追下去發現不只是少一欄：**規則是只用 VMID 配對的**，兩座叢集有同號 guest 時，
另一座的規則會被算進來 —— 規則數與展開的內容都會是錯的。VMID 只在單一叢集內唯一。
"""

from __future__ import annotations

import inspect
from pathlib import Path

FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend"


def test_endpoint_returns_the_cluster_for_states_and_rules() -> None:
    from app.api.v1.endpoints.virt import pve_firewall

    src = inspect.getsource(pve_firewall)
    for field in ('"cluster": inst_names.get(s_.instance_id)',
                  '"cluster": inst_names.get(r.instance_id)'):
        assert field in src, f"回應少了 {field}"
    assert '"instance_id": str(s_.instance_id)' in src, \
        "沒有回 instance_id，前端就沒辦法把規則限定在同一座叢集"


def test_rules_are_matched_within_the_same_cluster() -> None:
    """只比 VMID 會把另一座叢集的規則混進來。"""
    src = (FRONTEND / "src" / "views" / "Virtualization.vue").read_text(encoding="utf-8")
    fn = src[src.index("function rulesForGuest"):src.index("const SCOPE_LABEL")]
    assert "instanceId" in fn, "rulesForGuest 沒有帶叢集，多叢集會配對錯"
    assert "r.instance_id === instanceId" in fn
    # 呼叫端也要真的把叢集傳進去
    assert "rulesForGuest(r.vmid, r.instance_id)" in src


def test_cluster_column_exists() -> None:
    src = (FRONTEND / "src" / "views" / "Virtualization.vue").read_text(encoding="utf-8")
    assert 'key: "cluster"' in src, "防火牆分頁沒有叢集欄位"
