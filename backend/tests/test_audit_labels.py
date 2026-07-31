"""稽核「目標」欄的標籤解析。

客戶實測 FortiGate 時發現：整合的稽核列只顯示截斷 UUID（`a1b2c3d4…`），
多台同型整合時完全分不出是哪一台在同步。根因是 `_LABEL_REGISTRY` 只登錄了
14 種物件型別，所有整合實例都不在其中。
"""

from __future__ import annotations

import importlib

from app.api.v1.endpoints.audit import _LABEL_REGISTRY


def test_registry_entries_all_resolve() -> None:
    """每一條登錄都要真的指得到 model 與欄位（打錯字會被 except 吞掉、變回 UUID）。"""
    broken = []
    for otype, (module_path, cls_name, attr) in _LABEL_REGISTRY.items():
        try:
            model = getattr(importlib.import_module(module_path), cls_name)
        except (ImportError, AttributeError) as exc:
            broken.append(f"{otype}: {type(exc).__name__} {exc}")
            continue
        if not hasattr(model, attr):
            broken.append(f"{otype}: {cls_name}.{attr} 不存在")
    assert not broken, f"這些登錄解析不到：{broken}"


def test_every_integration_instance_type_is_registered() -> None:
    """新增整合時很容易忘了登錄 → 稽核頁就退回顯示 UUID。這裡釘住。"""
    required = {
        "fortigate_firewall", "pfsense_firewall", "opnsense_firewall",
        "librenms_instance", "wazuh_instance", "adguard_instance",
        "windows_dhcp_server", "proxmox_instance", "dns_server",
        "scan_agent", "cert_agent", "certificate",
    }
    missing = sorted(required - set(_LABEL_REGISTRY))
    assert not missing, f"這些整合型別沒登錄，稽核「目標」會顯示 UUID：{missing}"
