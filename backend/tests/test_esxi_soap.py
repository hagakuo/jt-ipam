"""vSphere SOAP（VIM API）的封包組裝與回應解析。

刻意**不依賴 pyvmomi**：那會繞過 `safe_request`（SSRF 檢查、每次重導向重新驗 URL、
統一的 verify_tls），而本專案每一個對外整合都走那一層。只讀不寫的話，需要的呼叫其實
只有 RetrieveServiceContent / Login / CreateContainerView / RetrievePropertiesEx / Logout。

解析一律容錯：VMware 的回應在不同版本、不同授權（免費版 ESXi vs vCenter）之間欄位有無
差異很大 —— 關機的 VM 沒有 `guest.*`、沒裝 VMware Tools 的沒有 IP、範本沒有 runtime.host。
少一個欄位就整批失敗的話，一台有問題的 VM 會讓整個同步一無所獲。
"""
from __future__ import annotations

import pytest
from app.services import esxi

# ── 真實回應的形狀（節錄）。命名空間前綴刻意混用，因為實機兩種都出現過。
SERVICE_CONTENT = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:vim25="urn:vim25">
<soapenv:Body>
<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval>
  <rootFolder type="Folder">group-d1</rootFolder>
  <propertyCollector type="PropertyCollector">propertyCollector</propertyCollector>
  <viewManager type="ViewManager">ViewManager</viewManager>
  <about><name>VMware ESXi</name><version>8.0.2</version><apiVersion>8.0.2.0</apiVersion>
    <fullName>VMware ESXi 8.0.2 build-23305546</fullName></about>
  <sessionManager type="SessionManager">ha-sessionmgr</sessionManager>
</returnval></RetrieveServiceContentResponse>
</soapenv:Body></soapenv:Envelope>"""

VMS = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body>
<RetrievePropertiesExResponse xmlns="urn:vim25"><returnval>
  <objects>
    <obj type="VirtualMachine">vm-101</obj>
    <propSet><name>name</name><val xsi:type="xsd:string"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">web-01</val></propSet>
    <propSet><name>runtime.powerState</name><val>poweredOn</val></propSet>
    <propSet><name>config.hardware.numCPU</name><val>4</val></propSet>
    <propSet><name>config.hardware.memoryMB</name><val>8192</val></propSet>
    <propSet><name>config.template</name><val>false</val></propSet>
    <propSet><name>guest.hostName</name><val>web-01.example.test</val></propSet>
    <propSet><name>guest.ipAddress</name><val>198.51.100.21</val></propSet>
    <propSet><name>runtime.host</name><val type="HostSystem">host-9</val></propSet>
    <propSet><name>guest.net</name><val>
      <GuestNicInfo><macAddress>00:50:56:aa:bb:01</macAddress><network>VM Network</network>
        <ipAddress>198.51.100.21</ipAddress><connected>true</connected></GuestNicInfo>
      <GuestNicInfo><macAddress>00:50:56:aa:bb:02</macAddress>
        <ipAddress>198.51.100.22</ipAddress></GuestNicInfo>
    </val></propSet>
  </objects>
  <objects>
    <obj type="VirtualMachine">vm-102</obj>
    <propSet><name>name</name><val>db-01</val></propSet>
    <propSet><name>runtime.powerState</name><val>poweredOff</val></propSet>
  </objects>
  <objects>
    <obj type="VirtualMachine">vm-103</obj>
    <propSet><name>name</name><val>ubuntu-template</val></propSet>
    <propSet><name>config.template</name><val>true</val></propSet>
    <propSet><name>runtime.powerState</name><val>poweredOff</val></propSet>
  </objects>
</returnval></RetrievePropertiesExResponse>
</soapenv:Body></soapenv:Envelope>"""

PAGED = """<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body><RetrievePropertiesExResponse xmlns="urn:vim25"><returnval>
  <token>tok-1</token>
  <objects><obj type="VirtualMachine">vm-201</obj>
    <propSet><name>name</name><val>paged-1</val></propSet></objects>
</returnval></RetrievePropertiesExResponse></soapenv:Body></soapenv:Envelope>"""

FAULT = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body><soapenv:Fault>
  <faultcode>ServerFaultCode</faultcode>
  <faultstring>Cannot complete login due to an incorrect user name or password.</faultstring>
</soapenv:Fault></soapenv:Body></soapenv:Envelope>"""


def test_service_content_is_parsed():
    sc = esxi.parse_service_content(SERVICE_CONTENT)
    assert sc["sessionManager"] == "ha-sessionmgr"
    assert sc["propertyCollector"] == "propertyCollector"
    assert sc["viewManager"] == "ViewManager"
    assert sc["rootFolder"] == "group-d1"
    assert sc["about"]["version"] == "8.0.2"


def test_vms_are_parsed():
    vms, token = esxi.parse_vms(VMS)
    assert token is None
    by = {v["moid"]: v for v in vms}
    web = by["vm-101"]
    assert web["name"] == "web-01"
    assert web["power_state"] == "poweredOn"
    assert web["vcpus"] == 4
    assert web["memory_mb"] == 8192
    assert web["hostname"] == "web-01.example.test"
    assert web["ip"] == "198.51.100.21"
    assert web["host"] == "host-9"
    assert web["is_template"] is False


def test_nics_are_parsed_with_macs():
    vms, _ = esxi.parse_vms(VMS)
    web = next(v for v in vms if v["moid"] == "vm-101")
    assert [n["mac"] for n in web["nics"]] == ["00:50:56:aa:bb:01", "00:50:56:aa:bb:02"]
    assert web["nics"][0]["ips"] == ["198.51.100.21"]


def test_a_vm_missing_most_fields_still_parses():
    """關機的 VM 沒有 guest.*、沒裝 Tools 的沒有 IP。

    少一個欄位就整批失敗的話，一台有問題的 VM 會讓整個同步一無所獲 ——
    這正是這個專案在其他整合上踩過的形狀。
    """
    vms, _ = esxi.parse_vms(VMS)
    db = next(v for v in vms if v["moid"] == "vm-102")
    assert db["name"] == "db-01"
    assert db["power_state"] == "poweredOff"
    assert db["vcpus"] is None and db["ip"] is None and db["nics"] == []


def test_templates_are_flagged():
    vms, _ = esxi.parse_vms(VMS)
    tpl = next(v for v in vms if v["moid"] == "vm-103")
    assert tpl["is_template"] is True


def test_paging_token_is_returned():
    """vCenter 的清單會分頁；漏掉 token 就只會拿到第一批，而且完全不會報錯。"""
    vms, token = esxi.parse_vms(PAGED)
    assert token == "tok-1"
    assert len(vms) == 1


def test_soap_fault_becomes_a_readable_error():
    with pytest.raises(esxi.ESXiError) as exc:
        esxi.raise_for_fault(FAULT)
    assert "incorrect user name or password" in str(exc.value)


def test_no_fault_passes_through():
    esxi.raise_for_fault(VMS)      # 不該丟例外


def test_envelope_escapes_credentials():
    """密碼可能含 & < > —— 直接字串拼接會產生無效 XML 或被誤讀。"""
    body = esxi.build_login("ha-sessionmgr", "adm&in", "p<a>ss&word")
    assert "adm&amp;in" in body
    assert "p&lt;a&gt;ss&amp;word" in body
    assert "<password>p<" not in body


def test_envelope_has_the_vim_namespace():
    body = esxi.build_login("ha-sessionmgr", "u", "p")
    assert 'xmlns="urn:vim25"' in body
    assert "<_this type=\"SessionManager\">ha-sessionmgr</_this>" in body


# ─────────── VM 的 IP 要挑得對（實機回報）───────────

def test_a_link_local_address_is_not_the_vm_ip():
    """客戶回報：VMware 的 VM 抓到 `fe80::…`。

    鏈路本地位址（IPv6 fe80::/10、IPv4 169.254/16）在同一個網段之外沒有意義，
    當不了管理位址、也對不到 IPAM 裡的任何子網路。VMware Tools 在客體還沒拿到
    位址、或只有 IPv6 自動組態時就會回報這種位址。
    **寧可留白，也不要填一個沒有用的位址** —— 留白看得出「還沒拿到」，
    填了 fe80 只會讓人以為那就是它的位址。
    """
    assert esxi.pick_vm_ip(["fe80::a64b:c1bf:a707:5638"]) is None
    assert esxi.pick_vm_ip(["169.254.10.5"]) is None
    assert esxi.pick_vm_ip(["127.0.0.1", "::1"]) is None


def test_ipv4_wins_over_ipv6():
    """兩者都有時取 IPv4：IPAM 的子網路、NAT、防火牆規則絕大多數以 IPv4 表達。"""
    assert esxi.pick_vm_ip(["2001:db8::5", "198.51.100.20"]) == "198.51.100.20"


def test_a_real_ipv6_is_still_accepted_when_it_is_all_there_is():
    assert esxi.pick_vm_ip(["fe80::1", "2001:db8::5"]) == "2001:db8::5"


def test_garbage_and_blanks_are_ignored():
    assert esxi.pick_vm_ip(["", None, "not-an-ip", "198.51.100.7"]) == "198.51.100.7"
    assert esxi.pick_vm_ip([]) is None


def test_the_reported_case_a_windows_guest_with_both_addresses():
    """客戶實機（vSphere 畫面）：一台 Windows 客體同時有 IPv4 與 fe80，我們挑到了 fe80。

    VMware Tools 版本較舊時，`guest.ipAddress` 未必是那個有用的位址，NIC 清單的順序
    也不保證 IPv4 在前。所以兩條路徑都要走同一套挑選規則，不能其中一條沒過濾。
    """
    # guest.ipAddress 回鏈路本地（最壞情況），NIC 清單裡才有真正的 IPv4
    assert esxi.pick_vm_ip(["fe80::1a2b:3c4d:5e6f:7a8b",
                            "192.168.120.193"]) == "192.168.120.193"
    # 反過來，NIC 清單以 fe80 開頭也要挑對
    assert esxi.pick_vm_ip(["fe80::1a2b:3c4d:5e6f:7a8b", "fe80::2",
                            "192.168.120.193"]) == "192.168.120.193"


def test_the_port_group_is_captured():
    """VMware 沒有「橋接」，對應的是 port group。

    之前沒讀這個欄位，所以畫面上那一欄永遠空白 —— 而空白分不出「沒有這個資料」
    與「抓失敗」，使用者只能猜。
    """
    vms, _ = esxi.parse_vms(VMS)
    web = next(v for v in vms if v["moid"] == "vm-101")
    assert web["nics"][0]["network"] == "VM Network"
