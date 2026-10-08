"""issue #45：獨立的 ISC DHCP Server（isc-dhcp-server）—— 由裝在 DHCP 主機上的掃描代理讀本機的
dhcpd.conf 與 dhcpd.leases，解析後只回報結構化資料（範圍、固定分配、租約）。

ISC dhcpd 沒有能列出全部租約的 API（OMAPI 只能逐筆查），只能讀檔。
dhcpd.conf 裡常有 DDNS／OMAPI 金鑰：解析器只取範圍與 host，其他區塊（key、zone、failover…）一律不碰，
回報裡不可以出現原文。
"""
from __future__ import annotations

import importlib.util
import pathlib
import uuid
from datetime import UTC, datetime

_AGENT = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_agent.py"


def _agent():
    spec = importlib.util.spec_from_file_location(f"jt_agent_dhcpd_{uuid.uuid4().hex[:6]}", _AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


CONF = r'''
# 全域設定
option domain-name "example.test";
key "ddns-key" {
  algorithm hmac-sha256;
  secret "c2VjcmV0LXRoYXQtbXVzdC1uZXZlci1sZWF2ZQ==";
}
omapi-key ddns-key;

subnet 192.0.2.0 netmask 255.255.255.0 {
  range 192.0.2.100 192.0.2.150;
  range dynamic-bootp 192.0.2.200 192.0.2.210;
  option routers 192.0.2.1;
  host printer-1 {
    hardware ethernet 00:00:5E:00:53:01;
    fixed-address 192.0.2.5;
    option host-name "printer-1.example.test";
  }
}

shared-network campus {
  subnet 198.51.100.0 netmask 255.255.255.128 {
    pool {
      failover peer "dhcp-failover";
      range 198.51.100.10 198.51.100.20;
    }
    range 198.51.100.30;           # 單一位址的範圍
  }
}

group {
  host nas { hardware ethernet 00:00:5e:00:53:02; fixed-address 198.51.100.50, 198.51.100.51; }
  host by-name { hardware ethernet 00:00:5e:00:53:03; fixed-address nas.example.test; }
}

include "extra.conf";
'''

EXTRA = '''
subnet 203.0.113.0 netmask 255.255.255.0 {
  range 203.0.113.10 203.0.113.99;
}
'''


def test_conf_ranges_hosts_and_includes() -> None:
    a = _agent()
    loaded: list[str] = []

    def loader(path: str) -> str | None:
        loaded.append(path)
        return EXTRA if path == "extra.conf" else None

    got = a._dhcpd_parse_conf(CONF, loader)
    assert got["pools"] == [
        {"subnet": "192.0.2.0/24", "start": "192.0.2.100", "end": "192.0.2.150"},
        {"subnet": "192.0.2.0/24", "start": "192.0.2.200", "end": "192.0.2.210"},
        {"subnet": "198.51.100.0/25", "start": "198.51.100.10", "end": "198.51.100.20"},
        {"subnet": "198.51.100.0/25", "start": "198.51.100.30", "end": "198.51.100.30"},
        {"subnet": "203.0.113.0/24", "start": "203.0.113.10", "end": "203.0.113.99"},
    ]
    assert got["reservations"] == [
        {"ip": "192.0.2.5", "mac": "00:00:5e:00:53:01", "hostname": "printer-1.example.test"},
        {"ip": "198.51.100.50", "mac": "00:00:5e:00:53:02", "hostname": "nas"},
        {"ip": "198.51.100.51", "mac": "00:00:5e:00:53:02", "hostname": "nas"},
    ], "fixed-address 寫主機名稱的（要靠 DNS 才知道位址）不收"
    assert loaded == ["extra.conf"]
    assert "c2VjcmV0" not in repr(got), "金鑰不可以出現在回報裡"


def test_includes_do_not_loop_forever() -> None:
    a = _agent()
    got = a._dhcpd_parse_conf('include "self.conf";', lambda p: 'include "self.conf";')
    assert got["pools"] == [] and got["reservations"] == []


LEASES = '''
# The format of this file is documented in the dhcpd.leases(5) manual page.
authoring-byte-order little-endian;
server-duid "\\000\\001\\000\\001";

lease 192.0.2.101 {
  starts 1 2026/09/28 01:00:00;
  ends 1 2026/09/28 13:00:00;
  cltt 1 2026/09/28 01:00:00;
  binding state active;
  next binding state free;
  hardware ethernet 00:00:5e:00:53:11;
  uid "\\001\\000\\000^\\000S\\021";
  client-hostname "laptop-11";
}
lease 192.0.2.102 {
  starts 1 2026/09/28 01:00:00;
  ends 1 2026/09/28 02:00:00;
  binding state active;
  hardware ethernet 00:00:5e:00:53:12;
}
lease 192.0.2.103 {
  starts 1 2026/09/28 01:00:00;
  ends 1 2026/09/28 13:00:00;
  binding state active;
  hardware ethernet 00:00:5e:00:53:13;
}
lease 192.0.2.103 {
  starts 1 2026/09/28 03:00:00;
  ends 1 2026/09/28 03:00:00;
  binding state free;
  hardware ethernet 00:00:5e:00:53:13;
}
lease 192.0.2.104 {
  starts 1 2026/09/28 01:00:00;
  ends never;
  binding state active;
  hardware ethernet 00:00:5e:00:53:14;
}
lease 192.0.2.105 {
  starts epoch 1790550000; # Mon Sep 28 ...
  ends epoch 1790600000;
  binding state active;
  hardware ethernet 00:00:5e:00:53:15;
}
host dyn-cam {
  dynamic;
  hardware ethernet 00:00:5e:00:53:21;
  fixed-address 192.0.2.60;
}
host dyn-old {
  dynamic;
  hardware ethernet 00:00:5e:00:53:22;
  fixed-address 192.0.2.61;
}
host dyn-old {
  dynamic;
  deleted;
}
'''


def test_leases_journal_last_entry_wins_and_only_active_ones_count() -> None:
    a = _agent()
    now = datetime(2026, 9, 28, 4, 0, tzinfo=UTC)
    got = a._dhcpd_parse_leases(LEASES, now=now)
    ips = [x["ip"] for x in got["leases"]]
    assert ips == ["192.0.2.101", "192.0.2.104", "192.0.2.105"], \
        ".102 已過期、.103 最後一筆是 free（檔案是日誌，後面的蓋前面的）"
    first = got["leases"][0]
    assert first["mac"] == "00:00:5e:00:53:11"
    assert first["hostname"] == "laptop-11"
    assert first["ends"] == "2026-09-28T13:00:00+00:00"
    assert got["leases"][1]["ends"] is None, "ends never＝沒有到期時間"
    # OMAPI 動態新增的 host（寫在租約檔裡）算固定分配；後來被刪掉的不算
    assert got["reservations"] == [{"ip": "192.0.2.60", "mac": "00:00:5e:00:53:21", "hostname": "dyn-cam"}]


def test_collect_reads_local_files_and_reports_file_status(tmp_path) -> None:
    a = _agent()
    conf = tmp_path / "dhcpd.conf"
    conf.write_text(CONF.replace('include "extra.conf";', f'include "{tmp_path / "extra.conf"}";'))
    (tmp_path / "extra.conf").write_text(EXTRA)
    leases = tmp_path / "dhcpd.leases"
    leases.write_text(LEASES)
    got = a._dhcpd_collect(str(conf), str(leases), now=datetime(2026, 9, 28, 4, 0, tzinfo=UTC))
    assert len(got["pools"]) == 5 and len(got["reservations"]) == 4 and len(got["leases"]) == 3
    assert got["files"]["conf"]["ok"] is True and got["files"]["leases"]["ok"] is True
    assert "c2VjcmV0" not in repr(got)

    missing = a._dhcpd_collect(str(tmp_path / "nope.conf"), str(leases))
    assert missing["files"]["conf"]["ok"] is False
    assert missing["files"]["conf"]["error"]
    assert missing["pools"] == []


def test_agent_reads_dhcpd_only_when_the_server_assigns_a_source(monkeypatch) -> None:
    """沒有 ISC DHCP 來源指到這台代理時，代理完全不碰 dhcpd 檔；有的話依間隔回報、不重疊。"""
    a = _agent()
    started: list[str] = []

    class FakeThread:
        def __init__(self, target, args=(), name=None, daemon=None):  # noqa: ANN001
            self.args = args

        def start(self) -> None:
            started.append(self.args[0])

    monkeypatch.setattr(a.threading, "Thread", FakeThread)
    a._dhcpd_maybe_report(None, 1000.0)
    a._dhcpd_maybe_report({}, 1000.0)
    assert started == []
    a._dhcpd_maybe_report({"source_id": "s-1", "interval_seconds": 300}, 1000.0)
    assert started == ["s-1"]
    a._dhcpd_maybe_report({"source_id": "s-1", "interval_seconds": 300}, 1100.0)
    assert started == ["s-1"], "上一次還在跑就不要再開一個"
    a._DHCPD_STATE["running"] = False
    a._dhcpd_maybe_report({"source_id": "s-1", "interval_seconds": 300}, 1200.0)
    assert started == ["s-1"], "還沒到間隔"
    a._dhcpd_maybe_report({"source_id": "s-1", "interval_seconds": 300}, 1301.0)
    assert started == ["s-1", "s-1"]


# 真的 isc-dhcpd 4.4.3-P1 寫出來的租約檔（2026-09-29 以容器實測產生；位址／MAC 換成文件用範圍）
REAL_LEASES = r'''# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-4.4.3-P1

# authoring-byte-order entry is generated, DO NOT DELETE
authoring-byte-order little-endian;

server-duid "\000\001\000\0012M\340\2276\244t\013\273\375";

lease 198.18.52.100 {
  starts 2 2026/09/29 02:36:13;
  ends 2 2026/09/29 02:46:13;
  cltt 2 2026/09/29 02:36:13;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 00:00:5e:00:53:61;
  uid "\001\000\000^\000Sa";
  set vendor-class-identifier = "udhcp 1.38.0";
  client-hostname "isc-client-61";
}
'''


def test_a_real_dhcpd_lease_file_parses() -> None:
    a = _agent()
    got = a._dhcpd_parse_leases(REAL_LEASES, now=datetime(2026, 9, 29, 2, 40, tzinfo=UTC))
    assert got["leases"] == [{"ip": "198.18.52.100", "mac": "00:00:5e:00:53:61", "hostname": "isc-client-61",
                              "ends": "2026-09-29T02:46:13+00:00"}]
