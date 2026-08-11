"""判讀之前，先把「這台在扮演什麼角色」算出來給模型。

實機回報：一台反向代理主機有 20 筆 A 記錄指向它，AI 判讀把這件事講成「DNS 記錄與
主機名稱來源之間存在顯著的矛盾」。**那不是模型的錯** —— 我們送過去的只是一串域名，
沒有任何訊號說「多個域名指向同一個位址對反向代理是正常的」，而提示詞又特別要求它
「指出矛盾」。於是它照做了，只是指錯了地方。

要修的是我們這端：把可以從事實算出來的角色訊號先算好，並在提示詞裡寫明哪些樣態
是常態、不要當成矛盾。
"""
from __future__ import annotations

from app.services.investigate import infer_role_hints


def _dossier(**kw):
    base = {"found": True, "ip": "192.0.2.10", "hostname": "revproxy1",
            "dns": [], "nat": [], "firewall": [], "arp": [], "hostname_sources": []}
    base.update(kw)
    return base


def test_many_names_on_one_address_is_recognised_as_a_shared_entry_point():
    d = _dossier(dns=[{"rtype": "A", "name": f"n{i}.example.com"} for i in range(20)])
    hints = infer_role_hints(d)
    assert any("reverse proxy" in h.lower() or "shared" in h.lower() for h in hints)
    assert any("20" in h for h in hints)


def test_a_single_name_is_not_called_a_reverse_proxy():
    """一個域名就是一台普通主機 —— 不能因為有 DNS 記錄就亂貼標籤。"""
    assert not any("proxy" in h.lower()
                   for h in infer_role_hints(_dossier(dns=[{"rtype": "A", "name": "a.example.com"}])))


def test_web_ports_forwarded_from_outside_is_flagged():
    d = _dossier(nat=[{"port": 443, "protocol": "tcp"}, {"port": 80, "protocol": "tcp"}])
    assert any("80" in h or "443" in h for h in infer_role_hints(d))


def test_hints_are_facts_not_verdicts():
    """訊號只描述觀察到的樣態，不下「安全 / 不安全」或「設定錯誤」的判斷。"""
    d = _dossier(dns=[{"rtype": "A", "name": f"n{i}.example.com"} for i in range(30)],
                 nat=[{"port": 443}])
    joined = " ".join(infer_role_hints(d)).lower()
    for word in ("insecure", "misconfigur", "should ", "risk"):
        assert word not in joined


def test_no_signal_means_no_hint():
    assert infer_role_hints(_dossier()) == []


def test_the_prompt_tells_the_model_not_to_report_normal_patterns_as_contradictions():
    """光算出訊號還不夠 —— 提示詞本來就寫著「特別指出矛盾」，得同時告訴它哪些不是。"""
    from app.api.v1.endpoints.investigate import _prompt
    d = _dossier(dns=[{"rtype": "A", "name": f"n{i}.example.com"} for i in range(20)])
    zh = _prompt(d, "zh-TW")
    assert "角色訊號" in zh
    assert "反向代理" in zh
    assert "不要當成矛盾" in zh
    en = _prompt(d, "en-US")
    assert "Role signals" in en and "reverse proxy" in en.lower()


def test_a_plain_host_gets_no_role_signal_block():
    from app.api.v1.endpoints.investigate import _prompt
    assert "角色訊號" not in _prompt(_dossier(), "zh-TW")
