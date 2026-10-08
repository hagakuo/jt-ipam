"""IP 的「建議建立／關聯裝置」：只給建議，按了才動手。

由來：DHCP 的筆電會散在十幾個 IP 上（同一個主機名稱、不同位址）。每一筆都手動建裝置、
手動關聯是純粹的苦工 —— 但要不要建立仍然是人決定，系統只負責把答案端到面前。

這裡守的是三件容易做錯的事：
1. **建議不可以有副作用**：GET 過之後資料庫不能有任何改變。
2. **對到多台就不猜**：同名裝置有兩台時不給建議（與 `ip_device_link` 的規則一致）。
3. **可見性要推進 SQL**：「還有幾筆同名 IP」不可以算進使用者看不到的資料。
"""

from __future__ import annotations

import inspect

from app.api.v1.endpoints import addresses


def _src(name: str) -> str:
    fn = getattr(addresses, name)
    return inspect.getsource(fn)


def test_suggestion_endpoint_exists_and_is_read_only():
    src = _src("device_suggestion")
    assert 'required="read"' in src or '"read"' in src, "建議端點沒有做讀取權限檢查"
    for writer in ("session.add(", "session.commit(", "append_audit(", "log_change("):
        assert writer not in src, (
            f"建議端點裡出現 {writer} —— 這支是「只給建議」，不可以有副作用"
        )


def test_suggestion_refuses_to_guess_when_several_devices_match():
    """同名裝置有多台時不給建議。猜錯的關聯比沒有關聯更難發現。"""
    src = _src("device_suggestion")
    assert "limit(2)" in src, "沒有多取一筆來判斷「是不是不只一台」"
    assert "len(row) == 1" in src, "沒有『只有一台才採用』的判斷"


def test_sibling_list_is_scoped_to_what_the_user_can_see():
    src = _src("_sibling_rows")
    assert "visible_ids(" in src, "同名 IP 的清單沒有套可見性"
    # 可見範圍用單一陣列參數（in_values）：部門帳號看得到超過 32767 個子網路時 .in_() 會超過參數上限
    assert "in_values(IPAddress.subnet_id, vis)" in src, "可見性沒有推進 SQL（先取再過濾會算錯）"
    assert "device_id.is_(None)" in src, "把已經有裝置的 IP 也算進去了"


def test_siblings_are_candidates_with_evidence_not_a_blanket_switch():
    """同主機名稱**不等於**同一台機器。

    實機（2026-08-30）：一台筆電的名字散在九筆 IP 上，裡面有 Proxmox 的 VM
    （`bc:24:11` 開頭）和一顆 ESP32（`48:3f:da`）。DHCP 把位址回收給別台之後，
    IP 記錄上的舊主機名稱還留著 —— 所以「全部掛上」的開關是把猜測當成事實。
    正確作法是把候選與**證據（MAC、廠商）**攤開，由人逐筆決定。
    """
    src = _src("device_suggestion")
    assert "same_mac" in src, "候選沒有標示 MAC 是否相同 —— 那是唯一夠強的線索"
    assert "mac_vendor" in src, "候選沒有附上廠商，使用者無從判斷"
    apply_src = _src("apply_device_suggestion")
    assert "link_siblings" not in apply_src, (
        "還留著「全部同名 IP 一起掛」的開關 —— 同名不足以認定是同一台機器"
    )
    assert "link_ip_ids" in apply_src, "沒有改成逐筆指定要關聯哪些 IP"


def test_apply_does_not_trust_the_ids_from_the_client():
    """客戶端送來的 id 要以伺服器自己算出來的集合為準，不能直接照單全收。"""
    src = _src("apply_device_suggestion")
    assert "allowed" in src and "not in allowed" in src, (
        "沒有把客戶端指定的 IP 與「這個使用者能寫、且確實同名未關聯」的集合取交集"
    )


def test_apply_requires_write_and_admin_for_creation():
    src = _src("apply_device_suggestion")
    assert '"write"' in src, "套用端點沒有要求寫入權限"
    assert "user.is_admin" in src, (
        "建立裝置沒有限定管理員 —— POST /devices 是 require_admin，這條捷徑不能比它寬鬆"
    )


def test_apply_never_overwrites_an_existing_link():
    """既有關聯永不覆寫 —— 與 ip_device_link 的第一條規則一致。"""
    src = _src("apply_device_suggestion")
    assert "obj.device_id is None" in src, "沒有檢查『這個 IP 已經有裝置』"
    assert "sib.device_id is not None" in src, "批次關聯時沒有跳過已經有裝置的 IP"


def test_apply_writes_history_and_audit():
    src = _src("apply_device_suggestion")
    assert "log_change(" in src, "沒有寫 IP 異動記錄，事後查不出誰把它接上去的"
    assert "append_audit(" in src, "沒有寫稽核記錄"


def test_apply_is_either_or():
    """關聯既有／建立新的必須二擇一，兩個都給或都不給要擋下來。"""
    src = _src("apply_device_suggestion")
    assert "bool(payload.device_id) == bool(payload.create_name)" in src, (
        "沒有擋下『兩個都填』或『兩個都沒填』"
    )
