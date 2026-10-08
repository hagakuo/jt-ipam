"""作業系統分類的顯示名稱要有三種語言（2026-10-06：日文介面的連線管理頁 OS 欄顯示英文「Network device」）。"""
from app.core.os_fingerprint import OS_FAMILIES, families_for_api


def test_every_os_family_has_three_labels() -> None:
    for key, labels in OS_FAMILIES.items():
        for lang in ("label_en", "label_zh", "label_ja"):
            assert (labels.get(lang) or "").strip(), f"{key} 少了 {lang}"


def test_api_carries_the_japanese_label() -> None:
    by_key = {f["key"]: f for f in families_for_api()}
    assert by_key["network"]["label_ja"] == "ネットワーク機器"
