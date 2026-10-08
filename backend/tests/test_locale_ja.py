"""日本語ロケールの守門テスト。

UI に言語を足すだけでは足りない。`user_preferences.locale` には CHECK 制約があり、
そこに新しい値を追加し忘れると、利用者が日本語を選んだ瞬間に保存が
IntegrityError で落ちる —— 画面には「保存に失敗しました」としか出ないので、
原因が制約だとは誰にも分からない。

それから、LLM へ「この言語で答えよ」と指示する対応表。ここに ja-JP が無いと
エラーにはならず、UI は日本語なのに AI の回答だけ中国語になる。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import Locale
from app.schemas.preferences import UserPreferenceUpdate
from app.services import ai, ai_audit

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"

LOCALES = ("zh-TW", "en-US", "ja-JP")


def test_config_locale_type_lists_every_locale() -> None:
    assert set(Locale.__args__) == set(LOCALES)


@pytest.mark.parametrize("locale", LOCALES)
def test_preferences_schema_accepts(locale: str) -> None:
    assert UserPreferenceUpdate(locale=locale).locale == locale


def test_preferences_schema_rejects_unknown() -> None:
    with pytest.raises(Exception):
        UserPreferenceUpdate(locale="de-DE")


def test_db_check_constraint_allows_every_locale() -> None:
    """モデル側の CHECK と、実際に適用されるマイグレーションの両方を見る。

    片方だけ直しても pytest は緑のまま通ってしまい、本番でだけ落ちる。
    """
    from app.models.user import UserPreference

    checks = [
        c for c in UserPreference.__table__.constraints
        if getattr(c, "sqltext", None) is not None and "locale" in str(c.sqltext)
    ]
    assert checks, "user_preferences に locale の CHECK 制約が無い"
    text = str(checks[0].sqltext)
    for loc in LOCALES:
        assert loc in text, f"モデルの CHECK 制約に {loc} が無い"

    migration = (Path(__file__).resolve().parents[1]
                 / "alembic" / "versions" / "0139_locale_ja.py").read_text(encoding="utf-8")
    for loc in LOCALES:
        assert loc in migration, f"マイグレーション 0139 に {loc} が無い"


@pytest.mark.parametrize("locale", LOCALES)
def test_llm_language_instruction_covers_locale(locale: str) -> None:
    """UI が日本語なのに AI だけ中国語で答える、という食い違いを防ぐ。"""
    assert locale in ai._LANG_MAP, f"ai.py の言語対応表に {locale} が無い"
    assert locale in ai_audit._LANGUAGES, f"ai_audit.py の言語対応表に {locale} が無い"


@pytest.mark.parametrize("locale", LOCALES)
def test_locale_file_exists_and_matches_keys(locale: str) -> None:
    path = FRONTEND / "src" / "i18n" / f"{locale}.json"
    assert path.exists(), f"{path} が無い"

    def flatten(obj: dict, prefix: str = "") -> set[str]:
        out: set[str] = set()
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            out |= flatten(v, key) if isinstance(v, dict) else {key}
        return out

    base = flatten(json.loads((FRONTEND / "src" / "i18n" / "zh-TW.json").read_text(encoding="utf-8")))
    here = flatten(json.loads(path.read_text(encoding="utf-8")))
    assert here == base, f"{locale} のキー集合が zh-TW と一致しない（差分 {len(here ^ base)} 件）"
