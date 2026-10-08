"""LLM へ渡す「回答の言語」の指示が、利用者の UI 言語に追従することの守門テスト。

なぜ必要か：言語の判定はかつて入口ごとにばらばらだった。調査ウィンドウは
`lang.startswith("zh")` の二分法（日本語の利用者は英語を受け取る）、判読カードと
ルール変更の解読はプロンプト本体が中国語固定（**英語の利用者まで中国語**）。
日本語を足したときも、この三か所は誰も直さなかった。しかもエラーは出ない。
答えの言語が違うだけなので、テストが無ければ次に言語を足すときも同じことが起きる。
"""
from __future__ import annotations

import inspect

import pytest

from app.services import ai, fw_review, ip_triage

LOCALES = ("zh-TW", "en-US", "ja-JP")


@pytest.mark.parametrize("locale", LOCALES)
def test_lang_map_covers_every_ui_locale(locale: str) -> None:
    assert locale in ai._LANG_MAP, f"_LANG_MAP に {locale} が無い"


def test_answer_language_is_the_single_source() -> None:
    """文字を LLM へ渡すすべての入口が、同じ一つのヘルパーを通ること。

    ここを増やすときは answer_language() を呼ぶこと。呼ばなければ、その機能だけ
    別の言語で答えるようになる —— そして誰も気づかない。
    """
    for mod, what in (
        (ip_triage, "未許可 IP の判読カード"),
        (fw_review, "ファイアウォールのルール変更の解読"),
    ):
        src = inspect.getsource(mod)
        assert "answer_language" in src, f"{what} が answer_language を使っていない"

    from app.api.v1.endpoints import investigate

    src = inspect.getsource(investigate)
    assert src.count("answer_language") >= 2, "調査ウィンドウは通常版と串流版の両方で必要"


@pytest.mark.parametrize("locale", LOCALES)
def test_answer_language_names_the_locale(locale: str) -> None:
    """指示文に、その言語の名前が実際に入ること。"""
    name = ai._LANG_MAP[locale]
    # answer_language は DB を引くので、ここでは組み立て部分だけを確認する
    assert name, f"{locale} の言語名が空"
    assert ai._lang_instruction(locale).find(name) > 0


def test_unknown_locale_does_not_force_a_language() -> None:
    """未知のロケールで中国語を押し付けない（以前の既定はそうなっていた）。"""
    out = ai._lang_instruction("de-DE")
    assert "same language as the user" in out
