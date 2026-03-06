from __future__ import annotations

from crimson.typo.typing import TYPING_MAX_CHARS, TypingBuffer


def test_typing_buffer_backspace_and_max_len() -> None:
    buf = TypingBuffer()
    buf.backspace()
    assert buf.text == ""

    for _ in range(TYPING_MAX_CHARS + 10):
        buf.push_char("a")
    assert buf.text == "a" * TYPING_MAX_CHARS

    buf.backspace()
    assert buf.text == "a" * (TYPING_MAX_CHARS - 1)


def test_typing_buffer_enter_noop_on_empty() -> None:
    buf = TypingBuffer()
    result = buf.enter(find_target=lambda _: None)
    assert result.fire_requested is False
    assert result.reload_requested is False
    assert result.target_creature_idx is None
    assert buf.shots_fired == 0
    assert buf.shots_hit == 0


def test_typing_buffer_enter_fire_when_match() -> None:
    buf = TypingBuffer(text="alpha")
    result = buf.enter(find_target=lambda text: 7 if text == "alpha" else None)
    assert result.fire_requested is True
    assert result.reload_requested is False
    assert result.target_creature_idx == 7
    assert buf.text == ""
    assert buf.shots_fired == 1
    assert buf.shots_hit == 1


def test_typing_buffer_enter_reload_keyword() -> None:
    buf = TypingBuffer(text="reload")
    result = buf.enter(find_target=lambda _: None)
    assert result.fire_requested is False
    assert result.reload_requested is True
    assert result.target_creature_idx is None
    assert buf.text == ""
    assert buf.shots_fired == 1
    assert buf.shots_hit == 0

