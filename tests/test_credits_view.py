from __future__ import annotations

from crimson.frontend.panels.credits import (
    _CREDITS_SECRET_LINES,
    _FLAG_CLICKED,
    _FLAG_HEADING,
    _CreditsLine,
    _credits_all_round_lines_flagged,
    _credits_build_lines,
    _credits_line_clear_flag,
    _credits_unlock_secret_lines,
)


def test_credits_build_lines_sets_expected_core_entries() -> None:
    lines, line_max_index, secret_base_index = _credits_build_lines()

    assert line_max_index == 0x7D
    assert secret_base_index == 0x54
    assert lines[0x01].text == "Crimsonland"
    assert lines[0x01].flags == _FLAG_HEADING
    assert lines[0x57].text == "You can stop watching now."
    assert lines[0x77].text == "Click the ones with the round ones!"


def test_credits_build_lines_keeps_repeated_index_behavior_from_decompile() -> None:
    lines, _, _ = _credits_build_lines()
    assert lines[0x42].text == ""


def test_credits_line_clear_flag_clears_last_flagged_line_before_index() -> None:
    lines = [_CreditsLine("x", 0) for _ in range(6)]
    lines[1].flags = _FLAG_CLICKED
    lines[4].flags = _FLAG_CLICKED

    changed = _credits_line_clear_flag(lines, 3)

    assert changed is True
    assert (lines[1].flags & _FLAG_CLICKED) == 0
    assert (lines[4].flags & _FLAG_CLICKED) != 0


def test_credits_all_round_lines_flagged_requires_lowercase_o_lines() -> None:
    lines = [
        _CreditsLine("Alpha", 0),
        _CreditsLine("Omega", _FLAG_CLICKED),
        _CreditsLine("tool", 0),
        _CreditsLine("BETA", 0),
    ]

    assert _credits_all_round_lines_flagged(lines) is False

    lines[2].flags |= _FLAG_CLICKED
    assert _credits_all_round_lines_flagged(lines) is True


def test_credits_unlock_secret_lines_sets_flags_and_text() -> None:
    lines = [_CreditsLine("", 0) for _ in range(0x100)]
    base = 0x54

    _credits_unlock_secret_lines(lines, base)

    for idx, expected in enumerate(_CREDITS_SECRET_LINES):
        line = lines[base + idx]
        assert line.text == expected
        assert (line.flags & _FLAG_CLICKED) != 0
