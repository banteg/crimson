from __future__ import annotations

from crimson.screens.panels.credits import (
    _FLAG_CLICKED,
    _credits_all_round_lines_flagged,
    _credits_line_clear_flag,
    _CreditsLine,
)


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
