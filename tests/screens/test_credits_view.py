from __future__ import annotations

from crimson.screens.actions import Route
from crimson.screens.assets import require_runtime_resources
from crimson.screens.panels.credits import (
    _FLAG_CLICKED,
    CreditsView,
    _credits_all_round_lines_flagged,
    _credits_line_clear_flag,
    _CreditsLine,
)
from tests.support.screens import finish_transition


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


def test_secret_path_takes_every_round_line_with_the_full_names(loop) -> None:
    loop.navigation.navigate(Route.CREDITS)
    finish_transition(loop)
    credits = loop.state.screens.active
    assert isinstance(credits, CreditsView)

    # The exe stores the Finnish names in cp1252 and Grim maps each byte to its own small-font cell.
    font = require_runtime_resources(loop.state).small_font
    texts = [line.text for line in credits._lines if line.text]
    assert all(font.widths[byte] for text in texts for byte in text.encode("cp1252"))
    assert {"Petri Järvilehto / Remedy", "Valtteri Pihlajamäki", "Ville Mäntylä"} <= set(texts)

    round_lines = [index for index, line in enumerate(credits._lines) if "o" in line.text]
    assert len(round_lines) == 37
    for index in round_lines:
        assert not credits._secret_unlock
        credits._click_line(index)
        loop.update(0.016)
    assert credits._secret_unlock
