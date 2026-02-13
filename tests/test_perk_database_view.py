from __future__ import annotations

from pathlib import Path
import random
import time
from typing import cast

import crimson.frontend.panels.databases as perk_db
from crimson.frontend.panels.databases import UnlockedPerksDatabaseView
from crimson.game.types import GameState
from crimson.persistence import save_status
from grim.config import CrimsonConfig, default_crimson_cfg_data
from grim.console import create_console
from grim.fonts.small import SmallFontData


def _make_state(tmp_path: Path) -> GameState:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"
    data = default_crimson_cfg_data()
    data["fx_toggle"] = 0
    config = CrimsonConfig(path=tmp_path / "game.cfg", data=data)
    return GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=random.Random(0),
        config=config,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=False,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=None,
        resource_paq=assets_dir / "crimson.paq",
        session_start=time.monotonic(),
    )


def test_selected_perk_id_uses_selected_row_index(tmp_path: Path) -> None:
    view = UnlockedPerksDatabaseView(_make_state(tmp_path))
    view._perk_ids = [1, 2, 4, 6]
    view._selected_row_index = 2
    assert view._selected_perk_id() == 4


def test_selected_perk_id_returns_none_for_out_of_range_row(tmp_path: Path) -> None:
    view = UnlockedPerksDatabaseView(_make_state(tmp_path))
    view._perk_ids = [1, 2, 4, 6]
    view._selected_row_index = 9
    assert view._selected_perk_id() is None


def test_hovered_perk_id_uses_hovered_row_index(tmp_path: Path) -> None:
    view = UnlockedPerksDatabaseView(_make_state(tmp_path))
    view._perk_ids = [1, 2, 4, 6]
    view._hovered_row_index = 3
    assert view._hovered_perk_id() == 6


def test_hovered_perk_id_returns_none_when_not_hovered(tmp_path: Path) -> None:
    view = UnlockedPerksDatabaseView(_make_state(tmp_path))
    view._perk_ids = [1, 2, 4, 6]
    view._hovered_row_index = -1
    assert view._hovered_perk_id() is None


def test_wrap_small_text_native_inserts_newline_at_previous_space(monkeypatch) -> None:
    monkeypatch.setattr(perk_db, "measure_small_text_width", lambda _font, text, _scale: float(len(text)))
    fake_font = cast(SmallFontData, object())
    wrapped = UnlockedPerksDatabaseView._wrap_small_text_native(fake_font, "alpha beta", 6.0, scale=1.0)
    assert wrapped == "alpha\nbeta"


def test_prewrapped_perk_desc_uses_cache(monkeypatch, tmp_path: Path) -> None:
    calls = {"count": 0}

    def _fake_measure(_font, text: str, _scale: float) -> float:
        calls["count"] += 1
        return float(len(text))

    monkeypatch.setattr(perk_db, "measure_small_text_width", _fake_measure)
    monkeypatch.setattr(
        UnlockedPerksDatabaseView,
        "_perk_desc",
        staticmethod(lambda _perk_id, *, fx_toggle=0, preserve_bugs=False: "alpha beta gamma"),  # noqa: ARG005
    )

    view = UnlockedPerksDatabaseView(_make_state(tmp_path))
    fake_font = cast(SmallFontData, object())
    first = view._prewrapped_perk_desc(5, fake_font, fx_toggle=0)
    count_after_first = calls["count"]
    second = view._prewrapped_perk_desc(5, fake_font, fx_toggle=0)

    assert first == second
    assert calls["count"] == count_after_first


def test_perk_prereq_name_uses_first_prereq_entry() -> None:
    assert UnlockedPerksDatabaseView._perk_prereq_name(37) == "Veins of Poison"
    assert UnlockedPerksDatabaseView._perk_prereq_name(40) == "Dodger"
    assert UnlockedPerksDatabaseView._perk_prereq_name(43) == "Perk Expert"
    assert UnlockedPerksDatabaseView._perk_prereq_name(45) == "Regeneration"
