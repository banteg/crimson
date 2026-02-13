from __future__ import annotations

from pathlib import Path
import random
import time

from crimson.frontend.panels.play_game import PlayGameMenuView
from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState, LanSessionConfig, PendingLanSession
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def _build_state(tmp_path: Path) -> GameState:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"
    cfg = ensure_crimson_cfg(tmp_path)
    return GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=random.Random(0),
        config=cfg,
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


def test_play_game_lan_entry_is_gated_by_console_cvar(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    view = PlayGameMenuView(state)

    entries_disabled = view._mode_entries()[0]
    assert all(entry.action != "open_lan_session" for entry in entries_disabled)

    state.console.register_cvar("cv_lanLockstepEnabled", "1")
    entries_enabled = view._mode_entries()[0]
    assert any(entry.action == "open_lan_session" for entry in entries_enabled)


def test_loop_view_maps_lan_start_action_into_mode_action(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    state.pending_lan_session = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="quests",
            player_count=3,
            quest_level="1.1",
            bind_host="0.0.0.0",
            host_ip="",
            port=31993,
            preserve_bugs=False,
        ),
        auto_start=False,
    )
    loop = GameLoopView(state)

    action = loop._resolve_lan_action("start_quest_lan")

    assert action == "start_quest"
    assert state.config.game_mode == 3
    assert state.config.player_count == 3
    assert state.pending_quest_level == "1.1"
    assert state.lan_in_lobby is True


def test_open_lan_session_route_requires_feature_cvar(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    loop = GameLoopView(state)

    assert loop._resolve_lan_action("open_lan_session") == "open_play_game"

    state.console.register_cvar("cv_lanLockstepEnabled", "1")
    assert loop._resolve_lan_action("open_lan_session") == "open_lan_session"


def test_auto_lan_start_action_consumes_pending_session_once(tmp_path: Path) -> None:
    state = _build_state(tmp_path)
    state.pending_lan_session = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="rush",
            player_count=2,
            quest_level="",
            bind_host="0.0.0.0",
            host_ip="",
            port=31993,
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    loop = GameLoopView(state)

    assert loop._auto_lan_start_action() == "start_rush_lan"
    assert state.pending_lan_session.started is True
    assert loop._auto_lan_start_action() is None
