from __future__ import annotations

from pathlib import Path
import random
import time

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState, LanSessionConfig, PendingLanSession
from crimson.net.net_runtime import NetRuntime
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


@pytest.mark.parametrize(
    ("mode", "action", "mode_id", "quest_level"),
    [
        ("survival", "start_survival_lan", 1, ""),
        ("rush", "start_rush_lan", 2, ""),
        ("quests", "start_quest_lan", 3, "1.1"),
    ],
)
def test_rollback_runtime_is_selected_for_all_network_modes(
    tmp_path: Path,
    mode: str,
    action: str,
    mode_id: int,
    quest_level: str,
) -> None:
    state = _build_state(tmp_path)
    pending = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode=mode,  # type: ignore[arg-type]
            player_count=2,
            quest_level=quest_level,
            bind_host="0.0.0.0",
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="",
            host_ip="127.0.0.1",
            port=31993,
            netcode_mode="rollback",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=False,
    )
    state.pending_net_session = pending
    state.pending_lan_session = pending
    loop = GameLoopView(state)

    resolved = loop._resolve_lan_action(action)

    assert resolved == "open_lan_lobby"
    assert state.config.game_mode == mode_id
    assert state.lan_in_lobby is True
    assert state.net_in_lobby is True
    assert isinstance(state.net_runtime, NetRuntime)
    assert state.net_runtime is state.lan_runtime
    assert state.net_runtime.cfg.mode_id == mode_id
    assert state.net_runtime.cfg.netcode_mode == "rollback"
    if mode == "quests":
        assert state.pending_quest_level == "1.1"
