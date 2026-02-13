from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from crimson.sim.input import PlayerInput
from crimson.game_world import GameWorld
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from grim.config import ensure_crimson_cfg
from grim.geom import Vec2
from grim.view import ViewContext


def test_game_world_init_honors_config_player_count(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 2

    world = GameWorld(assets_dir=assets_dir, config=cfg)
    assert [player.index for player in world.players] == [0, 1]


def test_game_world_reset_spreads_player_spawn_positions() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    world = GameWorld(assets_dir=assets_dir)
    world.reset(seed=0xBEEF, player_count=4)

    positions = {(round(player.pos.x, 3), round(player.pos.y, 3)) for player in world.players}
    assert len(positions) == 4


def test_survival_mode_uses_config_player_count(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 2
    ctx = ViewContext(assets_dir=assets_dir)

    mode = SurvivalMode(ctx, config=cfg)
    assert len(mode.world.players) == 2  # intentional: wiring smoke test


def test_quest_mode_update_uses_per_player_input_frame(monkeypatch, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 3
    ctx = ViewContext(assets_dir=assets_dir)
    mode = QuestMode(ctx, config=cfg)

    inputs = [PlayerInput(move=Vec2(float(idx), 0.0)) for idx in range(len(mode.world.players))]
    captured: dict[str, object] = {}

    class _FakeSession:
        def __init__(self) -> None:
            self.detail_preset = 5
            self.fx_toggle = 0
            self.spawn_entries = ()
            self.spawn_timeline_ms = 0.0
            self.no_creatures_timer_ms = 0.0
            self.completion_transition_ms = -1.0

        def step_tick(self, *, dt_frame, inputs, trace_rng=False):  # noqa: ANN001
            del dt_frame, trace_rng
            captured["inputs"] = inputs
            return SimpleNamespace(
                step=SimpleNamespace(),
                spawn_timeline_ms=0.0,
                no_creatures_timer_ms=0.0,
                completion_transition_ms=-1.0,
                play_hit_sfx=False,
                play_completion_music=False,
                completed=False,
            )

    mode._sim_session = _FakeSession()
    monkeypatch.setattr(mode, "_update_audio", lambda _dt: None)
    monkeypatch.setattr(mode, "_tick_frame", lambda _dt: (0.02, 20.0))
    monkeypatch.setattr(mode, "_handle_input", lambda: None)
    monkeypatch.setattr(mode, "_build_local_inputs", lambda *, dt_frame: inputs)
    monkeypatch.setattr(mode, "_death_transition_ready", lambda: False)
    monkeypatch.setattr("crimson.game_world.GameWorld.apply_step_result", lambda *_args, **_kwargs: None)

    mode.update(0.02)

    assert captured["inputs"] is inputs
    assert len(inputs) == 3


def test_base_gameplay_build_local_inputs_passes_creatures(monkeypatch, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = SurvivalMode(ctx, config=cfg)

    captured: dict[str, object] = {}

    def _fake_build_frame_inputs(*, players, config, mouse_screen, screen_to_world, dt_frame, creatures):  # noqa: ANN001
        captured["players"] = players
        captured["config"] = config
        captured["mouse_screen"] = mouse_screen
        captured["screen_to_world"] = screen_to_world
        captured["dt_frame"] = dt_frame
        captured["creatures"] = creatures
        return [PlayerInput() for _ in players]

    monkeypatch.setattr(mode._local_input, "build_frame_inputs", _fake_build_frame_inputs)

    frame = mode._build_local_inputs(dt_frame=0.016)

    assert len(frame) == len(mode.world.players)
    assert captured["creatures"] is mode.creatures.entries
