from __future__ import annotations

from types import SimpleNamespace

import pytest

import crimson.game.loop_view as loop_view_mod
from crimson.demo_trial import (
    DEMO_QUEST_GRACE_TIME_MS,
    DEMO_TOTAL_PLAY_TIME_MS,
    demo_trial_overlay_info,
    format_demo_trial_time,
    tick_demo_trial_timers,
)
from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel


class _DummyGameplay:
    close_requested = False
    default_game_mode_id = GameMode.SURVIVAL

    def __init__(self) -> None:
        self.prepare_overlay_calls = 0

    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def update(self, dt: float) -> None:
        _ = dt

    def draw(self) -> None:
        return None

    def take_action(self) -> str | None:
        return None

    def bind_status(self, status) -> None:
        _ = status

    def bind_screen_fade(self, fade) -> None:
        _ = fade

    def bind_audio(self, audio, audio_rng) -> None:
        _ = audio, audio_rng

    def set_lan_runtime(self, *, enabled: bool, role: str, expected_players: int, connected_players: int, waiting_for_players: bool) -> None:
        _ = enabled, role, expected_players, connected_players, waiting_for_players

    def bind_lan_runtime(self, runtime) -> None:
        _ = runtime

    def set_lan_match_start(self, *, seed: int, start_tick: int = 0, status=None) -> None:
        _ = seed, start_tick, status

    def steal_ground_for_menu(self):
        return None

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        _ = entity_alpha

    def menu_ground_camera(self):
        return None

    def console_elapsed_ms(self) -> float:
        return 0.0

    def prepare_demo_trial_overlay_frame(self) -> None:
        self.prepare_overlay_calls += 1

    def regenerate_terrain_for_console(self) -> None:
        return None

    def set_rtx_mode(self, mode) -> None:
        _ = mode

    def set_runtime_updates_per_frame(self, value: int) -> None:
        _ = value

    def frame_telemetry(self) -> tuple[int, int, int, float, float, float]:
        return 0, 0, 0, 0.0, 0.0, 0.0


def test_format_demo_trial_time() -> None:
    assert format_demo_trial_time(0) == "0:00.00"
    assert format_demo_trial_time(12_340) == "0:12.34"
    assert format_demo_trial_time(60_000) == "1:00.00"
    assert format_demo_trial_time(-1) == "0:00.00"


@pytest.mark.parametrize(
    (
        "demo_build",
        "game_mode_id",
        "global_playtime_ms",
        "quest_grace_elapsed_ms",
        "quest_level",
        "expected_visible",
        "expected_kind",
        "expected_remaining_ms",
        "expected_show_remaining_line",
    ),
    [
        (False, GameMode.SURVIVAL, DEMO_TOTAL_PLAY_TIME_MS, DEMO_QUEST_GRACE_TIME_MS, QuestLevel(4, 10), False, "none", None, False),
        (True, GameMode.SURVIVAL, DEMO_TOTAL_PLAY_TIME_MS, 0, QuestLevel(1, 1), True, "time_up", 0, False),
        (True, GameMode.QUESTS, 0, 0, QuestLevel(2, 1), True, "quest_tier_limit", None, True),
        (
            True,
            GameMode.SURVIVAL,
            DEMO_TOTAL_PLAY_TIME_MS,
            1_000,
            QuestLevel(1, 1),
            True,
            "quest_grace_left",
            DEMO_QUEST_GRACE_TIME_MS - 1_000,
            False,
        ),
        (True, GameMode.QUESTS, DEMO_TOTAL_PLAY_TIME_MS, 1_000, QuestLevel(1, 1), False, "none", None, False),
        (
            True,
            GameMode.QUESTS,
            DEMO_TOTAL_PLAY_TIME_MS,
            1_000,
            QuestLevel(2, 1),
            True,
            "quest_tier_limit",
            DEMO_QUEST_GRACE_TIME_MS - 1_000,
            False,
        ),
    ],
    ids=[
        "hidden-when-not-demo",
        "shows-when-global-time-exhausted",
        "shows-tier-limit-while-time-remains",
        "uses-grace-timer",
        "grace-allows-quest-mode",
        "shows-tier-limit-during-grace",
    ],
)
def test_demo_trial_overlay_info(
    demo_build: bool,
    game_mode_id: GameMode,
    global_playtime_ms: int,
    quest_grace_elapsed_ms: int,
    quest_level: QuestLevel | None,
    expected_visible: bool,
    expected_kind: str,
    expected_remaining_ms: int | None,
    expected_show_remaining_line: bool,
) -> None:
    info = demo_trial_overlay_info(
        demo_build=demo_build,
        game_mode_id=game_mode_id,
        global_playtime_ms=global_playtime_ms,
        quest_grace_elapsed_ms=quest_grace_elapsed_ms,
        quest_level=quest_level,
    )
    assert info.visible is expected_visible
    assert info.kind == expected_kind
    assert info.show_remaining_line is expected_show_remaining_line
    if expected_remaining_ms is not None:
        assert info.remaining_ms == expected_remaining_ms


def test_demo_trial_purchase_requests_quit(make_game_state, mocker) -> None:
    state = make_game_state(
        demo_enabled=True,
        config_updates={"game_mode": int(GameMode.SURVIVAL)},
    )
    state.status.play_time_ms = DEMO_TOTAL_PLAY_TIME_MS
    loop = GameLoopView(state)
    overlay = SimpleNamespace(update=mocker.Mock(return_value="purchase"))

    mocker.patch.object(loop, "_demo_trial_overlay_view", return_value=overlay)
    open_mock = mocker.patch.object(loop_view_mod.webbrowser, "open", return_value=True)

    handled = loop._update_demo_trial_overlay(0.016)

    assert handled is True
    assert state.quit_requested is True
    open_mock.assert_called_once()


def test_demo_trial_overlay_prepares_gameplay_frame_when_visible(make_game_state, mocker) -> None:
    state = make_game_state(
        demo_enabled=True,
        config_updates={"game_mode": int(GameMode.SURVIVAL)},
    )
    state.status.play_time_ms = DEMO_TOTAL_PLAY_TIME_MS
    loop = GameLoopView(state)
    gameplay = _DummyGameplay()
    loop._front_active = gameplay
    loop._active = gameplay
    overlay = SimpleNamespace(update=mocker.Mock(return_value=None))

    mocker.patch.object(loop, "_demo_trial_overlay_view", return_value=overlay)

    handled = loop._update_demo_trial_overlay(0.016)

    assert handled is True
    assert gameplay.prepare_overlay_calls == 1


@pytest.mark.parametrize(
    ("overlay_visible", "global_playtime_ms", "quest_grace_elapsed_ms", "dt_ms"),
    [
        (False, DEMO_TOTAL_PLAY_TIME_MS - 5, 0, 10),
        (True, DEMO_TOTAL_PLAY_TIME_MS, 0, 0),
    ],
    ids=["accumulates-and-starts-grace", "starts-grace-even-when-overlay-visible"],
)
def test_tick_demo_trial_timers_starts_grace_after_time_limit(
    overlay_visible: bool,
    global_playtime_ms: int,
    quest_grace_elapsed_ms: int,
    dt_ms: int,
) -> None:
    used_ms, grace_ms = tick_demo_trial_timers(
        demo_build=True,
        game_mode_id=GameMode.SURVIVAL,
        overlay_visible=overlay_visible,
        global_playtime_ms=global_playtime_ms,
        quest_grace_elapsed_ms=quest_grace_elapsed_ms,
        dt_ms=dt_ms,
    )
    assert used_ms == DEMO_TOTAL_PLAY_TIME_MS
    assert grace_ms == 1


def test_tick_demo_trial_timers_grace_counts_only_in_quests() -> None:
    used_ms, grace_ms = tick_demo_trial_timers(
        demo_build=True,
        game_mode_id=GameMode.QUESTS,
        overlay_visible=False,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=1,
        dt_ms=100,
    )
    assert used_ms == DEMO_TOTAL_PLAY_TIME_MS
    assert grace_ms == 101

    used_ms, grace_ms = tick_demo_trial_timers(
        demo_build=True,
        game_mode_id=GameMode.SURVIVAL,
        overlay_visible=False,
        global_playtime_ms=DEMO_TOTAL_PLAY_TIME_MS,
        quest_grace_elapsed_ms=1,
        dt_ms=100,
    )
    assert used_ms == DEMO_TOTAL_PLAY_TIME_MS
    assert grace_ms == 1
