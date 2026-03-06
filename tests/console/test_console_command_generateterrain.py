from __future__ import annotations

from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers
from crimson.game_modes import GameMode


def test_generateterrain_command_sets_regenerate_request(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    assert state.terrain_regenerate_requested is False
    handlers["generateterrain"]([])
    assert state.terrain_regenerate_requested is True


def test_game_loop_consumes_terrain_regenerate_request(make_game_state) -> None:
    class _FakeView:
        close_requested = False
        default_game_mode_id = GameMode.SURVIVAL
        called = 0

        def open(self) -> None:
            return

        def close(self) -> None:
            return

        def update(self, dt: float) -> None:
            _ = dt

        def draw(self) -> None:
            return

        def take_action(self) -> str | None:
            return None

        def bind_status(self, status) -> None:
            _ = status

        def bind_screen_fade(self, fade) -> None:
            _ = fade

        def bind_audio(self, audio, audio_rng) -> None:
            _ = (audio, audio_rng)

        def set_lan_runtime(
            self,
            *,
            enabled: bool,
            role: str,
            expected_players: int,
            connected_players: int,
            waiting_for_players: bool,
        ) -> None:
            _ = (enabled, role, expected_players, connected_players, waiting_for_players)

        def bind_lan_runtime(self, runtime) -> None:
            _ = runtime

        def set_lan_match_start(self, *, seed: int, start_tick: int = 0, status_snapshot=None) -> None:
            _ = (seed, start_tick, status_snapshot)

        def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
            _ = entity_alpha

        def steal_ground_for_menu(self):
            return None

        def menu_ground_camera(self):
            return None

        def console_elapsed_ms(self) -> float:
            return 0.0

        def set_rtx_mode(self, mode) -> None:
            _ = mode

        def set_runtime_updates_per_frame(self, value: int) -> None:
            _ = value

        def frame_telemetry(self) -> tuple[int, int, int, float, float, float]:
            return (0, 0, 0, 0.0, 0.0, 0.0)

        def regenerate_terrain_for_console(self) -> None:
            self.called += 1

    state = make_game_state()
    view = GameLoopView(state)
    fake = _FakeView()
    view._front_active = fake
    state.terrain_regenerate_requested = True

    view._handle_console_requests()

    assert state.terrain_regenerate_requested is False
    assert state.menu_ground is None
    assert fake.called == 1
