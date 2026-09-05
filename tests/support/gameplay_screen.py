from __future__ import annotations

from crimson.game_modes import GameMode
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer


class GameplayScreenStub:
    def __init__(
        self,
        *,
        game_mode_id: GameMode = GameMode.SURVIVAL,
        ground: GroundRenderer | None = None,
        camera: Vec2 | None = None,
        telemetry: tuple[int, int, int, float, float, float] = (0, 0, 0, 0.0, 0.0, 0.0),
        console_elapsed_ms: float = 0.0,
        action: str | None = None,
    ) -> None:
        self.close_requested = False
        self.default_game_mode_id = game_mode_id
        self._ground = ground
        self._camera = camera
        self._telemetry = telemetry
        self._console_elapsed_ms = float(console_elapsed_ms)
        self._action = action
        self.regenerate_calls = 0
        self.prepare_demo_trial_overlay_calls = 0
        self.last_status = None
        self.last_screen_fade = None
        self.last_audio = None
        self.last_audio_rng = None
        self.last_rtx_mode = None
        self.last_runtime_updates_per_frame = 0

    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def update(self, dt: float) -> None:
        _ = dt

    def draw(self) -> None:
        return None

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def bind_status(self, status) -> None:
        self.last_status = status

    def bind_screen_fade(self, fade) -> None:
        self.last_screen_fade = fade

    def bind_audio(self, audio, audio_rng) -> None:
        self.last_audio = audio
        self.last_audio_rng = audio_rng




    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        _ = entity_alpha

    def steal_ground_for_menu(self) -> GroundRenderer | None:
        ground = self._ground
        self._ground = None
        return ground

    def menu_ground_camera(self) -> Vec2 | None:
        return self._camera

    def console_elapsed_ms(self) -> float:
        return self._console_elapsed_ms

    def prepare_demo_trial_overlay_frame(self) -> None:
        self.prepare_demo_trial_overlay_calls += 1

    def regenerate_terrain_for_console(self) -> None:
        self.regenerate_calls += 1

    def set_rtx_mode(self, mode) -> None:
        self.last_rtx_mode = mode

    def set_runtime_updates_per_frame(self, value: int) -> None:
        self.last_runtime_updates_per_frame = int(value)

    def frame_telemetry(self) -> tuple[int, int, int, float, float, float]:
        return self._telemetry
