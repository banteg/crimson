from __future__ import annotations

from pathlib import Path
import random
from typing import TYPE_CHECKING, Protocol

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState, update_audio
from grim.console import ConsoleState
from grim.config import CrimsonConfig
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.view import ViewContext

from ..gameplay import PlayerInput, _creature_find_in_radius, perk_count_get
from ..game_world import GameWorld
from ..local_input import LocalInputInterpreter, clear_input_edges
from ..persistence.highscores import HighScoreRecord
from ..perks import PerkId
from ..ui.game_over import GameOverUi
from ..ui.hud import HudAssets, HudState, draw_target_health_bar, load_hud_assets

if TYPE_CHECKING:
    from ..persistence.save_status import GameStatus


class _ScreenFade(Protocol):
    screen_fade_alpha: float


class BaseGameplayMode:
    def __init__(
        self,
        ctx: ViewContext,
        *,
        world_size: float,
        default_game_mode_id: int,
        demo_mode_active: bool = False,
        difficulty_level: int = 0,
        hardcore: bool = False,
        texture_cache: PaqTextureCache | None = None,
        config: CrimsonConfig | None = None,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: random.Random | None = None,
    ) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._hud_missing: list[str] = []
        self._small: SmallFontData | None = None
        self._hud_assets: HudAssets | None = None
        self._hud_state = HudState()

        self._default_game_mode_id = int(default_game_mode_id)
        self._config = config
        self._console = console
        self._base_dir = config.path.parent if config is not None else Path.cwd()

        self.close_requested = False
        self._action: str | None = None
        self._paused = False
        self._status: GameStatus | None = None

        self._world = GameWorld(
            assets_dir=ctx.assets_dir,
            world_size=float(world_size),
            demo_mode_active=bool(demo_mode_active),
            difficulty_level=int(difficulty_level),
            hardcore=bool(hardcore),
            preserve_bugs=bool(ctx.preserve_bugs),
            texture_cache=texture_cache,
            config=config,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._bind_world()

        self._game_over_active = False
        self._game_over_record: HighScoreRecord | None = None
        self._game_over_ui = GameOverUi(
            assets_root=self._assets_root,
            base_dir=self._base_dir,
            config=config
            or CrimsonConfig(path=self._base_dir / "crimson.cfg", data={"game_mode": int(default_game_mode_id)}),
        )
        self._game_over_banner = "reaper"

        self._ui_mouse = Vec2()
        self._cursor_pulse_time = 0.0
        self._last_dt_ms = 0.0
        self._screen_fade: _ScreenFade | None = None
        self._local_input = LocalInputInterpreter()

    def _cvar_float(self, name: str, default: float = 0.0) -> float:
        console = self._console
        if console is None:
            return float(default)
        cvar = console.cvars.get(name)
        if cvar is None:
            return float(default)
        return float(cvar.value_f)

    def _hud_small_indicators(self) -> bool:
        return self._cvar_float("cv_uiSmallIndicators", 0.0) != 0.0

    def _config_game_mode_id(self) -> int:
        config = self._config
        if config is None:
            return int(self._default_game_mode_id)
        try:
            value = config.data.get("game_mode", self._default_game_mode_id)
            return int(value or self._default_game_mode_id)
        except Exception:
            return int(self._default_game_mode_id)

    def _draw_target_health_bar(self, *, alpha: float = 1.0) -> None:
        creatures = getattr(self._creatures, "entries", [])
        if not creatures:
            return

        if perk_count_get(self._player, PerkId.DOCTOR) <= 0:
            return

        target_idx = _creature_find_in_radius(
            creatures,
            pos=self._player.aim,
            radius=12.0,
            start_index=0,
        )
        if target_idx == -1:
            return

        creature = creatures[target_idx]
        if not bool(getattr(creature, "active", False)):
            return
        hp = float(getattr(creature, "hp", 0.0))
        max_hp = float(getattr(creature, "max_hp", 0.0))
        if max_hp <= 0.0:
            return

        ratio = hp / max_hp
        if ratio < 0.0:
            ratio = 0.0
        if ratio > 1.0:
            ratio = 1.0

        screen_left = self._world.world_to_screen(creature.pos + Vec2(-32.0, 32.0))
        screen_right = self._world.world_to_screen(creature.pos + Vec2(32.0, 32.0))
        width = screen_right.x - screen_left.x
        if width <= 1e-3:
            return
        draw_target_health_bar(pos=screen_left, width=width, ratio=ratio, alpha=alpha, scale=width / 64.0)

    def _bind_world(self) -> None:
        self._state = self._world.state
        self._creatures = self._world.creatures
        self._player = self._world.players[0]
        self._state.status = self._status

    def _any_player_alive(self) -> bool:
        return any(player.health > 0.0 for player in self._world.players)

    def bind_status(self, status: GameStatus | None) -> None:
        self._status = status
        self._state.status = status

    def bind_screen_fade(self, fade: _ScreenFade | None) -> None:
        self._screen_fade = fade

    def bind_audio(self, audio: AudioState | None, audio_rng: random.Random | None) -> None:
        self._world.audio = audio
        self._world.audio_rng = audio_rng

    def _update_audio(self, dt: float) -> None:
        if self._world.audio is not None:
            update_audio(self._world.audio, dt)

    def _ui_line_height(self, scale: float = 1.0) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _ui_text_width(self, text: str, scale: float = 1.0) -> int:
        if self._small is not None:
            return int(measure_small_text_width(self._small, text, scale))
        return int(rl.measure_text(text, int(20 * scale)))

    def _draw_ui_text(self, text: str, pos: Vec2, color: rl.Color, scale: float = 1.0) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, pos, scale, color)
        else:
            rl.draw_text(text, int(pos.x), int(pos.y), int(20 * scale), color)

    def _ui_mouse_pos(self) -> rl.Vector2:
        return self._ui_mouse.to_rl()

    def _update_ui_mouse(self) -> None:
        mouse = rl.get_mouse_position()
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        self._ui_mouse = Vec2.from_xy(mouse).clamp_rect(
            0.0,
            0.0,
            max(0.0, screen_w - 1.0),
            max(0.0, screen_h - 1.0),
        )

    def _tick_frame(self, dt: float, *, clamp_cursor_pulse: bool = False) -> tuple[float, float]:
        dt_frame = float(dt)
        dt_ui_ms = float(min(dt_frame, 0.1) * 1000.0)
        self._last_dt_ms = dt_ui_ms

        self._update_ui_mouse()

        pulse_dt = float(min(dt_frame, 0.1)) if clamp_cursor_pulse else dt_frame
        self._cursor_pulse_time += pulse_dt * 1.1

        return dt_frame, dt_ui_ms

    def _player_name_default(self) -> str:
        config = self._config
        if config is None:
            return ""
        raw = config.data.get("player_name")
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw).split(b"\x00", 1)[0].decode("latin-1", errors="ignore")
        if isinstance(raw, str):
            return raw
        return ""

    def open(self) -> None:
        self.close_requested = False
        self._action = None
        self._paused = False
        self._missing_assets.clear()
        self._hud_missing.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None

        self._hud_assets = load_hud_assets(self._assets_root)
        if self._hud_assets.missing:
            self._hud_missing = list(self._hud_assets.missing)
        self._hud_state = HudState()

        self._game_over_active = False
        self._game_over_record = None
        self._game_over_banner = "reaper"
        self._game_over_ui.close()

        player_count = 1
        config = self._config
        if config is not None:
            try:
                player_count = int(config.data.get("player_count", 1) or 1)
            except Exception:
                player_count = 1
        seed = random.getrandbits(32)
        self._world.reset(seed=seed, player_count=max(1, min(4, player_count)))
        self._world.open()
        self._bind_world()
        self._local_input.reset(players=self._world.players)

        self._ui_mouse = Vec2(float(rl.get_screen_width()) * 0.5, float(rl.get_screen_height()) * 0.5)
        self._cursor_pulse_time = 0.0

    def close(self) -> None:
        self._game_over_ui.close()
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        self._hud_assets = None
        self._world.close()

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _enter_game_over(self) -> None:
        raise NotImplementedError

    def _update_game_over_ui(self, dt: float) -> None:
        record = self._game_over_record
        if record is None:
            self._enter_game_over()
            record = self._game_over_record
        if record is None:
            return

        action = self._game_over_ui.update(
            dt,
            record=record,
            player_name_default=self._player_name_default(),
            play_sfx=self._world.audio_router.play_sfx,
            rand=self._state.rng.rand,
            mouse=self._ui_mouse_pos(),
        )
        if action == "play_again":
            self.open()
            return
        if action == "high_scores":
            self._action = "open_high_scores"
            return
        if action == "main_menu":
            self._action = "back_to_menu"
            self.close_requested = True

    def draw_pause_background(self) -> None:
        self._world.draw(draw_aim_indicators=False)

    def steal_ground_for_menu(self):
        ground = self._world.ground
        self._world.ground = None
        return ground

    def menu_ground_camera(self) -> Vec2:
        return self._world.camera

    def _draw_screen_fade(self) -> None:
        fade_alpha = 0.0
        if self._screen_fade is not None:
            fade_alpha = float(self._screen_fade.screen_fade_alpha)
        if fade_alpha <= 0.0:
            return
        alpha = int(255 * max(0.0, min(1.0, fade_alpha)))
        rl.draw_rectangle(0, 0, int(rl.get_screen_width()), int(rl.get_screen_height()), rl.Color(0, 0, 0, alpha))

    def _build_local_inputs(self, *, dt_frame: float) -> list[PlayerInput]:
        return self._local_input.build_frame_inputs(
            players=self._world.players,
            config=self._config,
            mouse_screen=self._ui_mouse,
            screen_to_world=self._world.screen_to_world,
            dt_frame=float(dt_frame),
        )

    @staticmethod
    def _clear_local_input_edges(inputs: list[PlayerInput]) -> list[PlayerInput]:
        return clear_input_edges(inputs)
