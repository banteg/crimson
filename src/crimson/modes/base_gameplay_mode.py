from __future__ import annotations

from pathlib import Path
import random
from typing import TYPE_CHECKING, Protocol

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState, update_audio
from grim.console import ConsoleState
from grim.config import CrimsonConfig, default_crimson_cfg_data
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer
from grim.view import ViewContext

from ..sim.input import PlayerInput
from ..debug import debug_enabled
from ..net.debug_log import lan_debug_log
from ..perks.runtime.effects import _creature_find_in_radius
from ..perks.helpers import perk_count_get
from ..game_world import GameWorld
from ..local_input import LocalInputInterpreter, clear_input_edges
from ..persistence.highscores import HighScoreRecord
from ..perks import PerkId
from ..ui.game_over import GameOverUi
from ..ui.hud import HudAssets, HudState, draw_target_health_bar, load_hud_assets

if TYPE_CHECKING:
    from ..persistence.save_status import GameStatus
    from ..net.runtime import LanRuntime


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

        mode_id = int(default_game_mode_id)
        if config is None:
            base_dir = Path.cwd()
            resolved_config = CrimsonConfig(path=base_dir / "crimson.cfg", data=default_crimson_cfg_data())
            resolved_config.game_mode = mode_id
        else:
            resolved_config = config
            base_dir = resolved_config.path.parent
        self.config: CrimsonConfig = resolved_config
        self._console = console
        self._base_dir = base_dir

        self.close_requested = False
        self._action: str | None = None
        self._paused = False
        self._status: GameStatus | None = None

        self.world = GameWorld(
            assets_dir=ctx.assets_dir,
            world_size=float(world_size),
            demo_mode_active=bool(demo_mode_active),
            difficulty_level=int(difficulty_level),
            hardcore=bool(hardcore),
            preserve_bugs=bool(ctx.preserve_bugs),
            texture_cache=texture_cache,
            config=self.config,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._bind_world()

        self._game_over_active = False
        self._game_over_record: HighScoreRecord | None = None
        self._game_over_ui = GameOverUi(
            assets_root=self._assets_root,
            base_dir=self._base_dir,
            config=self.config,
            preserve_bugs=bool(ctx.preserve_bugs),
        )
        self._game_over_banner = "reaper"

        self._ui_mouse = Vec2()
        self._cursor_pulse_time = 0.0
        self._last_dt_ms = 0.0
        self._screen_fade: _ScreenFade | None = None
        self._local_input = LocalInputInterpreter()
        self._lan_runtime: LanRuntime | None = None
        self._lan_local_slot_index = 0
        self._lan_seed_override: int | None = None
        self._lan_start_tick = 0
        self._lan_enabled = False
        self._lan_role = ""
        self._lan_expected_players = 1
        self._lan_connected_players = 1
        self._lan_waiting_for_players = False
        self._lan_trace_last_ms = -1000.0

    def bind_lan_runtime(self, runtime: LanRuntime | None) -> None:
        self._lan_runtime = runtime
        slot_index = 0
        if runtime is not None:
            slot_index = int(getattr(runtime, "local_slot_index", 0))
        self._lan_local_slot_index = max(0, min(3, int(slot_index)))

    def set_lan_match_start(self, *, seed: int, start_tick: int = 0) -> None:
        self._lan_seed_override = int(seed)
        self._lan_start_tick = int(start_tick)

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
        return self.config.game_mode

    def _draw_target_health_bar(self, *, alpha: float = 1.0) -> None:
        creatures = getattr(self.creatures, "entries", [])
        if not creatures:
            return

        if perk_count_get(self.player, PerkId.DOCTOR) <= 0:
            return

        target_idx = _creature_find_in_radius(
            creatures,
            pos=self.player.aim,
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

        screen_left = self.world.world_to_screen(creature.pos + Vec2(-32.0, 32.0))
        screen_right = self.world.world_to_screen(creature.pos + Vec2(32.0, 32.0))
        width = screen_right.x - screen_left.x
        if width <= 1e-3:
            return
        draw_target_health_bar(pos=screen_left, width=width, ratio=ratio, alpha=alpha, scale=width / 64.0)

    def _bind_world(self) -> None:
        self.state = self.world.state
        self.creatures = self.world.creatures
        self.player = self.world.players[0]
        self.state.status = self._status

    def _any_player_alive(self) -> bool:
        return any(player.health > 0.0 for player in self.world.players)

    def bind_status(self, status: GameStatus | None) -> None:
        self._status = status
        self.state.status = status

    def bind_screen_fade(self, fade: _ScreenFade | None) -> None:
        self._screen_fade = fade

    def bind_audio(self, audio: AudioState | None, audio_rng: random.Random | None) -> None:
        self.world.audio = audio
        self.world.audio_rng = audio_rng

    def _update_audio(self, dt: float) -> None:
        if self.world.audio is not None:
            update_audio(self.world.audio, dt)

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
        self._trace_lan_state_heartbeat()

        pulse_dt = float(min(dt_frame, 0.1)) if clamp_cursor_pulse else dt_frame
        self._cursor_pulse_time += pulse_dt * 1.1

        return dt_frame, dt_ui_ms

    def set_lan_runtime(
        self,
        *,
        enabled: bool,
        role: str,
        expected_players: int,
        connected_players: int,
        waiting_for_players: bool,
    ) -> None:
        role = str(role)
        expected_players = max(1, min(4, int(expected_players)))
        connected_players = max(0, min(expected_players, int(connected_players)))
        waiting_for_players = bool(waiting_for_players)

        if (
            bool(self._lan_enabled) == bool(enabled)
            and str(self._lan_role) == role
            and int(self._lan_expected_players) == int(expected_players)
            and int(self._lan_connected_players) == int(connected_players)
            and bool(self._lan_waiting_for_players) == bool(waiting_for_players)
        ):
            return
        self._lan_enabled = bool(enabled)
        self._lan_role = role
        self._lan_expected_players = int(expected_players)
        self._lan_connected_players = int(connected_players)
        self._lan_waiting_for_players = bool(waiting_for_players)
        self._lan_trace_last_ms = -1000.0
        lan_debug_log(
            "set_lan_runtime",
            mode=self.__class__.__name__,
            enabled=bool(self._lan_enabled),
            role=str(self._lan_role),
            expected_players=int(self._lan_expected_players),
            connected_players=int(self._lan_connected_players),
            waiting_for_players=bool(self._lan_waiting_for_players),
        )

    def _lan_wait_gate_active(self) -> bool:
        if not bool(self._lan_enabled):
            return False
        if not bool(self._lan_waiting_for_players):
            return False
        return int(self._lan_connected_players) < int(self._lan_expected_players)

    def _update_lan_wait_gate_debug_override(self) -> None:
        if not self._lan_wait_gate_active():
            return
        if (not debug_enabled()) or (not rl.is_key_pressed(rl.KeyboardKey.KEY_F10)):
            return
        self._lan_connected_players = int(self._lan_expected_players)
        self._lan_waiting_for_players = False
        lan_debug_log(
            "wait_gate_override",
            mode=self.__class__.__name__,
            role=str(self._lan_role),
            connected_players=int(self._lan_connected_players),
            expected_players=int(self._lan_expected_players),
        )

    def _trace_lan_state_heartbeat(self) -> None:
        if not bool(self._lan_enabled):
            return
        elapsed_ms = float(self.world._elapsed_ms)
        if (elapsed_ms - float(self._lan_trace_last_ms)) < 1000.0:
            return
        self._lan_trace_last_ms = float(elapsed_ms)
        lan_debug_log(
            "mode_heartbeat",
            mode=self.__class__.__name__,
            elapsed_ms=int(elapsed_ms),
            role=str(self._lan_role),
            expected_players=int(self._lan_expected_players),
            connected_players=int(self._lan_connected_players),
            waiting_for_players=bool(self._lan_waiting_for_players),
            wait_gate_active=bool(self._lan_wait_gate_active()),
            local_players=int(len(self.world.players)),
        )

    def _draw_lan_debug_info(self, *, x: float, y: float, line_h: float) -> float:
        if (not debug_enabled()) or (not bool(self._lan_enabled)):
            return float(y)

        role = str(self._lan_role or "?")
        expected = int(self._lan_expected_players)
        connected = int(self._lan_connected_players)
        state = "waiting" if self._lan_wait_gate_active() else "active"
        self._draw_ui_text(
            f"lan: role={role} players={connected}/{expected} state={state}",
            Vec2(float(x), float(y)),
            rl.Color(130, 180, 240, 255),
            scale=0.9,
        )
        y += float(line_h)

        if self._lan_wait_gate_active():
            self._draw_ui_text(
                "lan(wait): simulation paused until all peers are ready",
                Vec2(float(x), float(y)),
                rl.Color(130, 180, 240, 255),
                scale=0.9,
            )
            y += float(line_h)
            self._draw_ui_text(
                "debug: F10 force start (temporary bring-up override)",
                Vec2(float(x), float(y)),
                rl.Color(130, 180, 240, 255),
                scale=0.8,
            )
            y += float(line_h)

        return float(y)

    def _draw_lan_wait_overlay(self) -> None:
        if not self._lan_wait_gate_active():
            return

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        if screen_w <= 0.0 or screen_h <= 0.0:
            return

        rl.draw_rectangle(
            0,
            0,
            int(screen_w),
            int(screen_h),
            rl.Color(8, 12, 18, 148),
        )

        panel_w = min(560.0, max(320.0, screen_w - 80.0))
        panel_h = 156.0
        panel_x = 0.5 * (screen_w - panel_w)
        panel_y = max(36.0, 0.17 * screen_h)

        rl.draw_rectangle(
            int(panel_x),
            int(panel_y),
            int(panel_w),
            int(panel_h),
            rl.Color(17, 24, 34, 230),
        )
        rl.draw_rectangle_lines_ex(
            rl.Rectangle(panel_x, panel_y, panel_w, panel_h),
            2.0,
            rl.Color(108, 170, 230, 220),
        )

        dots = "." * int((self._cursor_pulse_time * 2.5) % 4)
        title = f"Waiting for LAN players{dots}"
        connected = int(self._lan_connected_players)
        expected = int(self._lan_expected_players)
        status = f"Connected peers: {connected}/{expected}"
        role = "Host" if str(self._lan_role) == "host" else "Client"
        role_line = f"Role: {role}"
        hint = (
            "Match will start automatically when all peers are connected."
            if role == "Host"
            else "Waiting for host to finish lobby and start the match."
        )

        text_x = panel_x + 22.0
        text_y = panel_y + 20.0
        line_h = float(self._ui_line_height(scale=0.95))
        self._draw_ui_text(title, Vec2(text_x, text_y), rl.Color(230, 237, 247, 255), scale=0.95)
        self._draw_ui_text(status, Vec2(text_x, text_y + line_h * 1.4), rl.Color(169, 214, 255, 255), scale=0.9)
        self._draw_ui_text(role_line, Vec2(text_x, text_y + line_h * 2.4), rl.Color(169, 214, 255, 255), scale=0.9)
        self._draw_ui_text(hint, Vec2(text_x, text_y + line_h * 3.5), rl.Color(186, 196, 214, 255), scale=0.82)

        if debug_enabled():
            self._draw_ui_text(
                "Debug override: press F10 to force start",
                Vec2(text_x, text_y + line_h * 4.5),
                rl.Color(232, 197, 117, 255),
                scale=0.8,
            )

    def _player_name_default(self) -> str:
        return str(self.config.player_name or "")

    def open(self) -> None:
        self.close_requested = False
        self._action = None
        self._paused = False
        self._missing_assets.clear()
        self._hud_missing.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)

        self._hud_assets = load_hud_assets(self._assets_root)
        if self._hud_assets.missing:
            self._hud_missing = list(self._hud_assets.missing)
        self._hud_state = HudState()

        self._game_over_active = False
        self._game_over_record = None
        self._game_over_banner = "reaper"
        self._game_over_ui.close()

        player_count = self.config.player_count
        if self._lan_seed_override is not None:
            seed = int(self._lan_seed_override)
        else:
            seed = random.getrandbits(32)
        self.world.reset(seed=seed, player_count=max(1, min(4, player_count)))
        self.world.open()
        self._bind_world()
        self._local_input.reset(players=self.world.players)

        self._ui_mouse = Vec2(float(rl.get_screen_width()) * 0.5, float(rl.get_screen_height()) * 0.5)
        self._cursor_pulse_time = 0.0

    def close(self) -> None:
        self._game_over_ui.close()
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        self._hud_assets = None
        self.world.close()

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
            play_sfx=self.world.audio_router.play_sfx,
            rand=self.state.rng.rand,
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

    def _world_entity_alpha(self) -> float:
        if not self._game_over_active:
            return 1.0
        return float(self._game_over_ui.world_entity_alpha())

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        alpha = float(entity_alpha)
        if alpha < 0.0:
            alpha = 0.0
        elif alpha > 1.0:
            alpha = 1.0
        self.world.draw(draw_aim_indicators=False, entity_alpha=self._world_entity_alpha() * alpha)

    def steal_ground_for_menu(self):
        ground = self.world.ground
        self.world.ground = None
        return ground

    def adopt_ground_from_menu(self, ground: GroundRenderer | None) -> None:
        if ground is None:
            return
        current = self.world.ground
        if current is not None and current is not ground and current.render_target is not None:
            rl.unload_render_texture(current.render_target)
            current.render_target = None
        self.world.ground = ground
        self.world._sync_ground_settings()

    def menu_ground_camera(self) -> Vec2:
        return self.world.camera

    def console_elapsed_ms(self) -> float:
        return float(self.world._elapsed_ms)

    def regenerate_terrain_for_console(self) -> None:
        if self.world.ground is None:
            return
        terrain_seed = int(self.state.rng.rand() % 10_000)
        self.world.ground.schedule_generate(seed=terrain_seed, layers=3)

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
            players=self.world.players,
            config=self.config,
            mouse_screen=self._ui_mouse,
            screen_to_world=self.world.screen_to_world,
            dt_frame=float(dt_frame),
            creatures=self.creatures.entries,
        )

    @staticmethod
    def _clear_local_input_edges(inputs: list[PlayerInput]) -> list[PlayerInput]:
        return clear_input_edges(inputs)
