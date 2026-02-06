from __future__ import annotations

from dataclasses import dataclass
import math

import pyray as rl

from grim.config import ensure_crimson_cfg
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.math import clamp
from grim.view import View, ViewContext

from ..bonuses import BonusId
from ..creatures.spawn import CreatureInit, CreatureTypeId
from ..game_world import GameWorld
from ..gameplay import PlayerInput, bonus_apply
from ..paths import default_runtime_dir
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view


WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


@dataclass(frozen=True, slots=True)
class _SpawnSpec:
    r: float
    angle_rad: float
    type_id: CreatureTypeId
    hp: float


class CameraShakeView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        runtime_dir = default_runtime_dir()
        config = None
        if runtime_dir.is_dir():
            try:
                config = ensure_crimson_cfg(runtime_dir)
            except Exception:
                config = None

        self.close_requested = False
        self._world = GameWorld(
            assets_dir=self._assets_root,
            world_size=WORLD_SIZE,
            demo_mode_active=False,
            difficulty_level=0,
            hardcore=False,
            preserve_bugs=bool(ctx.preserve_bugs),
            texture_cache=None,
            config=config,
            audio=None,
            audio_rng=None,
        )
        self._reflex_boost_locked = False
        self._reset_scene()

    def _spawn_creature(self, *, world_x: float, world_y: float, type_id: CreatureTypeId, hp: float) -> None:
        init = CreatureInit(
            origin_template_id=0,
            pos=Vec2(
                clamp(world_x, 64.0, WORLD_SIZE - 64.0),
                clamp(world_y, 64.0, WORLD_SIZE - 64.0),
            ),
            heading=math.pi,
            phase_seed=0.0,
            type_id=type_id,
            health=float(hp),
            max_health=float(hp),
            move_speed=0.0,
            reward_value=0.0,
            size=50.0,
            contact_damage=0.0,
        )
        self._world.creatures.spawn_init(init, rand=self._world.state.rng.rand)

    def _reset_scene(self) -> None:
        self._world.reset(seed=0xBEEF, player_count=1)
        self._world.state.camera_shake_offset = Vec2()
        self._world.state.camera_shake_timer = 0.0
        self._world.state.camera_shake_pulses = 0

        player = self._world.players[0]
        player.pos = Vec2(WORLD_SIZE * 0.5, WORLD_SIZE * 0.5)

        spawn = [
            _SpawnSpec(r=140.0, angle_rad=0.0, type_id=CreatureTypeId.ZOMBIE, hp=50.0),
            _SpawnSpec(r=160.0, angle_rad=math.pi * 0.5, type_id=CreatureTypeId.LIZARD, hp=60.0),
            _SpawnSpec(r=180.0, angle_rad=math.pi, type_id=CreatureTypeId.ALIEN, hp=70.0),
            _SpawnSpec(r=200.0, angle_rad=math.pi * 1.5, type_id=CreatureTypeId.SPIDER_SP1, hp=80.0),
            _SpawnSpec(r=320.0, angle_rad=math.pi * 0.25, type_id=CreatureTypeId.SPIDER_SP2, hp=90.0),
            _SpawnSpec(r=460.0, angle_rad=math.pi * 1.25, type_id=CreatureTypeId.ZOMBIE, hp=100.0),
        ]
        for entry in spawn:
            x = player.pos.x + math.cos(entry.angle_rad) * entry.r
            y = player.pos.y + math.sin(entry.angle_rad) * entry.r
            self._spawn_creature(world_x=x, world_y=y, type_id=entry.type_id, hp=entry.hp)

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None
        self._world.open()

    def close(self) -> None:
        self._world.close()
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._reset_scene()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_N):
            player = self._world.players[0]
            bonus_apply(
                self._world.state,
                player,
                BonusId.NUKE,
                origin=player,
                creatures=self._world.creatures.entries,
            )

        if rl.is_key_pressed(rl.KeyboardKey.KEY_T):
            self._reflex_boost_locked = not self._reflex_boost_locked
            self._world.state.bonuses.reflex_boost = 9999.0 if self._reflex_boost_locked else 0.0

    def _build_input(self) -> PlayerInput:
        move = Vec2(
            float(rl.is_key_down(rl.KeyboardKey.KEY_D)) - float(rl.is_key_down(rl.KeyboardKey.KEY_A)),
            float(rl.is_key_down(rl.KeyboardKey.KEY_S)) - float(rl.is_key_down(rl.KeyboardKey.KEY_W)),
        )

        mouse = rl.get_mouse_position()
        aim = self._world.screen_to_world(Vec2(mouse.x, mouse.y))

        fire_down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        fire_pressed = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        reload_pressed = rl.is_key_pressed(rl.KeyboardKey.KEY_R)

        return PlayerInput(
            move=move,
            aim=aim,
            fire_down=bool(fire_down),
            fire_pressed=bool(fire_pressed),
            reload_pressed=bool(reload_pressed),
        )

    def update(self, dt: float) -> None:
        self._handle_input()
        if self._reflex_boost_locked:
            self._world.state.bonuses.reflex_boost = 9999.0
        self._world.update(dt, inputs=[self._build_input()], auto_pick_perks=True, perk_progression_enabled=False)

    def draw(self) -> None:
        self._world.draw()

        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            draw_ui_text(self._small, message, 24, 24, scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)

        state = self._world.state
        cam_x, cam_y, _sx, _sy = self._world._world_params()
        lines = [
            "WASD move  N: nuke shake  T: toggle reflex-boost shake-rate  R: reset  Esc: exit",
            f"camera_offset=({cam_x:.1f},{cam_y:.1f})  camera_raw=({self._world.camera_x:.1f},{self._world.camera_y:.1f})",
            f"shake_offset=({state.camera_shake_offset.x:.1f},{state.camera_shake_offset.y:.1f})  "
            f"shake_timer={state.camera_shake_timer:.3f}  pulses={state.camera_shake_pulses}",
            f"reflex_boost={state.bonuses.reflex_boost:.2f}  creatures_alive={len(self._world.creatures.iter_active())}",
        ]
        x = 24.0
        y = 24.0 + float(ui_line_height(self._small, scale=UI_TEXT_SCALE)) + 12.0
        for idx, line in enumerate(lines):
            color = UI_HINT_COLOR if idx == 0 else UI_TEXT_COLOR
            draw_ui_text(self._small, line, x, y, scale=UI_TEXT_SCALE, color=color)
            y += float(ui_line_height(self._small, scale=UI_TEXT_SCALE))


@register_view("camera-shake", "Camera shake")
def build_camera_shake_view(*, ctx: ViewContext) -> View:
    return CameraShakeView(ctx)
