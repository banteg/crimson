from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random
from typing import Protocol

import pyray as rl

from .audio import AudioState, update_audio
from .assets import PaqTextureCache, load_paq_entries
from .config import CrimsonConfig
from .spawn_templates import CreatureFlags, CreatureTypeId, SPAWN_ID_TO_TEMPLATE
from .terrain_render import GroundRenderer
from .weapons import WEAPON_TABLE


WORLD_SIZE = 1024.0
DEMO_VARIANT_COUNT = 5


class DemoState(Protocol):
    assets_dir: Path
    rng: random.Random
    config: CrimsonConfig
    texture_cache: PaqTextureCache | None
    audio: AudioState | None


@dataclass(frozen=True, slots=True)
class _AnimInfo:
    base: int
    anim_rate: float
    mirror: bool


_TYPE_ANIM: dict[CreatureTypeId, _AnimInfo] = {
    CreatureTypeId.ZOMBIE: _AnimInfo(base=0x20, anim_rate=1.2, mirror=False),
    CreatureTypeId.LIZARD: _AnimInfo(base=0x10, anim_rate=1.6, mirror=True),
    CreatureTypeId.ALIEN: _AnimInfo(base=0x20, anim_rate=1.35, mirror=False),
    CreatureTypeId.SPIDER_SP1: _AnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.SPIDER_SP2: _AnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.TROOPER: _AnimInfo(base=0x00, anim_rate=1.0, mirror=False),
}


@dataclass(slots=True)
class DemoCreature:
    spawn_id: int
    x: float
    y: float
    phase: float = 0.0


@dataclass(slots=True)
class DemoPlayer:
    index: int
    x: float
    y: float
    weapon_id: int
    phase: float = 0.0


def _weapon_name(weapon_id: int) -> str:
    for weapon in WEAPON_TABLE:
        if weapon.weapon_id == weapon_id:
            return weapon.name or f"weapon_{weapon_id}"
    return f"weapon_{weapon_id}"


class DemoView:
    """Attract-mode demo scaffold.

    Modeled after the classic demo helpers in crimsonland.exe:
      - demo_setup_variant_0 @ 0x00402ED0
      - demo_setup_variant_1 @ 0x004030F0
      - demo_setup_variant_2 @ 0x00402FE0
      - demo_setup_variant_3 @ 0x00403250
      - demo_mode_start       @ 0x00403390
    """

    def __init__(self, state: DemoState) -> None:
        self._state = state
        self._ground: GroundRenderer | None = None
        self._creatures: list[DemoCreature] = []
        self._players: list[DemoPlayer] = []
        self._variant_index = 0
        self._variant_elapsed = 0.0
        self._variant_duration = 0.0
        self._finished = False
        self._camera_x = 0.0
        self._camera_y = 0.0

    def open(self) -> None:
        self._finished = False
        self._variant_index = 0
        self._start_variant(0)

    def close(self) -> None:
        if self._ground is not None and self._ground.render_target is not None:
            rl.unload_render_texture(self._ground.render_target)
        self._ground = None
        self._creatures.clear()
        self._players.clear()

    def is_finished(self) -> bool:
        return self._finished

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio)
        if self._finished:
            return
        if self._skip_triggered():
            self._finished = True
            return
        frame_dt = min(dt, 0.1)
        self._variant_elapsed += frame_dt
        self._advance_anim_phase(frame_dt)
        if self._variant_elapsed < self._variant_duration:
            return
        next_variant = self._variant_index + 1
        if next_variant >= DEMO_VARIANT_COUNT:
            self._finished = True
            return
        self._start_variant(next_variant)

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(self._camera_x, self._camera_y)
        self._draw_entities()
        self._draw_overlay()

    def _skip_triggered(self) -> bool:
        if rl.get_key_pressed() != 0:
            return True
        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            return True
        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT):
            return True
        return False

    def _advance_anim_phase(self, dt: float) -> None:
        for creature in self._creatures:
            template = SPAWN_ID_TO_TEMPLATE.get(creature.spawn_id)
            if template is None or template.type_id is None:
                continue
            info = _TYPE_ANIM.get(template.type_id)
            if info is None:
                continue
            creature.phase += info.anim_rate * dt * 60.0
        for player in self._players:
            info = _TYPE_ANIM.get(CreatureTypeId.TROOPER)
            if info is None:
                continue
            player.phase += info.anim_rate * dt * 60.0

    def _ensure_cache(self) -> PaqTextureCache:
        cache = self._state.texture_cache
        if cache is not None:
            return cache
        entries = load_paq_entries(self._state.assets_dir)
        cache = PaqTextureCache(entries=entries, textures={})
        self._state.texture_cache = cache
        return cache

    def _start_variant(self, index: int) -> None:
        self._variant_index = index
        self._variant_elapsed = 0.0
        self._creatures.clear()
        self._players.clear()
        self._apply_variant_ground(index)
        if index == 0:
            self._setup_variant_0()
        elif index == 1:
            self._setup_variant_1()
        elif index == 2:
            self._setup_variant_2()
        elif index == 3:
            self._setup_variant_3()
        else:
            self._setup_variant_0()

    def _apply_variant_ground(self, index: int) -> None:
        cache = self._ensure_cache()
        terrain = {
            0: ("ter_q1_base", "ter_q1_tex1", "ter/ter_q1_base.jaz", "ter/ter_q1_tex1.jaz"),
            1: ("ter_q2_base", "ter_q2_tex1", "ter/ter_q2_base.jaz", "ter/ter_q2_tex1.jaz"),
            2: ("ter_q3_base", "ter_q3_tex1", "ter/ter_q3_base.jaz", "ter/ter_q3_tex1.jaz"),
            3: ("ter_q4_base", "ter_q4_tex1", "ter/ter_q4_base.jaz", "ter/ter_q4_tex1.jaz"),
            4: ("ter_q1_base", "ter_q1_tex1", "ter/ter_q1_base.jaz", "ter/ter_q1_tex1.jaz"),
        }.get(index, ("ter_q1_base", "ter_q1_tex1", "ter/ter_q1_base.jaz", "ter/ter_q1_tex1.jaz"))
        base_key, overlay_key, base_path, overlay_path = terrain
        base = cache.get_or_load(base_key, base_path).texture
        if base is None:
            return
        overlay = cache.get_or_load(overlay_key, overlay_path).texture
        detail = overlay or base
        if self._ground is None:
            self._ground = GroundRenderer(
                texture=base,
                overlay=overlay,
                overlay_detail=detail,
                width=int(WORLD_SIZE),
                height=int(WORLD_SIZE),
                texture_scale=self._state.config.texture_scale,
                screen_width=float(self._state.config.screen_width),
                screen_height=float(self._state.config.screen_height),
            )
        else:
            self._ground.texture = base
            self._ground.overlay = overlay
            self._ground.overlay_detail = detail
            self._ground.texture_scale = self._state.config.texture_scale
            self._ground.screen_width = float(self._state.config.screen_width)
            self._ground.screen_height = float(self._state.config.screen_height)
        self._ground.generate(seed=self._state.rng.randrange(0, 10_000))

    def _wrap_pos(self, x: float, y: float) -> tuple[float, float]:
        return (x % WORLD_SIZE, y % WORLD_SIZE)

    def _spawn(self, spawn_id: int, x: float, y: float) -> None:
        x, y = self._wrap_pos(x, y)
        self._creatures.append(DemoCreature(spawn_id=spawn_id, x=x, y=y))

    def _setup_variant_0(self) -> None:
        self._variant_duration = 4.0
        weapon_id = 11
        self._players = [
            DemoPlayer(index=0, x=448.0, y=384.0, weapon_id=weapon_id),
            DemoPlayer(index=1, x=546.0, y=654.0, weapon_id=weapon_id),
        ]
        y = 256
        i = 0
        while y < 1696:
            col = i % 2
            self._spawn(0x38, float((col + 2) * 64), float(y))
            self._spawn(0x38, float(col * 64 + 798), float(y))
            y += 80
            i += 1

    def _setup_variant_1(self) -> None:
        self._variant_duration = 5.0
        weapon_id = 5
        self._players = [
            DemoPlayer(index=0, x=490.0, y=448.0, weapon_id=weapon_id),
            DemoPlayer(index=1, x=480.0, y=576.0, weapon_id=weapon_id),
        ]
        for idx in range(20):
            x = float(self._state.rng.randrange(200) + 32)
            y = float(self._state.rng.randrange(899) + 64)
            self._spawn(0x34, x, y)
            if idx % 3 != 0:
                x2 = float(self._state.rng.randrange(30) + 32)
                y2 = float(self._state.rng.randrange(899) + 64)
                self._spawn(0x35, x2, y2)

    def _setup_variant_2(self) -> None:
        self._variant_duration = 5.0
        weapon_id = 21
        self._players = [DemoPlayer(index=0, x=512.0, y=512.0, weapon_id=weapon_id)]
        y = 128
        i = 0
        while y < 848:
            col = i % 2
            self._spawn(0x41, float(col * 64 + 32), float(y))
            self._spawn(0x41, float((col + 2) * 64), float(y))
            self._spawn(0x41, float(col * 64 - 64), float(y))
            self._spawn(0x41, float((col + 12) * 64), float(y))
            y += 60
            i += 1

    def _setup_variant_3(self) -> None:
        self._variant_duration = 4.0
        weapon_id = 18
        self._players = [DemoPlayer(index=0, x=512.0, y=512.0, weapon_id=weapon_id)]
        for idx in range(20):
            x = float(self._state.rng.randrange(200) + 32)
            y = float(self._state.rng.randrange(899) + 64)
            self._spawn(0x24, x, y)
            if idx % 3 != 0:
                x2 = float(self._state.rng.randrange(30) + 32)
                y2 = float(self._state.rng.randrange(899) + 64)
                self._spawn(0x25, x2, y2)

    def _world_params(self) -> tuple[float, float, float, float]:
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_w = float(self._state.config.screen_width)
        screen_h = float(self._state.config.screen_height)
        if screen_w > WORLD_SIZE:
            screen_w = WORLD_SIZE
        if screen_h > WORLD_SIZE:
            screen_h = WORLD_SIZE

        cam_x = self._camera_x
        cam_y = self._camera_y
        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        if cam_x < min_x:
            cam_x = min_x
        if cam_x > -1.0:
            cam_x = -1.0
        if cam_y < min_y:
            cam_y = min_y
        if cam_y > -1.0:
            cam_y = -1.0

        scale_x = out_w / screen_w if screen_w > 0 else 1.0
        scale_y = out_h / screen_h if screen_h > 0 else 1.0
        return cam_x, cam_y, scale_x, scale_y

    def _world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        return (x + cam_x) * scale_x, (y + cam_y) * scale_y

    def _select_frame(self, spawn_id: int, phase: float) -> tuple[int, bool]:
        template = SPAWN_ID_TO_TEMPLATE.get(spawn_id)
        if template is None or template.type_id is None:
            return 0, False
        info = _TYPE_ANIM.get(template.type_id)
        if info is None:
            return 0, False
        flags = template.flags or CreatureFlags(0)
        long_strip = not (flags & CreatureFlags.ANIM_PING_PONG) or (
            flags & CreatureFlags.ANIM_LONG_STRIP
        )
        if long_strip:
            base_frame = int(phase) % 32
            frame = base_frame
            if flags & CreatureFlags.RANGED_ATTACK_SHOCK:
                frame += 0x20
            mirror = info.mirror and base_frame >= 16
            return frame, mirror
        ping = int(phase) % 16
        if ping >= 8:
            ping = 15 - ping
        frame = info.base + 0x10 + ping
        return frame, False

    def _draw_entities(self) -> None:
        cache = self._state.texture_cache
        if cache is None:
            return
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        del cam_x, cam_y

        player_tex = cache.get_or_load("trooper", "game/trooper.jaz").texture
        if player_tex is not None:
            for player in self._players:
                self._draw_sprite(
                    player_tex,
                    CreatureTypeId.TROOPER,
                    CreatureFlags(0),
                    player.phase,
                    player.x,
                    player.y,
                    scale_x,
                    scale_y,
                    tint=rl.Color(240, 240, 255, 255),
                )

        for creature in self._creatures:
            template = SPAWN_ID_TO_TEMPLATE.get(creature.spawn_id)
            if template is None or template.creature is None or template.type_id is None:
                continue
            texture = cache.texture(template.creature)
            if texture is None:
                rel_path = f"game/{template.creature}.jaz"
                texture = cache.get_or_load(template.creature, rel_path).texture
            if texture is None:
                continue
            self._draw_sprite(
                texture,
                template.type_id,
                template.flags or CreatureFlags(0),
                creature.phase,
                creature.x,
                creature.y,
                scale_x,
                scale_y,
                tint=rl.WHITE,
            )

    def _draw_sprite(
        self,
        texture: rl.Texture2D,
        type_id: CreatureTypeId,
        flags: CreatureFlags,
        phase: float,
        world_x: float,
        world_y: float,
        scale_x: float,
        scale_y: float,
        *,
        tint: rl.Color,
    ) -> None:
        info = _TYPE_ANIM.get(type_id)
        if info is None:
            return
        long_strip = not (flags & CreatureFlags.ANIM_PING_PONG) or (
            flags & CreatureFlags.ANIM_LONG_STRIP
        )
        if long_strip:
            base_frame = int(phase) % 32
            frame = base_frame
            if flags & CreatureFlags.RANGED_ATTACK_SHOCK:
                frame += 0x20
            mirror = info.mirror and base_frame >= 16
        else:
            ping = int(phase) % 16
            if ping >= 8:
                ping = 15 - ping
            frame = info.base + 0x10 + ping
            mirror = False

        grid = 8
        cell = float(texture.width) / grid if grid > 0 else float(texture.width)
        row = frame // grid
        col = frame % grid
        src = rl.Rectangle(float(col * cell), float(row * cell), float(cell), float(cell))
        if mirror:
            src.x += src.width
            src.width = -src.width
        screen_x, screen_y = self._world_to_screen(world_x, world_y)
        width = cell * scale_x
        height = cell * scale_y
        dst = rl.Rectangle(screen_x, screen_y, width, height)
        origin = rl.Vector2(width * 0.5, height * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, 0.0, tint)

    def _draw_overlay(self) -> None:
        title = f"DEMO MODE  ({self._variant_index + 1}/{DEMO_VARIANT_COUNT})"
        hint = "Press any key / click to skip"
        remaining = max(0.0, self._variant_duration - self._variant_elapsed)
        weapons = ", ".join(
            f"P{p.index + 1}:{_weapon_name(p.weapon_id)}" for p in self._players
        )
        detail = f"{weapons}  —  next in {remaining:0.1f}s"
        rl.draw_text(title, 16, 12, 20, rl.Color(240, 240, 240, 255))
        rl.draw_text(detail, 16, 36, 16, rl.Color(180, 180, 190, 255))
        rl.draw_text(hint, 16, 56, 16, rl.Color(140, 140, 150, 255))

