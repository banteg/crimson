from __future__ import annotations

from dataclasses import dataclass, field
import math
import random
from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache, load_paq_entries_from_path
from grim.audio import AudioState, play_sfx
from grim.config import CrimsonConfig
from grim.fx_queue import FxQueueTextures, bake_fx_queues
from grim.terrain_render import GroundRenderer

from .bonuses import BONUS_BY_ID
from .creatures.anim import creature_anim_advance_phase, creature_anim_select_frame
from .creatures.runtime import CreaturePool
from .creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from .effects import FxQueue, FxQueueRotated
from .gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_update,
    player_update,
    survival_progression_update,
    weapon_assign_player,
)
from .projectiles import (
    FIRE_BULLETS_PROJECTILE_TYPE_ID,
    GAUSS_GUN_PROJECTILE_TYPE_ID,
    ION_CANNON_PROJECTILE_TYPE_ID,
    ION_MINIGUN_PROJECTILE_TYPE_ID,
    ION_RIFLE_PROJECTILE_TYPE_ID,
    ROCKET_LAUNCHER_PROJECTILE_TYPE_ID,
    SHRINKIFIER_PROJECTILE_TYPE_ID,
)
from .weapon_sfx import resolve_weapon_sfx_ref
from .weapons import WEAPON_BY_ID, WEAPON_TABLE

GAME_MODE_SURVIVAL = 3


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


ProjectileHit = tuple[int, float, float, float, float]


@dataclass(frozen=True, slots=True)
class CreatureAnimInfo:
    base: int
    anim_rate: float
    mirror: bool


_CREATURE_ANIM: dict[CreatureTypeId, CreatureAnimInfo] = {
    CreatureTypeId.ZOMBIE: CreatureAnimInfo(base=0x20, anim_rate=1.2, mirror=False),
    CreatureTypeId.LIZARD: CreatureAnimInfo(base=0x10, anim_rate=1.6, mirror=True),
    CreatureTypeId.ALIEN: CreatureAnimInfo(base=0x20, anim_rate=1.35, mirror=False),
    CreatureTypeId.SPIDER_SP1: CreatureAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.SPIDER_SP2: CreatureAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.TROOPER: CreatureAnimInfo(base=0x00, anim_rate=1.0, mirror=False),
}

_CREATURE_ASSET: dict[CreatureTypeId, str] = {
    CreatureTypeId.ZOMBIE: "zombie",
    CreatureTypeId.LIZARD: "lizard",
    CreatureTypeId.ALIEN: "alien",
    CreatureTypeId.SPIDER_SP1: "spider_sp1",
    CreatureTypeId.SPIDER_SP2: "spider_sp2",
    CreatureTypeId.TROOPER: "trooper",
}

_KNOWN_PROJ_FRAMES: dict[int, tuple[int, int]] = {
    0x13: (2, 0),  # Jackhammer
    0x1D: (4, 3),  # Gauss Shotgun
    0x19: (4, 6),  # Spider Plasma
    ION_MINIGUN_PROJECTILE_TYPE_ID: (4, 2),
    ION_CANNON_PROJECTILE_TYPE_ID: (4, 2),
    SHRINKIFIER_PROJECTILE_TYPE_ID: (4, 2),
    FIRE_BULLETS_PROJECTILE_TYPE_ID: (4, 2),
    ION_RIFLE_PROJECTILE_TYPE_ID: (4, 2),
}

_BEAM_TYPES = frozenset(
    {
        ION_RIFLE_PROJECTILE_TYPE_ID,
        ION_MINIGUN_PROJECTILE_TYPE_ID,
        ION_CANNON_PROJECTILE_TYPE_ID,
        SHRINKIFIER_PROJECTILE_TYPE_ID,
        FIRE_BULLETS_PROJECTILE_TYPE_ID,
        0x1D,  # Gauss Shotgun
        0x19,  # Spider Plasma
    }
)

_BULLET_HIT_SFX = (
    "sfx_bullet_hit_01",
    "sfx_bullet_hit_02",
    "sfx_bullet_hit_03",
    "sfx_bullet_hit_04",
    "sfx_bullet_hit_05",
    "sfx_bullet_hit_06",
)

_CREATURE_DEATH_SFX: dict[CreatureTypeId, tuple[str, ...]] = {
    CreatureTypeId.ZOMBIE: (
        "sfx_zombie_die_01",
        "sfx_zombie_die_02",
        "sfx_zombie_die_03",
        "sfx_zombie_die_04",
    ),
    CreatureTypeId.LIZARD: (
        "sfx_lizard_die_01",
        "sfx_lizard_die_02",
        "sfx_lizard_die_03",
        "sfx_lizard_die_04",
    ),
    CreatureTypeId.ALIEN: (
        "sfx_alien_die_01",
        "sfx_alien_die_02",
        "sfx_alien_die_03",
        "sfx_alien_die_04",
    ),
    CreatureTypeId.SPIDER_SP1: (
        "sfx_spider_die_01",
        "sfx_spider_die_02",
        "sfx_spider_die_03",
        "sfx_spider_die_04",
    ),
    CreatureTypeId.SPIDER_SP2: (
        "sfx_spider_die_01",
        "sfx_spider_die_02",
        "sfx_spider_die_03",
        "sfx_spider_die_04",
    ),
    CreatureTypeId.TROOPER: (
        "sfx_trooper_die_01",
        "sfx_trooper_die_02",
        "sfx_trooper_die_03",
        "sfx_trooper_die_04",
    ),
}

_MAX_HIT_SFX_PER_FRAME = 4
_MAX_DEATH_SFX_PER_FRAME = 3

_RAD_TO_DEG = 57.29577951308232


@dataclass(slots=True)
class GameWorld:
    assets_dir: Path
    world_size: float = 1024.0
    demo_mode_active: bool = False
    difficulty_level: int = 0
    hardcore: bool = False
    texture_cache: PaqTextureCache | None = None
    config: CrimsonConfig | None = None
    audio: AudioState | None = None
    audio_rng: random.Random | None = None

    spawn_env: SpawnEnv = field(init=False)
    state: GameplayState = field(init=False)
    players: list[PlayerState] = field(init=False)
    creatures: CreaturePool = field(init=False)
    camera_x: float = field(init=False, default=-1.0)
    camera_y: float = field(init=False, default=-1.0)
    _damage_scale_by_type: dict[int, float] = field(init=False, default_factory=dict)
    missing_assets: list[str] = field(init=False, default_factory=list)
    ground: GroundRenderer | None = field(init=False, default=None)
    fx_queue: FxQueue = field(init=False)
    fx_queue_rotated: FxQueueRotated = field(init=False)
    fx_textures: FxQueueTextures | None = field(init=False, default=None)
    creature_textures: dict[str, rl.Texture] = field(init=False, default_factory=dict)
    projs_texture: rl.Texture | None = field(init=False, default=None)
    particles_texture: rl.Texture | None = field(init=False, default=None)
    bonuses_texture: rl.Texture | None = field(init=False, default=None)
    bodyset_texture: rl.Texture | None = field(init=False, default=None)
    _owned_textures: list[rl.Texture] = field(init=False, default_factory=list)
    _cache_owned: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        self.spawn_env = SpawnEnv(
            terrain_width=float(self.world_size),
            terrain_height=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            difficulty_level=int(self.difficulty_level),
        )
        self.state = GameplayState()
        self.players: list[PlayerState] = []
        self.creatures = CreaturePool(env=self.spawn_env)
        self.fx_queue = FxQueue()
        self.fx_queue_rotated = FxQueueRotated()
        self.camera_x = -1.0
        self.camera_y = -1.0
        self._damage_scale_by_type = {
            entry.weapon_id: float(entry.damage_mult or 1.0)
            for entry in WEAPON_TABLE
            if entry.weapon_id >= 0
        }
        self.reset()

    def reset(
        self,
        *,
        seed: int = 0xBEEF,
        player_count: int = 1,
        spawn_x: float | None = None,
        spawn_y: float | None = None,
    ) -> None:
        self.state = GameplayState()
        self.state.rng.srand(int(seed))
        self.creatures = CreaturePool(env=self.spawn_env)
        self.fx_queue.clear()
        self.fx_queue_rotated.clear()
        self.players = []
        base_x = float(self.world_size) * 0.5 if spawn_x is None else float(spawn_x)
        base_y = float(self.world_size) * 0.5 if spawn_y is None else float(spawn_y)
        for idx in range(max(1, int(player_count))):
            player = PlayerState(index=idx, pos_x=base_x, pos_y=base_y)
            weapon_assign_player(player, 0)
            self.players.append(player)
        self.camera_x = -1.0
        self.camera_y = -1.0
        if self.ground is not None:
            terrain_seed = int(self.state.rng.rand() % 10_000)
            self.ground.schedule_generate(seed=terrain_seed, layers=3)

    def _resolve_asset(self, rel_path: str) -> Path | None:
        direct = self.assets_dir / rel_path
        if direct.is_file():
            return direct
        legacy = self.assets_dir / "crimson" / rel_path
        if legacy.is_file():
            return legacy
        return None

    def _ensure_texture_cache(self) -> PaqTextureCache | None:
        if self.texture_cache is not None:
            return self.texture_cache
        paq_path = self.assets_dir / "crimson.paq"
        if not paq_path.is_file():
            return None
        entries = load_paq_entries_from_path(paq_path)
        cache = PaqTextureCache(entries=entries, textures={})
        self.texture_cache = cache
        self._cache_owned = True
        return cache

    def _load_texture(self, name: str, *, cache_path: str, file_path: str) -> rl.Texture | None:
        cache = self._ensure_texture_cache()
        if cache is not None:
            try:
                asset = cache.get_or_load(name, cache_path)
                return asset.texture
            except Exception:
                self.missing_assets.append(cache_path)
                return None

        path = self._resolve_asset(file_path)
        if path is None:
            self.missing_assets.append(file_path)
            return None
        texture = rl.load_texture(str(path))
        self._owned_textures.append(texture)
        return texture

    @staticmethod
    def _png_path_for(rel_path: str) -> str:
        lower = rel_path.lower()
        if lower.endswith(".jaz"):
            return rel_path[:-4] + ".png"
        return rel_path

    def _sync_ground_settings(self) -> None:
        if self.ground is None:
            return
        if self.config is None:
            self.ground.texture_scale = 1.0
            self.ground.screen_width = None
            self.ground.screen_height = None
            return
        self.ground.texture_scale = float(self.config.texture_scale)
        self.ground.screen_width = float(self.config.screen_width)
        self.ground.screen_height = float(self.config.screen_height)

    def set_terrain(self, *, base_key: str, overlay_key: str, base_path: str, overlay_path: str) -> None:
        base = self._load_texture(
            base_key,
            cache_path=base_path,
            file_path=self._png_path_for(base_path),
        )
        overlay = self._load_texture(
            overlay_key,
            cache_path=overlay_path,
            file_path=self._png_path_for(overlay_path),
        )
        detail = overlay or base
        if base is None:
            return
        if self.ground is None:
            self.ground = GroundRenderer(
                texture=base,
                overlay=overlay,
                overlay_detail=detail,
                width=int(self.world_size),
                height=int(self.world_size),
                texture_scale=1.0,
                screen_width=None,
                screen_height=None,
            )
        else:
            self.ground.texture = base
            self.ground.overlay = overlay
            self.ground.overlay_detail = detail
        self._sync_ground_settings()
        terrain_seed = int(self.state.rng.rand() % 10_000)
        self.ground.schedule_generate(seed=terrain_seed, layers=3)

    def open(self) -> None:
        self.close()
        self.missing_assets.clear()
        self.creature_textures.clear()

        base = self._load_texture(
            "ter_q1_base",
            cache_path="ter/ter_q1_base.jaz",
            file_path="ter/ter_q1_base.png",
        )
        overlay = self._load_texture(
            "ter_q1_tex1",
            cache_path="ter/ter_q1_tex1.jaz",
            file_path="ter/ter_q1_tex1.png",
        )
        detail = overlay or base
        if base is not None:
            if self.ground is None:
                self.ground = GroundRenderer(
                    texture=base,
                    overlay=overlay,
                    overlay_detail=detail,
                    width=int(self.world_size),
                    height=int(self.world_size),
                    texture_scale=1.0,
                    screen_width=None,
                    screen_height=None,
                )
            else:
                self.ground.texture = base
                self.ground.overlay = overlay
                self.ground.overlay_detail = detail
            self._sync_ground_settings()
            terrain_seed = int(self.state.rng.rand() % 10_000)
            self.ground.schedule_generate(seed=terrain_seed, layers=3)

        for asset in sorted(set(_CREATURE_ASSET.values())):
            texture = self._load_texture(
                asset,
                cache_path=f"game/{asset}.jaz",
                file_path=f"game/{asset}.png",
            )
            if texture is not None:
                self.creature_textures[asset] = texture

        self.projs_texture = self._load_texture(
            "projs",
            cache_path="game/projs.jaz",
            file_path="game/projs.png",
        )
        self.particles_texture = self._load_texture(
            "particles",
            cache_path="game/particles.jaz",
            file_path="game/particles.png",
        )
        self.bonuses_texture = self._load_texture(
            "bonuses",
            cache_path="game/bonuses.jaz",
            file_path="game/bonuses.png",
        )
        self.bodyset_texture = self._load_texture(
            "bodyset",
            cache_path="game/bodyset.jaz",
            file_path="game/bodyset.png",
        )

        if self.particles_texture is not None and self.bodyset_texture is not None:
            self.fx_textures = FxQueueTextures(
                particles=self.particles_texture,
                bodyset=self.bodyset_texture,
            )
        else:
            self.fx_textures = None

    def close(self) -> None:
        if self.ground is not None and self.ground.render_target is not None:
            rl.unload_render_texture(self.ground.render_target)
            self.ground.render_target = None
        self.ground = None

        for texture in self._owned_textures:
            rl.unload_texture(texture)
        self._owned_textures.clear()

        self.creature_textures.clear()
        self.projs_texture = None
        self.particles_texture = None
        self.bonuses_texture = None
        self.bodyset_texture = None
        self.fx_textures = None
        self.fx_queue.clear()
        self.fx_queue_rotated.clear()

        if self._cache_owned and self.texture_cache is not None:
            self.texture_cache.unload()
            self.texture_cache = None
            self._cache_owned = False

    def update(
        self,
        dt: float,
        *,
        inputs: list[PlayerInput] | None = None,
        auto_pick_perks: bool = False,
        game_mode: int = GAME_MODE_SURVIVAL,
    ) -> list[ProjectileHit]:
        if inputs is None:
            inputs = [PlayerInput() for _ in self.players]

        if self.ground is not None:
            self._sync_ground_settings()
            self.ground.process_pending()

        prev_positions = [(player.pos_x, player.pos_y) for player in self.players]
        prev_audio = [(player.ammo, player.reload_active, player.reload_timer) for player in self.players]

        hits = self.state.projectiles.update(
            dt,
            self.creatures.entries,
            world_size=float(self.world_size),
            damage_scale_by_type=self._damage_scale_by_type,
            rng=self.state.rng.rand,
            runtime_state=self.state,
        )
        self.state.secondary_projectiles.update_pulse_gun(dt, self.creatures.entries)
        if hits:
            self._queue_projectile_decals(hits)
            self._play_hit_sfx(hits)

        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player_update(player, input_state, dt, self.state, world_size=float(self.world_size))
            if idx < len(prev_audio):
                prev_ammo, prev_reload_active, prev_reload_timer = prev_audio[idx]
                self._handle_player_audio(
                    player,
                    prev_ammo=prev_ammo,
                    prev_reload_active=prev_reload_active,
                    prev_reload_timer=prev_reload_timer,
                )

        creature_result = self.creatures.update(
            dt,
            state=self.state,
            players=self.players,
            world_width=float(self.world_size),
            world_height=float(self.world_size),
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
        )
        if creature_result.deaths:
            self._play_death_sfx(creature_result.deaths)

        if dt > 0.0:
            self._advance_creature_anim(dt)
            self._advance_player_anim(dt, prev_positions)

        bonus_update(self.state, self.players, dt, creatures=self.creatures.entries, update_hud=True)

        if game_mode == GAME_MODE_SURVIVAL:
            survival_progression_update(self.state, self.players, game_mode=game_mode, auto_pick=auto_pick_perks)

        self._bake_fx_queues()
        self.update_camera(dt)
        return hits

    def _queue_projectile_decals(self, hits: list[ProjectileHit]) -> None:
        if self.ground is None or self.fx_textures is None:
            return
        rand = self.state.rng.rand
        for type_id, _ox, _oy, hit_x, hit_y in hits:
            effect_id = 0x07
            tint = (1.0, 0.25, 0.25, 1.0)
            if int(type_id) in _BEAM_TYPES:
                effect_id = 0x01
                tint = (0.7, 0.9, 1.0, 1.0)
            elif int(type_id) in (GAUSS_GUN_PROJECTILE_TYPE_ID, ROCKET_LAUNCHER_PROJECTILE_TYPE_ID):
                effect_id = 0x11
                tint = (1.0, 0.6, 0.3, 1.0)
            size = float(int(rand()) % 18 + 18)
            rotation = float(int(rand()) % 628) * 0.01
            self.fx_queue.add(
                effect_id=effect_id,
                pos_x=float(hit_x),
                pos_y=float(hit_y),
                width=size,
                height=size,
                rotation=rotation,
                rgba=tint,
            )

    def _rand_choice(self, options: tuple[str, ...]) -> str | None:
        if not options:
            return None
        idx = int(self.state.rng.rand()) % len(options)
        return options[idx]

    def _play_sfx(self, key: str | None) -> None:
        if self.audio is None:
            return
        play_sfx(self.audio, key, rng=self.audio_rng)

    def _handle_player_audio(self, player: PlayerState, *, prev_ammo: int, prev_reload_active: bool, prev_reload_timer: float) -> None:
        if self.audio is None:
            return
        weapon = WEAPON_BY_ID.get(int(player.weapon_id))
        if weapon is None:
            return

        if player.ammo < prev_ammo:
            self._play_sfx(resolve_weapon_sfx_ref(weapon.fire_sound))

        reload_started = (not prev_reload_active and player.reload_active) or (player.reload_timer > prev_reload_timer + 1e-6)
        if reload_started:
            self._play_sfx(resolve_weapon_sfx_ref(weapon.reload_sound))

    def _hit_sfx_for_type(self, type_id: int) -> str | None:
        if type_id == ROCKET_LAUNCHER_PROJECTILE_TYPE_ID:
            return "sfx_explosion_large"
        if type_id in _BEAM_TYPES:
            return "sfx_shock_hit_01"
        return self._rand_choice(_BULLET_HIT_SFX)

    def _play_hit_sfx(self, hits: list[ProjectileHit]) -> None:
        if self.audio is None or not hits:
            return
        for idx in range(min(len(hits), _MAX_HIT_SFX_PER_FRAME)):
            type_id = int(hits[idx][0])
            self._play_sfx(self._hit_sfx_for_type(type_id))

    def _play_death_sfx(self, deaths: tuple[object, ...]) -> None:
        if self.audio is None or not deaths:
            return
        for idx in range(min(len(deaths), _MAX_DEATH_SFX_PER_FRAME)):
            death = deaths[idx]
            type_id = getattr(death, "type_id", None)
            if type_id is None:
                continue
            try:
                creature_type = CreatureTypeId(int(type_id))
            except ValueError:
                continue
            options = _CREATURE_DEATH_SFX.get(creature_type)
            if options:
                self._play_sfx(self._rand_choice(options))

    def _advance_creature_anim(self, dt: float) -> None:
        for creature in self.creatures.entries:
            if not (creature.active and creature.hp > 0.0):
                continue
            try:
                type_id = CreatureTypeId(int(creature.type_id))
            except ValueError:
                continue
            info = _CREATURE_ANIM.get(type_id)
            if info is None:
                continue
            creature.anim_phase, _ = creature_anim_advance_phase(
                creature.anim_phase,
                anim_rate=info.anim_rate,
                move_speed=float(creature.move_speed),
                dt=dt,
                size=float(creature.size),
                local_scale=1.0,
                flags=creature.flags,
                ai_mode=int(creature.ai_mode),
            )

    def _advance_player_anim(self, dt: float, prev_positions: list[tuple[float, float]]) -> None:
        info = _CREATURE_ANIM.get(CreatureTypeId.TROOPER)
        if info is None:
            return
        for idx, player in enumerate(self.players):
            if idx >= len(prev_positions):
                continue
            prev_x, prev_y = prev_positions[idx]
            speed = math.hypot(player.pos_x - prev_x, player.pos_y - prev_y)
            move_speed = speed / dt / 120.0 if dt > 0.0 else 0.0
            player.move_phase, _ = creature_anim_advance_phase(
                player.move_phase,
                anim_rate=info.anim_rate,
                move_speed=move_speed,
                dt=dt,
                size=float(player.size),
                local_scale=1.0,
                flags=CreatureFlags(0),
                ai_mode=0,
            )

    def _bake_fx_queues(self) -> None:
        if self.ground is None or self.fx_textures is None:
            return
        if not (self.fx_queue.count or self.fx_queue_rotated.count):
            return
        bake_fx_queues(
            self.ground,
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            textures=self.fx_textures,
            corpse_frame_for_type=self._corpse_frame_for_type,
        )

    @staticmethod
    def _corpse_frame_for_type(type_id: int) -> int:
        return int(type_id) & 0xF

    def _camera_screen_size(self) -> tuple[float, float]:
        if self.config is not None:
            screen_w = float(self.config.screen_width)
            screen_h = float(self.config.screen_height)
        else:
            screen_w = float(rl.get_screen_width())
            screen_h = float(rl.get_screen_height())
        if screen_w > self.world_size:
            screen_w = float(self.world_size)
        if screen_h > self.world_size:
            screen_h = float(self.world_size)
        return screen_w, screen_h

    def _clamp_camera(self, cam_x: float, cam_y: float, screen_w: float, screen_h: float) -> tuple[float, float]:
        min_x = screen_w - float(self.world_size)
        min_y = screen_h - float(self.world_size)
        if cam_x > -1.0:
            cam_x = -1.0
        if cam_x < min_x:
            cam_x = min_x
        if cam_y > -1.0:
            cam_y = -1.0
        if cam_y < min_y:
            cam_y = min_y
        return cam_x, cam_y

    def _world_params(self) -> tuple[float, float, float, float]:
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        screen_w, screen_h = self._camera_screen_size()
        cam_x, cam_y = self._clamp_camera(self.camera_x, self.camera_y, screen_w, screen_h)
        scale_x = out_w / screen_w if screen_w > 0 else 1.0
        scale_y = out_h / screen_h if screen_h > 0 else 1.0
        return cam_x, cam_y, scale_x, scale_y

    def _color_from_rgba(self, rgba: tuple[float, float, float, float]) -> rl.Color:
        r = int(_clamp(rgba[0], 0.0, 1.0) * 255.0 + 0.5)
        g = int(_clamp(rgba[1], 0.0, 1.0) * 255.0 + 0.5)
        b = int(_clamp(rgba[2], 0.0, 1.0) * 255.0 + 0.5)
        a = int(_clamp(rgba[3], 0.0, 1.0) * 255.0 + 0.5)
        return rl.Color(r, g, b, a)

    def _bonus_icon_src(self, texture: rl.Texture, icon_id: int) -> rl.Rectangle:
        grid = 4
        cell_w = float(texture.width) / grid
        cell_h = float(texture.height) / grid
        col = int(icon_id) % grid
        row = int(icon_id) // grid
        return rl.Rectangle(float(col * cell_w), float(row * cell_h), float(cell_w), float(cell_h))

    def _draw_atlas_sprite(
        self,
        texture: rl.Texture,
        *,
        grid: int,
        frame: int,
        x: float,
        y: float,
        scale: float,
        rotation_rad: float = 0.0,
        tint: rl.Color = rl.WHITE,
    ) -> None:
        grid = max(1, int(grid))
        frame = max(0, int(frame))
        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        col = frame % grid
        row = frame // grid
        src = rl.Rectangle(cell_w * float(col), cell_h * float(row), cell_w, cell_h)
        w = cell_w * float(scale)
        h = cell_h * float(scale)
        dst = rl.Rectangle(float(x), float(y), w, h)
        origin = rl.Vector2(w * 0.5, h * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, float(rotation_rad * _RAD_TO_DEG), tint)

    def _draw_creature_sprite(
        self,
        texture: rl.Texture,
        *,
        type_id: CreatureTypeId,
        flags: CreatureFlags,
        phase: float,
        world_x: float,
        world_y: float,
        scale: float,
        size_scale: float,
        tint: rl.Color,
    ) -> None:
        info = _CREATURE_ANIM.get(type_id)
        if info is None:
            return
        frame, _, _ = creature_anim_select_frame(
            phase,
            base_frame=info.base,
            mirror_long=info.mirror,
            flags=flags,
        )
        grid = 8
        cell = float(texture.width) / grid if grid > 0 else float(texture.width)
        row = frame // grid
        col = frame % grid
        src = rl.Rectangle(float(col * cell), float(row * cell), float(cell), float(cell))
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        sx = (world_x + cam_x) * scale_x
        sy = (world_y + cam_y) * scale_y
        width = cell * scale * size_scale
        height = cell * scale * size_scale
        dst = rl.Rectangle(sx, sy, width, height)
        origin = rl.Vector2(width * 0.5, height * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, 0.0, tint)

    def _draw_projectile(self, proj: object, *, scale: float) -> None:
        texture = self.projs_texture
        sx, sy = self.world_to_screen(float(getattr(proj, "pos_x", 0.0)), float(getattr(proj, "pos_y", 0.0)))
        type_id = int(getattr(proj, "type_id", 0))
        mapping = _KNOWN_PROJ_FRAMES.get(type_id)
        if texture is None or mapping is None:
            rl.draw_circle(int(sx), int(sy), max(1.0, 3.0 * scale), rl.Color(240, 220, 160, 255))
            return

        grid, frame = mapping
        life = float(getattr(proj, "life_timer", 0.0))
        angle = float(getattr(proj, "angle", 0.0))

        color = rl.Color(240, 220, 160, 255)
        if type_id in (ION_RIFLE_PROJECTILE_TYPE_ID, ION_MINIGUN_PROJECTILE_TYPE_ID, ION_CANNON_PROJECTILE_TYPE_ID):
            color = rl.Color(120, 200, 255, 255)
        elif type_id == FIRE_BULLETS_PROJECTILE_TYPE_ID:
            color = rl.Color(255, 170, 90, 255)
        elif type_id == SHRINKIFIER_PROJECTILE_TYPE_ID:
            color = rl.Color(160, 255, 170, 255)
        elif type_id == 0x19:
            color = rl.Color(240, 120, 255, 255)

        if type_id in _BEAM_TYPES and life >= 0.4:
            ox = float(getattr(proj, "origin_x", 0.0))
            oy = float(getattr(proj, "origin_y", 0.0))
            dx = float(getattr(proj, "pos_x", 0.0)) - ox
            dy = float(getattr(proj, "pos_y", 0.0)) - oy
            dist = math.hypot(dx, dy)
            if dist > 1e-6:
                step = 14.0
                seg_count = max(1, int(dist // step) + 1)
                dir_x = dx / dist
                dir_y = dy / dist
                for idx in range(seg_count):
                    t = float(idx) / float(max(1, seg_count - 1))
                    px = ox + dir_x * dist * t
                    py = oy + dir_y * dist * t
                    alpha = int(220 * (1.0 - t * 0.75))
                    tint = rl.Color(color.r, color.g, color.b, alpha)
                    psx, psy = self.world_to_screen(px, py)
                    self._draw_atlas_sprite(
                        texture,
                        grid=grid,
                        frame=frame,
                        x=psx,
                        y=psy,
                        scale=0.55 * scale,
                        rotation_rad=angle,
                        tint=tint,
                    )
                return

        alpha = int(_clamp(life / 0.4, 0.0, 1.0) * 255)
        tint = rl.Color(color.r, color.g, color.b, alpha)
        self._draw_atlas_sprite(
            texture,
            grid=grid,
            frame=frame,
            x=sx,
            y=sy,
            scale=0.6 * scale,
            rotation_rad=angle,
            tint=tint,
        )

    def _draw_secondary_projectile(self, proj: object, *, scale: float) -> None:
        sx, sy = self.world_to_screen(float(getattr(proj, "pos_x", 0.0)), float(getattr(proj, "pos_y", 0.0)))
        proj_type = int(getattr(proj, "type_id", 0))
        if proj_type == 4:
            rl.draw_circle(int(sx), int(sy), max(1.0, 12.0 * scale), rl.Color(200, 120, 255, 255))
            return
        if proj_type == 3:
            t = _clamp(float(getattr(proj, "lifetime", 0.0)), 0.0, 1.0)
            radius = float(getattr(proj, "speed", 1.0)) * t * 80.0
            alpha = int((1.0 - t) * 180.0)
            color = rl.Color(200, 120, 255, alpha)
            rl.draw_circle_lines(int(sx), int(sy), max(1.0, radius * scale), color)
            return
        rl.draw_circle(int(sx), int(sy), max(1.0, 4.0 * scale), rl.Color(200, 200, 220, 200))

    def draw(self) -> None:
        clear_color = rl.Color(10, 10, 12, 255)
        screen_w, screen_h = self._camera_screen_size()
        cam_x, cam_y = self._clamp_camera(self.camera_x, self.camera_y, screen_w, screen_h)
        out_w = float(rl.get_screen_width())
        out_h = float(rl.get_screen_height())
        scale_x = out_w / screen_w if screen_w > 0 else 1.0
        scale_y = out_h / screen_h if screen_h > 0 else 1.0
        if self.ground is None:
            rl.clear_background(clear_color)
        else:
            rl.clear_background(clear_color)
            self.ground.draw(cam_x, cam_y, screen_w=screen_w, screen_h=screen_h)
        scale = (scale_x + scale_y) * 0.5

        # World bounds for debug if terrain is missing.
        if self.ground is None:
            x0 = (0.0 + cam_x) * scale_x
            y0 = (0.0 + cam_y) * scale_y
            x1 = (float(self.world_size) + cam_x) * scale_x
            y1 = (float(self.world_size) + cam_y) * scale_y
            rl.draw_rectangle_lines(int(x0), int(y0), int(x1 - x0), int(y1 - y0), rl.Color(40, 40, 55, 255))

        for bonus in self.state.bonus_pool.entries:
            if bonus.bonus_id == 0:
                continue
            sx = (bonus.pos_x + cam_x) * scale_x
            sy = (bonus.pos_y + cam_y) * scale_y
            drawn = False
            if self.bonuses_texture is not None:
                meta = BONUS_BY_ID.get(int(bonus.bonus_id))
                icon_id = meta.icon_id if meta is not None else None
                if icon_id is not None and int(icon_id) >= 0:
                    src = self._bonus_icon_src(self.bonuses_texture, int(icon_id))
                    size = 24.0 * scale
                    dst = rl.Rectangle(float(sx), float(sy), size, size)
                    origin = rl.Vector2(size * 0.5, size * 0.5)
                    rl.draw_texture_pro(self.bonuses_texture, src, dst, origin, 0.0, rl.WHITE)
                    drawn = True
            if not drawn:
                rl.draw_circle(int(sx), int(sy), max(1.0, 10.0 * scale), rl.Color(220, 220, 90, 255))

        for creature in self.creatures.entries:
            if not (creature.active and creature.hp > 0.0):
                continue
            try:
                type_id = CreatureTypeId(int(creature.type_id))
            except ValueError:
                type_id = None
            asset = _CREATURE_ASSET.get(type_id) if type_id is not None else None
            texture = self.creature_textures.get(asset) if asset is not None else None
            if texture is not None:
                tint = self._color_from_rgba((creature.tint_r, creature.tint_g, creature.tint_b, creature.tint_a))
                size_scale = _clamp(float(creature.size) / 64.0, 0.25, 2.0)
                self._draw_creature_sprite(
                    texture,
                    type_id=type_id or CreatureTypeId.ZOMBIE,
                    flags=creature.flags,
                    phase=creature.anim_phase,
                    world_x=creature.x,
                    world_y=creature.y,
                    scale=scale,
                    size_scale=size_scale,
                    tint=tint,
                )
            else:
                sx = (creature.x + cam_x) * scale_x
                sy = (creature.y + cam_y) * scale_y
                rl.draw_circle(int(sx), int(sy), max(1.0, creature.size * 0.5 * scale), rl.Color(220, 90, 90, 255))

        for proj in self.state.projectiles.iter_active():
            self._draw_projectile(proj, scale=scale)

        for proj in self.state.secondary_projectiles.iter_active():
            self._draw_secondary_projectile(proj, scale=scale)

        player = self.players[0] if self.players else None
        if player is not None:
            texture = self.creature_textures.get(_CREATURE_ASSET.get(CreatureTypeId.TROOPER))
            if texture is not None:
                size_scale = _clamp(float(player.size) / 64.0, 0.25, 2.0)
                self._draw_creature_sprite(
                    texture,
                    type_id=CreatureTypeId.TROOPER,
                    flags=CreatureFlags(0),
                    phase=float(player.move_phase),
                    world_x=player.pos_x,
                    world_y=player.pos_y,
                    scale=scale,
                    size_scale=size_scale,
                    tint=rl.Color(240, 240, 255, 255),
                )
            else:
                sx = (player.pos_x + cam_x) * scale_x
                sy = (player.pos_y + cam_y) * scale_y
                rl.draw_circle(int(sx), int(sy), max(1.0, 14.0 * scale), rl.Color(90, 190, 120, 255))

    def update_camera(self, dt: float) -> None:
        if not self.players:
            return
        screen_w, screen_h = self._camera_screen_size()

        focus = self.players[0]
        desired_x = (screen_w * 0.5) - focus.pos_x
        desired_y = (screen_h * 0.5) - focus.pos_y

        desired_x, desired_y = self._clamp_camera(desired_x, desired_y, screen_w, screen_h)

        t = _clamp(dt * 6.0, 0.0, 1.0)
        self.camera_x = _lerp(self.camera_x, desired_x, t)
        self.camera_y = _lerp(self.camera_y, desired_y, t)

    def world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        return (x + cam_x) * scale_x, (y + cam_y) * scale_y

    def screen_to_world(self, x: float, y: float) -> tuple[float, float]:
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        inv_x = 1.0 / scale_x if scale_x > 0 else 1.0
        inv_y = 1.0 / scale_y if scale_y > 0 else 1.0
        return x * inv_x - cam_x, y * inv_y - cam_y
