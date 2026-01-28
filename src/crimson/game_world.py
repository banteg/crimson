from __future__ import annotations

from dataclasses import dataclass, field
import math
import random
from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache, TextureLoader
from grim.audio import AudioState, play_sfx, trigger_game_tune
from grim.config import CrimsonConfig
from grim.math import clamp
from grim.terrain_render import GroundRenderer

from .bonuses import BONUS_BY_ID, BonusId
from .camera import camera_shake_update
from .creatures.anim import creature_anim_advance_phase, creature_anim_select_frame, creature_corpse_frame_for_type
from .creatures.runtime import CreaturePool
from .creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from .effects import FxQueue, FxQueueRotated
from .effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, SIZE_CODE_GRID
from .gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_update,
    perk_active,
    player_update,
    survival_progression_update,
    weapon_assign_player,
)
from .render.terrain_fx import FxQueueTextures, bake_fx_queues
from .perks import PerkId
from .projectiles import ProjectileTypeId
from .weapon_sfx import resolve_weapon_sfx_ref
from .weapons import WEAPON_BY_ID, WEAPON_TABLE

GAME_MODE_SURVIVAL = 3


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
    ProjectileTypeId.JACKHAMMER: (2, 0),
    ProjectileTypeId.GAUSS_SHOTGUN: (4, 3),
    ProjectileTypeId.SPIDER_PLASMA: (4, 6),
    ProjectileTypeId.ION_MINIGUN: (4, 2),
    ProjectileTypeId.ION_CANNON: (4, 2),
    ProjectileTypeId.SHRINKIFIER: (4, 2),
    ProjectileTypeId.FIRE_BULLETS: (4, 2),
    ProjectileTypeId.ION_RIFLE: (4, 2),
}

_BEAM_TYPES = frozenset(
    {
        ProjectileTypeId.ION_RIFLE,
        ProjectileTypeId.ION_MINIGUN,
        ProjectileTypeId.ION_CANNON,
        ProjectileTypeId.SHRINKIFIER,
        ProjectileTypeId.FIRE_BULLETS,
        ProjectileTypeId.GAUSS_SHOTGUN,
        ProjectileTypeId.SPIDER_PLASMA,
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
    bullet_texture: rl.Texture | None = field(init=False, default=None)
    bullet_trail_texture: rl.Texture | None = field(init=False, default=None)
    bonuses_texture: rl.Texture | None = field(init=False, default=None)
    bodyset_texture: rl.Texture | None = field(init=False, default=None)
    clock_table_texture: rl.Texture | None = field(init=False, default=None)
    clock_pointer_texture: rl.Texture | None = field(init=False, default=None)
    muzzle_flash_texture: rl.Texture | None = field(init=False, default=None)
    wicons_texture: rl.Texture | None = field(init=False, default=None)
    _elapsed_ms: float = field(init=False, default=0.0)
    _bonus_anim_phase: float = field(init=False, default=0.0)
    _texture_loader: TextureLoader | None = field(init=False, default=None)

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
            entry.weapon_id: float(entry.damage_scale or 1.0)
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
        self._elapsed_ms = 0.0
        self._bonus_anim_phase = 0.0
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

    def _ensure_texture_loader(self) -> TextureLoader:
        if self._texture_loader is not None:
            return self._texture_loader
        if self.texture_cache is not None:
            loader = TextureLoader(
                assets_root=self.assets_dir,
                cache=self.texture_cache,
                strict=False,
                missing=self.missing_assets,
            )
        else:
            loader = TextureLoader.from_assets_root(self.assets_dir, strict=False)
            loader.missing = self.missing_assets
            if loader.cache is not None:
                self.texture_cache = loader.cache
        self._texture_loader = loader
        return loader

    def _load_texture(self, name: str, *, cache_path: str, file_path: str) -> rl.Texture | None:
        loader = self._ensure_texture_loader()
        return loader.get(name=name, paq_rel=cache_path, fs_rel=file_path)

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
        self.bullet_texture = self._load_texture(
            "bullet_i",
            cache_path="load/bullet16.tga",
            file_path="load/bullet16.png",
        )
        self.bullet_trail_texture = self._load_texture(
            "bulletTrail",
            cache_path="load/bulletTrail.tga",
            file_path="load/bulletTrail.png",
        )
        self.bonuses_texture = self._load_texture(
            "bonuses",
            cache_path="game/bonuses.jaz",
            file_path="game/bonuses.png",
        )
        self.wicons_texture = self._load_texture(
            "ui_wicons",
            cache_path="ui/ui_wicons.jaz",
            file_path="ui/ui_wicons.png",
        )
        self.bodyset_texture = self._load_texture(
            "bodyset",
            cache_path="game/bodyset.jaz",
            file_path="game/bodyset.png",
        )
        self.clock_table_texture = self._load_texture(
            "ui_clockTable",
            cache_path="ui/ui_clockTable.jaz",
            file_path="ui/ui_clockTable.png",
        )
        self.clock_pointer_texture = self._load_texture(
            "ui_clockPointer",
            cache_path="ui/ui_clockPointer.jaz",
            file_path="ui/ui_clockPointer.png",
        )
        self.muzzle_flash_texture = self._load_texture(
            "muzzleFlash",
            cache_path="game/muzzleFlash.jaz",
            file_path="game/muzzleFlash.png",
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

        if self._texture_loader is not None:
            cache_owned = self._texture_loader._cache_owned
            self._texture_loader.unload()
            self._texture_loader = None
            if cache_owned:
                self.texture_cache = None

        self.creature_textures.clear()
        self.projs_texture = None
        self.particles_texture = None
        self.bullet_texture = None
        self.bullet_trail_texture = None
        self.bonuses_texture = None
        self.wicons_texture = None
        self.bodyset_texture = None
        self.clock_table_texture = None
        self.clock_pointer_texture = None
        self.muzzle_flash_texture = None
        self.fx_textures = None
        self.fx_queue.clear()
        self.fx_queue_rotated.clear()

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

        if dt > 0.0:
            self._elapsed_ms += float(dt) * 1000.0
            self._bonus_anim_phase += float(dt) * 1.3

        detail_preset = 5
        if self.config is not None:
            detail_preset = int(self.config.data.get("detail_preset", 5) or 5)

        if self.ground is not None:
            self._sync_ground_settings()
            self.ground.process_pending()

        prev_audio = [(player.shot_seq, player.reload_active, player.reload_timer) for player in self.players]

        # `effects_update` runs early in the native frame loop, before creature/projectile updates.
        self.state.effects.update(dt, fx_queue=self.fx_queue)

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
            self._play_hit_sfx(hits, game_mode=game_mode)

        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player_update(player, input_state, dt, self.state, world_size=float(self.world_size))
            if idx < len(prev_audio):
                prev_shot_seq, prev_reload_active, prev_reload_timer = prev_audio[idx]
                self._handle_player_audio(
                    player,
                    prev_shot_seq=prev_shot_seq,
                    prev_reload_active=prev_reload_active,
                    prev_reload_timer=prev_reload_timer,
                )

        creature_result = self.creatures.update(
            dt,
            state=self.state,
            players=self.players,
            detail_preset=detail_preset,
            world_width=float(self.world_size),
            world_height=float(self.world_size),
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
        )
        if creature_result.deaths:
            self._play_death_sfx(creature_result.deaths)

        if dt > 0.0:
            self._advance_creature_anim(dt)

        pickups = bonus_update(self.state, self.players, dt, creatures=self.creatures.entries, update_hud=True)
        if pickups:
            for pickup in pickups:
                self._play_sfx("sfx_ui_bonus")
                self.state.effects.spawn_burst(
                    pos_x=float(pickup.pos_x),
                    pos_y=float(pickup.pos_y),
                    count=12,
                    rand=self.state.rng.rand,
                    detail_preset=detail_preset,
                    lifetime=0.4,
                    scale_step=0.1,
                    color_r=0.4,
                    color_g=0.5,
                    color_b=1.0,
                    color_a=0.5,
                )
                if pickup.bonus_id == int(BonusId.REFLEX_BOOST):
                    self.state.effects.spawn_ring(
                        pos_x=float(pickup.pos_x),
                        pos_y=float(pickup.pos_y),
                        detail_preset=detail_preset,
                        color_r=0.6,
                        color_g=0.6,
                        color_b=1.0,
                        color_a=1.0,
                    )
                elif pickup.bonus_id == int(BonusId.FREEZE):
                    self.state.effects.spawn_ring(
                        pos_x=float(pickup.pos_x),
                        pos_y=float(pickup.pos_y),
                        detail_preset=detail_preset,
                        color_r=0.3,
                        color_g=0.5,
                        color_b=0.8,
                        color_a=1.0,
                    )

        if game_mode == GAME_MODE_SURVIVAL:
            survival_progression_update(self.state, self.players, game_mode=game_mode, auto_pick=auto_pick_perks)

        self._bake_fx_queues()
        self.update_camera(dt)
        return hits

    def _queue_projectile_decals(self, hits: list[ProjectileHit]) -> None:
        rand = self.state.rng.rand
        fx_toggle = 0
        detail_preset = 5
        if self.config is not None:
            fx_toggle = int(self.config.data.get("fx_toggle", 0) or 0)
            detail_preset = int(self.config.data.get("detail_preset", 5) or 5)

        freeze_active = self.state.bonuses.freeze > 0.0
        bloody = bool(self.players) and perk_active(self.players[0], PerkId.BLOODY_MESS_QUICK_LEARNER)

        for type_id, origin_x, origin_y, hit_x, hit_y in hits:
            type_id = int(type_id)

            if type_id in _BEAM_TYPES:
                if self.ground is None or self.fx_textures is None:
                    continue
                size = float(int(rand()) % 18 + 18)
                rotation = float(int(rand()) % 628) * 0.01
                self.fx_queue.add(
                    effect_id=0x01,
                    pos_x=float(hit_x),
                    pos_y=float(hit_y),
                    width=size,
                    height=size,
                    rotation=rotation,
                    rgba=(0.7, 0.9, 1.0, 1.0),
                )
                continue

            if type_id in (ProjectileTypeId.GAUSS_GUN, ProjectileTypeId.ROCKET_LAUNCHER):
                if self.ground is None or self.fx_textures is None:
                    continue
                size = float(int(rand()) % 18 + 18)
                rotation = float(int(rand()) % 628) * 0.01
                self.fx_queue.add(
                    effect_id=0x11,
                    pos_x=float(hit_x),
                    pos_y=float(hit_y),
                    width=size,
                    height=size,
                    rotation=rotation,
                    rgba=(1.0, 0.6, 0.3, 1.0),
                )
                continue

            if freeze_active:
                continue

            # Native hit path: spawn transient blood splatter particles and only
            # bake decals into the terrain once those particles expire.
            base_angle = math.atan2(float(hit_y) - float(origin_y), float(hit_x) - float(origin_x))
            if bloody:
                for _ in range(8):
                    spread = float((int(rand()) & 0x1F) - 0x10) * 0.0625
                    self.state.effects.spawn_blood_splatter(
                        pos_x=float(hit_x),
                        pos_y=float(hit_y),
                        angle=base_angle + spread,
                        age=0.0,
                        rand=rand,
                        detail_preset=detail_preset,
                        fx_toggle=fx_toggle,
                    )
                self.state.effects.spawn_blood_splatter(
                    pos_x=float(hit_x),
                    pos_y=float(hit_y),
                    angle=base_angle + math.pi,
                    age=0.0,
                    rand=rand,
                    detail_preset=detail_preset,
                    fx_toggle=fx_toggle,
                )
                continue

            for _ in range(2):
                self.state.effects.spawn_blood_splatter(
                    pos_x=float(hit_x),
                    pos_y=float(hit_y),
                    angle=base_angle,
                    age=0.0,
                    rand=rand,
                    detail_preset=detail_preset,
                    fx_toggle=fx_toggle,
                )
                if (int(rand()) & 7) == 2:
                    self.state.effects.spawn_blood_splatter(
                        pos_x=float(hit_x),
                        pos_y=float(hit_y),
                        angle=base_angle + math.pi,
                        age=0.0,
                        rand=rand,
                        detail_preset=detail_preset,
                        fx_toggle=fx_toggle,
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

    def _handle_player_audio(
        self,
        player: PlayerState,
        *,
        prev_shot_seq: int,
        prev_reload_active: bool,
        prev_reload_timer: float,
    ) -> None:
        if self.audio is None:
            return
        weapon = WEAPON_BY_ID.get(int(player.weapon_id))
        if weapon is None:
            return

        if int(player.shot_seq) > int(prev_shot_seq):
            self._play_sfx(resolve_weapon_sfx_ref(weapon.fire_sound))

        reload_started = (not prev_reload_active and player.reload_active) or (player.reload_timer > prev_reload_timer + 1e-6)
        if reload_started:
            self._play_sfx(resolve_weapon_sfx_ref(weapon.reload_sound))

    def _hit_sfx_for_type(self, type_id: int) -> str | None:
        if type_id == ProjectileTypeId.ROCKET_LAUNCHER:
            return "sfx_explosion_large"
        if type_id in _BEAM_TYPES:
            return "sfx_shock_hit_01"
        return self._rand_choice(_BULLET_HIT_SFX)

    def _play_hit_sfx(self, hits: list[ProjectileHit], *, game_mode: int) -> None:
        if self.audio is None or not hits:
            return

        # Original game: the first projectile hit in Survival starts a random "game tune"
        # and suppresses the impact SFX for that hit. We mirror the same gate.
        start_idx = 0
        if (not self.demo_mode_active) and (game_mode == GAME_MODE_SURVIVAL):
            if trigger_game_tune(self.audio, rand=self.state.rng.rand) is not None:
                start_idx = 1

        end = min(len(hits), start_idx + _MAX_HIT_SFX_PER_FRAME)
        for idx in range(start_idx, end):
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
                local_scale=float(getattr(creature, "move_scale", 1.0)),
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
        return creature_corpse_frame_for_type(type_id)

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
        r = int(clamp(rgba[0], 0.0, 1.0) * 255.0 + 0.5)
        g = int(clamp(rgba[1], 0.0, 1.0) * 255.0 + 0.5)
        b = int(clamp(rgba[2], 0.0, 1.0) * 255.0 + 0.5)
        a = int(clamp(rgba[3], 0.0, 1.0) * 255.0 + 0.5)
        return rl.Color(r, g, b, a)

    def _bonus_icon_src(self, texture: rl.Texture, icon_id: int) -> rl.Rectangle:
        grid = 4
        cell_w = float(texture.width) / grid
        cell_h = float(texture.height) / grid
        col = int(icon_id) % grid
        row = int(icon_id) // grid
        return rl.Rectangle(float(col * cell_w), float(row * cell_h), float(cell_w), float(cell_h))

    def _weapon_icon_src(self, texture: rl.Texture, icon_index: int) -> rl.Rectangle:
        grid = 8
        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        frame = int(icon_index) * 2
        col = frame % grid
        row = frame // grid
        return rl.Rectangle(float(col * cell_w), float(row * cell_h), float(cell_w * 2), float(cell_h))

    @staticmethod
    def _bonus_fade(time_left: float, time_max: float) -> float:
        time_left = float(time_left)
        time_max = float(time_max)
        if time_left <= 0.0 or time_max <= 0.0:
            return 0.0
        if time_left < 0.5:
            return clamp(time_left * 2.0, 0.0, 1.0)
        age = time_max - time_left
        if age < 0.5:
            return clamp(age * 2.0, 0.0, 1.0)
        return 1.0

    def _draw_bonus_pickups(
        self,
        *,
        cam_x: float,
        cam_y: float,
        scale_x: float,
        scale_y: float,
        scale: float,
        alpha: float = 1.0,
    ) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        if self.bonuses_texture is None:
            for bonus in self.state.bonus_pool.entries:
                if bonus.bonus_id == 0:
                    continue
                sx = (bonus.pos_x + cam_x) * scale_x
                sy = (bonus.pos_y + cam_y) * scale_y
                tint = rl.Color(220, 220, 90, int(255 * alpha + 0.5))
                rl.draw_circle(int(sx), int(sy), max(1.0, 10.0 * scale), tint)
            return

        bubble_src = self._bonus_icon_src(self.bonuses_texture, 0)
        bubble_size = 32.0 * scale

        for idx, bonus in enumerate(self.state.bonus_pool.entries):
            if bonus.bonus_id == 0:
                continue

            fade = self._bonus_fade(float(bonus.time_left), float(bonus.time_max))
            bubble_alpha = clamp(fade * 0.9, 0.0, 1.0) * alpha

            sx = (bonus.pos_x + cam_x) * scale_x
            sy = (bonus.pos_y + cam_y) * scale_y
            bubble_dst = rl.Rectangle(float(sx), float(sy), float(bubble_size), float(bubble_size))
            bubble_origin = rl.Vector2(bubble_size * 0.5, bubble_size * 0.5)
            tint = rl.Color(255, 255, 255, int(bubble_alpha * 255.0 + 0.5))
            rl.draw_texture_pro(self.bonuses_texture, bubble_src, bubble_dst, bubble_origin, 0.0, tint)

            bonus_id = int(bonus.bonus_id)
            if bonus_id == int(BonusId.WEAPON):
                weapon = WEAPON_BY_ID.get(int(bonus.amount))
                icon_index = int(weapon.icon_index) if weapon is not None and weapon.icon_index is not None else None
                if icon_index is None or not (0 <= icon_index <= 31) or self.wicons_texture is None:
                    continue

                pulse = math.sin(float(self._bonus_anim_phase)) ** 4 * 0.25 + 0.75
                icon_scale = fade * pulse
                if icon_scale <= 1e-3:
                    continue

                src = self._weapon_icon_src(self.wicons_texture, icon_index)
                w = 60.0 * icon_scale * scale
                h = 30.0 * icon_scale * scale
                dst = rl.Rectangle(float(sx), float(sy), float(w), float(h))
                origin = rl.Vector2(w * 0.5, h * 0.5)
                rl.draw_texture_pro(self.wicons_texture, src, dst, origin, 0.0, tint)
                continue

            meta = BONUS_BY_ID.get(bonus_id)
            icon_id = int(meta.icon_id) if meta is not None and meta.icon_id is not None else None
            if icon_id is None or icon_id < 0:
                continue
            if bonus_id == int(BonusId.POINTS) and int(bonus.amount) == 1000:
                icon_id += 1

            pulse = math.sin(float(idx) + float(self._bonus_anim_phase)) ** 4 * 0.25 + 0.75
            icon_scale = fade * pulse
            if icon_scale <= 1e-3:
                continue

            src = self._bonus_icon_src(self.bonuses_texture, icon_id)
            size = 32.0 * icon_scale * scale
            rotation_rad = math.sin(float(idx) - float(self._elapsed_ms) * 0.003) * 0.2
            dst = rl.Rectangle(float(sx), float(sy), float(size), float(size))
            origin = rl.Vector2(size * 0.5, size * 0.5)
            rl.draw_texture_pro(self.bonuses_texture, src, dst, origin, float(rotation_rad * _RAD_TO_DEG), tint)

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

    @staticmethod
    def _grim2d_circle_segments_filled(radius: float) -> int:
        # grim_draw_circle_filled (grim.dll): segments = trunc(radius * 0.125 + 12.0)
        return max(3, int(radius * 0.125 + 12.0))

    @staticmethod
    def _grim2d_circle_segments_outline(radius: float) -> int:
        # grim_draw_circle_outline (grim.dll): segments = trunc(radius * 0.2 + 14.0)
        return max(3, int(radius * 0.2 + 14.0))

    def _draw_aim_circle(self, *, x: float, y: float, radius: float, alpha: float = 1.0) -> None:
        if radius <= 1e-3:
            return
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return

        fill_a = int(77 * alpha + 0.5)  # ui_render_aim_indicators: rgba(0,0,0.1,0.3)
        outline_a = int(255 * 0.55 * alpha + 0.5)
        fill = rl.Color(0, 0, 26, fill_a)
        outline = rl.Color(255, 255, 255, outline_a)

        rl.begin_blend_mode(rl.BLEND_ALPHA)

        # The original uses a triangle fan (polygons). Raylib provides circle
        # primitives that still use triangles internally, but allow higher
        # segment counts for a smoother result when scaled.
        seg_count = max(self._grim2d_circle_segments_filled(radius), 64, int(radius))
        rl.draw_circle_sector(rl.Vector2(x, y), float(radius), 0.0, 360.0, int(seg_count), fill)

        seg_count = max(self._grim2d_circle_segments_outline(radius), int(seg_count))
        # grim_draw_circle_outline draws a 2px-thick ring (outer radius = r + 2).
        # The exe binds bulletTrail, but that texture is white; the visual intent is
        # a subtle white outline around the filled spread circle.
        rl.draw_ring(rl.Vector2(x, y), float(radius), float(radius + 2.0), 0.0, 360.0, int(seg_count), outline)

        rl.rl_set_texture(0)
        rl.end_blend_mode()

    def _draw_clock_gauge(self, *, x: float, y: float, ms: int, scale: float, alpha: float = 1.0) -> None:
        if self.clock_table_texture is None or self.clock_pointer_texture is None:
            return
        size = 32.0 * scale
        if size <= 1e-3:
            return
        tint = rl.Color(255, 255, 255, int(clamp(float(alpha), 0.0, 1.0) * 255.0 + 0.5))

        table_src = rl.Rectangle(0.0, 0.0, float(self.clock_table_texture.width), float(self.clock_table_texture.height))
        table_dst = rl.Rectangle(float(x), float(y), size, size)
        rl.draw_texture_pro(self.clock_table_texture, table_src, table_dst, rl.Vector2(0.0, 0.0), 0.0, tint)

        pointer_src = rl.Rectangle(
            0.0,
            0.0,
            float(self.clock_pointer_texture.width),
            float(self.clock_pointer_texture.height),
        )
        pointer_dst = rl.Rectangle(float(x), float(y), size, size)
        origin = rl.Vector2(size * 0.5, size * 0.5)
        # Mirrors `ui_draw_clock_gauge`: rotation = (ms/1000) * 0.10471976 rad.
        rotation_deg = float(ms) * 0.006
        rl.draw_texture_pro(self.clock_pointer_texture, pointer_src, pointer_dst, origin, rotation_deg, tint)

    def _draw_creature_sprite(
        self,
        texture: rl.Texture,
        *,
        type_id: CreatureTypeId,
        flags: CreatureFlags,
        phase: float,
        mirror_long: bool | None = None,
        shadow_alpha: int | None = None,
        world_x: float,
        world_y: float,
        rotation_rad: float,
        scale: float,
        size_scale: float,
        tint: rl.Color,
        shadow: bool = False,
    ) -> None:
        info = _CREATURE_ANIM.get(type_id)
        if info is None:
            return
        mirror_flag = info.mirror if mirror_long is None else bool(mirror_long)
        frame, _, _ = creature_anim_select_frame(
            phase,
            base_frame=info.base,
            mirror_long=mirror_flag,
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
        rotation_deg = float(rotation_rad * _RAD_TO_DEG)

        if shadow:
            # In the original exe this is a "darken" blend pass gated by fx_detail_0
            # (creature_render_type). We approximate it with a black silhouette draw.
            # The observed pass is slightly bigger than the main sprite and offset
            # down-right by ~1px at default sizes.
            alpha = int(shadow_alpha) if shadow_alpha is not None else int(clamp(float(tint.a) * 0.4, 0.0, 255.0) + 0.5)
            shadow_tint = rl.Color(0, 0, 0, alpha)
            shadow_scale = 1.07
            shadow_w = width * shadow_scale
            shadow_h = height * shadow_scale
            offset = width * 0.035 - 0.7 * scale
            shadow_dst = rl.Rectangle(sx + offset, sy + offset, shadow_w, shadow_h)
            shadow_origin = rl.Vector2(shadow_w * 0.5, shadow_h * 0.5)
            rl.draw_texture_pro(texture, src, shadow_dst, shadow_origin, rotation_deg, shadow_tint)

        dst = rl.Rectangle(sx, sy, width, height)
        origin = rl.Vector2(width * 0.5, height * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)

    def _draw_player_trooper_sprite(
        self,
        texture: rl.Texture,
        player: PlayerState,
        *,
        cam_x: float,
        cam_y: float,
        scale_x: float,
        scale_y: float,
        scale: float,
        alpha: float = 1.0,
    ) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        grid = 8
        cell = float(texture.width) / float(grid) if grid > 0 else float(texture.width)
        if cell <= 0.0:
            return

        sx = (player.pos_x + cam_x) * scale_x
        sy = (player.pos_y + cam_y) * scale_y
        base_size = float(player.size) * scale
        base_scale = base_size / cell

        tint = rl.Color(240, 240, 255, int(255 * alpha + 0.5))
        shadow_tint = rl.Color(0, 0, 0, int(90 * alpha + 0.5))

        def draw(frame: int, *, x: float, y: float, scale_mul: float, rotation: float, color: rl.Color) -> None:
            self._draw_atlas_sprite(
                texture,
                grid=grid,
                frame=max(0, min(63, int(frame))),
                x=x,
                y=y,
                scale=base_scale * float(scale_mul),
                rotation_rad=float(rotation),
                tint=color,
            )

        if player.health > 0.0:
            leg_frame = max(0, min(14, int(player.move_phase + 0.5)))
            torso_frame = leg_frame + 16

            recoil_dir = float(player.aim_heading) + math.pi / 2.0
            recoil = float(player.muzzle_flash_alpha) * 12.0 * scale
            recoil_x = math.cos(recoil_dir) * recoil
            recoil_y = math.sin(recoil_dir) * recoil

            draw(
                leg_frame,
                x=sx + 3.0 * scale,
                y=sy + 3.0 * scale,
                scale_mul=1.02,
                rotation=float(player.heading),
                color=shadow_tint,
            )
            draw(
                torso_frame,
                x=sx + recoil_x + 1.0 * scale,
                y=sy + recoil_y + 1.0 * scale,
                scale_mul=1.03,
                rotation=float(player.aim_heading),
                color=shadow_tint,
            )
            draw(
                leg_frame,
                x=sx,
                y=sy,
                scale_mul=1.0,
                rotation=float(player.heading),
                color=tint,
            )
            draw(
                torso_frame,
                x=sx + recoil_x,
                y=sy + recoil_y,
                scale_mul=1.0,
                rotation=float(player.aim_heading),
                color=tint,
            )
            if self.muzzle_flash_texture is not None and float(player.muzzle_flash_alpha) > 1e-3 and alpha > 1e-3:
                weapon = WEAPON_BY_ID.get(int(player.weapon_id))
                flags = int(weapon.flags) if weapon is not None and weapon.flags is not None else 0
                if (flags & 0x8) == 0:
                    flash_alpha = clamp(float(player.muzzle_flash_alpha) * 0.8, 0.0, 1.0) * alpha
                    if flash_alpha > 1e-3:
                        size = base_size * (0.5 if (flags & 0x4) else 1.0)
                        heading = float(player.aim_heading) + math.pi / 2.0
                        offset = (float(player.muzzle_flash_alpha) * 12.0 - 21.0) * scale
                        pos_x = sx + math.cos(heading) * offset
                        pos_y = sy + math.sin(heading) * offset
                        src = rl.Rectangle(
                            0.0,
                            0.0,
                            float(self.muzzle_flash_texture.width),
                            float(self.muzzle_flash_texture.height),
                        )
                        dst = rl.Rectangle(pos_x, pos_y, size, size)
                        origin = rl.Vector2(size * 0.5, size * 0.5)
                        tint_flash = rl.Color(255, 255, 255, int(flash_alpha * 255.0 + 0.5))
                        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
                        rl.draw_texture_pro(
                            self.muzzle_flash_texture,
                            src,
                            dst,
                            origin,
                            float(player.aim_heading * _RAD_TO_DEG),
                            tint_flash,
                        )
                        rl.end_blend_mode()
            return

        if player.death_timer >= 0.0:
            # Matches the observed frame ramp (32..52) in player_sprite_trace.jsonl.
            frame = 32 + int((16.0 - float(player.death_timer)) * 1.25)
            if frame > 52:
                frame = 52
            if frame < 32:
                frame = 32
        else:
            frame = 52

        draw(
            frame,
            x=sx + 1.0 * scale,
            y=sy + 1.0 * scale,
            scale_mul=1.03,
            rotation=float(player.aim_heading),
            color=shadow_tint,
        )
        draw(
            frame,
            x=sx,
            y=sy,
            scale_mul=1.0,
            rotation=float(player.aim_heading),
            color=tint,
        )

    def _draw_projectile(self, proj: object, *, scale: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        texture = self.projs_texture
        type_id = int(getattr(proj, "type_id", 0))
        pos_x = float(getattr(proj, "pos_x", 0.0))
        pos_y = float(getattr(proj, "pos_y", 0.0))
        sx, sy = self.world_to_screen(pos_x, pos_y)
        life = float(getattr(proj, "life_timer", 0.0))
        angle = float(getattr(proj, "angle", 0.0))

        if self._is_bullet_trail_type(type_id):
            life_alpha = int(clamp(life, 0.0, 1.0) * 255)
            alpha_byte = int(clamp(float(life_alpha) * alpha, 0.0, 255.0) + 0.5)
            drawn = False
            if self.bullet_trail_texture is not None:
                ox = float(getattr(proj, "origin_x", pos_x))
                oy = float(getattr(proj, "origin_y", pos_y))
                sx0, sy0 = self.world_to_screen(ox, oy)
                sx1, sy1 = sx, sy
                drawn = self._draw_bullet_trail(sx0, sy0, sx1, sy1, alpha=alpha_byte, scale=scale)

            if self.bullet_texture is not None and life >= 0.39:
                size = self._bullet_sprite_size(type_id, scale=scale)
                src = rl.Rectangle(
                    0.0,
                    0.0,
                    float(self.bullet_texture.width),
                    float(self.bullet_texture.height),
                )
                dst = rl.Rectangle(float(sx), float(sy), size, size)
                origin = rl.Vector2(size * 0.5, size * 0.5)
                tint = rl.Color(220, 220, 220, alpha_byte)
                rl.draw_texture_pro(self.bullet_texture, src, dst, origin, float(angle * _RAD_TO_DEG), tint)
                drawn = True

            if drawn:
                return

        mapping = _KNOWN_PROJ_FRAMES.get(type_id)
        if texture is None or mapping is None:
            rl.draw_circle(int(sx), int(sy), max(1.0, 3.0 * scale), rl.Color(240, 220, 160, int(255 * alpha + 0.5)))
            return

        grid, frame = mapping

        color = rl.Color(240, 220, 160, 255)
        if type_id in (ProjectileTypeId.ION_RIFLE, ProjectileTypeId.ION_MINIGUN, ProjectileTypeId.ION_CANNON):
            color = rl.Color(120, 200, 255, 255)
        elif type_id == ProjectileTypeId.FIRE_BULLETS:
            color = rl.Color(255, 170, 90, 255)
        elif type_id == ProjectileTypeId.SHRINKIFIER:
            color = rl.Color(160, 255, 170, 255)
        elif type_id == ProjectileTypeId.SPIDER_PLASMA:
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
                    seg_alpha = int(clamp(220.0 * (1.0 - t * 0.75) * alpha, 0.0, 255.0) + 0.5)
                    tint = rl.Color(color.r, color.g, color.b, seg_alpha)
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

        alpha_byte = int(clamp(clamp(life / 0.4, 0.0, 1.0) * 255.0 * alpha, 0.0, 255.0) + 0.5)
        tint = rl.Color(color.r, color.g, color.b, alpha_byte)
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

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return 0 <= type_id <= int(ProjectileTypeId.FLAMETHROWER) or type_id == int(ProjectileTypeId.GAUSS_SHOTGUN)

    @staticmethod
    def _bullet_sprite_size(type_id: int, *, scale: float) -> float:
        base = 4.0
        if type_id == int(ProjectileTypeId.ASSAULT_RIFLE):
            base = 6.0
        elif type_id == int(ProjectileTypeId.SUBMACHINE_GUN):
            base = 8.0
        return max(2.0, base * scale)

    def _draw_bullet_trail(self, sx0: float, sy0: float, sx1: float, sy1: float, *, alpha: int, scale: float) -> bool:
        if self.bullet_trail_texture is None:
            return False
        dx = sx1 - sx0
        dy = sy1 - sy0
        dist = math.hypot(dx, dy)
        if dist <= 1e-3:
            return False
        thickness = max(1.0, 2.1 * scale)
        half = thickness * 0.5
        inv = 1.0 / dist
        nx = dx * inv
        ny = dy * inv
        px = -ny
        py = nx
        ox = px * half
        oy = py * half
        x0 = sx0 - ox
        y0 = sy0 - oy
        x1 = sx0 + ox
        y1 = sy0 + oy
        x2 = sx1 + ox
        y2 = sy1 + oy
        x3 = sx1 - ox
        y3 = sy1 - oy

        head = rl.Color(200, 200, 200, alpha)
        tail = rl.Color(200, 200, 200, 0)
        rl.rl_set_texture(self.bullet_trail_texture.id)
        rl.rl_begin(rl.RL_QUADS)
        rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
        rl.rl_tex_coord2f(0.0, 0.0)
        rl.rl_vertex2f(x0, y0)
        rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
        rl.rl_tex_coord2f(1.0, 0.0)
        rl.rl_vertex2f(x1, y1)
        rl.rl_color4ub(head.r, head.g, head.b, head.a)
        rl.rl_tex_coord2f(1.0, 0.5)
        rl.rl_vertex2f(x2, y2)
        rl.rl_color4ub(head.r, head.g, head.b, head.a)
        rl.rl_tex_coord2f(0.0, 0.5)
        rl.rl_vertex2f(x3, y3)
        rl.rl_end()
        rl.rl_set_texture(0)
        return True

    def _draw_secondary_projectile(self, proj: object, *, scale: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        sx, sy = self.world_to_screen(float(getattr(proj, "pos_x", 0.0)), float(getattr(proj, "pos_y", 0.0)))
        proj_type = int(getattr(proj, "type_id", 0))
        if proj_type == 4:
            rl.draw_circle(int(sx), int(sy), max(1.0, 12.0 * scale), rl.Color(200, 120, 255, int(255 * alpha + 0.5)))
            return
        if proj_type == 3:
            t = clamp(float(getattr(proj, "lifetime", 0.0)), 0.0, 1.0)
            radius = float(getattr(proj, "speed", 1.0)) * t * 80.0
            alpha_byte = int(clamp((1.0 - t) * 180.0 * alpha, 0.0, 255.0) + 0.5)
            color = rl.Color(200, 120, 255, alpha_byte)
            rl.draw_circle_lines(int(sx), int(sy), max(1.0, radius * scale), color)
            return
        rl.draw_circle(int(sx), int(sy), max(1.0, 4.0 * scale), rl.Color(200, 200, 220, int(200 * alpha + 0.5)))

    def _draw_effect_pool(self, *, cam_x: float, cam_y: float, scale_x: float, scale_y: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        texture = self.particles_texture
        if texture is None:
            return

        effects = self.state.effects.entries
        if not any(entry.flags and entry.age >= 0.0 for entry in effects):
            return

        scale = (scale_x + scale_y) * 0.5

        src_cache: dict[int, rl.Rectangle] = {}

        def src_rect(effect_id: int) -> rl.Rectangle | None:
            cached = src_cache.get(effect_id)
            if cached is not None:
                return cached

            atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(effect_id))
            if atlas is None:
                return None
            grid = SIZE_CODE_GRID.get(int(atlas.size_code))
            if not grid:
                return None
            frame = int(atlas.frame)
            col = frame % grid
            row = frame // grid
            cell_w = float(texture.width) / float(grid)
            cell_h = float(texture.height) / float(grid)
            # Native effect pool clamps UVs to (cell_size - 2px) to avoid bleeding.
            src = rl.Rectangle(
                cell_w * float(col),
                cell_h * float(row),
                max(0.0, cell_w - 2.0),
                max(0.0, cell_h - 2.0),
            )
            src_cache[effect_id] = src
            return src

        def draw_entry(entry: object) -> None:
            src = src_rect(int(getattr(entry, "effect_id", 0)))
            if src is None or src.width <= 0.0 or src.height <= 0.0:
                return

            pos_x = float(getattr(entry, "pos_x", 0.0))
            pos_y = float(getattr(entry, "pos_y", 0.0))
            sx = (pos_x + cam_x) * scale_x
            sy = (pos_y + cam_y) * scale_y

            half_w = float(getattr(entry, "half_width", 0.0))
            half_h = float(getattr(entry, "half_height", 0.0))
            local_scale = float(getattr(entry, "scale", 1.0))
            w = max(0.0, half_w * 2.0 * local_scale * scale)
            h = max(0.0, half_h * 2.0 * local_scale * scale)
            if w <= 0.0 or h <= 0.0:
                return

            rotation_deg = float(getattr(entry, "rotation", 0.0)) * _RAD_TO_DEG
            tint = self._color_from_rgba(
                (
                    float(getattr(entry, "color_r", 1.0)),
                    float(getattr(entry, "color_g", 1.0)),
                    float(getattr(entry, "color_b", 1.0)),
                    float(getattr(entry, "color_a", 1.0)),
                )
            )
            tint = rl.Color(tint.r, tint.g, tint.b, int(tint.a * alpha + 0.5))

            dst = rl.Rectangle(float(sx), float(sy), float(w), float(h))
            origin = rl.Vector2(float(w) * 0.5, float(h) * 0.5)
            rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)

        rl.begin_blend_mode(rl.BLEND_ALPHA)
        for entry in effects:
            if not entry.flags or entry.age < 0.0:
                continue
            if int(entry.flags) & 0x40:
                draw_entry(entry)
        rl.end_blend_mode()

        rl.begin_blend_mode(rl.BLEND_ADDITIVE)
        for entry in effects:
            if not entry.flags or entry.age < 0.0:
                continue
            if not (int(entry.flags) & 0x40):
                draw_entry(entry)
        rl.end_blend_mode()

    def draw(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        entity_alpha = clamp(float(entity_alpha), 0.0, 1.0)
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

        if entity_alpha <= 1e-3:
            return

        for creature in self.creatures.entries:
            if not creature.active:
                continue
            try:
                type_id = CreatureTypeId(int(creature.type_id))
            except ValueError:
                type_id = None
            asset = _CREATURE_ASSET.get(type_id) if type_id is not None else None
            texture = self.creature_textures.get(asset) if asset is not None else None
            if texture is not None:
                info = _CREATURE_ANIM.get(type_id) if type_id is not None else None
                if info is None:
                    continue

                hitbox_size = float(creature.hitbox_size)
                tint_alpha = float(creature.tint_a)
                if hitbox_size < 0.0:
                    # Mirrors the main-pass alpha fade when hitbox_size ramps negative.
                    tint_alpha = max(0.0, tint_alpha + hitbox_size * 0.1)
                tint_alpha = clamp(tint_alpha * entity_alpha, 0.0, 1.0)
                tint = self._color_from_rgba((creature.tint_r, creature.tint_g, creature.tint_b, tint_alpha))

                size_scale = clamp(float(creature.size) / 64.0, 0.25, 2.0)
                fx_detail = bool(self.config.data.get("fx_detail_0", 0)) if self.config is not None else True
                # Mirrors `creature_render_type`: the "shadow-ish" pass is gated by fx_detail_0
                # and is disabled when the Monster Vision perk is active.
                shadow = fx_detail and (not self.players or not perk_active(self.players[0], PerkId.MONSTER_VISION))
                long_strip = (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0 or (
                    creature.flags & CreatureFlags.ANIM_LONG_STRIP
                ) != 0
                phase = float(creature.anim_phase)
                if long_strip:
                    if hitbox_size < 0.0:
                        # Negative phase selects the fallback "corpse" frame in creature_render_type.
                        phase = -1.0
                    elif hitbox_size < 16.0:
                        # Death staging: while hitbox_size ramps down (16..0), creature_render_type
                        # selects frames via `__ftol((base_frame + 15) - hitbox_size)`.
                        phase = float(info.base + 0x0F) - hitbox_size - 0.5

                shadow_alpha = None
                if shadow:
                    # Shadow pass uses tint_a * 0.4 and fades much faster for corpses (hitbox_size < 0).
                    shadow_a = float(creature.tint_a) * 0.4
                    if hitbox_size < 0.0:
                        shadow_a += hitbox_size * (0.5 if long_strip else 0.1)
                        shadow_a = max(0.0, shadow_a)
                    shadow_alpha = int(clamp(shadow_a * entity_alpha * 255.0, 0.0, 255.0) + 0.5)
                self._draw_creature_sprite(
                    texture,
                    type_id=type_id or CreatureTypeId.ZOMBIE,
                    flags=creature.flags,
                    phase=phase,
                    mirror_long=bool(info.mirror) and hitbox_size >= 16.0,
                    shadow_alpha=shadow_alpha,
                    world_x=creature.x,
                    world_y=creature.y,
                    rotation_rad=float(creature.heading) - math.pi / 2.0,
                    scale=scale,
                    size_scale=size_scale,
                    tint=tint,
                    shadow=shadow,
                )
            else:
                sx = (creature.x + cam_x) * scale_x
                sy = (creature.y + cam_y) * scale_y
                tint = rl.Color(220, 90, 90, int(255 * entity_alpha + 0.5))
                rl.draw_circle(int(sx), int(sy), max(1.0, creature.size * 0.5 * scale), tint)

        if self.players:
            texture = self.creature_textures.get(_CREATURE_ASSET.get(CreatureTypeId.TROOPER))
            for player in self.players:
                if texture is not None:
                    self._draw_player_trooper_sprite(
                        texture,
                        player,
                        cam_x=cam_x,
                        cam_y=cam_y,
                        scale_x=scale_x,
                        scale_y=scale_y,
                        scale=scale,
                        alpha=entity_alpha,
                    )
                else:
                    sx = (player.pos_x + cam_x) * scale_x
                    sy = (player.pos_y + cam_y) * scale_y
                    tint = rl.Color(90, 190, 120, int(255 * entity_alpha + 0.5))
                    rl.draw_circle(int(sx), int(sy), max(1.0, 14.0 * scale), tint)

        for proj in self.state.projectiles.iter_active():
            self._draw_projectile(proj, scale=scale, alpha=entity_alpha)

        for proj in self.state.secondary_projectiles.iter_active():
            self._draw_secondary_projectile(proj, scale=scale, alpha=entity_alpha)

        self._draw_bonus_pickups(cam_x=cam_x, cam_y=cam_y, scale_x=scale_x, scale_y=scale_y, scale=scale, alpha=entity_alpha)
        self._draw_effect_pool(cam_x=cam_x, cam_y=cam_y, scale_x=scale_x, scale_y=scale_y, alpha=entity_alpha)

        if draw_aim_indicators and (not self.demo_mode_active):
            for player in self.players:
                if player.health <= 0.0:
                    continue
                aim_x = float(getattr(player, "aim_x", player.pos_x))
                aim_y = float(getattr(player, "aim_y", player.pos_y))
                dist = math.hypot(aim_x - float(player.pos_x), aim_y - float(player.pos_y))
                radius = max(6.0, dist * float(getattr(player, "spread_heat", 0.0)) * 0.5)
                sx = (aim_x + cam_x) * scale_x
                sy = (aim_y + cam_y) * scale_y
                screen_radius = max(1.0, radius * scale)
                self._draw_aim_circle(x=sx, y=sy, radius=screen_radius, alpha=entity_alpha)
                reload_timer = float(getattr(player, "reload_timer", 0.0))
                reload_max = float(getattr(player, "reload_timer_max", 0.0))
                if reload_max > 1e-6 and reload_timer > 1e-6:
                    progress = reload_timer / reload_max
                    if progress > 0.0:
                        ms = int(progress * 60000.0)
                        self._draw_clock_gauge(x=float(int(sx)), y=float(int(sy)), ms=ms, scale=scale, alpha=entity_alpha)

    def update_camera(self, dt: float) -> None:
        if not self.players:
            return
        camera_shake_update(self.state, dt)

        screen_w, screen_h = self._camera_screen_size()

        alive = [player for player in self.players if player.health > 0.0]
        if alive:
            focus_x = sum(player.pos_x for player in alive) / float(len(alive))
            focus_y = sum(player.pos_y for player in alive) / float(len(alive))
            cam_x = (screen_w * 0.5) - focus_x
            cam_y = (screen_h * 0.5) - focus_y
        else:
            cam_x = self.camera_x
            cam_y = self.camera_y

        cam_x += self.state.camera_shake_offset_x
        cam_y += self.state.camera_shake_offset_y

        self.camera_x, self.camera_y = self._clamp_camera(cam_x, cam_y, screen_w, screen_h)

    def world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        return (x + cam_x) * scale_x, (y + cam_y) * scale_y

    def screen_to_world(self, x: float, y: float) -> tuple[float, float]:
        cam_x, cam_y, scale_x, scale_y = self._world_params()
        inv_x = 1.0 / scale_x if scale_x > 0 else 1.0
        inv_y = 1.0 / scale_y if scale_y > 0 else 1.0
        return x * inv_x - cam_x, y * inv_y - cam_y
