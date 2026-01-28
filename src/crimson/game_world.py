from __future__ import annotations

from dataclasses import dataclass, field
import math
import random
from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache, TextureLoader
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.terrain_render import GroundRenderer

from .bonuses import BonusId
from .camera import camera_shake_update
from .creatures.anim import creature_anim_advance_phase, creature_corpse_frame_for_type
from .creatures.runtime import CreaturePool
from .creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from .effects import FxQueue, FxQueueRotated
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
from .render.world_renderer import WorldRenderer
from .audio_router import AudioRouter
from .perks import PerkId
from .projectiles import ProjectileTypeId
from .sim.world_defs import BEAM_TYPES, CREATURE_ANIM, CREATURE_ASSET
from .weapons import WEAPON_TABLE

GAME_MODE_SURVIVAL = 3


ProjectileHit = tuple[int, float, float, float, float]

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
    audio_router: AudioRouter = field(init=False)
    renderer: WorldRenderer = field(init=False)

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
        self.audio_router = AudioRouter(
            audio=self.audio,
            audio_rng=self.audio_rng,
            demo_mode_active=self.demo_mode_active,
        )
        self.renderer = WorldRenderer(self)
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

        for asset in sorted(set(CREATURE_ASSET.values())):
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

        if self.audio_router is not None:
            self.audio_router.audio = self.audio
            self.audio_router.audio_rng = self.audio_rng
            self.audio_router.demo_mode_active = self.demo_mode_active

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
            self.audio_router.play_hit_sfx(
                hits,
                game_mode=game_mode,
                rand=self.state.rng.rand,
                beam_types=BEAM_TYPES,
            )

        for idx, player in enumerate(self.players):
            input_state = inputs[idx] if idx < len(inputs) else PlayerInput()
            player_update(player, input_state, dt, self.state, world_size=float(self.world_size))
            if idx < len(prev_audio):
                prev_shot_seq, prev_reload_active, prev_reload_timer = prev_audio[idx]
                self.audio_router.handle_player_audio(
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
            self.audio_router.play_death_sfx(creature_result.deaths, rand=self.state.rng.rand)

        if dt > 0.0:
            self._advance_creature_anim(dt)

        pickups = bonus_update(self.state, self.players, dt, creatures=self.creatures.entries, update_hud=True)
        if pickups:
            for pickup in pickups:
                self.audio_router.play_sfx("sfx_ui_bonus")
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

            if type_id in BEAM_TYPES:
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

    def _advance_creature_anim(self, dt: float) -> None:
        for creature in self.creatures.entries:
            if not (creature.active and creature.hp > 0.0):
                continue
            try:
                type_id = CreatureTypeId(int(creature.type_id))
            except ValueError:
                continue
            info = CREATURE_ANIM.get(type_id)
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
        info = CREATURE_ANIM.get(CreatureTypeId.TROOPER)
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

    def draw(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        self.renderer.draw(draw_aim_indicators=draw_aim_indicators, entity_alpha=entity_alpha)

    def update_camera(self, dt: float) -> None:
        if not self.players:
            return
        camera_shake_update(self.state, dt)

        screen_w, screen_h = self.renderer._camera_screen_size()

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

        self.camera_x, self.camera_y = self.renderer._clamp_camera(cam_x, cam_y, screen_w, screen_h)

    def world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        return self.renderer.world_to_screen(x, y)

    def screen_to_world(self, x: float, y: float) -> tuple[float, float]:
        return self.renderer.screen_to_world(x, y)
