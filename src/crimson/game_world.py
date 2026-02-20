from __future__ import annotations

import math
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from grim.assets import PaqTextureCache, TextureLoader
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

from .audio_router import AudioRouter
from .creatures.anim import creature_corpse_frame_for_type
from .creatures.runtime import CreaturePool
from .creatures.spawn import SpawnEnv
from .effects import FxQueue, FxQueueRotated
from .game_modes import GameMode
from .gameplay import GameplayState
from .render.frame import RenderFrame
from .render.terrain_fx import FxQueueTextures, bake_fx_queues
from .render.world import WorldRenderer
from .sim.input import PlayerInput
from .sim.presentation_step import (
    PresentationStepCommands,
    queue_projectile_decals,
)
from .sim.state_types import PlayerState
from .sim.step_pipeline import DeterministicStepResult, run_deterministic_step
from .sim.world_defs import CREATURE_ASSET
from .sim.world_state import ProjectileHit, WorldEvents, WorldState
from .terrain_assets import TerrainTextureId, terrain_texture_by_id
from .weapon_runtime import weapon_assign_player
from .weapons import WEAPON_TABLE


@dataclass(slots=True)
class GameWorld:
    assets_dir: Path
    world_size: float = 1024.0
    demo_mode_active: bool = False
    difficulty_level: int = 0
    hardcore: bool = False
    preserve_bugs: bool = False
    texture_cache: PaqTextureCache | None = None
    config: CrimsonConfig | None = None
    audio: AudioState | None = None
    audio_rng: random.Random | None = None
    audio_router: AudioRouter = field(init=False)
    renderer: WorldRenderer = field(init=False)
    world_state: WorldState = field(init=False)

    spawn_env: SpawnEnv = field(init=False)
    state: GameplayState = field(init=False)
    players: list[PlayerState] = field(init=False)
    creatures: CreaturePool = field(init=False)
    camera: Vec2 = field(init=False, default_factory=lambda: Vec2(-1.0, -1.0))
    _damage_scale_by_type: dict[int, float] = field(init=False, default_factory=dict)
    ground: GroundRenderer | None = field(init=False, default=None)
    fx_queue: FxQueue = field(init=False)
    fx_queue_rotated: FxQueueRotated = field(init=False)
    fx_textures: FxQueueTextures | None = field(init=False, default=None)
    creature_textures: dict[str, rl.Texture] = field(init=False, default_factory=dict)
    projs_texture: rl.Texture | None = field(init=False, default=None)
    particles_texture: rl.Texture | None = field(init=False, default=None)
    bullet_texture: rl.Texture | None = field(init=False, default=None)
    bullet_trail_texture: rl.Texture | None = field(init=False, default=None)
    arrow_texture: rl.Texture | None = field(init=False, default=None)
    bonuses_texture: rl.Texture | None = field(init=False, default=None)
    bodyset_texture: rl.Texture | None = field(init=False, default=None)
    clock_table_texture: rl.Texture | None = field(init=False, default=None)
    clock_pointer_texture: rl.Texture | None = field(init=False, default=None)
    aim_texture: rl.Texture | None = field(init=False, default=None)
    muzzle_flash_texture: rl.Texture | None = field(init=False, default=None)
    wicons_texture: rl.Texture | None = field(init=False, default=None)
    _elapsed_ms: float = field(init=False, default=0.0)
    _bonus_anim_phase: float = field(init=False, default=0.0)
    _game_tune_started: bool = field(init=False, default=False)
    _texture_loader: TextureLoader | None = field(init=False, default=None)
    last_events: WorldEvents = field(init=False)
    last_presentation: PresentationStepCommands = field(init=False)
    last_command_hash: str = field(init=False, default="")
    lan_player_rings_enabled: bool = field(init=False, default=False)
    lan_local_aim_indicators_only: bool = field(init=False, default=False)
    lan_local_player_slot_index: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self.world_state = WorldState.build(
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            difficulty_level=int(self.difficulty_level),
            preserve_bugs=bool(self.preserve_bugs),
        )
        self.spawn_env = self.world_state.spawn_env
        self.state = self.world_state.state
        self.players = self.world_state.players
        self.creatures = self.world_state.creatures
        self.fx_queue = FxQueue()
        self.fx_queue_rotated = FxQueueRotated()
        self.last_events = WorldEvents(hits=[], deaths=(), pickups=[], sfx=[])
        self.last_presentation = PresentationStepCommands()
        self.last_command_hash = ""
        self.camera = Vec2(-1.0, -1.0)
        self.audio_router = AudioRouter(
            audio=self.audio,
            audio_rng=self.audio_rng,
            demo_mode_active=self.demo_mode_active,
            reflex_boost_timer_source=lambda: float(self.state.bonuses.reflex_boost),
        )
        self.renderer = WorldRenderer(self)
        self._damage_scale_by_type = {}
        # Native `projectile_spawn` indexes the weapon table by `type_id`, so
        # `damage_scale_by_type` is just `weapon_table[type_id].damage_scale`.
        for entry in WEAPON_TABLE:
            if entry.weapon_id <= 0:
                continue
            self._damage_scale_by_type[int(entry.weapon_id)] = float(entry.damage_scale or 1.0)
        player_count = 1
        if self.config is not None:
            player_count = self.config.player_count
        self.reset(player_count=max(1, min(4, player_count)))

    def reset(
        self,
        *,
        seed: int = 0xBEEF,
        player_count: int = 1,
        spawn_pos: Vec2 | None = None,
    ) -> None:
        self.world_state = WorldState.build(
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            difficulty_level=int(self.difficulty_level),
            preserve_bugs=bool(self.preserve_bugs),
        )
        self.spawn_env = self.world_state.spawn_env
        self.state = self.world_state.state
        self.players = self.world_state.players
        self.creatures = self.world_state.creatures
        self.state.rng.srand(int(seed))
        self.fx_queue.clear()
        self.fx_queue_rotated.clear()
        self.last_events = WorldEvents(hits=[], deaths=(), pickups=[], sfx=[])
        self.last_presentation = PresentationStepCommands()
        self.last_command_hash = ""
        self._elapsed_ms = 0.0
        self._bonus_anim_phase = 0.0
        self._game_tune_started = False
        base = Vec2(float(self.world_size) * 0.5, float(self.world_size) * 0.5) if spawn_pos is None else spawn_pos
        count = max(1, int(player_count))
        if count <= 1:
            offsets = [Vec2()]
        else:
            radius = 32.0
            step = math.tau / float(count)
            offsets = [Vec2.from_angle(float(idx) * step) * radius for idx in range(count)]

        for idx in range(count):
            pos = (base + offsets[idx]).clamp_rect(0.0, 0.0, float(self.world_size), float(self.world_size))
            player = PlayerState(index=idx, pos=pos)
            weapon_assign_player(player, 1)
            self.players.append(player)
        self.camera = Vec2(-1.0, -1.0)
        if self.ground is not None:
            # Terrain generation seed should be stable across headless/interactive and must not
            # advance the authoritative gameplay RNG stream.
            terrain_seed = int(self.state.rng.state)
            self.ground.schedule_generate(seed=terrain_seed, layers=3)

    def load_world_state(self, world_state: WorldState) -> None:
        """Atomically swap the authoritative world-state backing references."""

        self.world_state = world_state
        self.spawn_env = self.world_state.spawn_env
        self.state = self.world_state.state
        self.players = self.world_state.players
        self.creatures = self.world_state.creatures
        self.last_events = WorldEvents(hits=[], deaths=(), pickups=[], sfx=[])
        self.last_presentation = PresentationStepCommands()
        self.last_command_hash = ""

    def _ensure_texture_loader(self) -> TextureLoader:
        if self._texture_loader is not None:
            return self._texture_loader
        if self.texture_cache is not None:
            loader = TextureLoader(
                assets_root=self.assets_dir,
                cache=self.texture_cache,
            )
        else:
            loader = TextureLoader.from_assets_root(self.assets_dir)
            if loader.cache is not None:
                self.texture_cache = loader.cache
        self._texture_loader = loader
        return loader

    def _load_texture(self, name: str, *, cache_path: str) -> rl.Texture | None:
        loader = self._ensure_texture_loader()
        return loader.get(name=name, paq_rel=cache_path)

    def _sync_ground_settings(self) -> None:
        if self.ground is None:
            return
        if self.config is None:
            self.ground.texture_scale = 1.0
            self.ground.screen_width = None
            self.ground.screen_height = None
            return
        self.ground.texture_scale = self.config.texture_scale
        self.ground.screen_width = float(self.config.screen_width)
        self.ground.screen_height = float(self.config.screen_height)

    def apply_bootstrap_terrain(
        self,
        *,
        terrain_ids: tuple[int, int, int],
        seed: int,
        layers: int = 3,
    ) -> None:
        """Apply a deterministic terrain selection/seed without consuming gameplay RNG."""

        base_id, overlay_id, detail_id = (int(terrain_ids[0]), int(terrain_ids[1]), int(terrain_ids[2]))
        base_spec = terrain_texture_by_id(int(base_id))
        overlay_spec = terrain_texture_by_id(int(overlay_id))
        detail_spec = terrain_texture_by_id(int(detail_id))

        def _load(spec: tuple[str, str] | None) -> rl.Texture | None:
            if spec is None:
                return None
            key, rel_path = spec
            return self._load_texture(
                str(key),
                cache_path=str(rel_path),
            )

        base = _load(base_spec)
        overlay = _load(overlay_spec)
        detail = _load(detail_spec) or overlay or base

        default_terrain = (TerrainTextureId.Q1_BASE, TerrainTextureId.Q1_OVERLAY, TerrainTextureId.Q1_BASE)
        if base is None and (base_id, overlay_id, detail_id) != default_terrain:
            # Fall back to default terrain if the chosen one is unavailable.
            base = _load(terrain_texture_by_id(TerrainTextureId.Q1_BASE))
            overlay = _load(terrain_texture_by_id(TerrainTextureId.Q1_OVERLAY))
            detail = _load(terrain_texture_by_id(TerrainTextureId.Q1_BASE)) or overlay or base
            base_id, overlay_id, detail_id = default_terrain

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
        self.ground.schedule_generate(seed=int(seed), layers=int(layers))

    def set_terrain(
        self,
        *,
        base_key: str,
        overlay_key: str,
        base_path: str,
        overlay_path: str,
        detail_key: str | None = None,
        detail_path: str | None = None,
    ) -> None:
        base = self._load_texture(
            base_key,
            cache_path=base_path,
        )
        overlay = self._load_texture(
            overlay_key,
            cache_path=overlay_path,
        )
        detail = None
        if detail_key is not None and detail_path is not None:
            detail = self._load_texture(
                detail_key,
                cache_path=detail_path,
            )
        if detail is None:
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
        terrain_seed = int(self.state.rng.state)
        self.ground.schedule_generate(seed=terrain_seed, layers=3)

    def open(self) -> None:
        self.close()
        self.creature_textures.clear()

        base = self._load_texture(
            "ter_q1_base",
            cache_path="ter/ter_q1_base.jaz",
        )
        overlay = self._load_texture(
            "ter_q1_tex1",
            cache_path="ter/ter_q1_tex1.jaz",
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
            terrain_seed = int(self.state.rng.state)
            self.ground.schedule_generate(seed=terrain_seed, layers=3)

        for asset in sorted(set(CREATURE_ASSET.values())):
            texture = self._load_texture(
                asset,
                cache_path=f"game/{asset}.jaz",
            )
            if texture is not None:
                self.creature_textures[asset] = texture

        self.projs_texture = self._load_texture(
            "projs",
            cache_path="game/projs.jaz",
        )
        self.particles_texture = self._load_texture(
            "particles",
            cache_path="game/particles.jaz",
        )
        self.bullet_texture = self._load_texture(
            "bullet_i",
            cache_path="load/bullet16.tga",
        )
        self.bullet_trail_texture = self._load_texture(
            "bulletTrail",
            cache_path="load/bulletTrail.tga",
        )
        self.arrow_texture = self._load_texture(
            "arrow",
            cache_path="load/arrow.tga",
        )
        self.bonuses_texture = self._load_texture(
            "bonuses",
            cache_path="game/bonuses.jaz",
        )
        self.wicons_texture = self._load_texture(
            "ui_wicons",
            cache_path="ui/ui_wicons.jaz",
        )
        self.bodyset_texture = self._load_texture(
            "bodyset",
            cache_path="game/bodyset.jaz",
        )
        self.clock_table_texture = self._load_texture(
            "ui_clockTable",
            cache_path="ui/ui_clockTable.jaz",
        )
        self.clock_pointer_texture = self._load_texture(
            "ui_clockPointer",
            cache_path="ui/ui_clockPointer.jaz",
        )
        self.aim_texture = self._load_texture(
            "ui_aim",
            cache_path="ui/ui_aim.jaz",
        )
        self.muzzle_flash_texture = self._load_texture(
            "muzzleFlash",
            cache_path="game/muzzleFlash.jaz",
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

        self._texture_loader = None

        self.creature_textures.clear()
        self.projs_texture = None
        self.particles_texture = None
        self.bullet_texture = None
        self.bullet_trail_texture = None
        self.arrow_texture = None
        self.bonuses_texture = None
        self.wicons_texture = None
        self.bodyset_texture = None
        self.clock_table_texture = None
        self.clock_pointer_texture = None
        self.aim_texture = None
        self.muzzle_flash_texture = None
        self.fx_textures = None
        self.fx_queue.clear()
        self.fx_queue_rotated.clear()
        self.last_events = WorldEvents(hits=[], deaths=(), pickups=[], sfx=[])
        self.last_presentation = PresentationStepCommands()
        self.last_command_hash = ""
        self._game_tune_started = False

    def update(
        self,
        dt: float,
        *,
        inputs: list[PlayerInput] | None = None,
        auto_pick_perks: bool = False,
        game_mode: int = int(GameMode.SURVIVAL),
        perk_progression_enabled: bool = False,
        defer_camera_shake_update: bool = False,
        rng_marks_out: dict[str, int] | None = None,
    ) -> list[ProjectileHit]:
        if self.audio_router is not None:
            self.audio_router.audio = self.audio
            self.audio_router.audio_rng = self.audio_rng
            self.audio_router.demo_mode_active = self.demo_mode_active

        detail_preset = 5
        fx_toggle = 0
        if self.config is not None:
            detail_preset = self.config.detail_preset
            fx_toggle = self.config.fx_toggle

        if self.ground is not None:
            self._sync_ground_settings()
            self.ground.process_pending()

        step = run_deterministic_step(
            world=self.world_state,
            dt_frame=float(dt),
            inputs=inputs,
            world_size=float(self.world_size),
            damage_scale_by_type=self._damage_scale_by_type,
            detail_preset=int(detail_preset),
            fx_toggle=int(fx_toggle),
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            auto_pick_perks=bool(auto_pick_perks),
            game_mode=int(game_mode),
            demo_mode_active=bool(self.demo_mode_active),
            perk_progression_enabled=bool(perk_progression_enabled),
            game_tune_started=bool(self._game_tune_started),
            defer_camera_shake_update=bool(defer_camera_shake_update),
            rng_marks_out=rng_marks_out,
        )
        self.apply_step_result(
            step,
            game_tune_started=bool(self._game_tune_started or step.presentation.trigger_game_tune),
            apply_audio=True,
            update_camera=True,
        )
        return step.events.hits

    def apply_step_result(
        self,
        step: DeterministicStepResult,
        *,
        game_tune_started: bool,
        apply_audio: bool = True,
        update_camera: bool = True,
    ) -> None:
        self.last_events = step.events
        self.last_presentation = step.presentation
        self.last_command_hash = step.command_hash

        if float(step.dt_sim) > 0.0:
            self._elapsed_ms += float(step.dt_sim) * 1000.0
            self._bonus_anim_phase += float(step.dt_sim) * 1.3

        self._game_tune_started = bool(game_tune_started)

        if apply_audio and step.presentation.trigger_game_tune:
            self.audio_router.trigger_game_tune()
        if apply_audio:
            for key in step.presentation.sfx_keys:
                self.audio_router.play_sfx_resolved(key)

        if update_camera:
            self.update_camera(step.dt_sim)

    def _queue_projectile_decals(self, hits: list[ProjectileHit], *, rand: Callable[[], int]) -> None:
        fx_toggle = 0
        detail_preset = 5
        if self.config is not None:
            fx_toggle = self.config.fx_toggle
            detail_preset = self.config.detail_preset
        queue_projectile_decals(
            state=self.state,
            players=self.players,
            fx_queue=self.fx_queue,
            hits=hits,
            rand=rand,
            detail_preset=detail_preset,
            fx_toggle=fx_toggle,
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
        # Bake decals into the ground render target as part of the render pass,
        # matching `fx_queue_render()` placement in `gameplay_render_world`.
        self._bake_fx_queues()
        self.renderer.draw(
            render_frame=self.build_render_frame(),
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def build_render_frame(self) -> RenderFrame:
        return RenderFrame(
            assets_dir=self.assets_dir,
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            config=self.config,
            camera=self.camera,
            ground=self.ground,
            state=self.state,
            players=self.players,
            creatures=self.creatures,
            creature_textures=self.creature_textures,
            projs_texture=self.projs_texture,
            particles_texture=self.particles_texture,
            bullet_texture=self.bullet_texture,
            bullet_trail_texture=self.bullet_trail_texture,
            arrow_texture=self.arrow_texture,
            bonuses_texture=self.bonuses_texture,
            bodyset_texture=self.bodyset_texture,
            clock_table_texture=self.clock_table_texture,
            clock_pointer_texture=self.clock_pointer_texture,
            aim_texture=self.aim_texture,
            muzzle_flash_texture=self.muzzle_flash_texture,
            wicons_texture=self.wicons_texture,
            elapsed_ms=float(self._elapsed_ms),
            bonus_anim_phase=float(self._bonus_anim_phase),
            lan_player_rings_enabled=bool(self.lan_player_rings_enabled),
            lan_local_aim_indicators_only=bool(self.lan_local_aim_indicators_only),
            lan_local_player_slot_index=int(self.lan_local_player_slot_index),
        )

    def update_camera(self, _dt: float) -> None:
        if not self.players:
            return

        screen_size = self.renderer._camera_screen_size()

        alive = [player for player in self.players if player.health > 0.0]
        if alive:
            inv_alive = 1.0 / float(len(alive))
            focus = Vec2(
                sum(player.pos.x for player in alive) * inv_alive,
                sum(player.pos.y for player in alive) * inv_alive,
            )
            camera = screen_size * 0.5 - focus
        else:
            camera = self.camera

        camera = camera + self.state.camera_shake_offset

        self.camera = self.renderer._clamp_camera(camera, screen_size)

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self.renderer.world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self.renderer.screen_to_world(pos)
