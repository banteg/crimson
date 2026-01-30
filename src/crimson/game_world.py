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

from .camera import camera_shake_update
from .creatures.anim import creature_corpse_frame_for_type
from .creatures.runtime import CreaturePool
from .creatures.spawn import SpawnEnv
from .effects import FxQueue, FxQueueRotated
from .gameplay import GameplayState, PlayerInput, PlayerState, perk_active, weapon_assign_player
from .render.terrain_fx import FxQueueTextures, bake_fx_queues
from .render.world_renderer import WorldRenderer
from .audio_router import AudioRouter
from .perks import PerkId
from .projectiles import ProjectileTypeId
from .sim.world_defs import BEAM_TYPES, CREATURE_ASSET
from .sim.world_state import ProjectileHit, WorldState
from .weapons import WEAPON_TABLE, projectile_type_id_from_weapon_id
from .game_modes import GameMode


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
    world_state: WorldState = field(init=False)

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
        self.world_state = WorldState.build(
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            difficulty_level=int(self.difficulty_level),
        )
        self.spawn_env = self.world_state.spawn_env
        self.state = self.world_state.state
        self.players = self.world_state.players
        self.creatures = self.world_state.creatures
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
            projectile_type_id_from_weapon_id(entry.weapon_id): float(entry.damage_scale or 1.0)
            for entry in WEAPON_TABLE
            if entry.weapon_id > 0
        }
        player_count = 1
        if self.config is not None:
            try:
                player_count = int(self.config.data.get("player_count", 1) or 1)
            except Exception:
                player_count = 1
        self.reset(player_count=max(1, min(4, player_count)))

    def reset(
        self,
        *,
        seed: int = 0xBEEF,
        player_count: int = 1,
        spawn_x: float | None = None,
        spawn_y: float | None = None,
    ) -> None:
        self.world_state = WorldState.build(
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            difficulty_level=int(self.difficulty_level),
        )
        self.spawn_env = self.world_state.spawn_env
        self.state = self.world_state.state
        self.players = self.world_state.players
        self.creatures = self.world_state.creatures
        self.state.rng.srand(int(seed))
        self.fx_queue.clear()
        self.fx_queue_rotated.clear()
        self._elapsed_ms = 0.0
        self._bonus_anim_phase = 0.0
        base_x = float(self.world_size) * 0.5 if spawn_x is None else float(spawn_x)
        base_y = float(self.world_size) * 0.5 if spawn_y is None else float(spawn_y)
        count = max(1, int(player_count))
        if count <= 1:
            offsets = [(0.0, 0.0)]
        else:
            radius = 32.0
            step = math.tau / float(count)
            offsets = [
                (math.cos(float(idx) * step) * radius, math.sin(float(idx) * step) * radius) for idx in range(count)
            ]

        for idx in range(count):
            offset_x, offset_y = offsets[idx]
            x = base_x + float(offset_x)
            y = base_y + float(offset_y)
            x = max(0.0, min(float(self.world_size), x))
            y = max(0.0, min(float(self.world_size), y))
            player = PlayerState(index=idx, pos_x=x, pos_y=y)
            weapon_assign_player(player, 1)
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
                missing=self.missing_assets,
            )
        else:
            loader = TextureLoader.from_assets_root(self.assets_dir)
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
            file_path=self._png_path_for(base_path),
        )
        overlay = self._load_texture(
            overlay_key,
            cache_path=overlay_path,
            file_path=self._png_path_for(overlay_path),
        )
        detail = None
        if detail_key is not None and detail_path is not None:
            detail = self._load_texture(
                detail_key,
                cache_path=detail_path,
                file_path=self._png_path_for(detail_path),
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

        self._texture_loader = None

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
        game_mode: int = int(GameMode.SURVIVAL),
        perk_progression_enabled: bool = False,
    ) -> list[ProjectileHit]:
        if inputs is None:
            inputs = [PlayerInput() for _ in self.players]

        self.state.game_mode = int(game_mode)
        self.state.demo_mode_active = bool(self.demo_mode_active)

        if self.audio_router is not None:
            self.audio_router.audio = self.audio
            self.audio_router.audio_rng = self.audio_rng
            self.audio_router.demo_mode_active = self.demo_mode_active

        # Time scale (Reflex Boost): gameplay_update_and_render @ 0x0040AAB0.
        # When active, `frame_dt` is scaled by `time_scale_factor`, with a linear
        # ramp from 0.3 -> 1.0 over the final second of the timer.
        time_scale_active = self.state.bonuses.reflex_boost > 0.0
        if time_scale_active:
            time_scale_factor = 0.3
            timer = float(self.state.bonuses.reflex_boost)
            if timer < 1.0:
                time_scale_factor = (1.0 - timer) * 0.7 + 0.3
            dt = float(dt) * float(time_scale_factor)

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
        prev_perk_pending = int(self.state.perk_selection.pending_count)

        events = self.world_state.step(
            dt,
            inputs=inputs,
            world_size=float(self.world_size),
            damage_scale_by_type=self._damage_scale_by_type,
            detail_preset=detail_preset,
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            auto_pick_perks=auto_pick_perks,
            game_mode=game_mode,
            perk_progression_enabled=bool(perk_progression_enabled),
        )

        if perk_progression_enabled and int(self.state.perk_selection.pending_count) > prev_perk_pending:
            self.audio_router.play_sfx("sfx_ui_levelup")

        if events.hits:
            self._queue_projectile_decals(events.hits)
            self.audio_router.play_hit_sfx(
                events.hits,
                game_mode=game_mode,
                rand=self.state.rng.rand,
                beam_types=BEAM_TYPES,
            )

        for idx, player in enumerate(self.players):
            if idx < len(prev_audio):
                prev_shot_seq, prev_reload_active, prev_reload_timer = prev_audio[idx]
                self.audio_router.handle_player_audio(
                    player,
                    prev_shot_seq=prev_shot_seq,
                    prev_reload_active=prev_reload_active,
                    prev_reload_timer=prev_reload_timer,
                )

        if events.deaths:
            self.audio_router.play_death_sfx(events.deaths, rand=self.state.rng.rand)

        if events.pickups:
            for _ in events.pickups:
                self.audio_router.play_sfx("sfx_ui_bonus")

        if events.sfx:
            for key in events.sfx[:4]:
                self.audio_router.play_sfx(key)

        self.update_camera(dt)
        return events.hits

    def _queue_projectile_decals(self, hits: list[ProjectileHit]) -> None:
        rand = self.state.rng.rand
        fx_toggle = 0
        detail_preset = 5
        if self.config is not None:
            fx_toggle = int(self.config.data.get("fx_toggle", 0) or 0)
            detail_preset = int(self.config.data.get("detail_preset", 5) or 5)

        freeze_active = self.state.bonuses.freeze > 0.0
        bloody = bool(self.players) and perk_active(self.players[0], PerkId.BLOODY_MESS_QUICK_LEARNER)

        for type_id, origin_x, origin_y, hit_x, hit_y, target_x, target_y in hits:
            type_id = int(type_id)

            base_angle = math.atan2(float(hit_y) - float(origin_y), float(hit_x) - float(origin_x))

            # Native: Gauss Gun + Fire Bullets spawn a distinct "streak" of large terrain decals.
            if type_id in (int(ProjectileTypeId.GAUSS_GUN), int(ProjectileTypeId.FIRE_BULLETS)):
                dir_x = math.cos(base_angle)
                dir_y = math.sin(base_angle)
                for _ in range(6):
                    dist = float(int(rand()) % 100) * 0.1
                    if dist > 4.0:
                        dist = float(int(rand()) % 0x5A + 10) * 0.1
                    if dist > 7.0:
                        dist = float(int(rand()) % 0x50 + 0x14) * 0.1
                    self.fx_queue.add_random(
                        pos_x=float(target_x) + dir_x * dist * 20.0,
                        pos_y=float(target_y) + dir_y * dist * 20.0,
                        rand=rand,
                    )
            elif type_id in BEAM_TYPES:
                if self.ground is not None and self.fx_textures is not None:
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
            elif type_id == int(ProjectileTypeId.ROCKET_LAUNCHER):
                if self.ground is not None and self.fx_textures is not None:
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
            elif not freeze_active:
                for _ in range(3):
                    spread = float(int(rand()) % 0x14 - 10) * 0.1
                    angle = base_angle + spread
                    dir_x = math.cos(angle) * 20.0
                    dir_y = math.sin(angle) * 20.0
                    self.fx_queue.add_random(pos_x=float(target_x), pos_y=float(target_y), rand=rand)
                    self.fx_queue.add_random(
                        pos_x=float(target_x) + dir_x * 1.5,
                        pos_y=float(target_y) + dir_y * 1.5,
                        rand=rand,
                    )
                    self.fx_queue.add_random(
                        pos_x=float(target_x) + dir_x * 2.0,
                        pos_y=float(target_y) + dir_y * 2.0,
                        rand=rand,
                    )
                    self.fx_queue.add_random(
                        pos_x=float(target_x) + dir_x * 2.5,
                        pos_y=float(target_y) + dir_y * 2.5,
                        rand=rand,
                    )

            if bloody:
                lo = -30
                hi = 30
                while lo > -60:
                    span = hi - lo
                    for _ in range(2):
                        dx = float(int(rand()) % span + lo)
                        dy = float(int(rand()) % span + lo)
                        self.fx_queue.add_random(
                            pos_x=float(target_x) + dx,
                            pos_y=float(target_y) + dy,
                            rand=rand,
                        )
                    lo -= 10
                    hi += 10

            # Native hit path: spawn transient blood splatter particles and only
            # bake decals into the terrain once those particles expire.
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

            if freeze_active:
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
