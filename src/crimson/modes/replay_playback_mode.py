from __future__ import annotations

import random
from pathlib import Path
from typing import Any, cast

from grim import music as grim_music
from grim.assets import PaqTextureCache, TextureLoader
from grim.audio import AudioState, init_audio_state, play_music, shutdown_audio, update_audio
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.view import ViewContext

from ..game_modes import GameMode
from ..render.rtx.mode import mode_from_rtx_flag
from ..render.world.renderer import WorldRenderer, WorldRenderHost
from ..replay import (
    Replay,
    apply_replay_bootstrap,
    load_replay_file,
    warn_on_game_version_mismatch,
)
from ..replay.types import ReplayHeader
from ..sim.bootstrap import BOOTSTRAP_KIND_TERRAIN_V1
from ..sim.clock import FixedStepClock
from ..sim.driver.playback_driver import (
    PlaybackDriver,
    PlaybackDriverConfig,
    PlaybackDriverOptions,
    PlaybackEventConfig,
    PlaybackSessionConfigs,
    PlaybackSessionDefaults,
    PlaybackTickOutcome,
    PlaybackTimingConfig,
    PlaybackWorldConfig,
    QuestSessionConfig,
    RushSessionConfig,
    SurvivalSessionConfig,
    resolve_replay_quest_setup,
)
from ..sim.driver.setup import ReplayRunnerError, status_from_snapshot
from ..sim.input_providers import FrameContext, InputStatus
from ..sim.tick_runner import TickRunner
from ..terrain_assets import terrain_texture_by_id
from ..ui.hud import (
    HUD_AMMO_BASE_POS,
    HUD_AMMO_TEXT_OFFSET,
    HudAssets,
    HudRenderContext,
    HudState,
    draw_hud_overlay,
    hud_flags_for_game_mode,
    hud_ui_scale,
    load_hud_assets,
)
from ..views.quest_run_overlay import (
    draw_quest_complete_banner_overlay,
    draw_quest_title_timer_overlay,
    quest_level_label,
)
from ..weapon_runtime import weapon_assign_player
from ..weapons import WeaponId
from ..world import AudioBridge, RenderResources, SimWorldState
from ..world.terrain_runtime import TerrainRuntime, normalize_terrain_ids

_PLAYBACK_SPEED_STEPS: tuple[float, ...] = (0.25, 0.5, 1.0, 2.0, 4.0, 8.0)
_DEFAULT_SPEED_INDEX = 2
_SKIP_SHORT_SECONDS = 5.0
_SKIP_LONG_SECONDS = 30.0
_REPLAY_WIDGET_PANEL_SIZE = Vec2(182.0, 53.0)
_REPLAY_WIDGET_ICON_SIZE = Vec2(32.0, 32.0)
_REPLAY_WIDGET_BAR_HEIGHT = 4.0
_REPLAY_WIDGET_X_SHIFT = 10.0
_REPLAY_WIDGET_TEXT_LINE1_Y = HUD_AMMO_BASE_POS[1] + HUD_AMMO_TEXT_OFFSET[1]
_REPLAY_WIDGET_PANEL_TO_LINE1_Y = -7.0
_REPLAY_WIDGET_PANEL_OFFSET_X = 0.0
_REPLAY_WIDGET_PANEL_OFFSET_Y = 0.0
_REPLAY_WIDGET_CLOCK_OFFSET_X = 0.0
_REPLAY_WIDGET_CLOCK_OFFSET_Y = 0.0
_REPLAY_WIDGET_TEXT_OFFSET_X = 0.0
_REPLAY_WIDGET_TEXT_OFFSET_Y = 0.0
_REPLAY_WIDGET_BAR_OFFSET_X = 0.0
_REPLAY_WIDGET_BAR_OFFSET_Y = 0.0


def _world_reset_seed_for_replay(header: ReplayHeader) -> int:
    match str(header.bootstrap_kind):
        case kind if kind == BOOTSTRAP_KIND_TERRAIN_V1:
            return int(header.bootstrap_seed)
        case _:
            return int(header.seed)


class ReplayPlaybackMode:
    def __init__(
        self,
        ctx: ViewContext,
        *,
        replay_path: Path,
        config: CrimsonConfig,
        console: ConsoleState,
        max_ticks: int | None = None,
        trace_rng: bool = False,
        rtx: bool = False,
        show_replay_widget: bool = True,
    ) -> None:
        self._ctx = ctx
        self._replay_path = Path(replay_path)
        self._config = config
        self._console = console
        self._max_ticks = max(0, int(max_ticks)) if max_ticks is not None else None
        self._trace_rng = bool(trace_rng)
        self._rtx = bool(rtx)
        self._show_replay_widget = bool(show_replay_widget)

        self.close_requested = False

        self._replay: Replay | None = None
        self._world_size = 1024.0
        self._difficulty_level = 0
        self._hardcore = False
        self._preserve_bugs = bool(ctx.preserve_bugs)
        self._demo_mode_active = False
        self._rtx_mode = mode_from_rtx_flag(self._rtx)
        self._texture_cache: PaqTextureCache | None = None
        self._sim_world: SimWorldState | None = None
        self._render_resources: RenderResources | None = None
        self._audio_bridge: AudioBridge | None = None
        self._terrain_runtime: TerrainRuntime | None = None
        self._renderer: WorldRenderer | None = None
        self._camera = Vec2(-1.0, -1.0)
        self._defer_menu_open = False
        self._small: SmallFontData | None = None
        self._hud_assets: HudAssets | None = None
        self._hud_state = HudState()
        self._grim_mono: GrimMonoFont | None = None
        self._quest_complete_texture: rl.Texture | None = None
        self._quest_title = ""
        self._quest_level = ""
        self._quest_name_timer_ms = 0.0
        self._quest_completion_transition_ms = -1.0

        self._tick_rate = 60
        self._dt = 1.0 / 60.0
        self._dt_accum = 0.0
        self._clock = FixedStepClock(tick_rate=60)
        self._frame_index = 0
        self._tick_index = 0
        self._finished = False
        self._terminal_events_applied = False
        self._paused = False
        self._step_once_pending = False
        self._speed_index = _DEFAULT_SPEED_INDEX

        self._driver: PlaybackDriver | None = None
        self._tick_runner: TickRunner | None = None
        self._survival = None
        self._rush = None
        self._quest = None
        self._quest_total_spawn_count = 0
        self._quest_spawn_timeline_ms = 0.0

        self._audio: AudioState | None = None
        self._audio_rng: random.Random | None = None

    @property
    def tick_index(self) -> int:
        return int(self._tick_index)

    @property
    def finished(self) -> bool:
        return bool(self._finished)

    @staticmethod
    def _format_time_text(seconds: float) -> str:
        total_seconds = max(0, int(seconds))
        minutes = total_seconds // 60
        rem_seconds = total_seconds % 60
        return f"{minutes}:{rem_seconds:02d}"

    def _replay_progress_ratio(self) -> float:
        replay = self._replay
        if replay is None:
            return 0.0
        total_ticks = len(replay.inputs)
        if total_ticks <= 0:
            return 1.0
        ratio = float(self._tick_index) / float(total_ticks)
        if ratio < 0.0:
            return 0.0
        if ratio > 1.0:
            return 1.0
        return ratio

    def _register_replay_audio_commands(self) -> None:
        console = self._console

        def cmd_snd_add_game_tune(args: list[str]) -> None:
            if len(args) != 1:
                console.log.log("snd_addGameTune <tuneName.ogg>")
                return
            audio = self._audio
            if audio is None:
                return
            rel_path = f"music/{args[0]}"
            result = grim_music.load_music_track(audio.music, self._ctx.assets_dir, rel_path, console=console)
            if result is None:
                return
            track_key, _track_id = result
            grim_music.queue_track(audio.music, track_key)

        console.register_command("snd_addGameTune", cmd_snd_add_game_tune)

    def _load_game_tune_queue(self) -> None:
        if self._audio is None:
            return
        self._console.exec_line("exec music/game_tunes.txt")

    def _sync_world_size_ownership(self) -> None:
        sim_world = self._sim_world
        render_resources = self._render_resources
        terrain_runtime = self._terrain_runtime
        if sim_world is None or render_resources is None or terrain_runtime is None:
            return
        world_size = float(self._world_size)
        sim_world.world_size = world_size
        render_resources.world_size = world_size
        terrain_runtime.world_size = world_size
        ground = render_resources.ground
        if ground is not None:
            side = max(0, int(world_size))
            ground.width = side
            ground.height = side

    def _reset_world_runtime(self, *, seed: int, player_count: int) -> None:
        sim_world = self._sim_world
        render_resources = self._render_resources
        terrain_runtime = self._terrain_runtime
        if sim_world is None or render_resources is None or terrain_runtime is None:
            return
        self._sync_world_size_ownership()
        sim_world.demo_mode_active = bool(self._demo_mode_active)
        sim_world.hardcore = bool(self._hardcore)
        sim_world.difficulty_level = int(self._difficulty_level)
        sim_world.preserve_bugs = bool(self._preserve_bugs)
        sim_world.reset(
            seed=int(seed),
            player_count=int(player_count),
        )
        render_resources.fx_queue.clear()
        render_resources.fx_queue_rotated.clear()
        self._camera = Vec2(-1.0, -1.0)
        if render_resources.ground is not None:
            terrain_runtime.schedule_from_rng_seed(
                seed=int(sim_world.state.rng.state),
                layers=3,
            )

    def _open_world_runtime(self) -> None:
        sim_world = self._sim_world
        render_resources = self._render_resources
        if sim_world is None or render_resources is None:
            return
        render_resources.texture_cache = self._texture_cache
        render_resources.config = self._config
        render_resources.open(terrain_seed=int(sim_world.state.rng.state))
        self._texture_cache = render_resources.texture_cache

    def _close_world_runtime(self) -> None:
        render_resources = self._render_resources
        sim_world = self._sim_world
        if render_resources is not None:
            render_resources.close()
        if sim_world is not None:
            sim_world.close_session()

    def sync_audio_bridge_state(self) -> None:
        audio_bridge = self._audio_bridge
        if audio_bridge is None:
            return
        audio_bridge.sync(
            audio=self._audio,
            audio_rng=self._audio_rng,
            demo_mode_active=bool(self._demo_mode_active),
        )

    def apply_bootstrap_terrain(
        self,
        *,
        terrain_ids: tuple[int, int, int],
        seed: int,
        layers: int = 3,
    ) -> None:
        terrain_runtime = self._terrain_runtime
        if terrain_runtime is None:
            return
        terrain_runtime.apply_bootstrap_terrain(
            terrain_ids=terrain_ids,
            seed=int(seed),
            layers=int(layers),
        )

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
        terrain_runtime = self._terrain_runtime
        sim_world = self._sim_world
        if terrain_runtime is None or sim_world is None:
            return
        terrain_runtime.set_terrain(
            base_key=base_key,
            overlay_key=overlay_key,
            base_path=base_path,
            overlay_path=overlay_path,
            detail_key=detail_key,
            detail_path=detail_path,
        )
        terrain_runtime.schedule_from_rng_seed(
            seed=int(sim_world.state.rng.state),
            layers=3,
        )

    def _bake_fx_queues(self) -> None:
        render_resources = self._render_resources
        if render_resources is None:
            return
        render_resources.bake_fx_queues()

    def build_render_frame(self):
        sim_world = self._sim_world
        render_resources = self._render_resources
        if sim_world is None or render_resources is None:
            raise RuntimeError("replay world runtime is not initialized")
        return render_resources.build_render_frame(
            state=sim_world.state,
            players=sim_world.players,
            creatures=sim_world.creatures,
            camera=self._camera,
            demo_mode_active=bool(self._demo_mode_active),
            elapsed_ms=float(sim_world.elapsed_ms),
            bonus_anim_phase=float(sim_world.bonus_anim_phase),
            lan_player_rings_enabled=False,
            lan_local_aim_indicators_only=False,
            lan_local_player_slot_index=0,
            rtx_mode=self._rtx_mode,
        )

    def _draw_world(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        renderer = self._renderer
        if renderer is None:
            return
        self._bake_fx_queues()
        renderer.draw(
            render_frame=self.build_render_frame(),
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def update_camera(self, _dt: float) -> None:
        sim_world = self._sim_world
        renderer = self._renderer
        if sim_world is None or renderer is None:
            return
        if not sim_world.players:
            return

        screen_size = renderer._camera_screen_size()

        alive = [player for player in sim_world.players if player.health > 0.0]
        if alive:
            inv_alive = 1.0 / float(len(alive))
            focus = Vec2(
                sum(player.pos.x for player in alive) * inv_alive,
                sum(player.pos.y for player in alive) * inv_alive,
            )
            camera = screen_size * 0.5 - focus
        else:
            camera = self._camera

        camera = camera + sim_world.state.camera_shake_offset
        self._camera = renderer._clamp_camera(camera, screen_size)

    def _replay_widget_metrics(self) -> tuple[float, float, float, float, float, float]:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = hud_ui_scale(screen_w, screen_h)

        panel_w = _REPLAY_WIDGET_PANEL_SIZE.x * scale
        panel_h = _REPLAY_WIDGET_PANEL_SIZE.y * scale
        panel_x = screen_w - panel_w - float(_REPLAY_WIDGET_X_SHIFT) * scale
        line1_y = float(_REPLAY_WIDGET_TEXT_LINE1_Y) * scale
        panel_y = max(2.0 * scale, line1_y + _REPLAY_WIDGET_PANEL_TO_LINE1_Y * scale)
        return scale, panel_x, panel_y, panel_w, panel_h, line1_y

    def _draw_replay_widget(self) -> None:
        replay = self._replay
        if replay is None:
            return

        scale, panel_x, panel_y, panel_w, panel_h, line1_y = self._replay_widget_metrics()
        panel_x += float(_REPLAY_WIDGET_PANEL_OFFSET_X) * scale
        panel_y += float(_REPLAY_WIDGET_PANEL_OFFSET_Y) * scale

        assets = self._hud_assets

        icon_w = _REPLAY_WIDGET_ICON_SIZE.x * scale
        icon_h = _REPLAY_WIDGET_ICON_SIZE.y * scale
        icon_x = panel_x + 2.0 * scale + float(_REPLAY_WIDGET_CLOCK_OFFSET_X) * scale
        icon_y = panel_y + 8.0 * scale + float(_REPLAY_WIDGET_CLOCK_OFFSET_Y) * scale

        if assets is not None and assets.clock_table is not None:
            src = rl.Rectangle(0.0, 0.0, float(assets.clock_table.width), float(assets.clock_table.height))
            dst = rl.Rectangle(icon_x, icon_y, icon_w, icon_h)
            rl.draw_texture_pro(assets.clock_table, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.Color(255, 255, 255, 230))

        elapsed_seconds = float(self._tick_index) / float(self._tick_rate)

        if assets is not None and assets.clock_pointer is not None:
            src = rl.Rectangle(0.0, 0.0, float(assets.clock_pointer.width), float(assets.clock_pointer.height))
            center_x = icon_x + icon_w * 0.5
            center_y = icon_y + icon_h * 0.5
            dst = rl.Rectangle(center_x, center_y, icon_w, icon_h)
            origin = rl.Vector2(icon_w * 0.5, icon_h * 0.5)
            rotation = max(0.0, float(elapsed_seconds)) * 6.0
            rl.draw_texture_pro(
                assets.clock_pointer,
                src,
                dst,
                origin,
                rotation,
                rl.Color(255, 255, 255, 220),
            )

        total_ticks = len(replay.inputs)
        total_seconds = float(total_ticks) / float(self._tick_rate)
        progress_ratio = self._replay_progress_ratio()

        text_x = icon_x + icon_w + 6.0 * scale + float(_REPLAY_WIDGET_TEXT_OFFSET_X) * scale
        line1_y = line1_y + float(_REPLAY_WIDGET_TEXT_OFFSET_Y) * scale
        text_scale = 1.0
        status = "PAUSE" if self._paused else "REPLAY"
        status_color = rl.Color(245, 210, 120, 230) if self._paused else rl.Color(230, 230, 230, 220)
        self._draw_ui_text(
            f"{status} {self._playback_speed():.2f}x",
            Vec2(text_x, line1_y),
            status_color,
            scale=text_scale,
        )

        elapsed_text = self._format_time_text(elapsed_seconds)
        total_text = self._format_time_text(total_seconds)
        elapsed_w = self._measure_ui_text_width(elapsed_text, scale=text_scale)
        total_w = self._measure_ui_text_width(total_text, scale=text_scale)
        line2_y = line1_y + 18.0 * scale

        right_limit = panel_x + panel_w - 4.0 * scale + float(_REPLAY_WIDGET_TEXT_OFFSET_X) * scale
        total_x = right_limit - total_w
        bar_x_base = text_x + elapsed_w + 6.0 * scale
        bar_w = max(8.0 * scale, total_x - 6.0 * scale - bar_x_base)
        bar_x = bar_x_base + float(_REPLAY_WIDGET_BAR_OFFSET_X) * scale
        bar_y = line2_y + 5.0 * scale + float(_REPLAY_WIDGET_BAR_OFFSET_Y) * scale
        bar_h = _REPLAY_WIDGET_BAR_HEIGHT * scale
        rl.draw_rectangle(int(bar_x), int(bar_y), int(bar_w), int(bar_h), rl.Color(46, 67, 96, 150))
        fill_w = bar_w * progress_ratio
        if fill_w > 0.0:
            rl.draw_rectangle(int(bar_x), int(bar_y), int(fill_w), int(bar_h), rl.Color(70, 130, 220, 225))

        self._draw_ui_text(
            elapsed_text,
            Vec2(text_x, line2_y),
            rl.Color(220, 220, 220, 210),
            scale=text_scale,
        )
        self._draw_ui_text(
            total_text,
            Vec2(total_x, line2_y),
            rl.Color(220, 220, 220, 210),
            scale=text_scale,
        )

    def open(self) -> None:
        self._small = load_small_font(self._ctx.assets_dir)
        self._hud_assets = load_hud_assets(self._ctx.assets_dir)
        self._hud_state = HudState()
        if self._grim_mono is not None:
            rl.unload_texture(self._grim_mono.texture)
            self._grim_mono = None
        self._quest_complete_texture = None
        self._quest_title = ""
        self._quest_level = ""
        self._quest_name_timer_ms = 0.0
        self._quest_completion_transition_ms = -1.0

        replay = load_replay_file(self._replay_path)
        self._replay = replay
        warn_on_game_version_mismatch(replay, action="playback")

        tick_rate = int(replay.header.tick_rate)
        if tick_rate <= 0:
            raise ValueError(f"invalid tick_rate: {tick_rate}")
        self._tick_rate = tick_rate
        self._dt = 1.0 / float(tick_rate)
        self._dt_accum = 0.0
        self._clock = FixedStepClock(tick_rate=int(tick_rate))
        self._frame_index = 0
        self._tick_index = 0
        self._finished = False
        self._terminal_events_applied = False
        self._paused = False
        self._step_once_pending = False
        self._speed_index = _DEFAULT_SPEED_INDEX
        self._defer_menu_open = False
        self._driver = None
        self._tick_runner = None

        world_size = float(replay.header.world_size)
        audio = init_audio_state(self._config, self._ctx.assets_dir, self._console)
        audio_rng = random.Random(int(replay.header.seed) & 0xFFFFFFFF)
        self._audio = audio
        self._audio_rng = audio_rng
        self._register_replay_audio_commands()
        self._load_game_tune_queue()

        self._world_size = float(world_size)
        self._difficulty_level = int(replay.header.difficulty_level)
        self._hardcore = bool(replay.header.hardcore)
        self._preserve_bugs = bool(replay.header.preserve_bugs)
        self._demo_mode_active = False
        self._rtx_mode = mode_from_rtx_flag(self._rtx)

        sim_world = SimWorldState(
            world_size=float(self._world_size),
            demo_mode_active=bool(self._demo_mode_active),
            hardcore=bool(self._hardcore),
            difficulty_level=int(self._difficulty_level),
            preserve_bugs=bool(self._preserve_bugs),
        )
        self._sim_world = sim_world
        self._render_resources = RenderResources(
            assets_dir=self._ctx.assets_dir,
            world_size=float(self._world_size),
            texture_cache=self._texture_cache,
            config=self._config,
        )
        self._audio_bridge = AudioBridge(
            demo_mode_active=bool(self._demo_mode_active),
            reflex_boost_timer_source=lambda: float(sim_world.state.bonuses.reflex_boost),
            audio=self._audio,
            audio_rng=self._audio_rng,
        )
        self._terrain_runtime = TerrainRuntime(
            world_size=float(self._world_size),
            render_resources=self._render_resources,
        )
        self._renderer = WorldRenderer(cast(WorldRenderHost, self))
        self._sync_world_size_ownership()
        self.sync_audio_bridge_state()
        self._reset_world_runtime(
            seed=_world_reset_seed_for_replay(replay.header),
            player_count=int(replay.header.player_count),
        )
        self._open_world_runtime()

        sim_world = self._sim_world
        render_resources = self._render_resources
        if sim_world is None or render_resources is None:
            raise RuntimeError("replay world runtime failed to initialize")

        self._hud_state.preserve_bugs = bool(sim_world.state.preserve_bugs)
        sim_world.state.status = status_from_snapshot(
            quest_unlock_index=int(replay.header.status.quest_unlock_index),
            quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
            weapon_usage_counts=replay.header.status.weapon_usage_counts,
        )
        bootstrap = apply_replay_bootstrap(
            replay.header,
            rng=sim_world.state.rng,
            world_size=float(world_size),
        )
        if bootstrap is not None:
            self.apply_bootstrap_terrain(
                terrain_ids=bootstrap.terrain.terrain_ids,
                seed=int(bootstrap.terrain.terrain_seed),
                layers=3,
            )

        mode_id = replay.header.game_mode_id
        spawn_entries = None
        quest_stage_major: int | None = None
        quest_stage_minor: int | None = None
        start_weapon_id: WeaponId | None = None
        match mode_id:
            case GameMode.QUESTS:
                quest, spawn_entries = resolve_replay_quest_setup(
                    replay,
                    world_size=float(self._world_size),
                    player_count=len(sim_world.players),
                )

                self._quest_title = str(quest.title)
                self._quest_level = quest_level_label(quest.major, quest.minor)
                self._grim_mono = load_grim_mono_font(self._ctx.assets_dir)
                self._quest_complete_texture = self._load_quest_complete_texture()
                quest_stage_major, quest_stage_minor = quest.level_key
                sim_world.state.quest_stage_major = int(quest_stage_major)
                sim_world.state.quest_stage_minor = int(quest_stage_minor)

                base_id, overlay_id, detail_id = normalize_terrain_ids(quest.terrain_ids)
                base = terrain_texture_by_id(base_id)
                overlay = terrain_texture_by_id(overlay_id)
                detail = terrain_texture_by_id(detail_id)
                if base is not None and overlay is not None:
                    base_key, base_path = base
                    overlay_key, overlay_path = overlay
                    detail_key = detail[0] if detail is not None else None
                    detail_path = detail[1] if detail is not None else None
                    self.set_terrain(
                        base_key=base_key,
                        overlay_key=overlay_key,
                        base_path=base_path,
                        overlay_path=overlay_path,
                        detail_key=detail_key,
                        detail_path=detail_path,
                    )

                start_weapon_id = quest.start_weapon_id
                if start_weapon_id <= WeaponId.NONE:
                    start_weapon_id = WeaponId.PISTOL
                for player in sim_world.players:
                    weapon_assign_player(player, start_weapon_id, state=sim_world.state)
                self._quest_total_spawn_count = int(sum(int(entry.count) for entry in spawn_entries))
                self._quest_spawn_timeline_ms = 0.0
            case _:
                self._quest_total_spawn_count = 0
                self._quest_spawn_timeline_ms = 0.0

        try:
            self._driver = PlaybackDriver(
                replay,
                PlaybackDriverOptions(
                    max_ticks=self._max_ticks,
                    trace_rng=bool(self._trace_rng),
                    version_mismatch_action=None,
                ),
                config=PlaybackDriverConfig(
                    timing=PlaybackTimingConfig(),
                    world=PlaybackWorldConfig(
                        world=sim_world.world_state,
                        world_size=float(self._world_size),
                        fx_queue=render_resources.fx_queue,
                        fx_queue_rotated=render_resources.fx_queue_rotated,
                        use_existing_world_state=True,
                    ),
                    events=PlaybackEventConfig(
                        defer_menu_open=False,
                        apply_terminal_tick_events=True,
                        terminal_events_use_resolved_dt=False,
                    ),
                    session_defaults=PlaybackSessionDefaults(
                        clear_fx_queues_each_tick=False,
                        game_tune_started=bool(sim_world.game_tune_started),
                    ),
                    sessions=PlaybackSessionConfigs(
                        survival=SurvivalSessionConfig(partition_events=True),
                        rush=RushSessionConfig(
                            enforce_loadout=True,
                        ),
                        quest=QuestSessionConfig(
                            partition_events=False,
                            disable_capture_spawn_events_authoritative=False,
                            finalize_post_render_lifecycle_each_tick=True,
                            result_uses_spawn_timeline_ms=False,
                            spawn_entries=spawn_entries,
                            quest_stage_major=quest_stage_major,
                            quest_stage_minor=quest_stage_minor,
                            start_weapon_id=start_weapon_id,
                        ),
                    ),
                ),
            )
        except ReplayRunnerError as exc:  # pragma: no cover
            raise ValueError(f"unsupported replay game_mode_id: {int(mode_id)}") from exc

        self._survival = self._driver.survival_session
        self._rush = self._driver.rush_session
        self._quest = self._driver.quest_session
        self._tick_runner = self._driver.build_tick_runner(
            defer_menu_open=(bool(self._defer_menu_open) if self._survival is not None else False),
        )

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._grim_mono is not None:
            rl.unload_texture(self._grim_mono.texture)
            self._grim_mono = None
        self._quest_complete_texture = None
        self._hud_assets = None
        self._driver = None
        self._tick_runner = None
        self._survival = None
        self._rush = None
        self._quest = None
        self._close_world_runtime()
        self._sim_world = None
        self._render_resources = None
        self._audio_bridge = None
        self._terrain_runtime = None
        self._renderer = None
        if self._audio is not None:
            shutdown_audio(self._audio)
            self._audio = None
            self._audio_rng = None

    def should_close(self) -> bool:
        return bool(self.close_requested)

    def consume_screenshot_request(self) -> bool:
        return False

    def _draw_ui_text(self, text: str, pos: Vec2, color: rl.Color, *, scale: float = 1.0) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, pos, scale, color)
        else:
            rl.draw_text(text, int(pos.x), int(pos.y), int(20 * scale), color)

    def _measure_ui_text_width(self, text: str, *, scale: float = 1.0) -> float:
        if self._small is not None:
            return float(measure_small_text_width(self._small, text, scale))
        return float(len(text)) * 8.0 * float(scale)

    def _load_quest_complete_texture(self) -> rl.Texture | None:
        loader = TextureLoader(
            assets_root=self._ctx.assets_dir,
            cache=self._texture_cache,
        )
        return loader.get(
            name="ui_textLevComp",
            paq_rel="ui/ui_textLevComp.jaz",
        )

    def _apply_tick_outcome(
        self,
        *,
        outcome: PlaybackTickOutcome,
        game_tune_started: bool,
        dt: float,
    ) -> float:
        sim_world = self._sim_world
        audio_bridge = self._audio_bridge
        if sim_world is None or audio_bridge is None:
            return 0.0

        sim_world.apply_step_metadata(
            events=outcome.step.events,
            presentation=outcome.step.presentation,
            command_hash=str(outcome.step.command_hash),
            dt_sim=float(outcome.step.dt_sim),
            game_tune_started=bool(game_tune_started),
        )
        self.sync_audio_bridge_state()
        audio_bridge.apply_plan(
            plan=outcome.step.presentation,
            apply_audio=True,
        )
        if outcome.spawn_timeline_ms is not None:
            self._quest_spawn_timeline_ms = float(outcome.spawn_timeline_ms)
            self._quest_name_timer_ms += float(dt) * 1000.0
            if outcome.completion_transition_ms is not None:
                self._quest_completion_transition_ms = float(outcome.completion_transition_ms)
            if bool(outcome.play_hit_sfx):
                audio_bridge.router.play_sfx("sfx_questhit")
            if bool(outcome.play_completion_music) and self._audio is not None:
                play_music(self._audio, "crimsonquest")
                playback = self._audio.music.playbacks.get("crimsonquest")
                if playback is not None:
                    playback.volume = 0.0
                    try:
                        rl.set_music_volume(playback.music, 0.0)
                    except RuntimeError:
                        playback.volume = 0.0

        return float(outcome.dt_sim)

    def _tick_limit(self) -> int:
        replay = self._replay
        if replay is None:
            return 0
        total_ticks = len(replay.inputs)
        if self._max_ticks is None:
            return int(total_ticks)
        return min(int(total_ticks), max(0, int(self._max_ticks)))

    def _session_game_tune_started(self) -> bool:
        if self._survival is not None:
            return bool(self._survival.game_tune_started)
        if self._quest is not None:
            return bool(self._quest.game_tune_started)
        if self._rush is not None:
            return bool(self._rush.game_tune_started)
        return False

    def _on_runner_tick_complete(self, _tick_index: int, tick: object) -> bool:
        outcome = cast(PlaybackTickOutcome, tick)
        dt_sim = self._apply_tick_outcome(
            outcome=outcome,
            game_tune_started=self._session_game_tune_started(),
            dt=float(self._dt),
        )
        self.update_camera(float(dt_sim))
        return False

    def _mark_finished_if_complete(self) -> None:
        tick_limit = int(self._tick_limit())
        if int(self._tick_index) < int(tick_limit):
            return
        replay = self._replay
        driver = self._driver
        if (
            replay is not None
            and driver is not None
            and (not self._terminal_events_applied)
            and int(self._tick_index) == len(replay.inputs)
        ):
            self._terminal_events_applied = True
            driver.apply_terminal_events(int(self._tick_index))
        self._finished = True

    def _advance_runner(
        self,
        *,
        dt_seconds: float,
        max_ticks: int | None = None,
        bake_fx_per_tick: bool = False,
    ) -> None:
        replay = self._replay
        render_resources = self._render_resources
        runner = self._tick_runner
        if replay is None or render_resources is None or runner is None:
            self._finished = True
            return
        if int(self._tick_index) >= int(self._tick_limit()):
            self._mark_finished_if_complete()
            return

        frame_dt = float(dt_seconds)
        ticks_requested = int(self._clock.advance(frame_dt))
        if max_ticks is not None:
            ticks_requested = min(int(ticks_requested), max(0, int(max_ticks)))
        self._frame_index = int(self._frame_index) + 1
        runner.begin_frame(
            FrameContext(
                dt_seconds=float(frame_dt),
                tick_dt_seconds=float(self._dt),
                frame_index=int(self._frame_index),
                candidate_ticks=max(0, int(ticks_requested)),
                is_networked=False,
                is_replay=True,
            ),
        )

        def _apply_completed(batch_results: list[object]) -> None:
            for tick_result in batch_results:
                result = cast(Any, tick_result)
                payload = result.payload
                if payload is None:
                    continue
                self._on_runner_tick_complete(int(result.tick_index), payload)
                if bake_fx_per_tick:
                    # Fast-seek runs many ticks without rendering; drain/clear
                    # per tick to mirror gameplay-side FX queue lifetime.
                    if render_resources.ground is not None and render_resources.fx_textures is not None:
                        self._bake_fx_queues()
                    else:
                        render_resources.fx_queue.clear()
                        render_resources.fx_queue_rotated.clear()

        batch = runner.advance_ticks(
            start_tick=int(self._tick_index),
            ticks_requested=max(0, int(ticks_requested)),
            tick_dt=float(self._dt),
        )
        _apply_completed(list(batch.completed_results))

        self._tick_index = int(batch.next_tick_index)
        if batch.batch_status is InputStatus.STALLED:
            raise RuntimeError(
                f"replay tick runner stalled before completion at tick {int(self._tick_index)}",
            )
        if batch.batch_status is InputStatus.EOS and int(self._tick_index) < int(self._tick_limit()):
            raise RuntimeError(
                f"replay tick runner hit eos before completion at tick {int(self._tick_index)}",
            )
        if batch.batch_status in (InputStatus.STALLED, InputStatus.EOS):
            unconsumed_ticks = max(0, int(ticks_requested) - int(batch.ticks_completed))
            if unconsumed_ticks > 0:
                self._clock.accum += float(unconsumed_ticks) * float(self._dt)
        self._mark_finished_if_complete()
        self._dt_accum = float(self._clock.accum)

    def _playback_speed(self) -> float:
        return float(_PLAYBACK_SPEED_STEPS[int(self._speed_index)])

    def _change_speed(self, delta: int) -> None:
        idx = int(self._speed_index) + int(delta)
        idx = max(0, min(idx, len(_PLAYBACK_SPEED_STEPS) - 1))
        self._speed_index = idx

    def _skip_forward_seconds(self, seconds: float) -> None:
        replay = self._replay
        if replay is None or self._finished:
            return
        ticks = int(round(float(seconds) * float(self._tick_rate)))
        if ticks <= 0:
            return
        target = min(int(self._tick_limit()), int(self._tick_index) + int(ticks))
        audio_bridge = self._audio_bridge
        prev_sfx_enabled: bool | None = None
        if audio_bridge is not None and audio_bridge.router is not None:
            prev_sfx_enabled = bool(audio_bridge.router.sfx_enabled)
            audio_bridge.router.sfx_enabled = False
        try:
            ticks_to_advance = max(0, int(target) - int(self._tick_index))
            if ticks_to_advance > 0:
                self._advance_runner(
                    dt_seconds=float(ticks_to_advance) * float(self._dt),
                    max_ticks=int(ticks_to_advance),
                    bake_fx_per_tick=True,
                )
        finally:
            if prev_sfx_enabled is not None and audio_bridge is not None and audio_bridge.router is not None:
                audio_bridge.router.sfx_enabled = bool(prev_sfx_enabled)
        self._clock.reset()
        self._dt_accum = 0.0

    def update(self, dt: float) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._paused = not bool(self._paused)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PERIOD) and bool(self._paused):
            self._step_once_pending = True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._change_speed(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._change_speed(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self._speed_index = _DEFAULT_SPEED_INDEX
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._skip_forward_seconds(_SKIP_SHORT_SECONDS)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
            self._skip_forward_seconds(_SKIP_LONG_SECONDS)

        if not self._finished and bool(self._paused) and bool(self._step_once_pending):
            self._clock.reset()
            self._advance_runner(
                dt_seconds=float(self._dt),
                max_ticks=1,
            )
            self._clock.reset()
            self._step_once_pending = False
            self._dt_accum = 0.0

        if not self._finished and (not self._paused):
            dt = float(dt)
            if dt < 0.0:
                dt = 0.0
            if dt > 0.1:
                dt = 0.1
            self._advance_runner(
                dt_seconds=dt * self._playback_speed(),
            )

        if self._audio is not None:
            update_audio(self._audio, float(dt))

        # Runtime open schedules terrain generation, but replay advances
        # deterministic world ticks directly, so we must process pending ground
        # work explicitly.
        render_resources = self._render_resources
        if render_resources is not None and render_resources.ground is not None:
            render_resources.ground.process_pending()

    def _draw_quest_title(self) -> None:
        replay = self._replay
        if replay is None or replay.header.game_mode_id != GameMode.QUESTS:
            return
        font = self._grim_mono
        if font is None:
            return
        title = str(self._quest_title or "")
        level = str(self._quest_level or "")
        if not title or not level:
            return

        draw_quest_title_timer_overlay(font, title, level, timer_ms=float(self._quest_name_timer_ms))

    def _draw_quest_complete_banner(self) -> None:
        replay = self._replay
        if replay is None or replay.header.game_mode_id != GameMode.QUESTS:
            return
        tex = self._quest_complete_texture
        if tex is None:
            return
        draw_quest_complete_banner_overlay(tex, timer_ms=float(self._quest_completion_transition_ms))

    def draw(self) -> None:
        sim_world = self._sim_world
        if sim_world is not None:
            self._draw_world(draw_aim_indicators=True)
        else:
            rl.clear_background(rl.BLACK)

        replay = self._replay
        if (
            sim_world is not None
            and replay is not None
            and self._hud_assets is not None
            and sim_world.players
        ):
            mode_id = replay.header.game_mode_id
            hud_flags = hud_flags_for_game_mode(mode_id)
            quest_progress_ratio: float | None = None
            elapsed_ms = float(sim_world.elapsed_ms)
            match mode_id:
                case GameMode.QUESTS:
                    total = int(self._quest_total_spawn_count)
                    kills = int(sim_world.creatures.kill_count)
                    quest_progress_ratio = float(kills) / float(total) if total > 0 else None
                    elapsed_ms = float(self._quest_spawn_timeline_ms)
                case _:
                    pass
            draw_hud_overlay(
                HudRenderContext(
                    assets=self._hud_assets,
                    state=self._hud_state,
                    font=self._small,
                    show_health=bool(hud_flags.show_health),
                    show_weapon=bool(hud_flags.show_weapon),
                    show_xp=bool(hud_flags.show_xp),
                    show_time=bool(hud_flags.show_time),
                    show_quest_hud=bool(hud_flags.show_quest_hud),
                    small_indicators=False,
                ),
                player=sim_world.players[0],
                players=sim_world.players,
                bonus_hud=sim_world.state.bonus_hud,
                elapsed_ms=elapsed_ms,
                frame_dt_ms=float(max(0.0, rl.get_frame_time()) * 1000.0),
                quest_progress_ratio=quest_progress_ratio,
            )

        self._draw_quest_title()
        self._draw_quest_complete_banner()

        if bool(self._show_replay_widget):
            self._draw_replay_widget()
