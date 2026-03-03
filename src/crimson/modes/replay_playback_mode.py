from __future__ import annotations

import random
from pathlib import Path
from typing import cast

from grim import music as grim_music
from grim.assets import TextureLoader
from grim.audio import AudioState, init_audio_state, play_music, shutdown_audio, update_audio
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.view import ViewContext

from ..game_modes import GameMode
from ..game_world import GameWorld
from ..render.rtx.mode import mode_from_rtx_flag
from ..replay import (
    Replay,
    apply_replay_bootstrap,
    load_replay_file,
    unpack_tick_inputs,
    warn_on_game_version_mismatch,
)
from ..replay.types import ReplayHeader
from ..sim.bootstrap import BOOTSTRAP_KIND_TERRAIN_V1
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
from ..sim.input import PlayerInput
from ..sim.input_providers import ReplayEndOfStream, ReplayInputProvider
from ..sim.tick_runner import TickRunner, TickRunnerConfig
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
from ..world.terrain_runtime import normalize_terrain_ids

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


class _ReplayDriverSession:
    def __init__(self, mode: "ReplayPlaybackMode") -> None:
        self._mode = mode
        self._next_tick_index = 0

    def timing_for_dt(self, dt: float) -> float:
        return float(dt)

    def step_tick(
        self,
        *,
        timing: float,
        inputs: list[PlayerInput] | None,
    ) -> PlaybackTickOutcome:
        _ = timing
        tick = self._mode._run_driver_tick(
            int(self._next_tick_index),
            inputs=inputs,
        )
        self._next_tick_index += 1
        return tick


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
        self._world: GameWorld | None = None
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
        self._tick_index = 0
        self._finished = False
        self._terminal_events_applied = False
        self._paused = False
        self._step_once_pending = False
        self._speed_index = _DEFAULT_SPEED_INDEX

        self._driver: PlaybackDriver | None = None
        self._driver_session: _ReplayDriverSession | None = None
        self._tick_runner: TickRunner | None = None
        self._survival = None
        self._rush = None
        self._quest = None
        self._quest_total_spawn_count = 0
        self._quest_spawn_timeline_ms = 0.0

        self._audio: AudioState | None = None
        self._audio_rng: random.Random | None = None
        self._replay_input_provider = ReplayInputProvider(
            player_count=0,
            resolve_tick_input=lambda _tick_index: None,
            tick_count=0,
        )

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
        self._replay_input_provider = ReplayInputProvider(
            player_count=max(0, int(replay.header.player_count)),
            resolve_tick_input=lambda tick_index: unpack_tick_inputs(replay.inputs[int(tick_index)]),
            tick_count=len(replay.inputs),
        )
        warn_on_game_version_mismatch(replay, action="playback")

        tick_rate = int(replay.header.tick_rate)
        if tick_rate <= 0:
            raise ValueError(f"invalid tick_rate: {tick_rate}")
        self._tick_rate = tick_rate
        self._dt = 1.0 / float(tick_rate)
        self._dt_accum = 0.0
        self._tick_index = 0
        self._finished = False
        self._terminal_events_applied = False
        self._paused = False
        self._step_once_pending = False
        self._speed_index = _DEFAULT_SPEED_INDEX
        self._defer_menu_open = False
        self._driver = None
        self._driver_session = None
        self._tick_runner = None

        world_size = float(replay.header.world_size)
        audio = init_audio_state(self._config, self._ctx.assets_dir, self._console)
        audio_rng = random.Random(int(replay.header.seed) & 0xFFFFFFFF)
        self._audio = audio
        self._audio_rng = audio_rng
        self._register_replay_audio_commands()
        self._load_game_tune_queue()

        world = GameWorld(
            assets_dir=self._ctx.assets_dir,
            world_size=world_size,
            demo_mode_active=False,
            difficulty_level=int(replay.header.difficulty_level),
            hardcore=bool(replay.header.hardcore),
            preserve_bugs=bool(replay.header.preserve_bugs),
            texture_cache=None,
            config=self._config,
            audio=audio,
            audio_rng=audio_rng,
            rtx_mode=mode_from_rtx_flag(self._rtx),
        )
        world.reset(
            seed=_world_reset_seed_for_replay(replay.header),
            player_count=int(replay.header.player_count),
        )
        world.open()
        self._hud_state.preserve_bugs = bool(world.state.preserve_bugs)
        world.state.status = status_from_snapshot(
            quest_unlock_index=int(replay.header.status.quest_unlock_index),
            quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
            weapon_usage_counts=replay.header.status.weapon_usage_counts,
        )
        bootstrap = apply_replay_bootstrap(
            replay.header,
            rng=world.state.rng,
            world_size=float(world_size),
        )
        if bootstrap is not None:
            world.apply_bootstrap_terrain(
                terrain_ids=bootstrap.terrain.terrain_ids,
                seed=int(bootstrap.terrain.terrain_seed),
                layers=3,
            )

        self._world = world

        mode_id = replay.header.game_mode_id
        spawn_entries = None
        quest_stage_major: int | None = None
        quest_stage_minor: int | None = None
        start_weapon_id: WeaponId | None = None
        match mode_id:
            case GameMode.QUESTS:
                quest, spawn_entries = resolve_replay_quest_setup(
                    replay,
                    world_size=float(world.world_size),
                    player_count=len(world.players),
                )

                self._quest_title = str(quest.title)
                self._quest_level = quest_level_label(quest.major, quest.minor)
                self._grim_mono = load_grim_mono_font(self._ctx.assets_dir)
                self._quest_complete_texture = self._load_quest_complete_texture(world)
                quest_stage_major, quest_stage_minor = quest.level_key
                world.state.quest_stage_major = int(quest_stage_major)
                world.state.quest_stage_minor = int(quest_stage_minor)

                base_id, overlay_id, detail_id = normalize_terrain_ids(quest.terrain_ids)
                base = terrain_texture_by_id(base_id)
                overlay = terrain_texture_by_id(overlay_id)
                detail = terrain_texture_by_id(detail_id)
                if base is not None and overlay is not None:
                    base_key, base_path = base
                    overlay_key, overlay_path = overlay
                    detail_key = detail[0] if detail is not None else None
                    detail_path = detail[1] if detail is not None else None
                    world.set_terrain(
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
                for player in world.players:
                    weapon_assign_player(player, start_weapon_id, state=world.state)
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
                        world=world.sim_world.world_state,
                        world_size=float(world.world_size),
                        fx_queue=world.render_resources.fx_queue,
                        fx_queue_rotated=world.render_resources.fx_queue_rotated,
                        use_existing_world_state=True,
                    ),
                    events=PlaybackEventConfig(
                        defer_menu_open=False,
                        apply_terminal_tick_events=True,
                        terminal_events_use_resolved_dt=False,
                    ),
                    session_defaults=PlaybackSessionDefaults(
                        clear_fx_queues_each_tick=False,
                        game_tune_started=bool(world.sim_world.game_tune_started),
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
        self._driver_session = _ReplayDriverSession(self)
        self._tick_runner = TickRunner(
            session=self._driver_session,
            input_provider=self._replay_input_provider,
            config=TickRunnerConfig(
                tick_rate=int(self._tick_rate),
                is_networked=False,
                is_replay=True,
            ),
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
        self._driver_session = None
        self._tick_runner = None
        self._survival = None
        self._rush = None
        self._quest = None
        world = self._world
        self._world = None
        if world is not None:
            world.close()
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

    def _load_quest_complete_texture(self, world: GameWorld | None = None) -> rl.Texture | None:
        loader = TextureLoader(
            assets_root=self._ctx.assets_dir,
            cache=world.texture_cache if world is not None else None,
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
        world = self._world
        if world is None:
            return 0.0

        world.apply_step_result(
            outcome.step,
            game_tune_started=bool(game_tune_started),
            apply_audio=True,
            update_camera=False,
        )
        if outcome.spawn_timeline_ms is not None:
            self._quest_spawn_timeline_ms = float(outcome.spawn_timeline_ms)
            self._quest_name_timer_ms += float(dt) * 1000.0
            if outcome.completion_transition_ms is not None:
                self._quest_completion_transition_ms = float(outcome.completion_transition_ms)
            if bool(outcome.play_hit_sfx):
                world.audio_bridge.router.play_sfx("sfx_questhit")
            if bool(outcome.play_completion_music) and world.audio is not None:
                play_music(world.audio, "crimsonquest")
                playback = world.audio.music.playbacks.get("crimsonquest")
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

    def _run_driver_tick(
        self,
        tick_index: int,
        *,
        inputs: list[PlayerInput] | None = None,
    ) -> PlaybackTickOutcome:
        driver = self._driver
        if driver is None:
            raise ReplayEndOfStream("replay driver unavailable")
        if inputs is None:
            raise RuntimeError("replay tick runner provided no inputs for playback tick")
        defer_menu_open = bool(self._defer_menu_open) if self._survival is not None else False
        return driver.run_tick(
            int(tick_index),
            defer_menu_open=bool(defer_menu_open),
            player_inputs=list(inputs),
        )

    def _on_runner_tick_complete(self, _tick_index: int, tick: object) -> bool:
        outcome = cast(PlaybackTickOutcome, tick)
        dt_sim = self._apply_tick_outcome(
            outcome=outcome,
            game_tune_started=self._session_game_tune_started(),
            dt=float(self._dt),
        )
        world = self._world
        if world is not None:
            world.update_camera(float(dt_sim))
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

    def _tick_one(self) -> None:
        replay = self._replay
        world = self._world
        runner = self._tick_runner
        if replay is None or world is None or runner is None:
            self._finished = True
            return

        if int(self._tick_index) >= int(self._tick_limit()):
            self._mark_finished_if_complete()
            return

        try:
            runner.advance_frame(
                float(self._dt),
                max_ticks=1,
                on_tick_complete=self._on_runner_tick_complete,
            )
        except ReplayEndOfStream:
            self._tick_index = int(runner.next_tick_index)
            self._mark_finished_if_complete()
            return
        self._tick_index = int(runner.next_tick_index)
        self._mark_finished_if_complete()

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
        world = self._world
        prev_sfx_enabled: bool | None = None
        if world is not None and world.audio_bridge.router is not None:
            prev_sfx_enabled = bool(world.audio_bridge.router.sfx_enabled)
            world.audio_bridge.router.sfx_enabled = False
        try:
            while self._tick_index < target and not self._finished:
                self._tick_one()
                if world is not None:
                    # Gameplay drains decal queues during render (`draw()` -> `_bake_fx_queues`).
                    # Fast-seek runs many ticks without drawing, so mirror that behavior per tick:
                    # bake when render targets are ready, otherwise clear to avoid queue saturation.
                    if world.render_resources.ground is not None and world.render_resources.fx_textures is not None:
                        world._bake_fx_queues()
                    else:
                        world.render_resources.fx_queue.clear()
                        world.render_resources.fx_queue_rotated.clear()
        finally:
            if prev_sfx_enabled is not None and world is not None and world.audio_bridge.router is not None:
                world.audio_bridge.router.sfx_enabled = bool(prev_sfx_enabled)
        # Avoid accidental overshoot from stale accumulated frame time after seek.
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
            runner = self._tick_runner
            if runner is not None:
                runner.reset_clock()
            self._tick_one()
            if runner is not None:
                runner.reset_clock()
            self._step_once_pending = False
            self._dt_accum = 0.0

        if not self._finished and (not self._paused):
            dt = float(dt)
            if dt < 0.0:
                dt = 0.0
            if dt > 0.1:
                dt = 0.1
            self._dt_accum += dt * self._playback_speed()

            while self._dt_accum + 1e-9 >= self._dt and not self._finished:
                self._tick_one()
                self._dt_accum -= self._dt

        if self._audio is not None:
            update_audio(self._audio, float(dt))

        # `GameWorld.open()` schedules terrain generation, but our playback loop
        # steps `WorldState` directly (bypassing `GameWorld.update()`), so we
        # must process pending ground work explicitly.
        world = self._world
        if world is not None and world.render_resources.ground is not None:
            world.render_resources.ground.process_pending()

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
        world = self._world
        if world is not None:
            world.draw(draw_aim_indicators=True)
        else:
            rl.clear_background(rl.BLACK)

        replay = self._replay
        if world is not None and replay is not None and self._hud_assets is not None and world.players:
            mode_id = replay.header.game_mode_id
            hud_flags = hud_flags_for_game_mode(mode_id)
            quest_progress_ratio: float | None = None
            elapsed_ms = float(world.sim_world.elapsed_ms)
            match mode_id:
                case GameMode.QUESTS:
                    total = int(self._quest_total_spawn_count)
                    kills = int(world.creatures.kill_count)
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
                player=world.players[0],
                players=world.players,
                bonus_hud=world.state.bonus_hud,
                elapsed_ms=elapsed_ms,
                frame_dt_ms=float(max(0.0, rl.get_frame_time()) * 1000.0),
                quest_progress_ratio=quest_progress_ratio,
            )

        self._draw_quest_title()
        self._draw_quest_complete_banner()

        if bool(self._show_replay_widget):
            self._draw_replay_widget()
