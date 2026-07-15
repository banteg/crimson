from __future__ import annotations

from typing import Literal

import msgspec

from grim.assets import TextureId
from grim.audio import AudioState, play_music
from grim.config import (
    CrimsonConfig,
)
from grim.console import ConsoleState
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..net.rollback_resync_v5 import (
    ModeStateSnapshotV2,
    QuestsRuntimeSnapshotV2,
    QuestsStateSnapshotV2,
)
from ..perks.selection import perk_selection_prepared_choices
from ..persistence.highscores import UNI_NUM_MASK
from ..persistence.save_status import GameStatus, GameStatusData
from ..quests import quest_by_level
from ..quests.level import QuestLevel
from ..quests.runtime import build_quest_spawn_table
from ..quests.status import tracked_quest_games_counter_index
from ..quests.types import QuestContext, QuestDefinition, SpawnEntry
from ..replay import Replay, ReplayHeader, ReplayRecorder
from ..replay.checkpoints import DEFAULT_CHECKPOINT_SAMPLE_RATE
from ..rng_caller_static import RngCallerStatic
from ..sim.bootstrap import advance_explicit_terrain, advance_unlock_terrain
from ..sim.hooks import TickResult
from ..sim.presentation_reactions import (
    PostApplyReaction,
    PostApplyReactionRuntime,
    apply_post_apply_reaction,
    build_post_apply_reaction,
)
from ..sim.session_builders import build_quest_session
from ..sim.sessions import DeterministicSession, DeterministicSessionTick, QuestSpawnState
from ..ui.cursor import draw_menu_cursor
from ..ui.hud import HudRenderContext, draw_hud_overlay, hud_flags_for_game_mode
from ..ui.overlays.quest_run import (
    draw_quest_complete_banner_overlay,
    draw_quest_title_timer_overlay,
)
from ..weapon_runtime import most_used_weapon_id_for_player, weapon_assign_player
from ..weapons import WEAPON_BY_ID, WeaponId
from .base_gameplay_mode import (
    BaseGameplayMode,
    LanSession,
    LanStepAction,
)
from .components.highscore_record_builder import shots_from_state
from .components.perk_menu_controller import PerkMenuController
from .components.perk_prompt_controller import PerkPromptState

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))

_DEBUG_WEAPON_IDS = tuple(sorted(WEAPON_BY_ID))


class QuestRunOutcome(msgspec.Struct, frozen=True):
    kind: str  # "completed" | "failed"
    level: QuestLevel
    base_time_ms: int
    player_health: float
    player2_health: float | None
    pending_perk_count: int
    experience: int
    kill_count: int
    weapon_id: WeaponId
    shots_fired: int
    shots_hit: int
    most_used_weapon_id: WeaponId
    highscore_random_tag: int
    player_health_values: tuple[float, ...] = ()


class _QuestPostApplyReactionRuntime(PostApplyReactionRuntime):
    mode: QuestMode

    def play_sfx(self, sfx: SfxId) -> None:
        self.mode.audio_bridge.router.play_sfx(sfx)

    def play_completion_music(self) -> None:
        self.mode._play_quest_completion_music()


class QuestMode(BaseGameplayMode):
    def __init__(
        self,
        ctx: ViewContext,
        *,
        demo_mode_active: bool = False,
        config: CrimsonConfig,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: Crand,
    ) -> None:
        super().__init__(
            ctx,
            world_size=WORLD_SIZE,
            default_game_mode_id=GameMode.QUESTS,
            demo_mode_active=bool(demo_mode_active),
            quest_fail_retry_count=0,
            hardcore=False,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._quest_def: QuestDefinition | None = None
        self._quest_level: QuestLevel | None = self.config.gameplay.quest_level or QuestLevel(1, 1)
        self._quest_total_spawn_count: int = 0
        self._quest_highscore_random_tag: int = 0
        self._outcome: QuestRunOutcome | None = None
        self._grim_mono: GrimMonoFont | None = None
        self._perk_prompt = PerkPromptState()
        self._perk_menu = PerkMenuController(runtime=self._perk_menu_runtime())
        self._quest_spawn_state = QuestSpawnState()
        self._sim_session: DeterministicSession | None = None
        self._replay_recorder: ReplayRecorder | None = None

    def open(self) -> None:
        super().open()
        self._quest_def = None
        self._quest_level = self.config.gameplay.quest_level or QuestLevel(1, 1)
        self._quest_total_spawn_count = 0
        self._quest_highscore_random_tag = 0
        self._outcome = None
        self._grim_mono = load_grim_mono_font(self._assets_root)

        self._perk_prompt.reset()
        self._perk_menu.reset()
        self._reset_gameplay_frame_clock()
        self._reset_lan_capture_clock()
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        self._sim_session = None

    def close(self) -> None:
        self._grim_mono = None
        self._sim_session = None
        super().close()

    def _new_sim_session(self, *, spawn_entries: tuple[SpawnEntry, ...]) -> DeterministicSession:
        quest_def = self._quest_def
        session, quest_spawn_state = build_quest_session(
            world=self.sim_world.world_state,
            world_size=float(self.world_size),
            damage_scale_by_type=self.sim_world.damage_scale_by_type,
            detail_preset=5,
            violence_disabled=0,
            game_tune_started=bool(self.sim_world.game_tune_started),
            demo_mode_active=bool(self.demo_mode_active),
            apply_world_dt_steps=False,
            finalize_post_render_lifecycle=True,
            spawn_entries=tuple(spawn_entries),
            quest_level=(None if quest_def is None else quest_def.level),
            start_weapon_id=(None if quest_def is None else quest_def.start_weapon_id),
        )
        self._quest_spawn_state = quest_spawn_state
        return session

    def _try_open_perk_menu(self) -> None:
        self._open_perk_menu_ui(
            menu=self._perk_menu,
            players=self.sim_world.players,
            game_mode=GameMode.QUESTS,
            player_count=max(1, len(self.sim_world.players)),
        )

    def _perk_menu_closed(self) -> None:
        self._perk_prompt.reset_if_pending(pending_count=int(self.state.perk_selection.pending_count))

    def _update_perk_ui(self, *, dt_ui_ms: float) -> None:
        perk_ctx = self._perk_menu_ui_context()
        pending_count = int(self.state.perk_selection.pending_count)
        choices = perk_selection_prepared_choices(self.sim_world.players, self.state.perk_selection)
        self._perk_prompt.begin_frame()
        if self._perk_menu.open:
            choice_index = self._perk_menu.handle_input(
                perk_ctx,
                choices,
                dt_ui_ms=float(dt_ui_ms),
            )
            if choice_index is not None:
                self.record_perk_pick_command(int(choice_index), player_index=0)
        if self._perk_prompt.poll_open_request(
            ctx=perk_ctx,
            config=self.config,
            pending_count=pending_count,
            player_count=max(1, len(self.sim_world.players)),
            any_alive=self._any_player_alive(),
            paused=self._paused,
            menu_active=self._perk_menu.active,
            prompt_scale=UI_TEXT_SCALE,
        ):
            self._try_open_perk_menu()
        self._perk_prompt.tick_timer(
            pending_count=pending_count,
            any_alive=self._any_player_alive(),
            paused=self._paused,
            menu_active=self._perk_menu.active,
            dt_ui_ms=float(dt_ui_ms),
        )
        if not self._paused:
            self._perk_prompt.tick_pulse(float(dt_ui_ms))
        self._perk_menu.tick_timeline(float(dt_ui_ms))

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return float(self._quest_spawn_state.spawn_timeline_ms)

    def _replay_claimed_stats_complete(self) -> bool:
        return bool(self._outcome is not None)

    def _replay_claimed_stats_elapsed_ms(self) -> int:
        return int(self._quest_spawn_state.spawn_timeline_ms)

    def _replay_output_basename(self, *, stamp: str, replay: Replay) -> str:
        replay_level = (
            ""
            if replay.header.quest_level is None
            else replay.header.quest_level.text
        )
        level = self._quest_level.text if self._quest_level is not None else (replay_level or "quest")
        kind = str(self._outcome.kind) if self._outcome is not None else "quest"
        base_time_ms = int(self._quest_spawn_state.spawn_timeline_ms)
        return f"quest_{level}_{stamp}_{kind}_t{base_time_ms}"

    def _replay_skip_save_when_empty(self, *, recorder: ReplayRecorder) -> bool:
        # Avoid emitting empty replays/checkpoint sidecars (usually indicates a
        # test harness calling failure/complete helpers without ticking).
        return int(recorder.tick_index) <= 0

    def _lan_mode_name(self) -> Literal["quests"]:
        return "quests"

    def _lan_match_session(self) -> DeterministicSession | None:
        return self._sim_session

    def _lan_on_paused(self, dt: float) -> None:
        self._tick_death_timers(dt, rate=1.0)
        if self._death_transition_ready():
            self._close_failed_run()

    def _lan_prepare_frame(
        self,
        role: str,
        dt_ui_ms: float,
        session: LanSession,
        dt_tick: float,
    ) -> bool:
        _ = role, dt_ui_ms, dt_tick
        session.detail_preset = int(self._deterministic_detail_preset())
        session.violence_disabled = int(self._deterministic_violence_disabled())
        return True

    def _lan_on_tick_applied(
        self,
        tick: DeterministicSessionTick,
        frame_tick_index: int | None,
        dt_tick: float,
    ) -> LanStepAction:
        session = self._sim_session
        _ = tick
        spawn_state = self._quest_spawn_state
        _ = dt_tick
        if frame_tick_index is not None:
            self._store_net_runtime_snapshot(
                snapshot=QuestsStateSnapshotV2(
                    tick_index=int(frame_tick_index),
                    replay_state=self._net_replay_snapshot_state(),
                    runtime_state=QuestsRuntimeSnapshotV2(
                        elapsed_ms=float(session.elapsed_ms if session is not None else 0.0),
                        spawn_entries=tuple(spawn_state.spawn_entries),
                        spawn_timeline_ms=float(spawn_state.spawn_timeline_ms),
                        no_creatures_timer_ms=float(spawn_state.no_creatures_timer_ms),
                        completion_transition_ms=float(spawn_state.completion_transition_ms),
                        perk_pending_count=int(self.state.perk_selection.pending_count),
                    ),
                ),
            )

        if spawn_state.completed:
            if self._outcome is None:
                assert self._quest_level is not None, "quest outcome requires active quest level"
                fired, hit = shots_from_state(self.state, player_index=int(self.player.index))
                most_used_weapon_id = most_used_weapon_id_for_player(
                    self.state,
                    player_index=int(self.player.index),
                    fallback_weapon_id=self.player.weapon.weapon_id,
                )
                player_health_values = tuple(float(player.health) for player in self.sim_world.players)
                player2_health = None
                if len(player_health_values) >= 2:
                    player2_health = float(player_health_values[1])
                self._outcome = QuestRunOutcome(
                    kind="completed",
                    level=self._quest_level,
                    base_time_ms=int(spawn_state.spawn_timeline_ms),
                    player_health=float(player_health_values[0] if player_health_values else self.player.health),
                    player2_health=player2_health,
                    player_health_values=player_health_values,
                    pending_perk_count=int(self.state.perk_selection.pending_count),
                    experience=int(self.player.experience),
                    kill_count=int(self.creatures.kill_count),
                    weapon_id=self.player.weapon.weapon_id,
                    shots_fired=fired,
                    shots_hit=hit,
                    most_used_weapon_id=most_used_weapon_id,
                    highscore_random_tag=int(self._quest_highscore_random_tag),
                )
            self._save_replay()
            self.close_requested = True
            return "stop_after_finalize"

        if self._death_transition_ready():
            self._close_failed_run()
            return "stop_after_finalize"
        return "continue"

    def _build_tick_post_apply_reaction(self, *, tick_result: TickResult) -> PostApplyReaction:
        return build_post_apply_reaction(
            tick_result=tick_result,
            quest_state=self._quest_spawn_state,
        )

    def _apply_tick_post_apply_reaction(self, reaction: PostApplyReaction, *, dt_seconds: float) -> None:
        _ = dt_seconds
        apply_post_apply_reaction(
            reaction=reaction,
            runtime=_QuestPostApplyReactionRuntime(mode=self),
        )

    def _play_quest_completion_music(self) -> None:
        if self.audio is None:
            return
        play_music(self.audio, "crimsonquest")
        playback = self.audio.music.playbacks.get("crimsonquest")
        if playback is None:
            return
        playback.volume = 0.0
        try:
            rl.set_music_volume(playback.music, 0.0)
        except RuntimeError:
            playback.volume = 0.0

    def _apply_resync_snapshot(self, snapshot: ModeStateSnapshotV2) -> None:
        if not isinstance(snapshot, QuestsStateSnapshotV2):
            return
        rs = snapshot.runtime_state
        self._quest_spawn_state.spawn_entries = tuple(rs.spawn_entries)
        self._quest_spawn_state.spawn_timeline_ms = float(rs.spawn_timeline_ms)
        self._quest_spawn_state.no_creatures_timer_ms = float(rs.no_creatures_timer_ms)
        self._quest_spawn_state.completion_transition_ms = float(rs.completion_transition_ms)
        self._quest_spawn_state.completed = False
        self._quest_spawn_state.play_hit_sfx = False
        self._quest_spawn_state.play_completion_music = False
        session = self._sim_session
        if session is not None:
            session.elapsed_ms = float(rs.elapsed_ms)

    def consume_outcome(self) -> QuestRunOutcome | None:
        outcome = self._outcome
        self._outcome = None
        return outcome

    def start_run(self, level: QuestLevel, *, status: GameStatus | None) -> None:
        quest = quest_by_level(level)
        if quest is None:
            self._quest_def = None
            self._quest_level = level
            self._quest_total_spawn_count = 0
            self._quest_highscore_random_tag = 0
            self._sim_session = None
            return
        self._outcome = None
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

        hardcore_flag = self.config.gameplay.hardcore

        self.hardcore = hardcore_flag
        # Native quest start does not reseed RNG per level; carry the current
        # session RNG state into the next run.
        seed = int(self.state.rng.state) & 0xFFFFFFFF
        self._run_reset_seed = int(seed)

        player_count = self.config.gameplay.player_count
        self._sync_world_runtime_config()
        self.world_runtime.reset(seed=seed, player_count=max(1, min(4, player_count)))
        self._bind_world()
        self._local_input.reset(players=self.sim_world.players)
        self.bind_status(status)
        bound_status = self.state.status
        generic_unlock_index = int(bound_status.quest_unlock_index) if bound_status is not None else 0
        advance_unlock_terrain(
            self.state.rng,
            unlock_index=int(generic_unlock_index),
            width=int(self.world_size),
            height=int(self.world_size),
        )
        # Native `quest_start_selected()` burns one `crt_rand()` for
        # `highscore_record_random_tag` before quest terrain and spawn setup.
        highscore_rand = self.state.rng.rand_tagged(
            RngCallerStatic.QUEST_START_SELECTED_HIGHSCORE_RANDOM_TAG,
        )
        self._quest_highscore_random_tag = int(highscore_rand) & UNI_NUM_MASK
        quest_terrain = advance_explicit_terrain(
            self.state.rng,
            terrain_slots=quest.terrain_slots,
            width=int(self.world_size),
            height=int(self.world_size),
        )
        self.apply_terrain_setup(
            terrain_slots=quest_terrain.terrain_slots,
            seed=int(quest_terrain.terrain_seed),
        )

        ctx = QuestContext(
            width=int(self.world_size),
            height=int(self.world_size),
            player_count=len(self.sim_world.players),
        )
        entries = build_quest_spawn_table(
            quest,
            ctx,
            rng=self.state.rng,
            hardcore=hardcore_flag,
            full_version=not self.demo_mode_active,
        )
        self.sim_world.state.rng.srand(int(self.state.rng.state))
        total_spawn_count = sum(int(entry.count) for entry in entries)
        self._quest_def = quest
        self._quest_level = quest.level
        self._quest_total_spawn_count = int(total_spawn_count)
        self._reset_gameplay_frame_clock()
        self._sim_session = self._new_sim_session(spawn_entries=tuple(entries))

        replay_status = GameStatusData() if status is None else status.as_data()
        record_replay = (not bool(self._lan_enabled)) or str(self._lan_role) == "host"
        if record_replay:
            self._replay_recorder = ReplayRecorder(
                ReplayHeader(
                    game_mode_id=GameMode.QUESTS,
                    seed=int(self._run_reset_seed),
                    quest_level=quest.level,
                    tick_rate=int(self._gameplay_tick_rate()),
                    quest_fail_retry_count=int(self.quest_fail_retry_count),
                    hardcore=bool(self.hardcore),
                    preserve_bugs=bool(self.state.preserve_bugs),
                    detail_preset=self.config.display.detail_preset,
                    violence_disabled=self.config.display.violence_disabled,
                    world_size=float(self.world_size),
                    player_count=len(self.sim_world.players),
                    status=replay_status,
                ),
            )
            self._replay_checkpoints_sample_rate = int(DEFAULT_CHECKPOINT_SAMPLE_RATE)
        else:
            self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

        if status is not None:
            idx = tracked_quest_games_counter_index(quest.level)
            if idx is not None:
                status.increment_quest_play_count(idx)

    def _handle_input(self) -> None:
        if self._perk_menu.open and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.audio_bridge.router.play_sfx(SfxId.UI_BUTTONCLICK)
            self._perk_menu.close()
            return

        if (not bool(self._lan_enabled)) and rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if debug_enabled() and (not self._perk_menu.open):
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F2):
                self.state.debug_god_mode = not bool(self.state.debug_god_mode)
                self.audio_bridge.router.play_sfx(SfxId.UI_BUTTONCLICK)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
                self.state.perk_selection.pending_count += 1
                self.state.perk_selection.choices_dirty = True
                self.audio_bridge.router.play_sfx(SfxId.UI_LEVELUP)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
                self._debug_cycle_weapon(-1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
                self._debug_cycle_weapon(1)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "open_pause_menu"
            return

    def _debug_cycle_weapon(self, delta: int) -> None:
        weapon_ids = _DEBUG_WEAPON_IDS
        if not weapon_ids:
            return
        current = self.player.weapon.weapon_id
        try:
            idx = weapon_ids.index(current)
        except ValueError:
            idx = 0
        weapon_id = WeaponId(weapon_ids[(idx + int(delta)) % len(weapon_ids)])
        weapon_assign_player(self.player, weapon_id, state=self.state)

    def _death_transition_ready(self) -> bool:
        dead_players = 0
        for player in self.sim_world.players:
            if float(player.health) > 0.0:
                return False
            dead_players += 1
            if float(player.death_timer) >= 0.0:
                return False
        return dead_players > 0

    def _tick_death_timers(self, dt: float, *, rate: float = 20.0) -> None:
        delta = float(dt) * float(rate)
        if delta <= 0.0:
            return
        for player in self.sim_world.players:
            if float(player.health) > 0.0:
                continue
            if float(player.death_timer) < 0.0:
                continue
            player.death_timer = float(player.death_timer) - delta

    def _close_failed_run(self) -> None:
        if self._outcome is None:
            assert self._quest_level is not None, "quest outcome requires active quest level"
            fired, hit = shots_from_state(self.state, player_index=int(self.player.index))
            most_used_weapon_id = most_used_weapon_id_for_player(
                self.state,
                player_index=int(self.player.index),
                fallback_weapon_id=self.player.weapon.weapon_id,
            )
            player_health_values = tuple(float(player.health) for player in self.sim_world.players)
            player2_health = None
            if len(player_health_values) >= 2:
                player2_health = float(player_health_values[1])
            self._outcome = QuestRunOutcome(
                kind="failed",
                level=self._quest_level,
                base_time_ms=int(self._quest_spawn_state.spawn_timeline_ms),
                player_health=float(player_health_values[0] if player_health_values else self.player.health),
                player2_health=player2_health,
                player_health_values=player_health_values,
                pending_perk_count=int(self.state.perk_selection.pending_count),
                experience=int(self.player.experience),
                kill_count=int(self.creatures.kill_count),
                weapon_id=self.player.weapon.weapon_id,
                shots_fired=fired,
                shots_hit=hit,
                most_used_weapon_id=most_used_weapon_id,
                highscore_random_tag=int(self._quest_highscore_random_tag),
            )
        self._save_replay()
        self.close_requested = True

    def update(self, dt: float) -> None:
        frame = self._begin_mode_update(float(dt))
        if frame is None:
            return
        if bool(self.close_requested):
            return
        if bool(self._lan_enabled) and self._lan_runtime is not None:
            self._update_lan_match(dt=float(frame.dt), dt_ui_ms=float(frame.dt_ui_ms))
            return

        self._update_perk_ui(dt_ui_ms=float(frame.dt_ui_ms))

        sim_dt = 0.0 if (self._paused or self._perk_menu.active) else float(frame.dt)
        session = self._sim_session
        if self._lan_wait_gate_active():
            self._reset_gameplay_frame_clock()
            return
        if sim_dt <= 0.0:
            self._reset_gameplay_frame_clock()
            # Match legacy transition behavior: keep countdown moving, but at
            # real-time pace while perk-menu transition is holding world ticks.
            self._tick_death_timers(float(frame.dt), rate=1.0)
            if self._death_transition_ready():
                self._close_failed_run()
            return
        if session is None:
            self._tick_death_timers(float(sim_dt))
            if self._death_transition_ready():
                self._close_failed_run()
            return

        session.detail_preset = int(self._deterministic_detail_preset())
        session.violence_disabled = int(self._deterministic_violence_disabled())

        self._world_runtime.sync_audio_bridge_state()
        if self.render_resources.ground is not None:
            self.render_resources.ground.process_pending()

        self._run_deterministic_session_ticks(
            dt_frame=float(sim_dt),
            session=session,
            recorder=self._replay_recorder,
            stop_on_mode_tick=True,
        )

    def draw(self) -> None:
        perk_menu_active = self._perk_menu.active
        debug_overlay_height = 0.0
        self._draw_world(
            draw_aim_indicators=not perk_menu_active,
            entity_alpha=self._world_entity_alpha(),
        )
        self._draw_screen_fade()

        hud_bottom = 0.0
        if not perk_menu_active:
            total = int(self._quest_total_spawn_count)
            kills = int(self.creatures.kill_count)
            quest_progress_ratio = float(kills) / float(total) if total > 0 else None
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar()
            hud_bottom = draw_hud_overlay(
                HudRenderContext(
                    resources=self.render_resources.resources,
                    state=self._hud_state,
                    font=self._small,
                    show_health=hud_flags.show_health,
                    show_weapon=hud_flags.show_weapon,
                    show_xp=hud_flags.show_xp,
                    show_time=hud_flags.show_time,
                    show_quest_hud=hud_flags.show_quest_hud,
                    small_indicators=self._hud_small_indicators(),
                ),
                player=self.player,
                players=self.sim_world.players,
                bonus_hud=self.state.bonus_hud,
                elapsed_ms=float(self._quest_spawn_state.spawn_timeline_ms),
                frame_dt_ms=self._last_dt_ms,
                quest_progress_ratio=quest_progress_ratio,
            )

        if debug_enabled() and (not perk_menu_active):
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            god = "on" if self.state.debug_god_mode else "off"
            line = float(self._ui_line_height(scale=0.9))
            self._draw_ui_text(f"debug: [/] weapon  F3 perk+1  F2 god={god}", Vec2(x, y), UI_HINT_COLOR, scale=0.9)
            overlay_end_y = self._draw_lan_debug_info(x=x, y=y + line, line_h=line)
            debug_overlay_height = max(0.0, float(overlay_end_y) - float(y))

        self._draw_quest_title()
        self._draw_quest_complete_banner()

        self._perk_prompt.draw(
            ctx=self._perk_menu_ui_context(),
            pending_count=int(self.state.perk_selection.pending_count),
            any_alive=self._any_player_alive(),
            menu_active=self._perk_menu.active,
            config=self.config,
            ui_text_width=self._ui_text_width,
            text_color=UI_TEXT_COLOR,
            prompt_scale=UI_TEXT_SCALE,
        )
        self._perk_menu.draw(
            self._perk_menu_ui_context(),
            perk_selection_prepared_choices(self.sim_world.players, self.state.perk_selection),
        )

        if perk_menu_active:
            self._draw_game_cursor()
        elif self._paused:
            self._draw_game_cursor()
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            y += float(debug_overlay_height)
            self._draw_ui_text("paused (TAB)", Vec2(x, y), UI_HINT_COLOR)
        self._draw_lan_wait_overlay()

    def _draw_game_cursor(self) -> None:
        resources = self.render_resources.resources
        mouse_pos = self._ui_mouse
        draw_menu_cursor(
            resources.texture(TextureId.PARTICLES),
            resources.texture(TextureId.UI_CURSOR),
            pos=mouse_pos,
            pulse_time=float(self._cursor_pulse_time),
        )

    def _draw_quest_title(self) -> None:
        font = self._grim_mono
        quest = self._quest_def
        if font is None or quest is None:
            return
        draw_quest_title_timer_overlay(
            font,
            quest.title,
            quest.level.text,
            timer_ms=float(self._quest_spawn_state.spawn_timeline_ms),
        )

    def _draw_quest_complete_banner(self) -> None:
        tex = self.render_resources.resources.texture(TextureId.UI_TEXT_LEVEL_COMPLETE)
        draw_quest_complete_banner_overlay(
            tex,
            timer_ms=float(self._quest_spawn_state.completion_transition_ms),
        )
