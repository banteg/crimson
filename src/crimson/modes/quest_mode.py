from __future__ import annotations

import random
from collections.abc import Callable
from typing import Literal, cast

import msgspec

from grim.assets import PaqTextureCache, TextureLoader
from grim.audio import AudioState, play_music
from grim.config import (
    CrimsonConfig,
)
from grim.console import ConsoleState
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..input_codes import (
    config_keybinds_for_player,
    input_code_is_down_for_player,
    input_code_is_pressed_for_player,
    input_primary_just_pressed,
)
from ..net.rollback_resync_v5 import (
    ModeStateSnapshotV2,
    QuestsRuntimeSnapshotV2,
    QuestsStateSnapshotV2,
)
from ..perks.state import CreatureForPerks
from ..persistence.save_status import GameStatus
from ..quests import quest_by_level
from ..quests.runtime import build_quest_spawn_table
from ..quests.types import QuestContext, QuestDefinition, SpawnEntry
from ..replay import Replay, ReplayHeader, ReplayRecorder, ReplayStatusSnapshot
from ..replay.checkpoints import DEFAULT_CHECKPOINT_SAMPLE_RATE
from ..replay.types import normalize_weapon_usage_counts
from ..sim.hooks import TickResult
from ..sim.input_providers import PerkMenuOpenCommand
from ..sim.presentation_reactions import (
    PostApplyReaction,
    apply_post_apply_reaction,
    merge_post_apply_reactions,
    resolve_quest_presentation_reaction,
)
from ..sim.sessions import DeterministicSession, DeterministicSessionTick, QuestSpawnState, quest_post_step
from ..terrain_assets import TerrainTextureId, terrain_texture_by_id
from ..ui.cursor import draw_menu_cursor
from ..ui.hud import HudRenderContext, draw_hud_overlay, hud_flags_for_game_mode
from ..ui.perk_menu import PerkMenuAssets, load_perk_menu_assets
from ..views.quest_run_overlay import (
    draw_quest_complete_banner_overlay,
    draw_quest_title_timer_overlay,
    quest_level_label,
)
from ..weapon_runtime import most_used_weapon_id_for_player, weapon_assign_player
from ..weapons import WEAPON_BY_ID, WeaponId
from .base_gameplay_mode import (
    BaseGameplayMode,
    LanFramePolicy,
    LanSession,
    LanStepAction,
)
from .components.highscore_record_builder import shots_from_state
from .components.perk_menu_controller import PerkMenuContext, PerkMenuController
from .components.perk_prompt_ui import PERK_PROMPT_MAX_TIMER_MS, PerkPromptUi

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))

_DEBUG_WEAPON_IDS = tuple(sorted(WEAPON_BY_ID))

QuestSessionFactory = Callable[..., DeterministicSession]


class _QuestRunState(msgspec.Struct):
    quest: QuestDefinition | None = None
    level: str = ""
    total_spawn_count: int = 0
    max_trigger_time_ms: int = 0


class QuestRunOutcome(msgspec.Struct, frozen=True):
    kind: str  # "completed" | "failed"
    level: str
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
    player_health_values: tuple[float, ...] = ()


def _quest_attempt_counter_index(major: int, minor: int) -> int | None:
    tier = int(major)
    quest = int(minor)
    global_index = (tier - 1) * 10 + (quest - 1)
    if not (0 <= global_index < 40):
        return None
    return global_index + 11


class QuestMode(BaseGameplayMode):
    def __init__(
        self,
        ctx: ViewContext,
        *,
        demo_mode_active: bool = False,
        texture_cache: PaqTextureCache | None = None,
        config: CrimsonConfig | None = None,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: random.Random | None = None,
        session_factory: QuestSessionFactory = DeterministicSession,
    ) -> None:
        super().__init__(
            ctx,
            world_size=WORLD_SIZE,
            default_game_mode_id=GameMode.QUESTS,
            demo_mode_active=bool(demo_mode_active),
            difficulty_level=0,
            hardcore=False,
            texture_cache=texture_cache,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._quest = _QuestRunState()
        self._selected_level: str | None = None
        self._outcome: QuestRunOutcome | None = None
        self._perk_menu_assets: PerkMenuAssets | None = None
        self._grim_mono: GrimMonoFont | None = None
        self._quest_complete_texture: rl.Texture | None = None

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_prompt_pulse = 0.0
        self._perk_menu = PerkMenuController(
            on_close=self._reset_perk_prompt,
            on_pick=self._record_perk_pick,
            defer_pick_apply=True,
        )
        self._session_factory = session_factory
        self._quest_spawn_state = QuestSpawnState()
        self._sim_session: DeterministicSession | None = self._new_sim_session(spawn_entries=())
        self._replay_recorder: ReplayRecorder | None = None

    def open(self) -> None:
        super().open()
        self._quest = _QuestRunState()
        self._outcome = None
        self._perk_menu_assets = load_perk_menu_assets(self._assets_root)
        self._quest_complete_texture = self._load_quest_complete_texture()
        self._grim_mono = load_grim_mono_font(self._assets_root)

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_prompt_pulse = 0.0
        self._perk_menu.reset()
        self._reset_gameplay_frame_clock()
        self._reset_lan_capture_clock()
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        self._sim_session = self._new_sim_session(spawn_entries=())

    def close(self) -> None:
        if self._grim_mono is not None:
            rl.unload_texture(self._grim_mono.texture)
            self._grim_mono = None
        self._quest_complete_texture = None
        self._perk_menu_assets = None
        self._sim_session = None
        super().close()

    def _load_quest_complete_texture(self) -> rl.Texture | None:
        loader = TextureLoader(
            assets_root=self._assets_root,
            cache=self.texture_cache,
        )
        texture = loader.get(
            name="ui_textLevComp",
            paq_rel="ui/ui_textLevComp.jaz",
        )
        return texture

    def _new_sim_session(self, *, spawn_entries: tuple[SpawnEntry, ...]) -> DeterministicSession:
        quest_spawn_state = QuestSpawnState(spawn_entries=tuple(spawn_entries))
        self._quest_spawn_state = quest_spawn_state
        return self._session_factory(
            world=self.sim_world.world_state,
            world_size=float(self.world_size),
            damage_scale_by_type=self.sim_world.damage_scale_by_type,
            fx_queue=self.render_resources.fx_queue,
            fx_queue_rotated=self.render_resources.fx_queue_rotated,
            game_mode=GameMode.QUESTS,
            perk_progression_enabled=True,
            detail_preset=5,
            gore_disabled=0,
            demo_mode_active=bool(self.demo_mode_active),
            clear_fx_queues_each_tick=False,
            finalize_post_render_lifecycle=True,
            post_step_hook=lambda ctx: quest_post_step(ctx, quest_spawn_state),
        )

    def _reset_perk_prompt(self) -> None:
        if int(self.state.perk_selection.pending_count) > 0:
            # Reset the prompt swing so each pending perk replays the intro.
            self._perk_prompt_timer_ms = 0.0
            self._perk_prompt_hover = False
            self._perk_prompt_pulse = 0.0

    def _record_perk_pick(self, choice_index: int) -> bool:
        self.record_perk_pick_command(int(choice_index), player_index=0)
        return True

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return float(self._quest_spawn_state.spawn_timeline_ms)

    def _replay_claimed_stats_complete(self) -> bool:
        return bool(self._outcome is not None)

    def _replay_claimed_stats_elapsed_ms(self) -> int:
        return int(self._quest_spawn_state.spawn_timeline_ms)

    def _replay_output_basename(self, *, stamp: str, replay: Replay) -> str:
        level = str(self._quest.level) if self._quest.level else str(replay.header.quest_level or "quest")
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

    def _lan_frame_policy(self) -> LanFramePolicy:
        return LanFramePolicy(
            prepare_frame=self._quest_prepare_lan_frame,
            on_tick_applied=self._quest_on_tick_applied,
            on_paused=self._quest_on_lan_paused,
        )

    def _quest_on_lan_paused(self, dt: float) -> None:
        self._tick_death_timers(dt, rate=1.0)
        if self._death_transition_ready():
            self._close_failed_run()

    def _quest_prepare_lan_frame(
        self,
        role: str,
        dt_ui_ms: float,
        session: LanSession,
        dt_tick: float,
    ) -> bool:
        _ = role, dt_ui_ms, dt_tick
        session.detail_preset = int(self._deterministic_detail_preset())
        session.gore_disabled = int(self._deterministic_gore_disabled())
        return True

    def _quest_on_tick_applied(
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
                    level=str(self._quest.level),
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
                )
            self._save_replay()
            self.close_requested = True
            return "stop_after_finalize"

        if self._death_transition_ready():
            self._close_failed_run()
            return "stop_after_finalize"
        return "continue"

    def _build_tick_post_apply_reaction(self, *, tick_result: TickResult) -> PostApplyReaction:
        reaction = super()._build_tick_post_apply_reaction(tick_result=tick_result)
        quest_reaction = resolve_quest_presentation_reaction(self._quest_spawn_state)
        return merge_post_apply_reactions(
            reaction,
            PostApplyReaction(quest=quest_reaction),
        )

    def _apply_tick_post_apply_reaction(self, reaction: PostApplyReaction, *, dt_seconds: float) -> None:
        _ = dt_seconds
        apply_post_apply_reaction(
            reaction=reaction,
            play_sfx=self.audio_bridge.router.play_sfx,
            play_completion_music=self._play_quest_completion_music,
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

    def _perk_menu_context(self) -> PerkMenuContext:
        gore_disabled = self.config.gore_disabled
        fx_detail = self.config.fx_detail(level=0, default=False)
        players = self.sim_world.players
        return PerkMenuContext(
            state=self.state,
            perk_state=self.state.perk_selection,
            players=players,
            creatures=cast("list[CreatureForPerks]", self.creatures.entries),
            player=self.player,
            game_mode=GameMode.QUESTS,
            player_count=len(players),
            gore_disabled=gore_disabled,
            fx_detail=fx_detail,
            font=self._small,
            assets=self._perk_menu_assets,
            mouse=self._ui_mouse_pos(),
            play_sfx=self.audio_bridge.router.play_sfx,
        )

    def select_level(self, level: str | None) -> None:
        self._selected_level = level

    def consume_outcome(self) -> QuestRunOutcome | None:
        outcome = self._outcome
        self._outcome = None
        return outcome

    def prepare_new_run(self, level: str, *, status: GameStatus | None) -> None:
        quest = quest_by_level(level)
        if quest is None:
            self._quest = _QuestRunState(level=level)
            return
        self._outcome = None
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

        hardcore_flag = self.config.hardcore

        self.hardcore = hardcore_flag
        # Native quest start does not reseed RNG per level; carry the current
        # session RNG state into the next run.
        seed = int(self.state.rng.state) & 0xFFFFFFFF

        player_count = self.config.player_count
        self._sync_world_runtime_config()
        self.world_runtime.reset(seed=seed, player_count=max(1, min(4, player_count)))
        self._bind_world()
        self._local_input.reset(players=self.sim_world.players)
        self.bind_status(status)
        self.state.quest_stage_major, self.state.quest_stage_minor = quest.level_key

        default_terrain = (TerrainTextureId.Q1_BASE, TerrainTextureId.Q1_OVERLAY, TerrainTextureId.Q1_BASE)
        terrain_ids = quest.terrain_ids
        if terrain_ids is None:
            base_id, overlay_id, detail_id = default_terrain
        else:
            try:
                base_id = TerrainTextureId(int(terrain_ids[0]))
                overlay_id = TerrainTextureId(int(terrain_ids[1]))
                detail_id = TerrainTextureId(int(terrain_ids[2]))
            except ValueError:
                base_id, overlay_id, detail_id = default_terrain
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

        # Quest metadata already stores native (1-based) weapon ids.
        start_weapon_id = quest.start_weapon_id
        if start_weapon_id <= WeaponId.NONE:
            start_weapon_id = WeaponId.PISTOL
        for player in self.sim_world.players:
            weapon_assign_player(player, start_weapon_id, state=self.state)

        ctx = QuestContext(
            width=int(self.world_size),
            height=int(self.world_size),
            player_count=len(self.sim_world.players),
        )
        entries = build_quest_spawn_table(
            quest,
            ctx,
            seed=seed,
            hardcore=hardcore_flag,
            full_version=not self.demo_mode_active,
        )
        total_spawn_count = sum(int(entry.count) for entry in entries)
        max_trigger_ms = max((int(entry.trigger_ms) for entry in entries), default=0)

        self._quest = _QuestRunState(
            quest=quest,
            level=quest.level,
            total_spawn_count=int(total_spawn_count),
            max_trigger_time_ms=int(max_trigger_ms),
        )
        self._reset_gameplay_frame_clock()
        self._sim_session = self._new_sim_session(spawn_entries=tuple(entries))

        weapon_usage_counts = normalize_weapon_usage_counts(
            status.data.get("weapon_usage_counts") if status is not None else None,
        )
        status_snapshot = ReplayStatusSnapshot(
            quest_unlock_index=int(status.quest_unlock_index) if status is not None else 0,
            quest_unlock_index_full=int(status.quest_unlock_index_full)
            if status is not None
            else 0,
            weapon_usage_counts=weapon_usage_counts,
        )
        record_replay = (not bool(self._lan_enabled)) or str(self._lan_role) == "host"
        if record_replay:
            self._replay_recorder = ReplayRecorder(
                ReplayHeader(
                    game_mode_id=GameMode.QUESTS,
                    seed=int(self.state.rng.state),
                    quest_level=str(quest.level),
                    tick_rate=int(self._gameplay_tick_rate()),
                    difficulty_level=int(self.difficulty_level),
                    hardcore=bool(self.hardcore),
                    preserve_bugs=bool(self.state.preserve_bugs),
                    detail_preset=self.config.detail_preset,
                    gore_disabled=self.config.gore_disabled,
                    world_size=float(self.world_size),
                    player_count=len(self.sim_world.players),
                    status=status_snapshot,
                ),
            )
            self._replay_checkpoints_sample_rate = int(DEFAULT_CHECKPOINT_SAMPLE_RATE)
        else:
            self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None

        if status is not None:
            idx = _quest_attempt_counter_index(quest.major, quest.minor)
            if idx is not None:
                status.increment_quest_play_count(idx)

    def _handle_input(self) -> None:
        if self._perk_menu.open and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.audio_bridge.router.play_sfx("sfx_ui_buttonclick")
            self._perk_menu.close()
            return

        if (not bool(self._lan_enabled)) and rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if debug_enabled() and (not self._perk_menu.open):
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F2):
                self.state.debug_god_mode = not bool(self.state.debug_god_mode)
                self.audio_bridge.router.play_sfx("sfx_ui_buttonclick")
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
                self.state.perk_selection.pending_count += 1
                self.state.perk_selection.choices_dirty = True
                self.audio_bridge.router.play_sfx("sfx_ui_levelup")
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
                level=str(self._quest.level),
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
            )
        self._save_replay()
        self.close_requested = True

    def _draw_perk_prompt(self) -> None:
        if self._perk_menu.active:
            return
        if not any(player.health > 0.0 for player in self.sim_world.players):
            return
        pending_count = int(self.state.perk_selection.pending_count)
        if pending_count <= 0:
            return
        label = PerkPromptUi.label(self.config, pending_count=pending_count)
        if not label:
            return
        PerkPromptUi.draw(
            font=self._small,
            assets=self._perk_menu_assets,
            label=label,
            timer_ms=float(self._perk_prompt_timer_ms),
            pulse=float(self._perk_prompt_pulse),
            ui_text_width=self._ui_text_width,
            text_color=UI_TEXT_COLOR,
            scale=UI_TEXT_SCALE,
        )

    def update(self, dt: float) -> None:
        frame = self._begin_mode_update(float(dt))
        if frame is None:
            return
        if bool(self.close_requested):
            return
        if bool(self._lan_enabled) and self._lan_runtime is not None:
            self._update_lan_match(dt=float(frame.dt), dt_ui_ms=float(frame.dt_ui_ms))
            return

        any_alive = self._any_player_alive()
        perk_pending = int(self.state.perk_selection.pending_count) > 0 and any_alive

        self._perk_prompt_hover = False
        perk_ctx = self._perk_menu_context()
        if self._perk_menu.open:
            self._perk_menu.handle_input(perk_ctx, dt=float(frame.dt), dt_ui_ms=float(frame.dt_ui_ms))

        perk_menu_active = self._perk_menu.active

        if (not perk_menu_active) and perk_pending and (not self._paused):
            label = PerkPromptUi.label(self.config, pending_count=int(self.state.perk_selection.pending_count))
            if label:
                rect = PerkPromptUi.rect(
                    label,
                    ui_text_width=self._ui_text_width,
                    ui_line_height=self._ui_line_height,
                    assets=self._perk_menu_assets,
                    scale=UI_TEXT_SCALE,
                )
                self._perk_prompt_hover = rect.contains(self._ui_mouse_pos())

            player0_binds = config_keybinds_for_player(self.config, player_index=0)
            fire_key = 0x100
            if len(player0_binds) >= 5:
                fire_key = int(player0_binds[4])

            pick_key = self.config.keybind_pick_perk

            if input_code_is_pressed_for_player(pick_key, player_index=0) and (
                not input_code_is_down_for_player(fire_key, player_index=0)
            ):
                self._perk_prompt_pulse = 1000.0
                if self._replay_recorder is not None:
                    self._record_replay_checkpoint(max(0, self._replay_recorder.tick_index - 1), force=True)
                opened = self._perk_menu.open_if_available(perk_ctx)
                if opened:
                    self.enqueue_input_command(PerkMenuOpenCommand(player_index=0))
            elif self._perk_prompt_hover and input_primary_just_pressed(
                self.config,
                player_count=len(self.sim_world.players),
            ):
                self._perk_prompt_pulse = 1000.0
                if self._replay_recorder is not None:
                    self._record_replay_checkpoint(max(0, self._replay_recorder.tick_index - 1), force=True)
                opened = self._perk_menu.open_if_available(perk_ctx)
                if opened:
                    self.enqueue_input_command(PerkMenuOpenCommand(player_index=0))

        perk_menu_active = self._perk_menu.active

        if not self._paused:
            pulse_delta = float(frame.dt_ui_ms) * (6.0 if self._perk_prompt_hover else -2.0)
            self._perk_prompt_pulse = clamp(self._perk_prompt_pulse + pulse_delta, 0.0, 1000.0)

        prompt_active = perk_pending and (not perk_menu_active) and (not self._paused)
        if prompt_active:
            self._perk_prompt_timer_ms = clamp(
                self._perk_prompt_timer_ms + float(frame.dt_ui_ms),
                0.0,
                PERK_PROMPT_MAX_TIMER_MS,
            )
        else:
            self._perk_prompt_timer_ms = clamp(
                self._perk_prompt_timer_ms - float(frame.dt_ui_ms),
                0.0,
                PERK_PROMPT_MAX_TIMER_MS,
            )

        self._perk_menu.tick_timeline(float(frame.dt_ui_ms))

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
        session.gore_disabled = int(self._deterministic_gore_disabled())

        if self.audio_bridge.router is not None:
            self.audio_bridge.router.audio = self.audio
            self.audio_bridge.router.audio_rng = self.audio_rng
            self.audio_bridge.router.demo_mode_active = self.demo_mode_active
        if self.render_resources.ground is not None:
            self.sync_ground_settings()
            self.render_resources.ground.process_pending()

        tick_dt = float(self._gameplay_tick_dt(session=session))

        def _on_tick(tick, tick_index: int | None) -> bool:
            _ = tick_index
            action = self._quest_on_tick_applied(tick, None, tick_dt)
            return action != "continue"

        def _on_checkpoint(tick_index: int, tick) -> None:
            self._record_replay_checkpoint_from_tick(
                tick_index=int(tick_index),
                tick=tick,
            )

        self._run_deterministic_session_ticks(
            dt_frame=float(sim_dt),
            session=session,
            recorder=self._replay_recorder,
            on_tick=_on_tick,
            on_checkpoint=_on_checkpoint,
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
        if (not perk_menu_active) and self._hud_assets is not None:
            total = int(self._quest.total_spawn_count)
            kills = int(self.creatures.kill_count)
            quest_progress_ratio = float(kills) / float(total) if total > 0 else None
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar()
            hud_bottom = draw_hud_overlay(
                HudRenderContext(
                    assets=self._hud_assets,
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

        self._draw_perk_prompt()
        self._perk_menu.draw(self._perk_menu_context())

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
        assets = self._perk_menu_assets
        cursor_tex = assets.cursor if assets is not None else None
        mouse_pos = self._ui_mouse
        draw_menu_cursor(
            self.render_resources.particles_texture,
            cursor_tex,
            pos=mouse_pos,
            pulse_time=float(self._cursor_pulse_time),
        )

    def _draw_quest_title(self) -> None:
        font = self._grim_mono
        quest = self._quest.quest
        if font is None or quest is None:
            return
        draw_quest_title_timer_overlay(
            font,
            quest.title,
            quest_level_label(quest.major, quest.minor),
            timer_ms=float(self._quest_spawn_state.spawn_timeline_ms),
        )

    def _draw_quest_complete_banner(self) -> None:
        tex = self._quest_complete_texture
        if tex is None:
            return
        draw_quest_complete_banner_overlay(
            tex,
            timer_ms=float(self._quest_spawn_state.completion_transition_ms),
        )
