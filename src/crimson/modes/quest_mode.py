from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import datetime as dt
import hashlib
import random
from typing import cast

import pyray as rl

from grim.assets import PaqTextureCache, TextureLoader
from grim.audio import AudioState, play_music
from grim.console import ConsoleState
from grim.config import (
    CrimsonConfig,
)
from grim.geom import Rect, Vec2
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.math import clamp
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..weapon_runtime import (
    most_used_weapon_id_for_player,
    weapon_assign_player,
)
from ..input_codes import (
    config_keybinds_for_player,
    input_code_is_down_for_player,
    input_code_is_pressed_for_player,
    input_primary_just_pressed,
)
from ..perks.state import CreatureForPerks
from ..persistence.save_status import GameStatus
from ..quests import quest_by_level
from ..quests.runtime import build_quest_spawn_table
from ..quests.runtime import tick_quest_completion_transition as _legacy_tick_quest_completion_transition
from ..quests.timeline import quest_spawn_table_empty as _legacy_quest_spawn_table_empty
from ..quests.timeline import tick_quest_mode_spawns as _legacy_tick_quest_mode_spawns
from ..quests.types import QuestContext, QuestDefinition, SpawnEntry
from ..terrain_assets import terrain_texture_by_id
from ..ui.cursor import draw_menu_cursor
from ..ui.hud import draw_hud_overlay, hud_flags_for_game_mode
from ..ui.perk_menu import PerkMenuAssets, load_perk_menu_assets
from ..replay import ReplayHeader, ReplayRecorder, ReplayStatusSnapshot, dump_replay
from ..replay.input_codec import pack_player_input, unpack_player_input
from ..replay.types import WEAPON_USAGE_COUNT
from ..replay.checkpoints import (
    FORMAT_VERSION as CHECKPOINTS_FORMAT_VERSION,
    ReplayCheckpoint,
    ReplayCheckpoints,
    build_checkpoint,
    default_checkpoints_path,
    dump_checkpoints_file,
    resolve_checkpoint_sample_rate,
)
from ..sim.clock import FixedStepClock
from ..sim.input import PlayerInput
from ..sim.sessions import QuestDeterministicSession
from ..net.protocol import STATE_HASH_PERIOD_TICKS, TickFrame
from ..views.quest_title_overlay import draw_quest_title_overlay
from ..weapons import WEAPON_BY_ID
from .base_gameplay_mode import BaseGameplayMode
from .components.highscore_record_builder import shots_from_state
from .components.perk_menu_controller import PerkMenuContext, PerkMenuController
from .components.perk_prompt_ui import PERK_PROMPT_MAX_TIMER_MS, PerkPromptUi

WORLD_SIZE = 1024.0
QUEST_TITLE_FADE_IN_MS = 500.0
QUEST_TITLE_HOLD_MS = 1000.0
QUEST_TITLE_FADE_OUT_MS = 500.0
QUEST_TITLE_TOTAL_MS = QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS + QUEST_TITLE_FADE_OUT_MS

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))

_DEBUG_WEAPON_IDS = tuple(sorted(WEAPON_BY_ID))
QUEST_COMPLETE_BANNER_BASE_W = 256.0
QUEST_COMPLETE_BANNER_BASE_H = 32.0
QUEST_COMPLETE_BANNER_SCALE_BASE = 0.95
QUEST_COMPLETE_BANNER_SCALE_RATE = 0.0004 * 0.13
QUEST_COMPLETE_BANNER_FADE_IN_MS = 500.0
QUEST_COMPLETE_BANNER_HOLD_END_MS = 1500.0
QUEST_COMPLETE_BANNER_FADE_OUT_END_MS = 2000.0

# Compatibility aliases used by existing monkeypatch-based tests.
tick_quest_mode_spawns = _legacy_tick_quest_mode_spawns
tick_quest_completion_transition = _legacy_tick_quest_completion_transition
quest_spawn_table_empty = _legacy_quest_spawn_table_empty


@dataclass(slots=True)
class _QuestRunState:
    quest: QuestDefinition | None = None
    level: str = ""
    spawn_entries: tuple[SpawnEntry, ...] = ()
    total_spawn_count: int = 0
    max_trigger_time_ms: int = 0
    spawn_timeline_ms: float = 0.0
    quest_name_timer_ms: float = 0.0
    no_creatures_timer_ms: float = 0.0
    completion_transition_ms: float = -1.0


@dataclass(frozen=True, slots=True)
class QuestRunOutcome:
    kind: str  # "completed" | "failed"
    level: str
    base_time_ms: int
    player_health: float
    player2_health: float | None
    pending_perk_count: int
    experience: int
    kill_count: int
    weapon_id: int
    shots_fired: int
    shots_hit: int
    most_used_weapon_id: int
    player_health_values: tuple[float, ...] = ()


def _quest_seed(major: int, minor: int) -> int:
    return int(major) * 100 + int(minor)


def _quest_attempt_counter_index(major: int, minor: int) -> int | None:
    tier = int(major)
    quest = int(minor)
    global_index = (tier - 1) * 10 + (quest - 1)
    if not (0 <= global_index < 40):
        return None
    return global_index + 11


def _quest_level_label(major: int, minor: int) -> str:
    major = int(major)
    minor = int(minor)

    # Match `ui_render_hud` (0x0041bf94): quest minor can temporarily exceed 10
    # (e.g. after incrementing), and the HUD carries it into the major.
    while minor > 10:
        major += 1
        minor -= 10
    return f"{major}.{minor}"


def _quest_complete_banner_alpha(timer_ms: float) -> float:
    t = float(timer_ms)
    if t <= 0.0:
        return 0.0
    if t < QUEST_COMPLETE_BANNER_FADE_IN_MS:
        return clamp(t / QUEST_COMPLETE_BANNER_FADE_IN_MS, 0.0, 1.0)
    if t < QUEST_COMPLETE_BANNER_HOLD_END_MS:
        return 1.0
    if t < QUEST_COMPLETE_BANNER_FADE_OUT_END_MS:
        return clamp((QUEST_COMPLETE_BANNER_FADE_OUT_END_MS - t) / QUEST_COMPLETE_BANNER_FADE_IN_MS, 0.0, 1.0)
    return 0.0


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
    ) -> None:
        super().__init__(
            ctx,
            world_size=WORLD_SIZE,
            default_game_mode_id=int(GameMode.QUESTS),
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
        self._perk_menu = PerkMenuController(on_close=self._reset_perk_prompt, on_pick=self._record_perk_pick)
        self._sim_clock = FixedStepClock(tick_rate=60)
        self._lan_capture_clock = FixedStepClock(tick_rate=60)
        self._sim_session: QuestDeterministicSession | None = None
        self._replay_recorder: ReplayRecorder | None = None
        self._replay_checkpoints: list[ReplayCheckpoint] = []
        self._replay_checkpoints_sample_rate: int = 60
        self._replay_checkpoints_last_tick: int | None = None

    def open(self) -> None:
        super().open()
        self._quest = _QuestRunState()
        self._outcome = None
        self._perk_menu_assets = load_perk_menu_assets(self._assets_root)
        if self._perk_menu_assets.missing:
            self._missing_assets.extend(self._perk_menu_assets.missing)
        self._quest_complete_texture = self._load_quest_complete_texture()
        self._grim_mono = load_grim_mono_font(self._assets_root, self._missing_assets)

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_prompt_pulse = 0.0
        self._perk_menu.reset()
        self._sim_clock.reset()
        self._lan_capture_clock.reset()
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        self._sim_session = QuestDeterministicSession(
            world=self.world.world_state,
            world_size=float(self.world.world_size),
            damage_scale_by_type=self.world._damage_scale_by_type,
            fx_queue=self.world.fx_queue,
            fx_queue_rotated=self.world.fx_queue_rotated,
            spawn_entries=(),
            detail_preset=5,
            fx_toggle=0,
            clear_fx_queues_each_tick=False,
        )

    def close(self) -> None:
        if self._grim_mono is not None:
            rl.unload_texture(self._grim_mono.texture)
            self._grim_mono = None
        self._quest_complete_texture = None
        self._perk_menu_assets = None
        self._sim_session = None
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        super().close()

    def _load_quest_complete_texture(self) -> rl.Texture | None:
        loader = TextureLoader(
            assets_root=self._assets_root, cache=self.world.texture_cache, missing=self._missing_assets
        )
        texture = loader.get_optional(
            name="ui_textLevComp",
            paq_rel="ui/ui_textLevComp.jaz",
        )
        if texture is None and "ui/ui_textLevComp.jaz" not in self._missing_assets:
            self._missing_assets.append("ui/ui_textLevComp.jaz")
        return texture

    def _reset_perk_prompt(self) -> None:
        if int(self.state.perk_selection.pending_count) > 0:
            # Reset the prompt swing so each pending perk replays the intro.
            self._perk_prompt_timer_ms = 0.0
            self._perk_prompt_hover = False
            self._perk_prompt_pulse = 0.0

    def _record_perk_pick(self, choice_index: int) -> None:
        recorder = self._replay_recorder
        if recorder is None:
            return
        recorder.record_perk_pick(player_index=0, choice_index=int(choice_index))

    def _record_replay_checkpoint(
        self,
        tick_index: int,
        *,
        force: bool = False,
        rng_marks: dict[str, int] | None = None,
        deaths: Sequence[object] | None = None,
        events: object | None = None,
        command_hash: str | None = None,
    ) -> None:
        recorder = self._replay_recorder
        if recorder is None:
            return
        if tick_index < 0:
            return
        if not force and (tick_index % int(self._replay_checkpoints_sample_rate or 1)) != 0:
            return
        if self._replay_checkpoints_last_tick == int(tick_index):
            return
        self._replay_checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=self.world.world_state,
                elapsed_ms=float(self._quest.spawn_timeline_ms),
                rng_marks=rng_marks,
                deaths=deaths,
                events=events,
                command_hash=command_hash,
            )
        )
        self._replay_checkpoints_last_tick = int(tick_index)

    def _save_replay(self) -> None:
        recorder = self._replay_recorder
        if recorder is None:
            return
        if int(recorder.tick_index) <= 0:
            # Avoid emitting empty replays/checkpoint sidecars (usually indicates a
            # test harness calling failure/complete helpers without ticking).
            self._replay_recorder = None
            self._replay_checkpoints.clear()
            self._replay_checkpoints_last_tick = None
            return
        replay = recorder.finish()
        self._record_replay_checkpoint(max(0, recorder.tick_index - 1), force=True)
        terminal_tick = int(recorder.tick_index)
        if any(int(getattr(event, "tick_index", -1)) == terminal_tick for event in replay.events):
            self._record_replay_checkpoint(terminal_tick, force=True)
        data = dump_replay(replay)
        digest = hashlib.sha256(data).hexdigest()
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        replay_dir = self._base_dir / "replays"
        replay_dir.mkdir(parents=True, exist_ok=True)
        level = str(self._quest.level) if self._quest.level else str(replay.header.quest_level or "quest")
        kind = str(getattr(self._outcome, "kind", "quest")) if self._outcome is not None else "quest"
        base_time_ms = int(self._quest.spawn_timeline_ms)
        base_name = f"quest_{level}_{stamp}_{kind}_t{base_time_ms}"
        path = replay_dir / f"{base_name}.crdemo.gz"
        counter = 1
        while path.exists():
            path = replay_dir / f"{base_name}_{counter}.crdemo.gz"
            counter += 1
        path.write_bytes(data)
        checkpoints_path = default_checkpoints_path(path)
        dump_checkpoints_file(
            checkpoints_path,
            ReplayCheckpoints(
                version=CHECKPOINTS_FORMAT_VERSION,
                replay_sha256=digest,
                sample_rate=int(self._replay_checkpoints_sample_rate or 0),
                checkpoints=list(self._replay_checkpoints),
            ),
        )
        self._replay_recorder = None
        self._replay_checkpoints.clear()
        self._replay_checkpoints_last_tick = None
        if self._console is not None:
            self._console.log.log(f"replay: saved {path}")
            self._console.log.log(f"replay: saved {checkpoints_path}")
            self._console.log.flush()

    def _perk_menu_context(self) -> PerkMenuContext:
        fx_toggle = self.config.fx_toggle
        fx_detail = self.config.fx_detail(level=0, default=False)
        players = self.world.players
        return PerkMenuContext(
            state=self.state,
            perk_state=self.state.perk_selection,
            players=players,
            creatures=cast("list[CreatureForPerks]", self.creatures.entries),
            player=self.player,
            game_mode=int(GameMode.QUESTS),
            player_count=len(players),
            fx_toggle=fx_toggle,
            fx_detail=fx_detail,
            font=self._small,
            assets=self._perk_menu_assets,
            mouse=self._ui_mouse_pos(),
            play_sfx=self.world.audio_router.play_sfx,
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

        self.world.hardcore = hardcore_flag
        seed = _quest_seed(quest.major, quest.minor)

        player_count = self.config.player_count
        self.world.reset(seed=seed, player_count=max(1, min(4, player_count)))
        self._bind_world()
        self._local_input.reset(players=self.world.players)
        self.bind_status(status)
        self.state.quest_stage_major, self.state.quest_stage_minor = quest.level_key

        base_id, overlay_id, detail_id = quest.terrain_ids or (0, 1, 0)
        base = terrain_texture_by_id(int(base_id))
        overlay = terrain_texture_by_id(int(overlay_id))
        detail = terrain_texture_by_id(int(detail_id))
        if base is not None and overlay is not None:
            base_key, base_path = base
            overlay_key, overlay_path = overlay
            detail_key = detail[0] if detail is not None else None
            detail_path = detail[1] if detail is not None else None
            self.world.set_terrain(
                base_key=base_key,
                overlay_key=overlay_key,
                base_path=base_path,
                overlay_path=overlay_path,
                detail_key=detail_key,
                detail_path=detail_path,
            )

        # Quest metadata already stores native (1-based) weapon ids.
        start_weapon_id = max(1, int(quest.start_weapon_id))
        for player in self.world.players:
            weapon_assign_player(player, start_weapon_id)

        ctx = QuestContext(
            width=int(self.world.world_size),
            height=int(self.world.world_size),
            player_count=len(self.world.players),
        )
        entries = build_quest_spawn_table(
            quest,
            ctx,
            seed=seed,
            hardcore=hardcore_flag,
            full_version=not self.world.demo_mode_active,
        )
        total_spawn_count = sum(int(entry.count) for entry in entries)
        max_trigger_ms = max((int(entry.trigger_ms) for entry in entries), default=0)

        self._quest = _QuestRunState(
            quest=quest,
            level=quest.level,
            spawn_entries=entries,
            total_spawn_count=int(total_spawn_count),
            max_trigger_time_ms=int(max_trigger_ms),
            spawn_timeline_ms=0.0,
            quest_name_timer_ms=0.0,
            no_creatures_timer_ms=0.0,
            completion_transition_ms=-1.0,
        )
        self._sim_clock.reset()
        self._sim_session = QuestDeterministicSession(
            world=self.world.world_state,
            world_size=float(self.world.world_size),
            damage_scale_by_type=self.world._damage_scale_by_type,
            fx_queue=self.world.fx_queue,
            fx_queue_rotated=self.world.fx_queue_rotated,
            spawn_entries=tuple(entries),
            detail_preset=5,
            fx_toggle=0,
            clear_fx_queues_each_tick=False,
        )

        weapon_usage_counts: tuple[int, ...] = ()
        if status is not None:
            raw_counts = status.data.get("weapon_usage_counts")
            if isinstance(raw_counts, list):
                coerced: list[int] = []
                for value in raw_counts[:WEAPON_USAGE_COUNT]:
                    try:
                        coerced.append(int(value) & 0xFFFFFFFF)
                    except (TypeError, ValueError, OverflowError):
                        coerced.append(0)
                weapon_usage_counts = tuple(coerced)
        if len(weapon_usage_counts) != WEAPON_USAGE_COUNT:
            weapon_usage_counts = tuple(weapon_usage_counts) + (0,) * max(
                0, WEAPON_USAGE_COUNT - len(weapon_usage_counts)
            )
            weapon_usage_counts = weapon_usage_counts[:WEAPON_USAGE_COUNT]
        status_snapshot = ReplayStatusSnapshot(
            quest_unlock_index=int(getattr(status, "quest_unlock_index", 0) or 0) if status is not None else 0,
            quest_unlock_index_full=int(getattr(status, "quest_unlock_index_full", 0) or 0)
            if status is not None
            else 0,
            weapon_usage_counts=weapon_usage_counts,
        )
        record_replay = (not bool(self._lan_enabled)) or str(self._lan_role) == "host"
        if record_replay:
            self._replay_recorder = ReplayRecorder(
                ReplayHeader(
                    game_mode_id=int(GameMode.QUESTS),
                    seed=int(self.state.rng.state),
                    quest_level=str(quest.level),
                    tick_rate=int(self._sim_clock.tick_rate),
                    difficulty_level=int(self.world.difficulty_level),
                    hardcore=bool(self.world.hardcore),
                    preserve_bugs=bool(self.world.preserve_bugs),
                    detail_preset=self.config.detail_preset,
                    fx_toggle=self.config.fx_toggle,
                    world_size=float(self.world.world_size),
                    player_count=len(self.world.players),
                    status=status_snapshot,
                )
            )
            tick_rate = int(self._replay_recorder.header.tick_rate)
            self._replay_checkpoints_sample_rate = resolve_checkpoint_sample_rate(tick_rate)
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
            self.world.audio_router.play_sfx("sfx_ui_buttonclick")
            self._perk_menu.close()
            return

        if (not bool(self._lan_enabled)) and rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if debug_enabled() and (not self._perk_menu.open):
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F2):
                self.state.debug_god_mode = not bool(self.state.debug_god_mode)
                self.world.audio_router.play_sfx("sfx_ui_buttonclick")
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
                self.state.perk_selection.pending_count += 1
                self.state.perk_selection.choices_dirty = True
                self.world.audio_router.play_sfx("sfx_ui_levelup")
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
        current = int(self.player.weapon_id)
        try:
            idx = weapon_ids.index(current)
        except ValueError:
            idx = 0
        weapon_id = int(weapon_ids[(idx + int(delta)) % len(weapon_ids)])
        weapon_assign_player(self.player, weapon_id, state=self.state)

    def _death_transition_ready(self) -> bool:
        dead_players = 0
        for player in self.world.players:
            if float(player.health) > 0.0:
                return False
            dead_players += 1
            if float(player.death_timer) >= 0.0:
                return False
        return dead_players > 0

    def _tick_death_timers(self, dt_frame: float, *, rate: float = 20.0) -> None:
        delta = float(dt_frame) * float(rate)
        if delta <= 0.0:
            return
        for player in self.world.players:
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
                fallback_weapon_id=int(self.player.weapon_id),
            )
            player_health_values = tuple(float(player.health) for player in self.world.players)
            player2_health = None
            if len(player_health_values) >= 2:
                player2_health = float(player_health_values[1])
            self._outcome = QuestRunOutcome(
                kind="failed",
                level=str(self._quest.level),
                base_time_ms=int(self._quest.spawn_timeline_ms),
                player_health=float(player_health_values[0] if player_health_values else self.player.health),
                player2_health=player2_health,
                player_health_values=player_health_values,
                pending_perk_count=int(self.state.perk_selection.pending_count),
                experience=int(self.player.experience),
                kill_count=int(self.creatures.kill_count),
                weapon_id=int(self.player.weapon_id),
                shots_fired=fired,
                shots_hit=hit,
                most_used_weapon_id=int(most_used_weapon_id),
            )
        self._save_replay()
        self.close_requested = True

    def _draw_perk_prompt(self) -> None:
        if self._perk_menu.active:
            return
        if not any(player.health > 0.0 for player in self.world.players):
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
        self._update_audio(dt)

        dt_frame, dt_ui_ms = self._tick_frame(dt)
        self._handle_input()
        if self._action == "open_pause_menu":
            return

        if self.close_requested:
            return

        if bool(self._lan_enabled) and self._lan_runtime is not None:
            self._update_lan_match(dt_frame=dt_frame, dt_ui_ms=dt_ui_ms)
            return

        any_alive = any(player.health > 0.0 for player in self.world.players)
        perk_pending = int(self.state.perk_selection.pending_count) > 0 and any_alive

        self._perk_prompt_hover = False
        perk_ctx = self._perk_menu_context()
        if self._perk_menu.open:
            self._perk_menu.handle_input(perk_ctx, dt_frame=dt_frame, dt_ui_ms=dt_ui_ms)

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
                if opened and self._replay_recorder is not None:
                    self._replay_recorder.record_perk_menu_open(player_index=0)
            elif self._perk_prompt_hover and input_primary_just_pressed(
                self.config,
                player_count=len(self.world.players),
            ):
                self._perk_prompt_pulse = 1000.0
                if self._replay_recorder is not None:
                    self._record_replay_checkpoint(max(0, self._replay_recorder.tick_index - 1), force=True)
                opened = self._perk_menu.open_if_available(perk_ctx)
                if opened and self._replay_recorder is not None:
                    self._replay_recorder.record_perk_menu_open(player_index=0)

        perk_menu_active = self._perk_menu.active

        if not self._paused:
            pulse_delta = dt_ui_ms * (6.0 if self._perk_prompt_hover else -2.0)
            self._perk_prompt_pulse = clamp(self._perk_prompt_pulse + pulse_delta, 0.0, 1000.0)

        prompt_active = perk_pending and (not perk_menu_active) and (not self._paused)
        if prompt_active:
            self._perk_prompt_timer_ms = clamp(self._perk_prompt_timer_ms + dt_ui_ms, 0.0, PERK_PROMPT_MAX_TIMER_MS)
        else:
            self._perk_prompt_timer_ms = clamp(self._perk_prompt_timer_ms - dt_ui_ms, 0.0, PERK_PROMPT_MAX_TIMER_MS)

        self._perk_menu.tick_timeline(dt_ui_ms)

        self._update_lan_wait_gate_debug_override()
        if self._lan_wait_gate_active():
            self._sim_clock.reset()
            return

        dt_world = 0.0 if self._paused or self._perk_menu.active else dt_frame
        if dt_world <= 0.0:
            self._sim_clock.reset()
            # Match legacy transition behavior: keep countdown moving, but at
            # real-time pace while perk-menu transition is holding world ticks.
            self._tick_death_timers(dt_frame, rate=1.0)
            if self._death_transition_ready():
                self._close_failed_run()
            return

        ticks_to_run = self._sim_clock.advance(dt_world)
        if ticks_to_run <= 0:
            return

        dt_tick = float(self._sim_clock.dt_tick)
        input_frame = self._build_local_inputs(dt_frame=dt_frame)
        session = self._sim_session
        if session is None:
            self._tick_death_timers(dt_world)
            if self._death_transition_ready():
                self._close_failed_run()
            return

        session.detail_preset = int(self._deterministic_detail_preset())
        session.fx_toggle = int(self._deterministic_fx_toggle())
        session.spawn_entries = tuple(self._quest.spawn_entries)
        session.spawn_timeline_ms = float(self._quest.spawn_timeline_ms)
        session.no_creatures_timer_ms = float(self._quest.no_creatures_timer_ms)
        session.completion_transition_ms = float(self._quest.completion_transition_ms)

        if self.world.audio_router is not None:
            self.world.audio_router.audio = self.world.audio
            self.world.audio_router.audio_rng = self.world.audio_rng
            self.world.audio_router.demo_mode_active = self.world.demo_mode_active
        if self.world.ground is not None:
            self.world._sync_ground_settings()
            self.world.ground.process_pending()

        for tick_offset in range(int(ticks_to_run)):
            inputs = input_frame if tick_offset == 0 else self._clear_local_input_edges(input_frame)
            recorder = self._replay_recorder
            if recorder is not None:
                tick_index = recorder.record_tick(inputs)
            else:
                tick_index = None
            tick = session.step_tick(
                dt_frame=dt_tick,
                inputs=inputs,
            )
            self.world.apply_step_result(
                tick.step,
                game_tune_started=False,
                apply_audio=True,
                update_camera=True,
            )
            self._quest.spawn_entries = tuple(session.spawn_entries)
            self._quest.spawn_timeline_ms = float(tick.spawn_timeline_ms)
            self._quest.no_creatures_timer_ms = float(tick.no_creatures_timer_ms)
            self._quest.completion_transition_ms = float(tick.completion_transition_ms)
            self._quest.quest_name_timer_ms += float(dt_tick) * 1000.0

            if tick_index is not None:
                world_events = tick.step.events
                self._record_replay_checkpoint(
                    int(tick_index),
                    rng_marks=tick.rng_marks,
                    deaths=world_events.deaths,
                    events=world_events,
                    command_hash=str(tick.step.command_hash),
                )

            if tick.play_hit_sfx:
                self.world.audio_router.play_sfx("sfx_questhit")
            if tick.play_completion_music and self.world.audio is not None:
                play_music(self.world.audio, "crimsonquest")
                playback = self.world.audio.music.playbacks.get("crimsonquest")
                if playback is not None:
                    playback.volume = 0.0
                    try:
                        rl.set_music_volume(playback.music, 0.0)
                    except RuntimeError:
                        playback.volume = 0.0

            if tick.completed:
                if self._outcome is None:
                    fired, hit = shots_from_state(self.state, player_index=int(self.player.index))
                    most_used_weapon_id = most_used_weapon_id_for_player(
                        self.state,
                        player_index=int(self.player.index),
                        fallback_weapon_id=int(self.player.weapon_id),
                    )
                    player_health_values = tuple(float(player.health) for player in self.world.players)
                    player2_health = None
                    if len(player_health_values) >= 2:
                        player2_health = float(player_health_values[1])
                    self._outcome = QuestRunOutcome(
                        kind="completed",
                        level=str(self._quest.level),
                        base_time_ms=int(self._quest.spawn_timeline_ms),
                        player_health=float(player_health_values[0] if player_health_values else self.player.health),
                        player2_health=player2_health,
                        player_health_values=player_health_values,
                        pending_perk_count=int(self.state.perk_selection.pending_count),
                        experience=int(self.player.experience),
                        kill_count=int(self.creatures.kill_count),
                        weapon_id=int(self.player.weapon_id),
                        shots_fired=fired,
                        shots_hit=hit,
                        most_used_weapon_id=int(most_used_weapon_id),
                    )
                self._save_replay()
                self.close_requested = True
                break

            if self._death_transition_ready():
                self._close_failed_run()
                break

    def _update_lan_match(self, *, dt_frame: float, dt_ui_ms: float) -> None:
        runtime = self._lan_runtime
        if runtime is None:
            return
        session = self._sim_session
        if session is None:
            return

        runtime.update()
        role = str(self._lan_role)
        if str(getattr(runtime, "error", "") or ""):
            self.close_requested = True
            return
        if self.world.audio_router is not None:
            self.world.audio_router.audio = self.world.audio
            self.world.audio_router.audio_rng = self.world.audio_rng
            self.world.audio_router.demo_mode_active = self.world.demo_mode_active
        if self.world.ground is not None:
            self.world._sync_ground_settings()
            self.world.ground.process_pending()
        self._trace_lan_terrain_generation()
        if bool(self._lan_terrain_generation_pending()):
            self._lan_capture_clock.reset()
            return

        if role == "host" and (not bool(runtime.host_remote_inputs_ready())):
            return

        if bool(self._paused):
            self._sim_clock.reset()
            # Mirror legacy: keep the fail transition timers moving at real-time pace while paused.
            self._tick_death_timers(dt_frame, rate=1.0)
            if self._death_transition_ready():
                self._close_failed_run()
            return

        dt_tick = float(self._lan_capture_clock.dt_tick)
        def _consume_lan_frames() -> bool:
            while True:
                frame = runtime.pop_tick_frame()
                if frame is None:
                    return False

                packed_inputs = list(getattr(frame, "frame_inputs", []) or [])
                player_inputs = [unpack_player_input(packed) for packed in packed_inputs]
                recorder = self._replay_recorder
                if recorder is not None:
                    tick_index = recorder.record_tick(player_inputs)
                else:
                    tick_index = None

                session.detail_preset = int(self._deterministic_detail_preset())
                session.fx_toggle = int(self._deterministic_fx_toggle())
                session.spawn_entries = tuple(self._quest.spawn_entries)
                session.spawn_timeline_ms = float(self._quest.spawn_timeline_ms)
                session.no_creatures_timer_ms = float(self._quest.no_creatures_timer_ms)
                session.completion_transition_ms = float(self._quest.completion_transition_ms)

                tick = session.step_tick(
                    dt_frame=float(dt_tick),
                    inputs=player_inputs,
                )

                remote_command_hash = str(getattr(frame, "command_hash", "") or "")
                remote_state_hash = str(getattr(frame, "state_hash", "") or "")
                local_command_hash = str(tick.step.command_hash)
                local_state_hash = ""
                if role == "join":
                    if remote_command_hash and remote_command_hash != local_command_hash:
                        runtime.note_desync(
                            kind="command_hash",
                            tick_index=int(frame.tick_index),
                            expected=str(remote_command_hash),
                            actual=str(local_command_hash),
                        )
                    if remote_state_hash:
                        local_state_hash = str(
                            build_checkpoint(
                                tick_index=int(frame.tick_index),
                                world=self.world.world_state,
                                elapsed_ms=float(tick.elapsed_ms),
                                creature_count_override=int(tick.creature_count_world_step),
                            ).state_hash
                        )
                        if local_state_hash != remote_state_hash:
                            runtime.note_desync(
                                kind="state_hash",
                                tick_index=int(frame.tick_index),
                                expected=str(remote_state_hash),
                                actual=str(local_state_hash),
                            )

                state_hash = ""
                if role == "host":
                    tick_i = int(frame.tick_index)
                    if int(tick_i) < 5 or (int(tick_i) % int(STATE_HASH_PERIOD_TICKS)) == 0:
                        state_hash = str(
                            build_checkpoint(
                                tick_index=int(frame.tick_index),
                                world=self.world.world_state,
                                elapsed_ms=float(tick.elapsed_ms),
                                creature_count_override=int(tick.creature_count_world_step),
                            ).state_hash
                        )
                self.world.apply_step_result(
                    tick.step,
                    game_tune_started=False,
                    apply_audio=True,
                    update_camera=True,
                )
                self._quest.spawn_entries = tuple(session.spawn_entries)
                self._quest.spawn_timeline_ms = float(tick.spawn_timeline_ms)
                self._quest.no_creatures_timer_ms = float(tick.no_creatures_timer_ms)
                self._quest.completion_transition_ms = float(tick.completion_transition_ms)
                self._quest.quest_name_timer_ms += float(dt_tick) * 1000.0

                if tick_index is not None:
                    world_events = tick.step.events
                    self._record_replay_checkpoint(
                        int(tick_index),
                        rng_marks=tick.rng_marks,
                        deaths=world_events.deaths,
                        events=world_events,
                        command_hash=str(tick.step.command_hash),
                    )

                if tick.play_hit_sfx:
                    self.world.audio_router.play_sfx("sfx_questhit")
                if tick.play_completion_music and self.world.audio is not None:
                    play_music(self.world.audio, "crimsonquest")
                    playback = self.world.audio.music.playbacks.get("crimsonquest")
                    if playback is not None:
                        playback.volume = 0.0
                        try:
                            rl.set_music_volume(playback.music, 0.0)
                        except RuntimeError:
                            playback.volume = 0.0

                if role == "host":
                    runtime.broadcast_tick_frame(
                        TickFrame(
                            tick_index=int(frame.tick_index),
                            frame_inputs=list(frame.frame_inputs),
                            command_hash=str(local_command_hash),
                            state_hash=str(state_hash),
                        )
                    )

                if tick.completed:
                    if self._outcome is None:
                        fired, hit = shots_from_state(self.state, player_index=int(self.player.index))
                        most_used_weapon_id = most_used_weapon_id_for_player(
                            self.state,
                            player_index=int(self.player.index),
                            fallback_weapon_id=int(self.player.weapon_id),
                        )
                        player_health_values = tuple(float(player.health) for player in self.world.players)
                        player2_health = None
                        if len(player_health_values) >= 2:
                            player2_health = float(player_health_values[1])
                        self._outcome = QuestRunOutcome(
                            kind="completed",
                            level=str(self._quest.level),
                            base_time_ms=int(self._quest.spawn_timeline_ms),
                            player_health=float(player_health_values[0] if player_health_values else self.player.health),
                            player2_health=player2_health,
                            player_health_values=player_health_values,
                            pending_perk_count=int(self.state.perk_selection.pending_count),
                            experience=int(self.player.experience),
                            kill_count=int(self.creatures.kill_count),
                            weapon_id=int(self.player.weapon_id),
                            shots_fired=fired,
                            shots_hit=hit,
                            most_used_weapon_id=int(most_used_weapon_id),
                        )
                    self._save_replay()
                    self.close_requested = True
                    return True

                if self._death_transition_ready():
                    self._close_failed_run()
                    return True

        if role == "join":
            if _consume_lan_frames():
                return

        ticks_to_capture = self._lan_capture_clock.advance(dt_frame)
        if ticks_to_capture > 0:
            input_frame = self._build_local_inputs(dt_frame=dt_frame)
            # In LAN sessions each peer is a single local player, so always sample
            # inputs using the configured Player 1 bindings (index 0). The network
            # slot mapping is handled by the lockstep runtime.
            local_input_index = 0
            for tick_offset in range(int(ticks_to_capture)):
                inputs = input_frame if tick_offset == 0 else self._clear_local_input_edges(input_frame)
                local_input = PlayerInput()
                if 0 <= local_input_index < len(inputs):
                    local_input = inputs[local_input_index]
                runtime.queue_local_input(pack_player_input(local_input))
        # Pump networking again after queuing local inputs so the host can emit frames
        # in the same render frame (reduces perceived host-side input latency).
        runtime.update()

        _consume_lan_frames()

    def draw(self) -> None:
        perk_menu_active = self._perk_menu.active
        debug_overlay_height = 0.0
        self.world.draw(
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
                self._hud_assets,
                state=self._hud_state,
                player=self.player,
                players=self.world.players,
                bonus_hud=self.state.bonus_hud,
                elapsed_ms=float(self._quest.spawn_timeline_ms),
                font=self._small,
                frame_dt_ms=self._last_dt_ms,
                show_health=hud_flags.show_health,
                show_weapon=hud_flags.show_weapon,
                show_xp=hud_flags.show_xp,
                show_time=hud_flags.show_time,
                show_quest_hud=hud_flags.show_quest_hud,
                quest_progress_ratio=quest_progress_ratio,
                small_indicators=self._hud_small_indicators(),
                preserve_bugs=bool(self.world.preserve_bugs),
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

        warn_y = float(rl.get_screen_height()) - 28.0
        if self.world.missing_assets:
            warn = "Missing world assets: " + ", ".join(self.world.missing_assets)
            self._draw_ui_text(warn, Vec2(24.0, warn_y), rl.Color(240, 80, 80, 255), scale=0.8)
            warn_y -= float(self._ui_line_height(scale=0.8)) + 2.0
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, Vec2(24.0, warn_y), rl.Color(240, 80, 80, 255), scale=0.8)

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
            self.world.particles_texture,
            cursor_tex,
            pos=mouse_pos,
            pulse_time=float(self._cursor_pulse_time),
        )

    def _draw_quest_title(self) -> None:
        font = self._grim_mono
        quest = self._quest.quest
        if font is None or quest is None:
            return
        timer_ms = float(self._quest.quest_name_timer_ms)
        if timer_ms <= 0.0 or timer_ms > QUEST_TITLE_TOTAL_MS:
            return
        if timer_ms < QUEST_TITLE_FADE_IN_MS and QUEST_TITLE_FADE_IN_MS > 1e-3:
            alpha = timer_ms / QUEST_TITLE_FADE_IN_MS
        elif timer_ms < (QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS):
            alpha = 1.0
        else:
            t = timer_ms - (QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS)
            alpha = max(0.0, 1.0 - (t / max(1e-3, QUEST_TITLE_FADE_OUT_MS)))

        draw_quest_title_overlay(font, quest.title, _quest_level_label(quest.major, quest.minor), alpha=alpha)

    def _draw_quest_complete_banner(self) -> None:
        tex = self._quest_complete_texture
        timer_ms = float(self._quest.completion_transition_ms)
        if tex is None or timer_ms <= 0.0:
            return
        alpha = _quest_complete_banner_alpha(timer_ms)
        if alpha <= 0.0:
            return
        scale = QUEST_COMPLETE_BANNER_SCALE_BASE + timer_ms * QUEST_COMPLETE_BANNER_SCALE_RATE
        width = QUEST_COMPLETE_BANNER_BASE_W * scale
        height = QUEST_COMPLETE_BANNER_BASE_H * scale
        center_x = float(rl.get_screen_width()) * 0.5
        center_y = float(rl.get_screen_height()) * 0.5
        src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
        dst = Rect.from_center(Vec2(center_x, center_y), width, height).to_rl()
        tint = rl.Color(255, 255, 255, int(clamp(alpha, 0.0, 1.0) * 255.0))
        rl.draw_texture_pro(tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)
