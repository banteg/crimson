from __future__ import annotations

from typing import Any, cast

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.terrain_render import GroundRenderer

from ...frontend.menu import ensure_menu_ground, menu_ground_camera
from ...frontend.transitions import _draw_screen_fade
from ..types import GameState, HighScoresRequest
from .shared import _next_quest_level, _player_name_default


def _parse_level_pair(level: object) -> tuple[int, int]:
    level_text = str(level or "")
    major_text, dot, minor_text = level_text.partition(".")
    if dot == "":
        return (0, 0)
    try:
        return (int(major_text), int(minor_text))
    except ValueError:
        return (0, 0)


def _int_or_zero(value: object) -> int:
    if value is None:
        return 0
    try:
        return int(cast(Any, value))
    except (TypeError, ValueError):
        return 0


class QuestResultsView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._ground: GroundRenderer | None = None
        self._quest_level: str = ""
        self._quest_title: str = ""
        self._quest_stage_major = 0
        self._quest_stage_minor = 0
        self._unlock_weapon_name: str = ""
        self._unlock_perk_name: str = ""
        self._ui = None
        self._action: str | None = None

    def open(self) -> None:
        from ...persistence.highscores import HighScoreRecord
        from ...quests.results import compute_quest_final_time
        from ...ui.quest_results import QuestResultsUi

        self._action = None
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self.state.quest_fail_retry_count = 0
        outcome = self.state.quest_outcome
        self.state.quest_outcome = None
        self._quest_level = ""
        self._quest_title = ""
        self._quest_stage_major = 0
        self._quest_stage_minor = 0
        self._unlock_weapon_name = ""
        self._unlock_perk_name = ""
        self._ui = None
        if outcome is None:
            return
        self._quest_level = str(outcome.level or "")

        major, minor = _parse_level_pair(outcome.level)
        self._quest_stage_major = int(major)
        self._quest_stage_minor = int(minor)

        try:
            from ...quests import quest_by_level
        except ImportError as exc:
            self._log_nonfatal("quest registry import failed", exc)
            quest = None
        else:
            quest = quest_by_level(str(outcome.level or ""))

        self._quest_title = quest.title if quest is not None else ""
        if quest is not None:
            weapon_id_native = _int_or_zero(quest.unlock_weapon_id)
            if weapon_id_native > 0:
                from ...weapons import WEAPON_BY_ID, weapon_display_name

                weapon_entry = WEAPON_BY_ID.get(weapon_id_native)
                self._unlock_weapon_name = (
                    weapon_display_name(weapon_id_native, preserve_bugs=bool(self.state.preserve_bugs))
                    if weapon_entry is not None and weapon_entry.name
                    else f"weapon_{weapon_id_native}"
                )

            from ...perks import PERK_BY_ID, PerkId, perk_display_name

            perk_id = _int_or_zero(quest.unlock_perk_id)
            if perk_id != int(PerkId.ANTIPERK):
                perk_entry = PERK_BY_ID.get(perk_id)
                if perk_entry is not None and perk_entry.name:
                    fx_toggle = self.state.config.fx_toggle
                    self._unlock_perk_name = perk_display_name(
                        perk_id,
                        fx_toggle=fx_toggle,
                        preserve_bugs=bool(self.state.preserve_bugs),
                    )
                else:
                    self._unlock_perk_name = f"perk_{perk_id}"

        record = HighScoreRecord.blank()
        record.game_mode_id = 3
        record.quest_stage_major = major
        record.quest_stage_minor = minor
        record.score_xp = int(outcome.experience)
        record.creature_kill_count = int(outcome.kill_count)
        record.most_used_weapon_id = int(outcome.most_used_weapon_id)
        fired = max(0, int(outcome.shots_fired))
        hit = max(0, min(int(outcome.shots_hit), fired))
        record.shots_fired = fired
        record.shots_hit = hit

        player_health_values = tuple(float(v) for v in getattr(outcome, "player_health_values", ()) or ())
        if len(player_health_values) == 0:
            player_health_values = (float(outcome.player_health),)
            if outcome.player2_health is not None:
                player_health_values = player_health_values + (float(outcome.player2_health),)
        breakdown = compute_quest_final_time(
            base_time_ms=int(outcome.base_time_ms),
            player_health=float(outcome.player_health),
            player2_health=(float(outcome.player2_health) if outcome.player2_health is not None else None),
            player_health_values=player_health_values,
            pending_perk_count=int(outcome.pending_perk_count),
        )
        record.survival_elapsed_ms = int(breakdown.final_time_ms)
        player_name_default = _player_name_default(self.state.config) or "Player"
        record.set_name(player_name_default)

        global_index = (int(major) - 1) * 10 + (int(minor) - 1)
        if 0 <= global_index < 40:
            try:
                # `sub_447d40` reads completed counts from indices 51..90.
                self.state.status.increment_quest_play_count(global_index + 51)
            except (IndexError, KeyError, TypeError, ValueError) as exc:
                self._log_nonfatal("failed to increment quest play count", exc)

        # Advance quest unlock progression when completing the currently-unlocked quest.
        if global_index >= 0:
            next_unlock = int(global_index + 1)
            hardcore = self.state.config.hardcore
            try:
                if hardcore:
                    if next_unlock > int(self.state.status.quest_unlock_index_full):
                        self.state.status.quest_unlock_index_full = next_unlock
                else:
                    if next_unlock > int(self.state.status.quest_unlock_index):
                        self.state.status.quest_unlock_index = next_unlock
            except (KeyError, TypeError, ValueError) as exc:
                self._log_nonfatal("failed to update quest unlock progression", exc)

        try:
            self.state.status.save_if_dirty()
        except (OSError, ValueError) as exc:
            self._log_nonfatal("failed to save status", exc)

        self._ui = QuestResultsUi(
            assets_root=self.state.assets_dir,
            base_dir=self.state.base_dir,
            config=self.state.config,
            preserve_bugs=bool(self.state.preserve_bugs),
        )
        self._ui.open(
            record=record,
            breakdown=breakdown,
            quest_level=str(outcome.level or ""),
            quest_title=str(self._quest_title or ""),
            quest_stage_major=int(self._quest_stage_major),
            quest_stage_minor=int(self._quest_stage_minor),
            unlock_weapon_name=str(self._unlock_weapon_name or ""),
            unlock_perk_name=str(self._unlock_perk_name or ""),
            player_name_default=player_name_default,
        )

    def close(self) -> None:
        if self._ui is not None:
            self._ui.close()
            self._ui = None
        self._ground = None
        self._quest_stage_major = 0
        self._quest_stage_minor = 0
        self._quest_level = ""
        self._quest_title = ""
        self._unlock_weapon_name = ""
        self._unlock_perk_name = ""

    def update(self, dt: float) -> None:
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        ui = self._ui
        if ui is None:
            return
        audio = self.state.audio
        rng = self.state.rng

        def _play(name: str) -> None:
            if audio is None:
                return
            play_sfx(audio, name, rng=rng)

        action = ui.update(dt, play_sfx=_play if audio is not None else None, rand=lambda: rng.getrandbits(32))
        if action == "play_again":
            self.state.pending_quest_level = self._quest_level
            self._action = "start_quest"
            return
        if action == "play_next":
            if int(self._quest_stage_major) == 5 and int(self._quest_stage_minor) == 10:
                self._action = "end_note"
                return
            next_level = _next_quest_level(self._quest_level)
            if next_level is not None:
                self.state.pending_quest_level = next_level
                self._action = "start_quest"
            else:
                self._action = "back_to_menu"
            return
        if action == "high_scores":
            self._open_high_scores_list()
            return
        if action == "main_menu":
            self._action = "back_to_menu"
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        ui = self._ui
        bg_alpha = 1.0
        if ui is not None:
            bg_alpha = float(ui.world_entity_alpha())
        pause_background = self.state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background(entity_alpha=bg_alpha)
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)
        if ui is not None:
            ui.draw()
            return

        rl.draw_text("Quest results unavailable.", 32, 140, 28, rl.Color(235, 235, 235, 255))
        rl.draw_text("Press ESC to return to the menu.", 32, 180, 18, rl.Color(190, 190, 200, 255))

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _open_high_scores_list(self) -> None:
        highlight_rank = None
        if self._ui is not None:
            highlight_rank = self._ui.highlight_rank
        self.state.pending_high_scores = HighScoresRequest(
            game_mode_id=3,
            quest_stage_major=int(self._quest_stage_major),
            quest_stage_minor=int(self._quest_stage_minor),
            highlight_rank=highlight_rank,
        )
        self._action = "open_high_scores"

    def _log_nonfatal(self, message: str, exc: Exception) -> None:
        self.state.console.log.log(f"quest results: {message}: {exc}")


__all__ = ["QuestResultsView"]
