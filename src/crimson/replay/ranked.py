"""The ranked rules: which verified runs rank, and on which board.

docs/rewrite/ranked-rules.md is the contract. A ranked run starts from the canonical profile
(`ranked_run_spec`): one player, full detail with violence on, friendly fire off, the documented
fixes, the quests the run's own progression has unlocked, no weapon history and no quest retries. Every tick uses human
controls, and every aim point is one a cursor clamped to a 1024x768 view could reach. Only
finished runs rank: a Survival death or a completed quest.
"""

from __future__ import annotations

import secrets

import msgspec

from grim.geom import Vec2

from ..aim_schemes import AimScheme
from ..camera import camera_update_for_players
from ..game_modes import GameMode
from ..local_input import PAD_AIM_DIST_MUL_DEFAULT
from ..movement_controls import MovementControlType
from ..quests.level import QUEST_COUNT, QuestLevel
from ..render.world.viewport import clamp_camera
from ..sim.hooks import TickResult
from ..sim.run_result import RunOutcome, RunResult
from ..sim.run_spec import RunSpec, RunStatus
from ..sim.world_state import WorldState
from .driver.playback_driver import PlaybackWalkObserver
from .input_codec import unpack_player_input
from .types import Replay

# The native resolution the ranked view is fixed at: the cursor, and so the aim, reaches this much of the arena.
RANKED_VIEW = Vec2(1024.0, 768.0)
RANKED_PAD_AIM_DIST_MUL = PAD_AIM_DIST_MUL_DEFAULT
# The longest pad reach, `min(|stick|, 1) * cv_padAimDistMul + 42`.
_PAD_AIM_REACH = RANKED_PAD_AIM_DIST_MUL + 42.0
# Aim points are stored as f32; this absorbs their rounding, not a real reach.
_AIM_SLACK = 0.01
RANKED_DETAIL_PRESET = 5
HUMAN_MOVEMENT = frozenset({
    MovementControlType.RELATIVE,
    MovementControlType.STATIC,
    MovementControlType.DUAL_ACTION_PAD,
    MovementControlType.MOUSE_POINT_CLICK,
})
HUMAN_AIM = frozenset({
    AimScheme.MOUSE,
    AimScheme.KEYBOARD,
    AimScheme.JOYSTICK,
    AimScheme.MOUSE_RELATIVE,
    AimScheme.DUAL_ACTION_PAD,
})
RANKED_MODES = frozenset({GameMode.SURVIVAL, GameMode.QUESTS})
_FINISHED = {GameMode.SURVIVAL: RunOutcome.DEATH, GameMode.QUESTS: RunOutcome.QUEST_COMPLETED}


def ranked_status(quest_level: QuestLevel | None = None, *, hardcore: bool = False) -> RunStatus:
    """The canonical save, with no weapon used yet.

    Survival plays with every quest done in both difficulties. A quest plays on the save that has
    just unlocked it: a normal quest with the quests before it done, a hardcore quest with the whole
    normal campaign and the hardcore quests before it.
    """

    if quest_level is None:
        return RunStatus(quest_unlock_index=QUEST_COUNT, quest_unlock_index_hardcore=QUEST_COUNT)
    if hardcore:
        return RunStatus(quest_unlock_index=QUEST_COUNT, quest_unlock_index_hardcore=quest_level.global_index)
    return RunStatus(quest_unlock_index=quest_level.global_index)


def ranked_run_seed() -> int:
    return secrets.randbits(32)


def ranked_run_spec(game_mode: GameMode, *, seed: int, quest_level: QuestLevel | None = None, hardcore: bool = False) -> RunSpec:
    """The run a ranked attempt plays; hardcore only changes quests, so Survival has one board."""

    hardcore = hardcore and game_mode == GameMode.QUESTS
    return RunSpec(
        game_mode_id=game_mode,
        seed=seed,
        quest_level=quest_level,
        player_count=1,
        hardcore=hardcore,
        preserve_bugs=False,
        quest_fail_retry_count=0,
        detail_preset=RANKED_DETAIL_PRESET,
        violence_disabled=0,
        friendly_fire=False,
        status=ranked_status(quest_level, hardcore=hardcore),
    )


def human_controls(movement: MovementControlType, aim: AimScheme) -> bool:
    return movement in HUMAN_MOVEMENT and aim in HUMAN_AIM


def ranked_board(run: RunSpec) -> str | None:
    """The leaderboard a ranked run of `run` goes to."""

    if run.game_mode_id == GameMode.SURVIVAL:
        return "survival"
    if run.game_mode_id == GameMode.QUESTS:
        return "quests-hardcore" if run.hardcore else "quests"
    return None


def unranked_reasons(run: RunSpec) -> list[str]:
    """Why a run's setup falls outside the ranked profile; empty when it can rank."""

    reasons = []
    if run.game_mode_id not in RANKED_MODES:
        reasons.append("mode")
    if run.player_count != 1:
        reasons.append("players")
    if run.preserve_bugs:
        reasons.append("original_rules")
    if run.detail_preset != RANKED_DETAIL_PRESET:
        reasons.append("detail_preset")
    if run.violence_disabled:
        reasons.append("violence_disabled")
    if run.friendly_fire:
        reasons.append("friendly_fire")
    if run.hardcore and run.game_mode_id != GameMode.QUESTS:
        reasons.append("hardcore")
    if run.quest_fail_retry_count:
        reasons.append("quest_retry")
    canonical = ranked_status(run.quest_level, hardcore=run.hardcore)
    if (run.status.quest_unlock_index, run.status.quest_unlock_index_hardcore) != (
        canonical.quest_unlock_index,
        canonical.quest_unlock_index_hardcore,
    ):
        reasons.append("unlocks")
    if run.status.weapon_usage_counts != canonical.weapon_usage_counts:
        reasons.append("weapon_usage")
    return reasons


def outcome_reasons(run: RunSpec, result: RunResult) -> list[str]:
    finished = _FINISHED.get(GameMode(run.game_mode_id))
    return [] if finished is not None and result.outcome == finished else ["unfinished"]


class RankedTickMonitor(PlaybackWalkObserver):
    """Checks each tick's controls and aim against the ranked view while a replay plays back.

    The aim a tick carries was read through the camera the previous tick left, so the camera is
    rebuilt after every tick the way live play builds it: centred on the living players, plus
    the shake, clamped to the arena, for the 1024x768 view. A smaller live view always lies
    inside that rectangle.
    """

    replay: Replay
    reasons: set[str] = msgspec.field(default_factory=set)
    camera: Vec2 | None = None
    move_target: Vec2 | None = None

    def before_tick(self, tick_index: int, world: WorldState, dt_tick: float) -> None:
        _ = dt_tick
        if self.camera is None:
            self._update_camera(world)
        camera = self.camera
        assert camera is not None
        player = unpack_player_input(self.replay.ticks[tick_index].inputs[0])
        if not human_controls(player.move_mode, player.aim_scheme):
            self.reasons.add("controls")
        if player.aim_scheme == AimScheme.MOUSE and not _in_view(player.aim + camera):
            self.reasons.add("aim_out_of_view")
        if player.aim_scheme == AimScheme.DUAL_ACTION_PAD and player.aim.length() > _PAD_AIM_REACH + _AIM_SLACK:
            self.reasons.add("aim_out_of_view")
        if player.move_mode == MovementControlType.MOUSE_POINT_CLICK:
            target = None if player.move.x == -1.0 else player.move
            # A target is set by a click; it may drift out of view while the player walks to it.
            if target is not None and target != self.move_target and not _in_view(target + camera):
                self.reasons.add("aim_out_of_view")
            self.move_target = target

    def after_tick(self, tick_result: TickResult, world: WorldState) -> None:
        _ = tick_result
        self._update_camera(world)

    def _update_camera(self, world: WorldState) -> None:
        update = camera_update_for_players(world.players, world.state.camera_shake_offset)
        camera = self.camera if update.focus is None else RANKED_VIEW * 0.5 - update.focus
        if camera is not None:
            self.camera = clamp_camera(camera=camera + update.shake, screen_size=RANKED_VIEW)


def _in_view(screen: Vec2) -> bool:
    return -_AIM_SLACK <= screen.x <= RANKED_VIEW.x + _AIM_SLACK and -_AIM_SLACK <= screen.y <= RANKED_VIEW.y + _AIM_SLACK


__all__ = [
    "RANKED_MODES",
    "RANKED_PAD_AIM_DIST_MUL",
    "RANKED_VIEW",
    "RankedTickMonitor",
    "human_controls",
    "outcome_reasons",
    "ranked_board",
    "ranked_run_seed",
    "ranked_run_spec",
    "ranked_status",
    "unranked_reasons",
]
