from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Literal

import msgspec

from ...bonuses.ids import BonusId, bonus_display_name
from ...game_modes import GameMode
from ...perks.ids import PerkId, perk_display_name
from ...replay import REPLAY_TICK_RATE, Replay
from ...sim.commands import PerkMenuOpenCommand, TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from ...sim.hooks import TickResult
from ...sim.state_types import BonusPickupEvent, PerkCounts, PlayerState
from ...weapons import WeaponId, weapon_display_name
from .playback_driver import PlaybackDriver, PlaybackWalkObserver
from .setup import ReplayRunnerError

_EPSILON = 1e-6
ReplayInfoCoreEventKind = Literal[
    "bonus_pickup",
    "weapon_change",
    "perk_pick",
    "level_up",
    "health_damage",
    "health_heal",
    "player_death",
]
ReplayInfoExtraEventKind = Literal[
    "creature_deaths",
    "perk_menu_open",
    "typo_backspace",
    "typo_char",
    "typo_submit",
]
type ReplayInfoEventKind = ReplayInfoCoreEventKind | ReplayInfoExtraEventKind

_CORE_EVENT_KINDS: frozenset[ReplayInfoCoreEventKind] = frozenset(
    (
        "bonus_pickup",
        "weapon_change",
        "perk_pick",
        "level_up",
        "health_damage",
        "health_heal",
        "player_death",
    ),
)


class ReplayInfoTimelineEvent(msgspec.Struct, frozen=True):
    tick_index: int
    elapsed_ms: int
    elapsed_s: float
    kind: ReplayInfoEventKind
    player_index: int | None
    detail: str
    data: dict[str, object]


class ReplayInfoResult(msgspec.Struct, frozen=True):
    game_mode_id: GameMode
    tick_rate: int
    ticks_simulated: int
    elapsed_ms: int
    player_count: int
    timeline: list[ReplayInfoTimelineEvent]


class _PlayerSnapshot(msgspec.Struct, frozen=True):
    health: float
    level: int
    experience: int
    weapon_id: WeaponId
    perk_counts: tuple[int, ...]


def _capture_snapshots(players: list[PlayerState], perks: PerkCounts) -> list[_PlayerSnapshot]:
    # Perk picks are attributed to player one, whose struct holds the perk table.
    snapshots: list[_PlayerSnapshot] = []
    for player in players:
        snapshots.append(
            _PlayerSnapshot(
                health=player.health,
                level=player.level,
                experience=player.experience,
                weapon_id=player.weapon.weapon_id,
                perk_counts=tuple(perks.counts) if player.index == 0 else (),
            ),
        )
    return snapshots


class _TickEvents(msgspec.Struct):
    """One tick's slice of the timeline; `add` drops the events the filters exclude."""

    timeline: list[ReplayInfoTimelineEvent]
    tick_index: int
    elapsed_ms: int
    player_filter: int | None
    include_extra_events: bool

    def add(self, kind: ReplayInfoEventKind, player_index: int | None, detail: str, data: dict[str, object]) -> None:
        if kind not in _CORE_EVENT_KINDS and not self.include_extra_events:
            return
        if self.player_filter is not None and player_index is not None and player_index != self.player_filter:
            return
        self.timeline.append(
            ReplayInfoTimelineEvent(
                tick_index=self.tick_index,
                elapsed_ms=self.elapsed_ms,
                elapsed_s=self.elapsed_ms / 1000.0,
                kind=kind,
                player_index=player_index,
                detail=detail,
                data=data,
            ),
        )


def _append_extra_replay_commands(events: _TickEvents, commands: Sequence[object]) -> None:
    for cmd in commands:
        if isinstance(cmd, PerkMenuOpenCommand):
            events.add(
                "perk_menu_open",
                cmd.player_index,
                f"p{cmd.player_index} perk menu opened",
                {"player_index": cmd.player_index},
            )
        elif isinstance(cmd, TypoCharCommand):
            events.add(
                "typo_char",
                cmd.player_index,
                f"p{cmd.player_index} typed '{cmd.ch}'",
                {"player_index": cmd.player_index, "ch": cmd.ch},
            )
        elif isinstance(cmd, TypoBackspaceCommand):
            events.add(
                "typo_backspace",
                cmd.player_index,
                f"p{cmd.player_index} typo backspace",
                {"player_index": cmd.player_index},
            )
        elif isinstance(cmd, TypoSubmitCommand):
            events.add(
                "typo_submit",
                cmd.player_index,
                f"p{cmd.player_index} typo submit",
                {"player_index": cmd.player_index},
            )


def _append_bonus_pickup_events(events: _TickEvents, pickups: list[BonusPickupEvent]) -> None:
    for pickup in pickups:
        bonus_id = pickup.bonus_id
        bonus_name = bonus_display_name(bonus_id)
        detail = f"p{pickup.player_index} picked {bonus_name} ({bonus_id}) amount={pickup.amount}"
        data: dict[str, object] = {
            "bonus_id": bonus_id,
            "bonus_name": bonus_name,
            "amount": pickup.amount,
        }
        if bonus_id == BonusId.WEAPON:
            weapon_id = WeaponId(pickup.amount)
            weapon_name = weapon_display_name(weapon_id)
            detail += f" -> {weapon_name}"
            data["weapon_id"] = weapon_id
            data["weapon_name"] = weapon_name
        events.add("bonus_pickup", pickup.player_index, detail, data)


def _append_snapshot_diff_events(
    events: _TickEvents,
    *,
    before: list[_PlayerSnapshot],
    after: list[_PlayerSnapshot],
    violence_disabled: int,
) -> None:
    players_len = min(len(before), len(after))
    for idx in range(players_len):
        pre = before[idx]
        post = after[idx]

        if pre.weapon_id != post.weapon_id:
            weapon_before_name = weapon_display_name(pre.weapon_id)
            weapon_after_name = weapon_display_name(post.weapon_id)
            events.add(
                "weapon_change",
                idx,
                f"p{idx} weapon {weapon_before_name} -> {weapon_after_name}",
                {
                    "weapon_id_before": pre.weapon_id,
                    "weapon_name_before": weapon_before_name,
                    "weapon_id_after": post.weapon_id,
                    "weapon_name_after": weapon_after_name,
                },
            )

        if post.level > pre.level:
            events.add(
                "level_up",
                idx,
                f"p{idx} level {pre.level} -> {post.level} (xp={post.experience})",
                {
                    "level_before": pre.level,
                    "level_after": post.level,
                    "xp": post.experience,
                },
            )

        perk_len = min(len(pre.perk_counts), len(post.perk_counts))
        for perk_id in range(perk_len):
            before_count = pre.perk_counts[perk_id]
            after_count = post.perk_counts[perk_id]
            if after_count <= before_count:
                continue
            perk_name = perk_display_name(
                PerkId(perk_id),
                violence_disabled=violence_disabled,
            )
            events.add(
                "perk_pick",
                idx,
                f"p{idx} perk {perk_name} ({perk_id}) x{after_count}",
                {
                    "perk_id": perk_id,
                    "perk_name": perk_name,
                    "count_before": before_count,
                    "count_after": after_count,
                },
            )

        health_before = pre.health
        health_after = post.health
        if health_after < health_before - _EPSILON:
            amount = health_before - health_after
            events.add(
                "health_damage",
                idx,
                f"p{idx} damage {amount:.6f} (health {health_before:.6f}->{health_after:.6f})",
                {
                    "amount": amount,
                    "health_before": health_before,
                    "health_after": health_after,
                },
            )
        elif health_after > health_before + _EPSILON:
            amount = health_after - health_before
            events.add(
                "health_heal",
                idx,
                f"p{idx} heal {amount:.6f} (health {health_before:.6f}->{health_after:.6f})",
                {
                    "amount": amount,
                    "health_before": health_before,
                    "health_after": health_after,
                },
            )

        if health_before > 0.0 and health_after <= 0.0:
            events.add(
                "player_death",
                idx,
                f"p{idx} died (health {health_before:.6f}->{health_after:.6f})",
                {
                    "health_before": health_before,
                    "health_after": health_after,
                },
            )


def _validate_player_filter(*, replay: Replay, player_index: int | None) -> int | None:
    if player_index is None:
        return None
    if player_index < 0:
        raise ReplayRunnerError(f"invalid player_index filter: {player_index}")
    if replay.run.player_count > 0 and player_index >= replay.run.player_count:
        raise ReplayRunnerError(
            f"player_index filter out of range: {player_index} (player_count={replay.run.player_count})",
        )
    return player_index


def collect_replay_info(
    driver: PlaybackDriver,
    *,
    player_index: int | None = None,
    include_extra_events: bool = True,
) -> ReplayInfoResult:
    replay = driver.replay
    mode = driver.mode_id
    player_filter = _validate_player_filter(replay=replay, player_index=player_index)
    timeline: list[ReplayInfoTimelineEvent] = []

    def _append_tick(
        tick_result: TickResult,
        *,
        after_players: list[PlayerState],
        perks: PerkCounts,
        before: list[_PlayerSnapshot],
    ) -> None:
        tick_index = int(tick_result.tick_index)
        tick = tick_result.payload
        after = _capture_snapshots(after_players, perks)
        events = _TickEvents(
            timeline=timeline,
            tick_index=tick_index,
            elapsed_ms=int(tick.elapsed_ms),
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )

        if include_extra_events:
            _append_extra_replay_commands(events, replay.ticks[tick_index].commands)
        _append_bonus_pickup_events(events, tick.events.pickups)
        if tick.events.deaths:
            events.add(
                "creature_deaths",
                None,
                f"creature deaths={len(tick.events.deaths)}",
                {"count": len(tick.events.deaths)},
            )
        _append_snapshot_diff_events(
            events,
            before=before,
            after=after,
            violence_disabled=replay.run.violence_disabled,
        )

    class _ReplayInfoWalkObserver(PlaybackWalkObserver):
        before: list[_PlayerSnapshot] | None = None

        def before_tick(self, tick_index: int, world, dt_tick: float) -> None:
            _ = tick_index, dt_tick
            self.before = _capture_snapshots(world.players, world.state.perks)

        def after_tick(self, tick_result: TickResult, world) -> None:
            before_snapshot = self.before
            assert before_snapshot is not None, "missing pre-step replay snapshot"
            _append_tick(tick_result, after_players=world.players, perks=world.state.perks, before=before_snapshot)

    walk_result = driver.walk_ticks(
        observer=_ReplayInfoWalkObserver(),
    )

    return ReplayInfoResult(
        game_mode_id=mode,
        tick_rate=REPLAY_TICK_RATE,
        ticks_simulated=int(walk_result.ticks_completed),
        elapsed_ms=int(driver.elapsed_ms),
        player_count=len(driver.world.players),
        timeline=timeline,
    )


def event_counts_by_kind(timeline: list[ReplayInfoTimelineEvent]) -> dict[str, int]:
    counts: Counter[ReplayInfoEventKind] = Counter()
    for event in timeline:
        counts[event.kind] += 1
    return {str(kind): int(count) for kind, count in sorted(counts.items())}
