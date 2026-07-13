from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Literal, TypeAlias

import msgspec

from ...bonuses.ids import BonusId, bonus_display_name
from ...game_modes import GameMode
from ...perks.ids import PerkId, perk_display_name
from ...replay import Replay
from ...sim.hooks import TickResult
from ...sim.input_providers import (
    GameFrameRngAdvanceOperation,
    PerkMenuOpenCommand,
    TypoBackspaceCommand,
    TypoCharCommand,
    TypoSubmitCommand,
)
from ...sim.state_types import BonusPickupEvent, PlayerState
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
    "game_frame_rng_advance",
    "typo_backspace",
    "typo_char",
    "typo_submit",
]
ReplayInfoEventKind: TypeAlias = ReplayInfoCoreEventKind | ReplayInfoExtraEventKind

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


def _capture_snapshots(players: list[PlayerState]) -> list[_PlayerSnapshot]:
    snapshots: list[_PlayerSnapshot] = []
    for player in players:
        snapshots.append(
            _PlayerSnapshot(
                health=player.health,
                level=player.level,
                experience=player.experience,
                weapon_id=player.weapon.weapon_id,
                perk_counts=tuple(player.perk_counts),
            ),
        )
    return snapshots


def _append_event(
    timeline: list[ReplayInfoTimelineEvent],
    *,
    tick_index: int,
    elapsed_ms: int,
    kind: ReplayInfoEventKind,
    player_index: int | None,
    detail: str,
    data: dict[str, object],
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    if kind not in _CORE_EVENT_KINDS and not include_extra_events:
        return
    if player_filter is not None and player_index is not None and player_index != player_filter:
        return
    timeline.append(
        ReplayInfoTimelineEvent(
            tick_index=tick_index,
            elapsed_ms=elapsed_ms,
            kind=kind,
            player_index=player_index,
            detail=detail,
            data=data,
        ),
    )


def _append_extra_replay_commands(
    *,
    commands: Sequence[object],
    tick_index: int,
    elapsed_ms: int,
    timeline: list[ReplayInfoTimelineEvent],
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    if not include_extra_events:
        return
    for cmd in commands:
        if isinstance(cmd, GameFrameRngAdvanceOperation):
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="game_frame_rng_advance",
                player_index=None,
                detail=f"replay advanced {cmd.frames} native frame RNG side effect(s)",
                data={"frames": cmd.frames},
                player_filter=player_filter,
                include_extra_events=True,
            )
        elif isinstance(cmd, PerkMenuOpenCommand):
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="perk_menu_open",
                player_index=cmd.player_index,
                detail=f"p{cmd.player_index} perk menu opened",
                data={"player_index": cmd.player_index},
                player_filter=player_filter,
                include_extra_events=True,
            )
        elif isinstance(cmd, TypoCharCommand):
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="typo_char",
                player_index=cmd.player_index,
                detail=f"p{cmd.player_index} typed '{cmd.ch}'",
                data={"player_index": cmd.player_index, "ch": cmd.ch},
                player_filter=player_filter,
                include_extra_events=True,
            )
        elif isinstance(cmd, TypoBackspaceCommand):
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="typo_backspace",
                player_index=cmd.player_index,
                detail=f"p{cmd.player_index} typo backspace",
                data={"player_index": cmd.player_index},
                player_filter=player_filter,
                include_extra_events=True,
            )
        elif isinstance(cmd, TypoSubmitCommand):
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="typo_submit",
                player_index=cmd.player_index,
                detail=f"p{cmd.player_index} typo submit",
                data={"player_index": cmd.player_index},
                player_filter=player_filter,
                include_extra_events=True,
            )


def _append_bonus_pickup_events(
    *,
    tick_index: int,
    elapsed_ms: int,
    timeline: list[ReplayInfoTimelineEvent],
    pickups: list[BonusPickupEvent],
    preserve_bugs: bool,
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    for pickup in pickups:
        bonus_id = pickup.bonus_id
        bonus_name = bonus_display_name(bonus_id, preserve_bugs=preserve_bugs)
        detail = f"p{pickup.player_index} picked {bonus_name} ({bonus_id}) amount={pickup.amount}"
        data: dict[str, object] = {
            "bonus_id": bonus_id,
            "bonus_name": bonus_name,
            "amount": pickup.amount,
        }
        if bonus_id == BonusId.WEAPON:
            weapon_id = WeaponId(pickup.amount)
            weapon_name = weapon_display_name(weapon_id, preserve_bugs=preserve_bugs)
            detail += f" -> {weapon_name}"
            data["weapon_id"] = weapon_id
            data["weapon_name"] = weapon_name
        _append_event(
            timeline,
            tick_index=tick_index,
            elapsed_ms=elapsed_ms,
            kind="bonus_pickup",
            player_index=pickup.player_index,
            detail=detail,
            data=data,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )


def _append_snapshot_diff_events(
    *,
    tick_index: int,
    elapsed_ms: int,
    before: list[_PlayerSnapshot],
    after: list[_PlayerSnapshot],
    timeline: list[ReplayInfoTimelineEvent],
    preserve_bugs: bool,
    violence_disabled: int,
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    players_len = min(len(before), len(after))
    for idx in range(players_len):
        pre = before[idx]
        post = after[idx]

        if pre.weapon_id != post.weapon_id:
            weapon_before_name = weapon_display_name(pre.weapon_id, preserve_bugs=preserve_bugs)
            weapon_after_name = weapon_display_name(post.weapon_id, preserve_bugs=preserve_bugs)
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="weapon_change",
                player_index=idx,
                detail=f"p{idx} weapon {weapon_before_name} -> {weapon_after_name}",
                data={
                    "weapon_id_before": pre.weapon_id,
                    "weapon_name_before": weapon_before_name,
                    "weapon_id_after": post.weapon_id,
                    "weapon_name_after": weapon_after_name,
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        if post.level > pre.level:
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="level_up",
                player_index=idx,
                detail=f"p{idx} level {pre.level} -> {post.level} (xp={post.experience})",
                data={
                    "level_before": pre.level,
                    "level_after": post.level,
                    "xp": post.experience,
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
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
                preserve_bugs=preserve_bugs,
            )
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="perk_pick",
                player_index=idx,
                detail=f"p{idx} perk {perk_name} ({perk_id}) x{after_count}",
                data={
                    "perk_id": perk_id,
                    "perk_name": perk_name,
                    "count_before": before_count,
                    "count_after": after_count,
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        health_before = pre.health
        health_after = post.health
        if health_after < health_before - _EPSILON:
            amount = health_before - health_after
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="health_damage",
                player_index=idx,
                detail=f"p{idx} damage {amount:.6f} (health {health_before:.6f}->{health_after:.6f})",
                data={
                    "amount": amount,
                    "health_before": health_before,
                    "health_after": health_after,
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )
        elif health_after > health_before + _EPSILON:
            amount = health_after - health_before
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="health_heal",
                player_index=idx,
                detail=f"p{idx} heal {amount:.6f} (health {health_before:.6f}->{health_after:.6f})",
                data={
                    "amount": amount,
                    "health_before": health_before,
                    "health_after": health_after,
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        if health_before > 0.0 and health_after <= 0.0:
            _append_event(
                timeline,
                tick_index=tick_index,
                elapsed_ms=elapsed_ms,
                kind="player_death",
                player_index=idx,
                detail=f"p{idx} died (health {health_before:.6f}->{health_after:.6f})",
                data={
                    "health_before": health_before,
                    "health_after": health_after,
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )


def _validate_player_filter(*, replay: Replay, player_index: int | None) -> int | None:
    if player_index is None:
        return None
    if player_index < 0:
        raise ReplayRunnerError(f"invalid player_index filter: {player_index}")
    if replay.header.player_count > 0 and player_index >= replay.header.player_count:
        raise ReplayRunnerError(
            f"player_index filter out of range: {player_index} (player_count={replay.header.player_count})",
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
        before: list[_PlayerSnapshot],
    ) -> None:
        source_tick = tick_result.source_tick
        tick = tick_result.payload
        after = _capture_snapshots(after_players)

        elapsed_ms = int(tick.elapsed_ms)
        _append_extra_replay_commands(
            commands=(*source_tick.prelude, *source_tick.commands),
            tick_index=int(source_tick.tick_index),
            elapsed_ms=elapsed_ms,
            timeline=timeline,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )

        _append_bonus_pickup_events(
            tick_index=int(source_tick.tick_index),
            elapsed_ms=elapsed_ms,
            timeline=timeline,
            pickups=tick.step.events.pickups,
            preserve_bugs=replay.header.preserve_bugs,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )

        if tick.step.events.deaths:
            _append_event(
                timeline,
                tick_index=int(source_tick.tick_index),
                elapsed_ms=elapsed_ms,
                kind="creature_deaths",
                player_index=None,
                detail=f"creature deaths={len(tick.step.events.deaths)}",
                data={"count": len(tick.step.events.deaths)},
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        _append_snapshot_diff_events(
            tick_index=int(source_tick.tick_index),
            elapsed_ms=elapsed_ms,
            before=before,
            after=after,
            timeline=timeline,
            preserve_bugs=replay.header.preserve_bugs,
            violence_disabled=replay.header.violence_disabled,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )

        _append_extra_replay_commands(
            commands=source_tick.postlude,
            tick_index=int(source_tick.tick_index),
            elapsed_ms=elapsed_ms,
            timeline=timeline,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )

    class _ReplayInfoWalkObserver(PlaybackWalkObserver):
        before: list[_PlayerSnapshot] | None = None

        def before_tick(self, tick_index: int, world, dt_tick: float) -> None:
            _ = tick_index, dt_tick
            self.before = _capture_snapshots(world.players)

        def after_tick(self, tick_result: TickResult, world) -> None:
            before_snapshot = self.before
            assert before_snapshot is not None, "missing pre-step replay snapshot"
            _append_tick(tick_result, after_players=world.players, before=before_snapshot)

    walk_result = driver.walk_ticks(
        observer=_ReplayInfoWalkObserver(),
    )
    run_result = driver.build_run_result(ticks=int(walk_result.ticks_completed))

    return ReplayInfoResult(
        game_mode_id=mode,
        tick_rate=replay.header.tick_rate,
        ticks_simulated=int(walk_result.ticks_completed),
        elapsed_ms=int(run_result.elapsed_ms),
        player_count=len(driver.world.players),
        timeline=timeline,
    )


def event_counts_by_kind(timeline: list[ReplayInfoTimelineEvent]) -> dict[str, int]:
    counts: Counter[ReplayInfoEventKind] = Counter()
    for event in timeline:
        counts[event.kind] += 1
    return {str(kind): int(count) for kind, count in sorted(counts.items())}
