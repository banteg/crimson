from __future__ import annotations

from collections import Counter
from typing import Literal, TypeAlias

import msgspec

from ...bonuses.ids import BonusId, bonus_display_name
from ...game_modes import GameMode
from ...perks.ids import PerkId, perk_display_name
from ...replay import Replay
from ...weapons import WeaponId, weapon_display_name
from ..input_providers import GameCommand, PerkMenuOpenCommand
from ..state_types import BonusPickupEvent, PlayerState
from .playback_driver import (
    PlaybackDriver,
    PlaybackDriverConfig,
    PlaybackDriverOptions,
    PlaybackSessionConfigs,
    PlaybackSessionDefaults,
    PlaybackTickOutcome,
    PlaybackTimingConfig,
    QuestSessionConfig,
    RushSessionConfig,
    SurvivalSessionConfig,
)
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
                health=float(player.health),
                level=int(player.level),
                experience=int(player.experience),
                weapon_id=player.weapon.weapon_id,
                perk_counts=tuple(int(value) for value in player.perk_counts),
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
    if kind not in _CORE_EVENT_KINDS and not bool(include_extra_events):
        return
    if player_filter is not None and player_index is not None and int(player_index) != int(player_filter):
        return
    timeline.append(
        ReplayInfoTimelineEvent(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            kind=kind,
            player_index=(None if player_index is None else int(player_index)),
            detail=str(detail),
            data=dict(data),
        ),
    )


def _append_extra_replay_commands(
    *,
    commands: list[GameCommand],
    tick_index: int,
    elapsed_ms: int,
    timeline: list[ReplayInfoTimelineEvent],
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    if not bool(include_extra_events):
        return
    for cmd in commands:
        if isinstance(cmd, PerkMenuOpenCommand):
            player_idx = int(cmd.player_index)
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="perk_menu_open",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} perk menu opened",
                data={"player_index": int(player_idx)},
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
        player_idx = int(pickup.player_index)
        bonus_id = pickup.bonus_id
        amount = int(pickup.amount)
        bonus_name = bonus_display_name(bonus_id, preserve_bugs=bool(preserve_bugs))
        detail = f"p{int(player_idx)} picked {str(bonus_name)} ({int(bonus_id)}) amount={int(amount)}"
        data: dict[str, object] = {
            "bonus_id": int(bonus_id),
            "bonus_name": str(bonus_name),
            "amount": int(amount),
        }
        if bonus_id == BonusId.WEAPON:
            weapon_id = WeaponId(amount)
            weapon_name = weapon_display_name(weapon_id, preserve_bugs=bool(preserve_bugs))
            detail += f" -> {str(weapon_name)}"
            data["weapon_id"] = weapon_id
            data["weapon_name"] = str(weapon_name)
        _append_event(
            timeline,
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            kind="bonus_pickup",
            player_index=int(player_idx),
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
    gore_disabled: int,
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    players_len = min(len(before), len(after))
    for idx in range(players_len):
        pre = before[idx]
        post = after[idx]
        player_idx = int(idx)

        if pre.weapon_id != post.weapon_id:
            weapon_before_name = weapon_display_name(pre.weapon_id, preserve_bugs=bool(preserve_bugs))
            weapon_after_name = weapon_display_name(post.weapon_id, preserve_bugs=bool(preserve_bugs))
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="weapon_change",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} weapon {weapon_before_name} -> {weapon_after_name}",
                data={
                    "weapon_id_before": pre.weapon_id,
                    "weapon_name_before": str(weapon_before_name),
                    "weapon_id_after": post.weapon_id,
                    "weapon_name_after": str(weapon_after_name),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        if int(post.level) > int(pre.level):
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="level_up",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} level {int(pre.level)} -> {int(post.level)} (xp={int(post.experience)})",
                data={
                    "level_before": int(pre.level),
                    "level_after": int(post.level),
                    "xp": int(post.experience),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        perk_len = min(len(pre.perk_counts), len(post.perk_counts))
        for perk_id in range(perk_len):
            before_count = int(pre.perk_counts[perk_id])
            after_count = int(post.perk_counts[perk_id])
            if int(after_count) <= int(before_count):
                continue
            perk_name = perk_display_name(
                PerkId(perk_id),
                gore_disabled=int(gore_disabled),
                preserve_bugs=bool(preserve_bugs),
            )
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="perk_pick",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} perk {str(perk_name)} ({int(perk_id)}) x{int(after_count)}",
                data={
                    "perk_id": int(perk_id),
                    "perk_name": str(perk_name),
                    "count_before": int(before_count),
                    "count_after": int(after_count),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        health_before = float(pre.health)
        health_after = float(post.health)
        if float(health_after) < float(health_before) - float(_EPSILON):
            amount = float(health_before) - float(health_after)
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="health_damage",
                player_index=int(player_idx),
                detail=(
                    f"p{int(player_idx)} damage {float(amount):.6f} "
                    f"(health {float(health_before):.6f}->{float(health_after):.6f})"
                ),
                data={
                    "amount": float(amount),
                    "health_before": float(health_before),
                    "health_after": float(health_after),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )
        elif float(health_after) > float(health_before) + float(_EPSILON):
            amount = float(health_after) - float(health_before)
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="health_heal",
                player_index=int(player_idx),
                detail=(
                    f"p{int(player_idx)} heal {float(amount):.6f} "
                    f"(health {float(health_before):.6f}->{float(health_after):.6f})"
                ),
                data={
                    "amount": float(amount),
                    "health_before": float(health_before),
                    "health_after": float(health_after),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        if float(health_before) > 0.0 and float(health_after) <= 0.0:
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="player_death",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} died (health {float(health_before):.6f}->{float(health_after):.6f})",
                data={
                    "health_before": float(health_before),
                    "health_after": float(health_after),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )


def _validate_player_filter(*, replay: Replay, player_index: int | None) -> int | None:
    if player_index is None:
        return None
    idx = int(player_index)
    if int(idx) < 0:
        raise ReplayRunnerError(f"invalid player_index filter: {player_index}")
    player_count = int(replay.header.player_count)
    if int(player_count) > 0 and int(idx) >= int(player_count):
        raise ReplayRunnerError(
            f"player_index filter out of range: {player_index} (player_count={int(player_count)})",
        )
    return int(idx)


def _run_replay_info(
    replay: Replay,
    *,
    max_ticks: int | None,
    player_filter: int | None,
    include_extra_events: bool,
) -> ReplayInfoResult:
    mode_raw = int(replay.header.game_mode_id)
    try:
        mode = GameMode(mode_raw)
    except ValueError as exc:
        raise ReplayRunnerError(f"unsupported replay game_mode_id={mode_raw}") from exc

    options = PlaybackDriverOptions(
        max_ticks=max_ticks,
        trace_rng=False,
        version_mismatch_action="verification",
    )
    config = PlaybackDriverConfig(
        timing=PlaybackTimingConfig(),
        session_defaults=PlaybackSessionDefaults(
            clear_fx_queues_each_tick=True,
            game_tune_started=False,
        ),
        sessions=PlaybackSessionConfigs(
            survival=SurvivalSessionConfig(),
            rush=RushSessionConfig(
                enforce_loadout=True,
            ),
            quest=QuestSessionConfig(
                disable_capture_spawn_events_authoritative=True,
                finalize_post_render_lifecycle_each_tick=True,
                result_uses_spawn_timeline_ms=True,
            ),
        ),
    )
    driver = PlaybackDriver(replay, options, config=config)

    timeline: list[ReplayInfoTimelineEvent] = []
    before_snapshots: list[_PlayerSnapshot] | None = None

    def _on_tick_begin(
        tick_index: int,
        world,
        dt_tick: float,
    ) -> None:
        _ = tick_index, dt_tick
        nonlocal before_snapshots
        before_snapshots = _capture_snapshots(world.players)

    def _on_tick_end(outcome: PlaybackTickOutcome) -> None:
        nonlocal before_snapshots
        before = before_snapshots if before_snapshots is not None else _capture_snapshots(outcome.world.players)
        after = _capture_snapshots(outcome.world.players)
        before_snapshots = None

        elapsed_ms = int(outcome.elapsed_ms)
        if mode != GameMode.RUSH:
            _append_extra_replay_commands(
                commands=outcome.commands,
                tick_index=int(outcome.tick_index),
                elapsed_ms=int(elapsed_ms),
                timeline=timeline,
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        _append_bonus_pickup_events(
            tick_index=int(outcome.tick_index),
            elapsed_ms=int(elapsed_ms),
            timeline=timeline,
            pickups=outcome.step_events.pickups,
            preserve_bugs=bool(replay.header.preserve_bugs),
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )

        if len(outcome.step_events.deaths) > 0:
            _append_event(
                timeline,
                tick_index=int(outcome.tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="creature_deaths",
                player_index=None,
                detail=f"creature deaths={len(outcome.step_events.deaths)}",
                data={"count": len(outcome.step_events.deaths)},
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        _append_snapshot_diff_events(
            tick_index=int(outcome.tick_index),
            elapsed_ms=int(elapsed_ms),
            before=before,
            after=after,
            timeline=timeline,
            preserve_bugs=bool(replay.header.preserve_bugs),
            gore_disabled=int(replay.header.gore_disabled),
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )

    run_result = driver.run_to_completion(
        tick_begin_observer=_on_tick_begin,
        tick_end_observer=_on_tick_end,
    )

    return ReplayInfoResult(
        game_mode_id=mode,
        tick_rate=int(replay.header.tick_rate),
        ticks_simulated=int(driver.tick_limit),
        elapsed_ms=int(run_result.elapsed_ms),
        player_count=len(driver.world.players),
        timeline=timeline,
    )


def run_replay_info(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    player_index: int | None = None,
    include_extra_events: bool = True,
) -> ReplayInfoResult:
    player_filter = _validate_player_filter(replay=replay, player_index=player_index)
    return _run_replay_info(
        replay,
        max_ticks=max_ticks,
        player_filter=player_filter,
        include_extra_events=bool(include_extra_events),
    )


def event_counts_by_kind(timeline: list[ReplayInfoTimelineEvent]) -> dict[str, int]:
    counts: Counter[ReplayInfoEventKind] = Counter()
    for event in timeline:
        counts[event.kind] += 1
    return {str(kind): int(count) for kind, count in sorted(counts.items())}
