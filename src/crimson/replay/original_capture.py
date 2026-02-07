from __future__ import annotations

"""Schema + conversion helpers for original-game differential sidecars."""

import gzip
import json
from dataclasses import dataclass, field
from pathlib import Path

from grim.geom import Vec2

from .checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoint,
    ReplayCheckpoints,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)

ORIGINAL_CAPTURE_FORMAT_VERSION = 1


class OriginalCaptureError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OriginalCaptureTick:
    tick_index: int
    state_hash: str
    command_hash: str
    rng_state: int = 0
    elapsed_ms: int = 0
    score_xp: int = 0
    kills: int = 0
    creature_count: int = 0
    perk_pending: int = 0
    players: list[ReplayPlayerCheckpoint] = field(default_factory=list)
    bonus_timers: dict[str, int] = field(default_factory=dict)
    rng_marks: dict[str, int] = field(default_factory=dict)
    deaths: list[ReplayDeathLedgerEntry] = field(default_factory=list)
    perk: ReplayPerkSnapshot = field(default_factory=ReplayPerkSnapshot)
    events: ReplayEventSummary = field(
        default_factory=lambda: ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1)
    )


@dataclass(frozen=True, slots=True)
class OriginalCaptureSidecar:
    version: int
    sample_rate: int
    ticks: list[OriginalCaptureTick]
    replay_sha256: str = ""


def _parse_player(raw: object) -> ReplayPlayerCheckpoint:
    if not isinstance(raw, dict):
        raise OriginalCaptureError(f"player must be an object: {raw!r}")
    pos_raw = raw.get("pos") or {}
    if not isinstance(pos_raw, dict):
        raise OriginalCaptureError("player.pos must be an object")
    return ReplayPlayerCheckpoint(
        pos=Vec2(float(pos_raw.get("x", 0.0)), float(pos_raw.get("y", 0.0))),
        health=float(raw.get("health", 0.0)),
        weapon_id=int(raw.get("weapon_id", 0)),
        ammo=float(raw.get("ammo", 0.0)),
        experience=int(raw.get("experience", 0)),
        level=int(raw.get("level", 0)),
    )


def _parse_death(raw: object) -> ReplayDeathLedgerEntry:
    if not isinstance(raw, dict):
        raise OriginalCaptureError(f"death entry must be an object: {raw!r}")
    return ReplayDeathLedgerEntry(
        creature_index=int(raw.get("creature_index", -1)),
        type_id=int(raw.get("type_id", 0)),
        reward_value=float(raw.get("reward_value", 0.0)),
        xp_awarded=int(raw.get("xp_awarded", 0)),
        owner_id=int(raw.get("owner_id", -100)),
    )


def _parse_perk(raw: object) -> ReplayPerkSnapshot:
    if not isinstance(raw, dict):
        return ReplayPerkSnapshot()
    raw_choices = raw.get("choices") or []
    raw_counts = raw.get("player_nonzero_counts") or []
    choices = [int(value) for value in raw_choices] if isinstance(raw_choices, list) else []

    player_nonzero_counts: list[list[list[int]]] = []
    if isinstance(raw_counts, list):
        for player_counts in raw_counts:
            if not isinstance(player_counts, list):
                player_nonzero_counts.append([])
                continue
            parsed_player: list[list[int]] = []
            for pair in player_counts:
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    parsed_player.append([int(pair[0]), int(pair[1])])
            player_nonzero_counts.append(parsed_player)

    return ReplayPerkSnapshot(
        pending_count=int(raw.get("pending_count", 0)),
        choices_dirty=bool(raw.get("choices_dirty", False)),
        choices=choices,
        player_nonzero_counts=player_nonzero_counts,
    )


def _parse_events(raw: object) -> ReplayEventSummary:
    if raw is None:
        return ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1, sfx_head=[])
    if not isinstance(raw, dict):
        raise OriginalCaptureError("events must be an object")
    sfx_head_raw = raw.get("sfx_head") or []
    if not isinstance(sfx_head_raw, list):
        raise OriginalCaptureError("events.sfx_head must be a list")
    return ReplayEventSummary(
        hit_count=int(raw.get("hit_count", -1)),
        pickup_count=int(raw.get("pickup_count", -1)),
        sfx_count=int(raw.get("sfx_count", -1)),
        sfx_head=[str(value) for value in sfx_head_raw[:4]],
    )


def _parse_tick(raw: object) -> OriginalCaptureTick:
    if not isinstance(raw, dict):
        raise OriginalCaptureError(f"tick must be an object: {raw!r}")

    players_raw = raw.get("players") or []
    if not isinstance(players_raw, list):
        raise OriginalCaptureError("tick.players must be a list")
    players = [_parse_player(item) for item in players_raw]

    deaths_raw = raw.get("deaths") or []
    if not isinstance(deaths_raw, list):
        raise OriginalCaptureError("tick.deaths must be a list")
    deaths = [_parse_death(item) for item in deaths_raw]

    bonus_timers_raw = raw.get("bonus_timers") or {}
    if not isinstance(bonus_timers_raw, dict):
        raise OriginalCaptureError("tick.bonus_timers must be an object")
    bonus_timers = {str(key): int(value) for key, value in bonus_timers_raw.items()}

    rng_marks_raw = raw.get("rng_marks") or {}
    if not isinstance(rng_marks_raw, dict):
        raise OriginalCaptureError("tick.rng_marks must be an object")
    rng_marks = {str(key): int(value) for key, value in rng_marks_raw.items()}

    return OriginalCaptureTick(
        tick_index=int(raw.get("tick_index", 0)),
        state_hash=str(raw.get("state_hash", "")),
        command_hash=str(raw.get("command_hash", "")),
        rng_state=int(raw.get("rng_state", 0)),
        elapsed_ms=int(raw.get("elapsed_ms", 0)),
        score_xp=int(raw.get("score_xp", 0)),
        kills=int(raw.get("kills", 0)),
        creature_count=int(raw.get("creature_count", 0)),
        perk_pending=int(raw.get("perk_pending", 0)),
        players=players,
        bonus_timers=bonus_timers,
        rng_marks=rng_marks,
        deaths=deaths,
        perk=_parse_perk(raw.get("perk")),
        events=_parse_events(raw.get("events")),
    )


def load_original_capture_sidecar(path: Path) -> OriginalCaptureSidecar:
    raw = Path(path).read_bytes()
    if raw.startswith(b"\x1f\x8b"):
        raw = gzip.decompress(raw)
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise OriginalCaptureError("original capture root must be an object")

    version = int(obj.get("v", 0))
    if version != ORIGINAL_CAPTURE_FORMAT_VERSION:
        raise OriginalCaptureError(f"unsupported original capture version: {version}")

    ticks_raw = obj.get("ticks") or []
    if not isinstance(ticks_raw, list):
        raise OriginalCaptureError("original capture ticks must be a list")
    ticks = [_parse_tick(item) for item in ticks_raw]
    sample_rate = max(1, int(obj.get("sample_rate", 1)))

    return OriginalCaptureSidecar(
        version=version,
        sample_rate=sample_rate,
        ticks=ticks,
        replay_sha256=str(obj.get("replay_sha256", "")),
    )


def convert_original_capture_to_checkpoints(
    capture: OriginalCaptureSidecar,
    *,
    replay_sha256: str = "",
) -> ReplayCheckpoints:
    checkpoints: list[ReplayCheckpoint] = []
    for tick in capture.ticks:
        checkpoints.append(
            ReplayCheckpoint(
                tick_index=int(tick.tick_index),
                rng_state=int(tick.rng_state),
                elapsed_ms=int(tick.elapsed_ms),
                score_xp=int(tick.score_xp),
                kills=int(tick.kills),
                creature_count=int(tick.creature_count),
                perk_pending=int(tick.perk_pending),
                players=list(tick.players),
                bonus_timers=dict(tick.bonus_timers),
                state_hash=str(tick.state_hash),
                command_hash=str(tick.command_hash),
                rng_marks=dict(tick.rng_marks),
                deaths=list(tick.deaths),
                perk=tick.perk,
                events=tick.events,
            )
        )

    return ReplayCheckpoints(
        version=FORMAT_VERSION,
        replay_sha256=str(replay_sha256 or capture.replay_sha256),
        sample_rate=max(1, int(capture.sample_rate)),
        checkpoints=checkpoints,
    )
