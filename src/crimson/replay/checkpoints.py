from __future__ import annotations

import gzip
import hashlib
import json
import os
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

from grim.geom import Vec2
from ..bonuses import BonusId
from ..gameplay import PlayerState
from ..sim.world_state import WorldState

FORMAT_VERSION = 1


class ReplayCheckpointsError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReplayPlayerCheckpoint:
    pos: Vec2
    health: float
    weapon_id: int
    ammo: float
    experience: int
    level: int


@dataclass(frozen=True, slots=True)
class ReplayCheckpoint:
    tick_index: int
    rng_state: int
    elapsed_ms: int
    score_xp: int
    kills: int
    creature_count: int
    perk_pending: int
    players: list[ReplayPlayerCheckpoint]
    bonus_timers: dict[str, int]
    state_hash: str
    command_hash: str = ""
    rng_marks: dict[str, int] = field(default_factory=dict)
    deaths: list["ReplayDeathLedgerEntry"] = field(default_factory=list)
    perk: "ReplayPerkSnapshot" = field(default_factory=lambda: ReplayPerkSnapshot())
    events: "ReplayEventSummary" = field(default_factory=lambda: ReplayEventSummary())


@dataclass(frozen=True, slots=True)
class ReplayDeathLedgerEntry:
    creature_index: int
    type_id: int
    reward_value: float
    xp_awarded: int
    owner_id: int


@dataclass(frozen=True, slots=True)
class ReplayPerkSnapshot:
    pending_count: int = 0
    choices_dirty: bool = False
    choices: list[int] = field(default_factory=list)
    player_nonzero_counts: list[list[list[int]]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ReplayEventSummary:
    # Legacy sidecars may omit this block; -1 marks "unknown/not recorded".
    hit_count: int = 0
    pickup_count: int = 0
    sfx_count: int = 0
    sfx_head: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ReplayCheckpoints:
    version: int
    replay_sha256: str
    sample_rate: int
    checkpoints: list[ReplayCheckpoint] = field(default_factory=list)


def default_checkpoints_path(replay_path: Path) -> Path:
    replay_path = Path(replay_path)
    name = replay_path.name
    if name.endswith(".crdemo.gz"):
        stem = name[: -len(".crdemo.gz")]
        return replay_path.with_name(f"{stem}.checkpoints.json.gz")
    return replay_path.with_name(f"{name}.checkpoints.json.gz")


def resolve_checkpoint_sample_rate(default_rate: int) -> int:
    rate = max(1, int(default_rate))
    raw = os.environ.get("CRIMSON_REPLAY_CHECKPOINT_SAMPLE_RATE")
    if raw is None:
        return rate
    try:
        return max(1, int(raw))
    except ValueError:
        return rate


def _bonus_timer_ms(value: float) -> int:
    # Keep checkpoint values compact/stable: ms resolution is enough for divergence detection.
    ms = int(round(value * 1000.0))
    if ms < 0:
        return 0
    return ms


def build_checkpoint(
    *,
    tick_index: int,
    world: WorldState,
    elapsed_ms: float,
    rng_marks: dict[str, int] | None = None,
    deaths: Sequence[object] | None = None,
    events: object | None = None,
    command_hash: str | None = None,
) -> ReplayCheckpoint:
    state = world.state
    players: list[PlayerState] = list(world.players)
    score_xp = sum(int(player.experience) for player in players)
    kills = int(world.creatures.kill_count)
    creature_count = sum(1 for creature in world.creatures.entries if creature.active)

    player_ckpts: list[ReplayPlayerCheckpoint] = []
    for player in players:
        player_ckpts.append(
            ReplayPlayerCheckpoint(
                pos=Vec2(round(player.pos.x, 4), round(player.pos.y, 4)),
                health=round(player.health, 4),
                weapon_id=int(player.weapon_id),
                ammo=round(player.ammo, 4),
                experience=int(player.experience),
                level=int(player.level),
            )
        )

    bonus_timers = {
        str(BonusId.WEAPON_POWER_UP): _bonus_timer_ms(state.bonuses.weapon_power_up),
        str(BonusId.REFLEX_BOOST): _bonus_timer_ms(state.bonuses.reflex_boost),
        str(BonusId.ENERGIZER): _bonus_timer_ms(state.bonuses.energizer),
        str(BonusId.DOUBLE_EXPERIENCE): _bonus_timer_ms(state.bonuses.double_experience),
        str(BonusId.FREEZE): _bonus_timer_ms(state.bonuses.freeze),
    }

    perk_counts: list[list[list[int]]] = []
    for player in players:
        nonzero: list[list[int]] = []
        for perk_id, count in enumerate(player.perk_counts):
            count_i = int(count)
            if count_i != 0:
                nonzero.append([int(perk_id), count_i])
        perk_counts.append(nonzero)

    perk_snapshot = ReplayPerkSnapshot(
        pending_count=int(state.perk_selection.pending_count),
        choices_dirty=bool(state.perk_selection.choices_dirty),
        choices=[int(perk_id) for perk_id in state.perk_selection.choices],
        player_nonzero_counts=perk_counts,
    )

    death_entries: list[ReplayDeathLedgerEntry] = []
    for death in deaths or ():
        death_entries.append(
            ReplayDeathLedgerEntry(
                creature_index=int(getattr(death, "index", -1)),
                type_id=int(getattr(death, "type_id", 0)),
                reward_value=float(getattr(death, "reward_value", 0.0)),
                xp_awarded=int(getattr(death, "xp_awarded", 0)),
                owner_id=int(getattr(death, "owner_id", -100)),
            )
        )

    marks: dict[str, int] = {}
    if rng_marks:
        for key, value in rng_marks.items():
            marks[str(key)] = int(value)

    hits = list(getattr(events, "hits", ()) or ())
    pickups = list(getattr(events, "pickups", ()) or ())
    sfx = list(getattr(events, "sfx", ()) or ())
    event_summary = ReplayEventSummary(
        hit_count=int(len(hits)),
        pickup_count=int(len(pickups)),
        sfx_count=int(len(sfx)),
        sfx_head=[str(key) for key in sfx[:4]],
    )

    # Hash a full-ish snapshot for faster comparisons than deep diffs.
    hash_obj = {
        "rng_state": int(state.rng.state),
        "score_xp": int(score_xp),
        "kills": int(kills),
        "perk_pending": int(state.perk_selection.pending_count),
        "players": [asdict(p) for p in player_ckpts],
        "creatures": [
            {
                "type_id": int(creature.type_id),
                **creature.pos.to_dict(ndigits=4),
                "hp": round(creature.hp, 4),
                "active": bool(creature.active),
            }
            for creature in world.creatures.entries
            if creature.active
        ],
        "bonuses": [
            {
                "bonus_id": int(bonus.bonus_id),
                "pos": bonus.pos.to_dict(ndigits=4),
                "time_left": round(bonus.time_left, 4),
                "picked": bool(bonus.picked),
                "amount": int(bonus.amount),
            }
            for bonus in state.bonus_pool.iter_active()
        ],
        "projectiles": [
            {
                "type_id": int(proj.type_id),
                "x": round(proj.pos.x, 4),
                "y": round(proj.pos.y, 4),
                "active": bool(proj.active),
            }
            for proj in state.projectiles.entries
            if proj.active
        ],
        "bonus_timers": dict(bonus_timers),
    }
    state_hash = hashlib.sha256(
        json.dumps(hash_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]

    return ReplayCheckpoint(
        tick_index=int(tick_index),
        rng_state=int(state.rng.state),
        elapsed_ms=int(round(elapsed_ms)),
        score_xp=int(score_xp),
        kills=int(kills),
        creature_count=int(creature_count),
        perk_pending=int(state.perk_selection.pending_count),
        players=player_ckpts,
        bonus_timers=bonus_timers,
        state_hash=str(state_hash),
        command_hash=str(command_hash or ""),
        rng_marks=marks,
        deaths=death_entries,
        perk=perk_snapshot,
        events=event_summary,
    )


def dump_checkpoints(checkpoints: ReplayCheckpoints) -> bytes:
    obj = {
        "v": int(checkpoints.version),
        "replay_sha256": str(checkpoints.replay_sha256),
        "sample_rate": int(checkpoints.sample_rate),
        "checkpoints": [asdict(ckpt) for ckpt in checkpoints.checkpoints],
    }
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return gzip.compress(raw, compresslevel=9, mtime=0)


def load_checkpoints(data: bytes) -> ReplayCheckpoints:
    if data.startswith(b"\x1f\x8b"):
        data = gzip.decompress(data)
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ReplayCheckpointsError("checkpoints root must be an object")
    version = int(obj.get("v", 0))
    if version != FORMAT_VERSION:
        raise ReplayCheckpointsError(f"unsupported checkpoints version: {version}")
    replay_sha256 = str(obj.get("replay_sha256", ""))
    sample_rate = int(obj.get("sample_rate", 0) or 0)
    raw_ckpts = obj.get("checkpoints") or []
    if not isinstance(raw_ckpts, list):
        raise ReplayCheckpointsError("checkpoints must be a list")

    checkpoints: list[ReplayCheckpoint] = []
    for item in raw_ckpts:
        if not isinstance(item, dict):
            raise ReplayCheckpointsError(f"checkpoint must be an object: {item!r}")
        players_in = item.get("players") or []
        if not isinstance(players_in, list):
            raise ReplayCheckpointsError("checkpoint players must be a list")
        players: list[ReplayPlayerCheckpoint] = []
        for p in players_in:
            if not isinstance(p, dict):
                raise ReplayCheckpointsError(f"checkpoint player must be an object: {p!r}")
            pos_raw = p.get("pos")
            if not isinstance(pos_raw, dict):
                raise ReplayCheckpointsError("checkpoint player pos must be an object")
            px = float(pos_raw.get("x", 0.0))
            py = float(pos_raw.get("y", 0.0))
            players.append(
                ReplayPlayerCheckpoint(
                    pos=Vec2(px, py),
                    health=float(p.get("health", 0.0)),
                    weapon_id=int(p.get("weapon_id", 0)),
                    ammo=float(p.get("ammo", 0.0)),
                    experience=int(p.get("experience", 0)),
                    level=int(p.get("level", 0)),
                )
            )
        bonus_timers_in = item.get("bonus_timers") or {}
        if not isinstance(bonus_timers_in, dict):
            raise ReplayCheckpointsError("checkpoint bonus_timers must be an object")

        rng_marks_in = item.get("rng_marks") or {}
        if not isinstance(rng_marks_in, dict):
            raise ReplayCheckpointsError("checkpoint rng_marks must be an object")

        deaths_in = item.get("deaths") or []
        if not isinstance(deaths_in, list):
            raise ReplayCheckpointsError("checkpoint deaths must be a list")
        deaths: list[ReplayDeathLedgerEntry] = []
        for death in deaths_in:
            if not isinstance(death, dict):
                raise ReplayCheckpointsError(f"checkpoint death must be an object: {death!r}")
            deaths.append(
                ReplayDeathLedgerEntry(
                    creature_index=int(death.get("creature_index", -1)),
                    type_id=int(death.get("type_id", 0)),
                    reward_value=float(death.get("reward_value", 0.0)),
                    xp_awarded=int(death.get("xp_awarded", 0)),
                    owner_id=int(death.get("owner_id", -100)),
                )
            )

        perk_in = item.get("perk")
        if perk_in is None:
            perk = ReplayPerkSnapshot(pending_count=int(item.get("perk_pending", 0)))
        else:
            if not isinstance(perk_in, dict):
                raise ReplayCheckpointsError("checkpoint perk must be an object")
            raw_choices = perk_in.get("choices") or []
            if not isinstance(raw_choices, list):
                raise ReplayCheckpointsError("checkpoint perk choices must be a list")
            raw_nonzero = perk_in.get("player_nonzero_counts") or []
            if not isinstance(raw_nonzero, list):
                raise ReplayCheckpointsError("checkpoint perk player_nonzero_counts must be a list")
            player_nonzero_counts: list[list[list[int]]] = []
            for player_counts in raw_nonzero:
                if not isinstance(player_counts, list):
                    raise ReplayCheckpointsError("checkpoint perk player counts must be a list")
                rows: list[list[int]] = []
                for row in player_counts:
                    if not isinstance(row, list):
                        raise ReplayCheckpointsError("checkpoint perk row must be a list")
                    if len(row) < 2:
                        raise ReplayCheckpointsError("checkpoint perk row must have [perk_id, count]")
                    rows.append([int(row[0]), int(row[1])])
                player_nonzero_counts.append(rows)
            perk = ReplayPerkSnapshot(
                pending_count=int(perk_in.get("pending_count", item.get("perk_pending", 0))),
                choices_dirty=bool(perk_in.get("choices_dirty", False)),
                choices=[int(perk_id) for perk_id in raw_choices],
                player_nonzero_counts=player_nonzero_counts,
            )

        events_in = item.get("events")
        if events_in is None:
            events = ReplayEventSummary(
                hit_count=-1,
                pickup_count=-1,
                sfx_count=-1,
                sfx_head=[],
            )
        else:
            if not isinstance(events_in, dict):
                raise ReplayCheckpointsError("checkpoint events must be an object")
            raw_sfx_head = events_in.get("sfx_head") or []
            if not isinstance(raw_sfx_head, list):
                raise ReplayCheckpointsError("checkpoint events sfx_head must be a list")
            events = ReplayEventSummary(
                hit_count=int(events_in.get("hit_count", 0)),
                pickup_count=int(events_in.get("pickup_count", 0)),
                sfx_count=int(events_in.get("sfx_count", 0)),
                sfx_head=[str(key) for key in raw_sfx_head],
            )

        checkpoints.append(
            ReplayCheckpoint(
                tick_index=int(item.get("tick_index", 0)),
                rng_state=int(item.get("rng_state", 0)),
                elapsed_ms=int(item.get("elapsed_ms", 0)),
                score_xp=int(item.get("score_xp", 0)),
                kills=int(item.get("kills", 0)),
                creature_count=int(item.get("creature_count", 0)),
                perk_pending=int(item.get("perk_pending", 0)),
                players=players,
                bonus_timers={str(k): int(v) for k, v in bonus_timers_in.items()},
                state_hash=str(item.get("state_hash", "")),
                command_hash=str(item.get("command_hash", "")),
                rng_marks={str(k): int(v) for k, v in rng_marks_in.items()},
                deaths=deaths,
                perk=perk,
                events=events,
            )
        )

    return ReplayCheckpoints(
        version=version,
        replay_sha256=replay_sha256,
        sample_rate=sample_rate,
        checkpoints=checkpoints,
    )


def dump_checkpoints_file(path: Path, checkpoints: ReplayCheckpoints) -> None:
    Path(path).write_bytes(dump_checkpoints(checkpoints))


def load_checkpoints_file(path: Path) -> ReplayCheckpoints:
    return load_checkpoints(Path(path).read_bytes())
