from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..bonuses import BonusId
from ..gameplay import PlayerState
from ..sim.world_state import WorldState

FORMAT_VERSION = 1


class ReplayCheckpointsError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReplayPlayerCheckpoint:
    pos_x: float
    pos_y: float
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


def _bonus_timer_ms(value: float) -> int:
    # Keep checkpoint values compact/stable: ms resolution is enough for divergence detection.
    ms = int(round(float(value) * 1000.0))
    if ms < 0:
        return 0
    return ms


def build_checkpoint(
    *,
    tick_index: int,
    world: WorldState,
    elapsed_ms: float,
) -> ReplayCheckpoint:
    state = world.state
    players: list[PlayerState] = list(world.players)
    score_xp = sum(int(player.experience) for player in players)
    kills = int(world.creatures.kill_count)
    creature_count = sum(1 for creature in world.creatures.entries if bool(getattr(creature, "active", False)))

    player_ckpts: list[ReplayPlayerCheckpoint] = []
    for player in players:
        player_ckpts.append(
            ReplayPlayerCheckpoint(
                pos_x=round(float(player.pos_x), 4),
                pos_y=round(float(player.pos_y), 4),
                health=round(float(player.health), 4),
                weapon_id=int(player.weapon_id),
                ammo=round(float(player.ammo), 4),
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

    # Hash a full-ish snapshot for faster comparisons than deep diffs.
    hash_obj = {
        "rng_state": int(state.rng.state),
        "score_xp": int(score_xp),
        "kills": int(kills),
        "perk_pending": int(state.perk_selection.pending_count),
        "players": [asdict(p) for p in player_ckpts],
        "creatures": [
            {
                "type_id": int(getattr(creature, "type_id", 0)),
                "x": round(float(getattr(creature, "x", 0.0)), 4),
                "y": round(float(getattr(creature, "y", 0.0)), 4),
                "hp": round(float(getattr(creature, "hp", 0.0)), 4),
                "active": bool(getattr(creature, "active", False)),
            }
            for creature in world.creatures.entries
            if bool(getattr(creature, "active", False))
        ],
        "bonuses": [
            {
                "bonus_id": int(getattr(bonus, "bonus_id", 0)),
                "pos_x": round(float(getattr(bonus, "pos_x", 0.0)), 4),
                "pos_y": round(float(getattr(bonus, "pos_y", 0.0)), 4),
                "time_left": round(float(getattr(bonus, "time_left", 0.0)), 4),
                "picked": bool(getattr(bonus, "picked", False)),
                "amount": int(getattr(bonus, "amount", 0)),
            }
            for bonus in state.bonus_pool.iter_active()
        ],
        "projectiles": [
            {
                "type_id": int(getattr(proj, "type_id", 0)),
                "x": round(float(getattr(proj, "x", 0.0)), 4),
                "y": round(float(getattr(proj, "y", 0.0)), 4),
                "active": bool(getattr(proj, "active", False)),
            }
            for proj in state.projectiles.entries
            if bool(getattr(proj, "active", False))
        ],
        "bonus_timers": dict(bonus_timers),
    }
    state_hash = hashlib.sha256(json.dumps(hash_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()[:16]

    return ReplayCheckpoint(
        tick_index=int(tick_index),
        rng_state=int(state.rng.state),
        elapsed_ms=int(round(float(elapsed_ms))),
        score_xp=int(score_xp),
        kills=int(kills),
        creature_count=int(creature_count),
        perk_pending=int(state.perk_selection.pending_count),
        players=player_ckpts,
        bonus_timers=bonus_timers,
        state_hash=str(state_hash),
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
            players.append(
                ReplayPlayerCheckpoint(
                    pos_x=float(p.get("pos_x", 0.0)),
                    pos_y=float(p.get("pos_y", 0.0)),
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
