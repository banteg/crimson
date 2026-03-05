from __future__ import annotations

import hashlib
import io
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, cast

import msgspec
import zstandard as zstd

from grim.geom import Vec2

from ..bonuses import BonusId
from ..owner_ref import OwnerRef
from ..sim.state_types import PlayerState
from ..sim.timing import ftol_ms_i32
from ..sim.world_state import WorldState
from ..weapons import WeaponId


class _DeathLike(Protocol):
    index: int
    type_id: int
    reward_value: float
    xp_awarded: int
    owner: OwnerRef


class _EventsLike(Protocol):
    hits: Sequence[object]
    pickups: list[object]
    sfx: list[str]

FORMAT_VERSION = 2
DEFAULT_CHECKPOINT_SAMPLE_RATE = 1
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_DEFAULT_MAX_CHECKPOINTS_PAYLOAD_BYTES = 256 * 1024 * 1024
_CHECKPOINTS_ZSTD_LEVEL = 19


class ReplayCheckpointsError(ValueError):
    pass


class ReplayPlayerCheckpoint(msgspec.Struct, frozen=True):
    pos: Vec2
    health: float
    weapon_id: WeaponId
    ammo: float
    experience: int
    level: int

class ReplayCheckpoint(msgspec.Struct, frozen=True):
    tick_index: int
    rng_state: int
    elapsed_ms: int
    score_xp: int
    kills: int
    creature_count: int
    perk_pending: int
    players: list[ReplayPlayerCheckpoint]
    bonus_timers: dict[str, int]
    state_hash: str = ""
    rng_marks: dict[str, int] = msgspec.field(default_factory=dict)
    deaths: list["ReplayDeathLedgerEntry"] = msgspec.field(default_factory=list)
    perk: "ReplayPerkSnapshot" = msgspec.field(default_factory=lambda: ReplayPerkSnapshot())
    events: "ReplayEventSummary" = msgspec.field(default_factory=lambda: ReplayEventSummary())


class ReplayDeathLedgerEntry(msgspec.Struct, frozen=True):
    creature_index: int
    type_id: int
    reward_value: float
    xp_awarded: int
    owner: OwnerRef


class ReplayPerkSnapshot(msgspec.Struct, frozen=True):
    pending_count: int = 0
    choices_dirty: bool = False
    choices: list[int] = msgspec.field(default_factory=list)
    player_nonzero_counts: list[list[list[int]]] = msgspec.field(default_factory=list)


class ReplayEventSummary(msgspec.Struct, frozen=True):
    # Legacy sidecars may omit this block; -1 marks "unknown/not recorded".
    hit_count: int = 0
    pickup_count: int = 0
    sfx_count: int = 0
    sfx_head: list[str] = msgspec.field(default_factory=list)


class ReplayCheckpoints(msgspec.Struct, frozen=True):
    version: int
    replay_sha256: str
    sample_rate: int
    checkpoints: list[ReplayCheckpoint] = msgspec.field(default_factory=list)


def _replay_player_checkpoint_to_obj(player: ReplayPlayerCheckpoint) -> dict[str, object]:
    return {
        "pos": {"x": float(player.pos.x), "y": float(player.pos.y)},
        "health": float(player.health),
        "weapon_id": int(player.weapon_id),
        "ammo": float(player.ammo),
        "experience": int(player.experience),
        "level": int(player.level),
    }


_CHECKPOINTS_ENCODER = msgspec.msgpack.Encoder()
_CHECKPOINTS_DECODER = msgspec.msgpack.Decoder(type=ReplayCheckpoints)


def default_checkpoints_path(replay_path: Path) -> Path:
    replay_path = Path(replay_path)
    return replay_path.with_name(f"{replay_path.name}.chk")


def _is_zstd(data: bytes) -> bool:
    return bytes(data).startswith(_ZSTD_MAGIC)


def _decompress_zstd_checkpoints(data: bytes, *, max_output_bytes: int) -> bytes:
    try:
        with zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)) as stream:
            payload = stream.read(int(max_output_bytes) + 1)
    except zstd.ZstdError as exc:
        raise ReplayCheckpointsError("invalid checkpoints zstd payload") from exc
    if len(payload) > int(max_output_bytes):
        raise ReplayCheckpointsError(
            f"checkpoints payload too large after zstd decompression (> {int(max_output_bytes)} bytes)",
        )
    return payload


def _bonus_timer_ms(value: float) -> int:
    # Keep checkpoint values compact/stable: ms resolution is enough for divergence detection.
    ms = int(ftol_ms_i32(float(value)))
    if ms < 0:
        return 0
    return ms


def build_checkpoint(
    *,
    tick_index: int,
    world: WorldState,
    elapsed_ms: float,
    creature_count_override: int | None = None,
    rng_marks: dict[str, int] | None = None,
    deaths: Sequence[object] | None = None,
    events: object | None = None,
) -> ReplayCheckpoint:
    state = world.state
    players: list[PlayerState] = list(world.players)
    score_xp = sum(int(player.experience) for player in players)
    kills = int(world.creatures.kill_count)
    if creature_count_override is None:
        creature_count = sum(1 for creature in world.creatures.entries if creature.active)
    else:
        creature_count = int(creature_count_override)

    player_ckpts: list[ReplayPlayerCheckpoint] = []
    for player in players:
        player_ckpts.append(
            ReplayPlayerCheckpoint(
                pos=Vec2(round(player.pos.x, 4), round(player.pos.y, 4)),
                health=round(player.health, 4),
                weapon_id=WeaponId(player.weapon.weapon_id),
                ammo=round(player.weapon.ammo, 4),
                experience=int(player.experience),
                level=int(player.level),
            ),
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
        death_view = cast(_DeathLike, death)
        death_entries.append(
            ReplayDeathLedgerEntry(
                creature_index=int(death_view.index),
                type_id=int(death_view.type_id),
                reward_value=float(death_view.reward_value),
                xp_awarded=int(death_view.xp_awarded),
                owner=death_view.owner,
            ),
        )

    marks: dict[str, int] = {}
    if rng_marks:
        for key, value in rng_marks.items():
            marks[str(key)] = int(value)

    events_view = cast(_EventsLike | None, events)
    hits = list(events_view.hits) if events_view is not None else []
    pickups = list(events_view.pickups) if events_view is not None else []
    sfx = list(events_view.sfx) if events_view is not None else []
    event_summary = ReplayEventSummary(
        hit_count=len(hits),
        pickup_count=len(pickups),
        sfx_count=len(sfx),
        sfx_head=[str(key) for key in sfx[:4]],
    )

    # Hash a full-ish snapshot for faster comparisons than deep diffs.
    hash_obj = {
        "rng_state": int(state.rng.state),
        "score_xp": int(score_xp),
        "kills": int(kills),
        "perk_pending": int(state.perk_selection.pending_count),
        "players": [_replay_player_checkpoint_to_obj(player) for player in player_ckpts],
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
        msgspec.msgpack.encode(hash_obj),
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
        rng_marks=marks,
        deaths=death_entries,
        perk=perk_snapshot,
        events=event_summary,
    )


def dump_checkpoints(checkpoints: ReplayCheckpoints) -> bytes:
    raw = _CHECKPOINTS_ENCODER.encode(checkpoints)
    return zstd.ZstdCompressor(level=_CHECKPOINTS_ZSTD_LEVEL).compress(raw)


def load_checkpoints(data: bytes) -> ReplayCheckpoints:
    max_payload_bytes = int(_DEFAULT_MAX_CHECKPOINTS_PAYLOAD_BYTES)
    payload = bytes(data)
    if _is_zstd(payload):
        payload = _decompress_zstd_checkpoints(payload, max_output_bytes=max_payload_bytes)
    if len(payload) > int(max_payload_bytes):
        raise ReplayCheckpointsError(f"checkpoints payload too large (> {int(max_payload_bytes)} bytes)")
    try:
        decoded = _CHECKPOINTS_DECODER.decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCheckpointsError("invalid checkpoints msgpack payload") from exc

    if int(decoded.version) != FORMAT_VERSION:
        raise ReplayCheckpointsError(f"unsupported checkpoints version: {int(decoded.version)}")
    return decoded


def dump_checkpoints_file(path: Path, checkpoints: ReplayCheckpoints) -> None:
    Path(path).write_bytes(dump_checkpoints(checkpoints))


def load_checkpoints_file(path: Path) -> ReplayCheckpoints:
    return load_checkpoints(Path(path).read_bytes())
