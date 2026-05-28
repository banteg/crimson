from __future__ import annotations

import io
from collections.abc import Sequence
from pathlib import Path

import msgspec
import zstandard as zstd

from grim.geom import Vec2

from ..bonuses import BonusId
from ..creatures.runtime import CreatureDeath
from ..game_modes import GameMode
from ..sim.state_types import PlayerState
from ..sim.timing import ftol_ms_i32
from ..sim.world_state import WorldEvents, WorldState
from ..weapons import WeaponId

FORMAT_VERSION = 4
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


class ReplayTypoNameEntry(msgspec.Struct, frozen=True):
    creature_index: int
    name: str


class ReplayTypoSnapshot(msgspec.Struct, frozen=True):
    input_text: str = ""
    submit_count: int = 0
    match_count: int = 0
    spawn_cooldown_ms: int = 0
    active_names: list[ReplayTypoNameEntry] = msgspec.field(default_factory=list)


class ReplayTutorialSnapshot(msgspec.Struct, frozen=True):
    stage_index: int = -1
    stage_timer_ms: int = 0
    stage_transition_timer_ms: int = -1000
    hint_index: int = -1
    hint_alpha: int = 0
    hint_fade_in: bool = False
    repeat_spawn_count: int = 0
    hint_bonus_creature_ref: int | None = None
    prompt_text: str = ""
    prompt_alpha: float = 0.0
    hint_text: str = ""
    hint_alpha_overlay: float = 0.0


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
    deaths: list["ReplayDeathLedgerEntry"] = msgspec.field(default_factory=list)
    perk: "ReplayPerkSnapshot" = msgspec.field(default_factory=lambda: ReplayPerkSnapshot())
    events: "ReplayEventSummary" = msgspec.field(default_factory=lambda: ReplayEventSummary())
    tutorial: ReplayTutorialSnapshot | None = None
    typo: ReplayTypoSnapshot | None = None


class ReplayDeathLedgerEntry(msgspec.Struct, frozen=True):
    creature_index: int
    type_id: int
    reward_value: float
    xp_awarded: int
    owner_id: int = -1


class ReplayHitSummaryEntry(msgspec.Struct, frozen=True):
    type_id: int
    origin: Vec2
    hit: Vec2
    target: Vec2


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
    hit_head: list[ReplayHitSummaryEntry] = msgspec.field(default_factory=list)


class ReplayCheckpoints(msgspec.Struct, frozen=True):
    version: int
    sample_rate: int
    checkpoints: list[ReplayCheckpoint] = msgspec.field(default_factory=list)

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
    deaths: Sequence[CreatureDeath] | None = None,
    events: WorldEvents | None = None,
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
        death_entries.append(
            ReplayDeathLedgerEntry(
                creature_index=int(death.index),
                type_id=int(death.type_id),
                reward_value=float(death.reward_value),
                xp_awarded=int(death.xp_awarded),
                owner_id=int(death.owner.to_legacy()),
            ),
        )

    hits = list(events.hits) if events is not None else []
    pickups = list(events.pickups) if events is not None else []
    sfx = list(events.sfx) if events is not None else []
    event_summary = ReplayEventSummary(
        hit_count=len(hits),
        pickup_count=len(pickups),
        sfx_count=len(sfx),
        sfx_head=[key.value for key in sfx[:4]],
        hit_head=[
            ReplayHitSummaryEntry(
                type_id=int(hit.type_id),
                origin=Vec2(round(hit.origin.x, 4), round(hit.origin.y, 4)),
                hit=Vec2(round(hit.hit.x, 4), round(hit.hit.y, 4)),
                target=Vec2(round(hit.target.x, 4), round(hit.target.y, 4)),
            )
            for hit in hits[:8]
        ],
    )

    typo_snapshot: ReplayTypoSnapshot | None = None
    tutorial_snapshot: ReplayTutorialSnapshot | None = None
    if state.game_mode == GameMode.TUTORIAL:
        tutorial = state.tutorial
        overlay = state.tutorial_overlay
        tutorial_snapshot = ReplayTutorialSnapshot(
            stage_index=int(tutorial.stage_index),
            stage_timer_ms=int(tutorial.stage_timer_ms),
            stage_transition_timer_ms=int(tutorial.stage_transition_timer_ms),
            hint_index=int(tutorial.hint_index),
            hint_alpha=int(tutorial.hint_alpha),
            hint_fade_in=bool(tutorial.hint_fade_in),
            repeat_spawn_count=int(tutorial.repeat_spawn_count),
            hint_bonus_creature_ref=(
                None if tutorial.hint_bonus_creature_ref is None else int(tutorial.hint_bonus_creature_ref)
            ),
            prompt_text=str(overlay.prompt_text),
            prompt_alpha=float(overlay.prompt_alpha),
            hint_text=str(overlay.hint_text),
            hint_alpha_overlay=float(overlay.hint_alpha),
        )
    if state.game_mode == GameMode.TYPO:
        active_mask = [bool(creature.active) for creature in world.creatures.entries]
        active_names = [
            ReplayTypoNameEntry(
                creature_index=int(creature_index),
                name=str(name),
            )
            for creature_index, name in state.typo.names.active_entries(active_mask=active_mask)
        ]
        typo_snapshot = ReplayTypoSnapshot(
            input_text=str(state.typo.typing.text),
            submit_count=int(state.typo.typing.submit_count),
            match_count=int(state.typo.typing.match_count),
            spawn_cooldown_ms=int(state.typo.spawn_cooldown_ms),
            active_names=active_names,
        )

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
        deaths=death_entries,
        perk=perk_snapshot,
        events=event_summary,
        tutorial=tutorial_snapshot,
        typo=typo_snapshot,
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
