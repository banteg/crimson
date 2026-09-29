from __future__ import annotations

import math
from collections.abc import Sequence
from pathlib import Path

import msgspec

from grim.atomic_write import atomic_write_bytes

from ..bonuses import BonusId
from ..creatures.runtime import CreatureDeath
from ..game_modes import GameMode
from ..math_parity import f32
from ..sim.state_types import PlayerState
from ..sim.timing import nearest_ms_i32
from ..sim.world_state import WorldEvents, WorldState
from ..weapons import WeaponId
from .codec import zstd_pack, zstd_unpack

FORMAT_VERSION = 5
DEFAULT_CHECKPOINT_SAMPLE_RATE = 1
MAX_CHECKPOINTS_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_CHECKPOINTS_FILE_BYTES = 257 * 1024 * 1024


class ReplayCheckpointsError(ValueError):
    pass


class ReplayCheckpointVec2(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    x: float
    y: float


class ReplayPlayerCheckpoint(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    pos: ReplayCheckpointVec2
    health: float
    weapon_id: WeaponId
    ammo: float
    experience: int
    level: int


class ReplayTypoNameEntry(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    creature_index: int
    name: str


class ReplayTypoSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    input_text: str
    submit_count: int
    match_count: int
    spawn_cooldown_ms: int
    active_names: list[ReplayTypoNameEntry]


class ReplayTutorialSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    stage_index: int
    stage_timer_ms: int
    stage_transition_timer_ms: int
    hint_index: int
    hint_alpha: int
    hint_fade_in: bool
    repeat_spawn_count: int
    hint_bonus_creature_ref: int | None
    prompt_text: str
    prompt_alpha: float
    hint_text: str
    hint_alpha_overlay: float


class ReplayCheckpoint(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_index: int
    rng_state: int
    elapsed_ms: int
    score_xp: int
    kills: int
    creature_count: int
    perk_pending: int
    players: list[ReplayPlayerCheckpoint]
    bonus_timers: dict[str, int]
    deaths: list[ReplayDeathLedgerEntry]
    perk: ReplayPerkSnapshot
    events: ReplayEventSummary
    tutorial: ReplayTutorialSnapshot | None
    typo: ReplayTypoSnapshot | None


class ReplayDeathLedgerEntry(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    creature_index: int
    type_id: int
    reward_value: float
    xp_awarded: int
    owner_id: int


class ReplayHitSummaryEntry(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    type_id: int
    origin: ReplayCheckpointVec2
    hit: ReplayCheckpointVec2
    target: ReplayCheckpointVec2


class ReplayPerkSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    pending_count: int
    choices_dirty: bool
    choices: list[int]
    player_nonzero_counts: list[list[list[int]]]


class ReplayEventSummary(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    hit_count: int
    pickup_count: int
    sfx_count: int
    sfx_head: list[str]
    hit_head: list[ReplayHitSummaryEntry]


class ReplayCheckpoints(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    version: int
    sample_rate: int
    checkpoints: list[ReplayCheckpoint]


_CHECKPOINTS_ENCODER = msgspec.msgpack.Encoder()
_CHECKPOINTS_DECODER = msgspec.msgpack.Decoder(type=ReplayCheckpoints)


def default_checkpoints_path(replay_path: Path) -> Path:
    replay_path = Path(replay_path)
    return replay_path.with_name(f"{replay_path.name}.chk")


def _bonus_timer_ms(value: float) -> int:
    # Keep checkpoint values compact/stable: ms resolution is enough for divergence detection.
    ms = nearest_ms_i32(value)
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
                pos=ReplayCheckpointVec2(float(player.pos.x), float(player.pos.y)),
                health=float(player.health),
                weapon_id=WeaponId(player.weapon.weapon_id),
                ammo=float(player.weapon.ammo),
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

    # The perk table lives in player one's struct natively; other players' tables stay zero.
    perk_counts: list[list[list[int]]] = [
        [[perk_id, count] for perk_id, count in enumerate(state.perks.counts) if count] if index == 0 else []
        for index in range(len(players))
    ]

    perk_choices = [int(perk_id) for perk_id in state.perk_selection.choices]
    if len(perk_choices) > 7:
        raise ValueError(f"perk selection contains {len(perk_choices)} choices, expected at most 7")
    perk_choices.extend([0] * (7 - len(perk_choices)))
    perk_snapshot = ReplayPerkSnapshot(
        pending_count=int(state.perk_selection.pending_count),
        choices_dirty=bool(state.perk_selection.choices_dirty),
        choices=perk_choices,
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
        hit_count=len(hits) + (int(events.secondary_hit_count) if events is not None else 0),
        pickup_count=len(pickups),
        sfx_count=len(sfx),
        sfx_head=[request.sfx_id.value for request in sfx[:4]],
        hit_head=[
            ReplayHitSummaryEntry(
                type_id=int(hit.type_id),
                origin=ReplayCheckpointVec2(float(hit.origin.x), float(hit.origin.y)),
                hit=ReplayCheckpointVec2(float(hit.hit.x), float(hit.hit.y)),
                target=ReplayCheckpointVec2(float(hit.target.x), float(hit.target.y)),
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


def _canonical_f32(value: float, *, field: str) -> float:
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ReplayCheckpointsError(f"{field} must be a finite f32")
    try:
        return f32(numeric)
    except (OverflowError, ValueError) as exc:
        raise ReplayCheckpointsError(f"{field} must be a finite f32") from exc


def _canonical_vec2(
    value: ReplayCheckpointVec2,
    *,
    field: str,
) -> ReplayCheckpointVec2:
    return ReplayCheckpointVec2(
        _canonical_f32(value.x, field=f"{field}.x"),
        _canonical_f32(value.y, field=f"{field}.y"),
    )


def _canonical_checkpoint(checkpoint: ReplayCheckpoint) -> ReplayCheckpoint:
    players = [
        msgspec.structs.replace(
            player,
            pos=_canonical_vec2(
                player.pos,
                field=f"checkpoint.players[{index}].pos",
            ),
            health=_canonical_f32(
                player.health,
                field=f"checkpoint.players[{index}].health",
            ),
            ammo=_canonical_f32(
                player.ammo,
                field=f"checkpoint.players[{index}].ammo",
            ),
        )
        for index, player in enumerate(checkpoint.players)
    ]
    deaths = [
        msgspec.structs.replace(
            death,
            reward_value=_canonical_f32(
                death.reward_value,
                field=f"checkpoint.deaths[{index}].reward_value",
            ),
        )
        for index, death in enumerate(checkpoint.deaths)
    ]
    hit_head = [
        msgspec.structs.replace(
            hit,
            origin=_canonical_vec2(
                hit.origin,
                field=f"checkpoint.events.hit_head[{index}].origin",
            ),
            hit=_canonical_vec2(
                hit.hit,
                field=f"checkpoint.events.hit_head[{index}].hit",
            ),
            target=_canonical_vec2(
                hit.target,
                field=f"checkpoint.events.hit_head[{index}].target",
            ),
        )
        for index, hit in enumerate(checkpoint.events.hit_head)
    ]
    events = msgspec.structs.replace(checkpoint.events, hit_head=hit_head)
    tutorial = checkpoint.tutorial
    if tutorial is not None:
        tutorial = msgspec.structs.replace(
            tutorial,
            prompt_alpha=_canonical_f32(
                tutorial.prompt_alpha,
                field="checkpoint.tutorial.prompt_alpha",
            ),
            hint_alpha_overlay=_canonical_f32(
                tutorial.hint_alpha_overlay,
                field="checkpoint.tutorial.hint_alpha_overlay",
            ),
        )
    return msgspec.structs.replace(
        checkpoint,
        players=players,
        deaths=deaths,
        events=events,
        tutorial=tutorial,
    )


def _require_i32(value: int, *, field: str) -> int:
    integer = int(value)
    if not (-(1 << 31) <= integer <= (1 << 31) - 1):
        raise ReplayCheckpointsError(f"{field} must fit i32")
    return integer


def _validate_checkpoint_integer_widths(checkpoint: ReplayCheckpoint, *, index: int) -> None:
    prefix = f"checkpoints[{index}]"
    if not (0 <= int(checkpoint.rng_state) <= 0xFFFFFFFF):
        raise ReplayCheckpointsError(f"{prefix}.rng_state must be a uint32")
    for field in ("tick_index", "elapsed_ms", "score_xp", "kills", "creature_count", "perk_pending"):
        value = _require_i32(getattr(checkpoint, field), field=f"{prefix}.{field}")
        if value < 0:
            raise ReplayCheckpointsError(f"{prefix}.{field} must be non-negative")
    for key, value in checkpoint.bonus_timers.items():
        _require_i32(value, field=f"{prefix}.bonus_timers[{key!r}]")
    for player_index, player in enumerate(checkpoint.players):
        for field in ("weapon_id", "experience", "level"):
            _require_i32(getattr(player, field), field=f"{prefix}.players[{player_index}].{field}")
    for death_index, death in enumerate(checkpoint.deaths):
        for field in ("creature_index", "type_id", "xp_awarded", "owner_id"):
            _require_i32(getattr(death, field), field=f"{prefix}.deaths[{death_index}].{field}")
    _require_i32(checkpoint.perk.pending_count, field=f"{prefix}.perk.pending_count")
    for choice_index, choice in enumerate(checkpoint.perk.choices):
        _require_i32(choice, field=f"{prefix}.perk.choices[{choice_index}]")
    for player_index, rows in enumerate(checkpoint.perk.player_nonzero_counts):
        for row_index, row in enumerate(rows):
            for value_index, value in enumerate(row):
                _require_i32(
                    value,
                    field=f"{prefix}.perk.player_nonzero_counts[{player_index}][{row_index}][{value_index}]",
                )
    for field in ("hit_count", "pickup_count", "sfx_count"):
        _require_i32(getattr(checkpoint.events, field), field=f"{prefix}.events.{field}")
    for hit_index, hit in enumerate(checkpoint.events.hit_head):
        _require_i32(hit.type_id, field=f"{prefix}.events.hit_head[{hit_index}].type_id")
    if checkpoint.tutorial is not None:
        tutorial = checkpoint.tutorial
        for field in (
            "stage_index",
            "stage_timer_ms",
            "stage_transition_timer_ms",
            "hint_index",
            "hint_alpha",
            "repeat_spawn_count",
        ):
            _require_i32(getattr(tutorial, field), field=f"{prefix}.tutorial.{field}")
        if tutorial.hint_bonus_creature_ref is not None:
            _require_i32(
                tutorial.hint_bonus_creature_ref,
                field=f"{prefix}.tutorial.hint_bonus_creature_ref",
            )
    if checkpoint.typo is not None:
        typo = checkpoint.typo
        for field in ("submit_count", "match_count", "spawn_cooldown_ms"):
            _require_i32(getattr(typo, field), field=f"{prefix}.typo.{field}")
        for name_index, entry in enumerate(typo.active_names):
            _require_i32(entry.creature_index, field=f"{prefix}.typo.active_names[{name_index}].creature_index")


def _validate_and_canonicalize(checkpoints: ReplayCheckpoints) -> ReplayCheckpoints:
    _require_i32(checkpoints.version, field="checkpoints.version")
    _require_i32(checkpoints.sample_rate, field="checkpoints.sample_rate")
    if int(checkpoints.version) != FORMAT_VERSION:
        raise ReplayCheckpointsError(f"unsupported checkpoints version: {int(checkpoints.version)}")
    if int(checkpoints.sample_rate) <= 0:
        raise ReplayCheckpointsError("checkpoints sample_rate must be positive")
    if not checkpoints.checkpoints:
        raise ReplayCheckpointsError("checkpoints must contain at least one row")
    canonical = [
        _canonical_checkpoint(checkpoint) for checkpoint in checkpoints.checkpoints
    ]
    previous_tick: int | None = None
    for index, checkpoint in enumerate(canonical):
        _validate_checkpoint_integer_widths(checkpoint, index=index)
        tick = int(checkpoint.tick_index)
        if tick < 0:
            raise ReplayCheckpointsError(f"checkpoints[{index}].tick_index must be non-negative")
        if previous_tick is not None and tick <= previous_tick:
            raise ReplayCheckpointsError("checkpoint tick indices must be strictly increasing and unique")
        if not checkpoint.players:
            raise ReplayCheckpointsError(f"checkpoints[{index}].players must be non-empty")
        if len(checkpoint.perk.choices) != 7:
            raise ReplayCheckpointsError(f"checkpoints[{index}].perk.choices must contain exactly 7 slots")
        if int(checkpoint.perk_pending) != int(checkpoint.perk.pending_count):
            raise ReplayCheckpointsError(
                f"checkpoints[{index}].perk_pending must equal perk.pending_count",
            )
        previous_tick = tick
    return msgspec.structs.replace(checkpoints, checkpoints=canonical)


def dump_checkpoints(checkpoints: ReplayCheckpoints) -> bytes:
    try:
        decoded = _CHECKPOINTS_DECODER.decode(_CHECKPOINTS_ENCODER.encode(checkpoints))
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCheckpointsError("invalid checkpoints payload for the current schema") from exc
    return zstd_pack(_CHECKPOINTS_ENCODER.encode(_validate_and_canonicalize(decoded)))


def load_checkpoints(data: bytes) -> ReplayCheckpoints:
    """Load a sidecar that is exactly what `dump_checkpoints` writes.

    Re-encoding the validated checkpoints must reproduce the payload byte for byte, which rejects floats that are
    not canonical f32 or were encoded as integers, reordered or duplicate keys and non-minimal encodings.
    """

    payload = zstd_unpack(
        data,
        what="checkpoints",
        max_file_bytes=MAX_CHECKPOINTS_FILE_BYTES,
        max_payload_bytes=MAX_CHECKPOINTS_PAYLOAD_BYTES,
        error=ReplayCheckpointsError,
    )
    try:
        decoded = _CHECKPOINTS_DECODER.decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCheckpointsError("invalid checkpoints msgpack payload") from exc
    checkpoints = _validate_and_canonicalize(decoded)
    if _CHECKPOINTS_ENCODER.encode(checkpoints) != payload:
        raise ReplayCheckpointsError("checkpoints payload is not canonically encoded")
    return checkpoints


def dump_checkpoints_file(path: Path, checkpoints: ReplayCheckpoints) -> None:
    atomic_write_bytes(Path(path), dump_checkpoints(checkpoints))


def load_checkpoints_file(path: Path) -> ReplayCheckpoints:
    return load_checkpoints(Path(path).read_bytes())
