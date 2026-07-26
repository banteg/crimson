from __future__ import annotations

from typing import cast

import msgspec
import pytest
import zstandard as zstd

import crimson.replay.checkpoints as replay_checkpoints_mod
from crimson.bonuses.ids import BonusId
from crimson.creatures.runtime import CreatureDeath
from crimson.creatures.spawn_ids import CreatureTypeId
from crimson.game_modes import GameMode
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.replay.checkpoints import (
    DEFAULT_CHECKPOINT_SAMPLE_RATE,
    FORMAT_VERSION,
    ReplayCheckpoints,
    ReplayCheckpointsError,
    ReplayTypoNameEntry,
    build_checkpoint,
    dump_checkpoints,
    load_checkpoints,
)
from crimson.sim.state_types import BonusPickupEvent
from crimson.sim.world_state import WorldEvents, WorldState
from crimson.typo.state import reset_typo_state
from grim.sfx_map import SfxId


def _wire(value: object) -> bytes:
    return zstd.ZstdCompressor(level=19).compress(msgspec.msgpack.encode(value))


def test_checkpoints_codec_roundtrip_is_stable(base_world: WorldState) -> None:
    world = base_world
    player = world.players[0]
    player.experience = 123
    player.level = 2
    player.perk_counts[1] = 1
    world.state.perk_selection.pending_count = 1
    world.state.perk_selection.choices_dirty = False
    world.state.perk_selection.choices = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.FASTLOADER,
    ]
    ckpt = build_checkpoint(tick_index=0, world=world, elapsed_ms=0.0)
    checkpoints = ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=60, checkpoints=[ckpt])

    data0 = dump_checkpoints(checkpoints)
    data1 = dump_checkpoints(checkpoints)
    assert data0 == data1

    decoded = load_checkpoints(data0)
    assert decoded == checkpoints
    assert decoded.checkpoints[0].perk.choices == [
        int(PerkId.BLOODY_MESS_QUICK_LEARNER),
        int(PerkId.SHARPSHOOTER),
        int(PerkId.FASTLOADER),
        0,
        0,
        0,
        0,
    ]


def test_checkpoints_codec_roundtrip_preserves_debug_fields(base_world: WorldState) -> None:
    world = base_world
    world.state.perk_selection.pending_count = 2
    world.state.perk_selection.choices_dirty = False
    world.state.perk_selection.choices = [
        PerkId.INSTANT_WINNER,
        PerkId.PLAGUEBEARER,
        PerkId.POISON_BULLETS,
    ]
    world.players[0].perk_counts[7] = 2

    ckpt = build_checkpoint(
        tick_index=15,
        world=world,
        elapsed_ms=250.0,
        deaths=[
            CreatureDeath(
                index=33,
                pos=world.players[0].pos,
                type_id=CreatureTypeId.ZOMBIE,
                reward_value=75.0,
                xp_awarded=10,
                owner=OwnerRef.from_player(0),
            ),
        ],
        events=WorldEvents(
            hits=[
                ProjectileHit(
                    type_id=ProjectileTemplateId.PISTOL,
                    origin=world.players[0].pos,
                    hit=world.players[0].pos,
                    target=world.players[0].pos,
                )
                for _ in range(2)
            ],
            secondary_hit_count=1,
            deaths=(),
            pickups=[
                BonusPickupEvent(
                    player_index=0,
                    bonus_id=BonusId.POINTS,
                    amount=1,
                    pos=world.players[0].pos,
                ),
            ],
            sfx=[
                SfxId.UI_BONUS,
                SfxId.UI_BUTTONCLICK,
                SfxId.UI_PANELCLICK,
                SfxId.UI_TYPEENTER,
                SfxId.UI_CLINK_01,
            ],
        ),
    )
    checkpoints = ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[ckpt])
    decoded = load_checkpoints(dump_checkpoints(checkpoints))
    assert decoded == checkpoints
    assert decoded.checkpoints[0].deaths[0].owner_id == -1
    assert decoded.checkpoints[0].events.hit_count == 3
    assert len(decoded.checkpoints[0].events.hit_head) == 2
    assert decoded.checkpoints[0].events.hit_head[0].type_id == int(ProjectileTemplateId.PISTOL)


def test_load_checkpoints_rejects_missing_current_checkpoint_fields() -> None:
    payload_obj = {
        "version": FORMAT_VERSION,
        "sample_rate": 60,
        "checkpoints": [
            {
                "tick_index": 10,
                "rng_state": 20,
                "elapsed_ms": 300,
                "score_xp": 40,
                "kills": 2,
                "creature_count": 3,
                "perk_pending": 4,
                "players": [],
                "bonus_timers": {},
            },
        ],
    }
    with pytest.raises(ReplayCheckpointsError, match="invalid checkpoints msgpack payload"):
        load_checkpoints(_wire(payload_obj))


def test_load_checkpoints_rejects_missing_death_owner_id() -> None:
    payload_obj = {
        "version": FORMAT_VERSION,
        "sample_rate": 60,
        "checkpoints": [
            {
                "tick_index": 10,
                "rng_state": 20,
                "elapsed_ms": 300,
                "score_xp": 40,
                "kills": 2,
                "creature_count": 3,
                "perk_pending": 0,
                "players": [],
                "bonus_timers": {},
                "deaths": [
                    {
                        "creature_index": 5,
                        "type_id": 2,
                        "reward_value": 75.0,
                        "xp_awarded": 10,
                    },
                ],
                "perk": {
                    "pending_count": 0,
                    "choices_dirty": False,
                    "choices": [],
                    "player_nonzero_counts": [],
                },
                "events": {
                    "hit_count": 0,
                    "pickup_count": 0,
                    "sfx_count": 0,
                    "sfx_head": [],
                    "hit_head": [],
                },
                "tutorial": None,
                "typo": None,
            },
        ],
    }
    with pytest.raises(ReplayCheckpointsError, match="invalid checkpoints msgpack payload"):
        load_checkpoints(_wire(payload_obj))


def test_build_checkpoint_captures_typo_sidecar(base_world: WorldState) -> None:
    world = base_world
    world.state.game_mode = GameMode.TYPO
    reset_typo_state(
        world.state.typo,
        creature_capacity=len(world.creatures.entries),
        dictionary_words=("amber", "onyx"),
    )
    world.state.typo.typing.text = "alpha"
    world.state.typo.typing.submit_count = 3
    world.state.typo.typing.match_count = 2
    world.state.typo.spawn_cooldown_ms = 777
    world.creatures.entries[4].active = True
    world.state.typo.names.names[4] = "alpha"

    ckpt = build_checkpoint(tick_index=7, world=world, elapsed_ms=500.0)

    assert ckpt.typo is not None
    assert ckpt.typo.input_text == "alpha"
    assert ckpt.typo.submit_count == 3
    assert ckpt.typo.match_count == 2
    assert ckpt.typo.spawn_cooldown_ms == 777
    assert ckpt.typo.active_names == [ReplayTypoNameEntry(creature_index=4, name="alpha")]


def test_load_checkpoints_rejects_invalid_msgpack_payload() -> None:
    with pytest.raises(ReplayCheckpointsError, match="invalid checkpoints msgpack payload"):
        load_checkpoints(zstd.ZstdCompressor().compress(b"\x81\xa7version\xc3"))


def test_load_checkpoints_rejects_invalid_zstd_payload() -> None:
    with pytest.raises(ReplayCheckpointsError, match="invalid checkpoints zstd payload"):
        load_checkpoints(b"\x28\xb5\x2f\xfdnot-a-zstd-stream")


@pytest.mark.parametrize(
    "suffix",
    [b"trailing-garbage", zstd.ZstdCompressor().compress(b"second-frame")],
)
def test_load_checkpoints_rejects_data_after_zstd_frame(base_world: WorldState, suffix: bytes) -> None:
    checkpoint = build_checkpoint(tick_index=0, world=base_world, elapsed_ms=0)
    checkpoints = ReplayCheckpoints(
        version=FORMAT_VERSION,
        sample_rate=1,
        checkpoints=[checkpoint],
    )
    with pytest.raises(ReplayCheckpointsError, match="invalid checkpoints zstd payload"):
        load_checkpoints(dump_checkpoints(checkpoints) + suffix)


@pytest.mark.parametrize("sample_rate", [0, -1])
def test_checkpoints_reject_nonpositive_sample_rate(base_world: WorldState, sample_rate: int) -> None:
    checkpoint = build_checkpoint(tick_index=0, world=base_world, elapsed_ms=0)
    payload = ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=sample_rate, checkpoints=[checkpoint])

    with pytest.raises(ReplayCheckpointsError, match="sample_rate must be positive"):
        dump_checkpoints(payload)


def test_checkpoints_reject_empty_rows() -> None:
    payload = ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[])

    with pytest.raises(ReplayCheckpointsError, match="at least one row"):
        dump_checkpoints(payload)


def test_checkpoints_reject_duplicate_or_out_of_order_ticks(base_world: WorldState) -> None:
    checkpoint = build_checkpoint(tick_index=1, world=base_world, elapsed_ms=16)
    duplicate = ReplayCheckpoints(
        version=FORMAT_VERSION,
        sample_rate=1,
        checkpoints=[checkpoint, checkpoint],
    )

    with pytest.raises(ReplayCheckpointsError, match="strictly increasing and unique"):
        dump_checkpoints(duplicate)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("rng_state", -1, "uint32"),
        ("rng_state", 1 << 32, "uint32"),
        ("elapsed_ms", 1 << 31, "fit i32"),
        ("score_xp", 1 << 31, "fit i32"),
        ("kills", -1, "non-negative"),
    ],
)
def test_checkpoints_reject_values_outside_native_wire(
    base_world: WorldState,
    field: str,
    value: int,
    message: str,
) -> None:
    checkpoint = build_checkpoint(tick_index=0, world=base_world, elapsed_ms=0)
    checkpoint = msgspec.structs.replace(checkpoint, **{field: value})
    payload = ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[checkpoint])

    with pytest.raises(ReplayCheckpointsError, match=message):
        dump_checkpoints(payload)


def test_load_checkpoints_rejects_raw_msgpack_payload() -> None:
    with pytest.raises(ReplayCheckpointsError, match="canonical zstd envelope"):
        load_checkpoints(msgspec.msgpack.encode({"version": FORMAT_VERSION}))


def test_load_checkpoints_rejects_noncanonical_f32(base_world: WorldState) -> None:
    checkpoint = build_checkpoint(tick_index=0, world=base_world, elapsed_ms=0)
    player = msgspec.structs.replace(checkpoint.players[0], health=0.123456789123)
    checkpoint = msgspec.structs.replace(checkpoint, players=[player])
    payload = ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[checkpoint])

    with pytest.raises(ReplayCheckpointsError, match="health must be canonical f32"):
        load_checkpoints(_wire(payload))


@pytest.mark.parametrize(
    "path",
    [
        ("players", 0, "pos", "x"),
        ("players", 0, "health"),
        ("players", 0, "ammo"),
        ("deaths", 0, "reward_value"),
        ("events", "hit_head", 0, "origin", "x"),
        ("events", "hit_head", 0, "hit", "y"),
        ("events", "hit_head", 0, "target", "x"),
        ("tutorial", "prompt_alpha"),
        ("tutorial", "hint_alpha_overlay"),
    ],
)
def test_load_checkpoints_rejects_integer_tokens_for_f32_fields(
    base_world: WorldState,
    path: tuple[str | int, ...],
) -> None:
    base_world.state.game_mode = GameMode.TUTORIAL
    checkpoint = build_checkpoint(
        tick_index=0,
        world=base_world,
        elapsed_ms=0,
        deaths=[
            CreatureDeath(
                index=1,
                pos=base_world.players[0].pos,
                type_id=CreatureTypeId.ZOMBIE,
                reward_value=1.0,
                xp_awarded=1,
                owner=OwnerRef.from_player(0),
            ),
        ],
        events=WorldEvents(
            hits=[
                ProjectileHit(
                    type_id=ProjectileTemplateId.PISTOL,
                    origin=base_world.players[0].pos,
                    hit=base_world.players[0].pos,
                    target=base_world.players[0].pos,
                ),
            ],
            deaths=(),
            pickups=[],
            sfx=[],
        ),
    )
    encoded = dump_checkpoints(ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[checkpoint]))
    root = cast("dict[str, object]", msgspec.msgpack.decode(zstd.ZstdDecompressor().decompress(encoded)))
    row = cast("dict[str, object]", cast("list[object]", root["checkpoints"])[0])
    current: object = row
    for segment in path[:-1]:
        if isinstance(segment, int):
            assert isinstance(current, list)
            current = current[segment]
        else:
            assert isinstance(current, dict)
            current = cast("dict[str, object]", current)[segment]
    leaf = path[-1]
    if isinstance(leaf, int):
        assert isinstance(current, list)
        cast("list[object]", current)[leaf] = 0
    else:
        assert isinstance(current, dict)
        cast("dict[str, object]", current)[leaf] = 0

    with pytest.raises(ReplayCheckpointsError, match="msgpack float"):
        load_checkpoints(_wire(root))


def test_checkpoints_require_fixed_perk_slots_and_matching_pending(base_world: WorldState) -> None:
    checkpoint = build_checkpoint(tick_index=0, world=base_world, elapsed_ms=0)
    short_perk = msgspec.structs.replace(checkpoint.perk, choices=[1, 2, 3])
    short = msgspec.structs.replace(checkpoint, perk=short_perk)
    with pytest.raises(ReplayCheckpointsError, match="exactly 7 slots"):
        dump_checkpoints(ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[short]))

    mismatched = msgspec.structs.replace(checkpoint, perk_pending=int(checkpoint.perk.pending_count) + 1)
    with pytest.raises(ReplayCheckpointsError, match="must equal"):
        dump_checkpoints(ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[mismatched]))


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_load_checkpoints_requires_exact_vec2_fields(base_world: WorldState, mutation: str) -> None:
    checkpoint = build_checkpoint(tick_index=0, world=base_world, elapsed_ms=0)
    encoded = dump_checkpoints(ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[checkpoint]))
    raw = msgspec.msgpack.decode(zstd.ZstdDecompressor().decompress(encoded))
    root = cast("dict[str, object]", raw)
    checkpoints = cast("list[object]", root["checkpoints"])
    row = cast("dict[str, object]", checkpoints[0])
    players = cast("list[object]", row["players"])
    player = cast("dict[str, object]", players[0])
    pos = cast("dict[str, object]", player["pos"])
    if mutation == "missing":
        pos.pop("x")
    else:
        pos["extra"] = 1

    with pytest.raises(ReplayCheckpointsError, match="invalid checkpoints msgpack payload"):
        load_checkpoints(_wire(root))


def test_load_checkpoints_rejects_zstd_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay_checkpoints_mod, "MAX_CHECKPOINTS_PAYLOAD_BYTES", 4)
    payload = zstd.ZstdCompressor(level=19).compress(b"12345")
    with pytest.raises(ReplayCheckpointsError, match="payload too large"):
        load_checkpoints(payload)


def test_load_checkpoints_rejects_file_over_compressed_envelope_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = zstd.ZstdCompressor(level=19).compress(b"12345")
    monkeypatch.setattr(replay_checkpoints_mod, "MAX_CHECKPOINTS_FILE_BYTES", len(payload) - 1)

    with pytest.raises(ReplayCheckpointsError, match="checkpoints file too large"):
        load_checkpoints(payload)


def test_default_checkpoint_sample_rate_is_every_tick() -> None:
    assert int(DEFAULT_CHECKPOINT_SAMPLE_RATE) == 1
