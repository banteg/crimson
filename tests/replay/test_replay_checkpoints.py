from __future__ import annotations

import msgspec
import pytest
import zstandard as zstd

import crimson.replay.checkpoints as replay_checkpoints_mod
from crimson.bonuses.ids import BonusId
from crimson.creatures.runtime import CreatureDeath
from crimson.creatures.spawn_ids import CreatureTypeId
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.replay.checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoints,
    ReplayCheckpointsError,
    build_checkpoint,
    dump_checkpoints,
    load_checkpoints,
)
from crimson.sim.state_types import BonusPickupEvent
from crimson.sim.world_state import WorldEvents, WorldState
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest


def _wire(value: object) -> bytes:
    return zstd.ZstdCompressor(level=19).compress(msgspec.msgpack.encode(value))


def test_checkpoints_codec_roundtrip_is_stable(base_world: WorldState) -> None:
    world = base_world
    player = world.players[0]
    player.experience = 123
    player.level = 2
    world.state.perks[1] = 1
    world.state.perk_selection.pending_count = 1
    world.state.perk_selection.choices_dirty = False
    world.state.perk_selection.choices = [
        PerkId.BLOODY_MESS_QUICK_LEARNER,
        PerkId.SHARPSHOOTER,
        PerkId.FASTLOADER,
    ]
    ckpt = build_checkpoint(tick_index=0, world=world, elapsed_ms=0.0, rng_callers_crc32=0)
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
    world.state.perks[7] = 2

    ckpt = build_checkpoint(
        tick_index=15,
        world=world,
        elapsed_ms=250.0,
        rng_callers_crc32=0,
        deaths=[
            CreatureDeath(
                index=33,
                pos=world.players[0].pos,
                type_id=CreatureTypeId.ZOMBIE,
                reward_value=75.0,
                xp_awarded=10,
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
                SfxRequest(SfxId.UI_BONUS),
                SfxRequest(SfxId.UI_BUTTONCLICK),
                SfxRequest(SfxId.UI_PANELCLICK),
                SfxRequest(SfxId.UI_TYPEENTER),
                SfxRequest(SfxId.UI_CLINK_01),
            ],
        ),
    )
    checkpoints = ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[ckpt])
    decoded = load_checkpoints(dump_checkpoints(checkpoints))
    assert decoded == checkpoints
    assert decoded.checkpoints[0].events.hit_count == 3
    assert len(decoded.checkpoints[0].events.hit_head) == 2
    assert decoded.checkpoints[0].events.hit_head[0].type_id == int(ProjectileTemplateId.PISTOL)


def test_load_checkpoints_rejects_noncanonical_f32(base_world: WorldState) -> None:
    checkpoint = build_checkpoint(tick_index=0, world=base_world, elapsed_ms=0, rng_callers_crc32=0)
    player = msgspec.structs.replace(checkpoint.players[0], health=0.123456789123)
    checkpoint = msgspec.structs.replace(checkpoint, players=[player])
    payload = ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=[checkpoint])

    with pytest.raises(ReplayCheckpointsError, match="not canonically encoded"):
        load_checkpoints(_wire(payload))


def test_load_checkpoints_rejects_zstd_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay_checkpoints_mod, "MAX_CHECKPOINTS_PAYLOAD_BYTES", 4)
    payload = zstd.ZstdCompressor(level=19).compress(b"12345")
    with pytest.raises(ReplayCheckpointsError, match="payload too large"):
        load_checkpoints(payload)
