from __future__ import annotations

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


def test_load_checkpoints_defaults_optional_checkpoint_fields() -> None:
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
    payload = msgspec.msgpack.encode(payload_obj)
    loaded = load_checkpoints(payload)
    assert loaded.checkpoints[0].perk.pending_count == 0
    assert loaded.checkpoints[0].perk.choices == []
    assert loaded.checkpoints[0].deaths == []
    assert loaded.checkpoints[0].events.hit_count == 0
    assert loaded.checkpoints[0].events.pickup_count == 0
    assert loaded.checkpoints[0].events.sfx_count == 0
    assert loaded.checkpoints[0].typo is None


def test_load_checkpoints_defaults_legacy_death_owner_id() -> None:
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
                "deaths": [
                    {
                        "creature_index": 5,
                        "type_id": 2,
                        "reward_value": 75.0,
                        "xp_awarded": 10,
                    },
                ],
            },
        ],
    }
    payload = msgspec.msgpack.encode(payload_obj)
    loaded = load_checkpoints(payload)
    assert loaded.checkpoints[0].deaths[0].owner_id == -1


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
        load_checkpoints(b"\x81\xa7version\xc3")


def test_load_checkpoints_rejects_invalid_zstd_payload() -> None:
    with pytest.raises(ReplayCheckpointsError, match="invalid checkpoints zstd payload"):
        load_checkpoints(b"\x28\xb5\x2f\xfdnot-a-zstd-stream")


def test_load_checkpoints_rejects_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay_checkpoints_mod, "_DEFAULT_MAX_CHECKPOINTS_PAYLOAD_BYTES", 4)
    payload = b"12345"
    with pytest.raises(ReplayCheckpointsError, match="payload too large"):
        load_checkpoints(payload)


def test_load_checkpoints_rejects_zstd_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay_checkpoints_mod, "_DEFAULT_MAX_CHECKPOINTS_PAYLOAD_BYTES", 4)
    payload = zstd.ZstdCompressor(level=19).compress(b"12345")
    with pytest.raises(ReplayCheckpointsError, match="payload too large"):
        load_checkpoints(payload)


def test_default_checkpoint_sample_rate_is_every_tick() -> None:
    assert int(DEFAULT_CHECKPOINT_SAMPLE_RATE) == 1
