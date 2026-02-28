from __future__ import annotations

import msgspec
import pytest

from crimson.replay.checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoints,
    ReplayCheckpointsError,
    build_checkpoint,
    dump_checkpoints,
    load_checkpoints,
    resolve_checkpoint_sample_rate,
)
from crimson.sim.world_state import WorldState


class _Death:
    def __init__(self, *, index: int, type_id: int, reward_value: float, xp_awarded: int, owner_id: int) -> None:
        self.index = int(index)
        self.type_id = int(type_id)
        self.reward_value = float(reward_value)
        self.xp_awarded = int(xp_awarded)
        self.owner_id = int(owner_id)


class _Events:
    def __init__(self, *, hits: int, pickups: int, sfx: list[str]) -> None:
        self.hits = [object() for _ in range(int(hits))]
        self.pickups = [object() for _ in range(int(pickups))]
        self.sfx = list(sfx)


def test_checkpoints_codec_roundtrip_is_stable(base_world: WorldState) -> None:
    world = base_world
    player = world.players[0]
    player.experience = 123
    player.level = 2
    player.perk_counts[1] = 1
    world.state.perk_selection.pending_count = 1
    world.state.perk_selection.choices_dirty = False
    world.state.perk_selection.choices = [1, 2, 3]
    ckpt = build_checkpoint(tick_index=0, world=world, elapsed_ms=0.0)
    checkpoints = ReplayCheckpoints(version=FORMAT_VERSION, replay_sha256="0" * 64, sample_rate=60, checkpoints=[ckpt])

    data0 = dump_checkpoints(checkpoints)
    data1 = dump_checkpoints(checkpoints)
    assert data0 == data1

    decoded = load_checkpoints(data0)
    assert decoded == checkpoints


def test_checkpoints_codec_roundtrip_preserves_debug_fields(base_world: WorldState) -> None:
    world = base_world
    world.state.perk_selection.pending_count = 2
    world.state.perk_selection.choices_dirty = False
    world.state.perk_selection.choices = [7, 10, 25]
    world.players[0].perk_counts[7] = 2

    ckpt = build_checkpoint(
        tick_index=15,
        world=world,
        elapsed_ms=250.0,
        rng_marks={"before_world_step": 111, "after_world_step": 222},
        deaths=[_Death(index=33, type_id=18, reward_value=75.0, xp_awarded=10, owner_id=-1)],
        events=_Events(hits=2, pickups=1, sfx=["sfx_a", "sfx_b", "sfx_c", "sfx_d", "sfx_e"]),
        command_hash="0123456789abcdef",
    )
    checkpoints = ReplayCheckpoints(version=FORMAT_VERSION, replay_sha256="f" * 64, sample_rate=1, checkpoints=[ckpt])
    decoded = load_checkpoints(dump_checkpoints(checkpoints))
    assert decoded == checkpoints


def test_load_checkpoints_defaults_optional_checkpoint_fields() -> None:
    payload_obj = {
        "version": FORMAT_VERSION,
        "replay_sha256": "0" * 64,
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
                "state_hash": "deadbeefcafebabe",
            },
        ],
    }
    payload = msgspec.msgpack.encode(payload_obj)
    loaded = load_checkpoints(payload)
    assert loaded.checkpoints[0].perk.pending_count == 0
    assert loaded.checkpoints[0].perk.choices == []
    assert loaded.checkpoints[0].rng_marks == {}
    assert loaded.checkpoints[0].command_hash == ""
    assert loaded.checkpoints[0].deaths == []
    assert loaded.checkpoints[0].events.hit_count == 0
    assert loaded.checkpoints[0].events.pickup_count == 0
    assert loaded.checkpoints[0].events.sfx_count == 0


def test_load_checkpoints_rejects_invalid_msgpack_payload() -> None:
    with pytest.raises(ReplayCheckpointsError, match="invalid checkpoints msgpack payload"):
        load_checkpoints(b"\x81\xa7version\xc3")


def test_load_checkpoints_rejects_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRIMSON_REPLAY_CHECKPOINTS_MAX_DECOMPRESSED_BYTES", "4")
    payload = b"12345"
    with pytest.raises(ReplayCheckpointsError, match="payload too large"):
        load_checkpoints(payload)


def test_resolve_checkpoint_sample_rate_env_override(monkeypatch) -> None:
    monkeypatch.delenv("CRIMSON_REPLAY_CHECKPOINT_SAMPLE_RATE", raising=False)
    assert resolve_checkpoint_sample_rate(60) == 60

    monkeypatch.setenv("CRIMSON_REPLAY_CHECKPOINT_SAMPLE_RATE", "1")
    assert resolve_checkpoint_sample_rate(60) == 1

    monkeypatch.setenv("CRIMSON_REPLAY_CHECKPOINT_SAMPLE_RATE", "0")
    assert resolve_checkpoint_sample_rate(60) == 1

    monkeypatch.setenv("CRIMSON_REPLAY_CHECKPOINT_SAMPLE_RATE", "not-a-number")
    assert resolve_checkpoint_sample_rate(60) == 60
