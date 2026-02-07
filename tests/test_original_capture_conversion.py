from __future__ import annotations

import gzip
import json
from pathlib import Path

from crimson.replay.checkpoints import dump_checkpoints, load_checkpoints
from crimson.replay.original_capture import (
    ORIGINAL_CAPTURE_FORMAT_VERSION,
    convert_original_capture_to_checkpoints,
    load_original_capture_sidecar,
)


def test_convert_original_capture_to_checkpoints_roundtrip(tmp_path: Path) -> None:
    capture_obj = {
        "v": ORIGINAL_CAPTURE_FORMAT_VERSION,
        "sample_rate": 2,
        "replay_sha256": "orig-hash",
        "ticks": [
            {
                "tick_index": 0,
                "state_hash": "aaaaaaaaaaaaaaaa",
                "command_hash": "bbbbbbbbbbbbbbbb",
                "rng_state": 100,
                "elapsed_ms": 16,
                "score_xp": 10,
                "kills": 1,
                "creature_count": 20,
                "perk_pending": 0,
                "players": [
                    {
                        "pos": {"x": 512.0, "y": 512.0},
                        "health": 100.0,
                        "weapon_id": 1,
                        "ammo": 12.0,
                        "experience": 10,
                        "level": 1,
                    }
                ],
                "rng_marks": {"gw_begin": 1234},
                "events": {"hit_count": 2, "pickup_count": 1, "sfx_count": 3, "sfx_head": ["sfx_a"]},
            },
            {
                "tick_index": 1,
                "state_hash": "cccccccccccccccc",
                "command_hash": "dddddddddddddddd",
            },
        ],
    }

    path = tmp_path / "capture.json.gz"
    path.write_bytes(gzip.compress(json.dumps(capture_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")))

    capture = load_original_capture_sidecar(path)
    checkpoints = convert_original_capture_to_checkpoints(capture)

    assert checkpoints.sample_rate == 2
    assert checkpoints.replay_sha256 == "orig-hash"
    assert len(checkpoints.checkpoints) == 2
    assert checkpoints.checkpoints[0].tick_index == 0
    assert checkpoints.checkpoints[0].command_hash == "bbbbbbbbbbbbbbbb"
    assert checkpoints.checkpoints[0].events.hit_count == 2
    assert checkpoints.checkpoints[1].events.hit_count == -1
    assert checkpoints.checkpoints[1].events.pickup_count == -1
    assert checkpoints.checkpoints[1].events.sfx_count == -1

    loaded = load_checkpoints(dump_checkpoints(checkpoints))
    assert loaded == checkpoints


def test_load_original_capture_sidecar_supports_plain_json(tmp_path: Path) -> None:
    capture_obj = {
        "v": ORIGINAL_CAPTURE_FORMAT_VERSION,
        "sample_rate": 1,
        "ticks": [{"tick_index": 0, "state_hash": "hash0", "command_hash": "cmd0"}],
    }
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(capture_obj, separators=(",", ":"), sort_keys=True), encoding="utf-8")

    capture = load_original_capture_sidecar(path)
    assert capture.version == ORIGINAL_CAPTURE_FORMAT_VERSION
    assert capture.sample_rate == 1
    assert [tick.tick_index for tick in capture.ticks] == [0]

