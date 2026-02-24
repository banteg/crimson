from __future__ import annotations

import copy
import gzip
import json
from pathlib import Path
from typing import cast

import msgspec
import pytest
import zstandard as zstd

from crimson.original.capture import CaptureError, load_capture
from crimson.original.schema import CAPTURE_FORMAT_VERSION, CaptureConfig, CaptureFile
from tests.builders.capture import build_capture_config, capture_file_to_dict, capture_value_to_builtins
from tests.test_original_capture_conversion import (
    _base_tick,
    _capture_obj,
    _sample_creature,
)


def _as_builtins_dict(value: object) -> dict[str, object]:
    builtins_value = capture_value_to_builtins(value)
    assert isinstance(builtins_value, dict)
    for key in builtins_value:
        assert isinstance(key, str)
    return cast(dict[str, object], builtins_value)


def _base_config(**kwargs: object) -> CaptureConfig:
    return msgspec.structs.replace(build_capture_config(), **kwargs)


def _capture_meta_dict(capture: CaptureFile) -> dict[str, object]:
    meta_capture = copy.deepcopy(capture)
    meta_capture.ticks = []
    return _as_builtins_dict(meta_capture)


def _write_capture_malformed(path: Path, obj: dict[str, object]) -> None:
    capture_row = copy.deepcopy(obj)
    ticks_obj = capture_row["ticks"]
    assert isinstance(ticks_obj, list)
    capture_row["ticks"] = []

    rows = [json.dumps({"event": "capture_meta", "capture": capture_row}, separators=(",", ":"), sort_keys=True)]
    rows.extend(json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in ticks_obj)
    encoded = ("\n".join(rows) + "\n").encode("utf-8")
    if str(path).endswith(".gz"):
        path.write_bytes(gzip.compress(encoded))
    else:
        path.write_bytes(encoded)


def _write_capture_stream_malformed(path: Path, *, meta: dict[str, object], ticks: list[dict[str, object]]) -> None:
    rows = [json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True)]
    rows.extend(json.dumps({"event": "tick", "tick": tick}, separators=(",", ":"), sort_keys=True) for tick in ticks)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_load_capture_rejects_missing_capture_format_version(tmp_path: Path) -> None:
    obj = capture_file_to_dict(_capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)]))
    obj.pop("capture_format_version", None)
    path = tmp_path / "capture.json"
    _write_capture_malformed(path, obj)

    with pytest.raises(CaptureError, match="invalid capture file"):
        load_capture(path)


def test_load_capture_rejects_unsupported_capture_format_version(tmp_path: Path) -> None:
    obj = capture_file_to_dict(_capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)]))
    obj["capture_format_version"] = int(CAPTURE_FORMAT_VERSION) - 1
    path = tmp_path / "capture.json"
    _write_capture_malformed(path, obj)

    with pytest.raises(ValueError, match="unsupported capture format version"):
        load_capture(path)


def test_load_capture_rejects_legacy_canonical_json(tmp_path: Path) -> None:
    obj = _capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)])
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(capture_file_to_dict(obj), separators=(",", ":"), sort_keys=True), encoding="utf-8")

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_stream_accepts_known_config_fields(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = _capture_meta_dict(obj)
    meta["config"] = _as_builtins_dict(
        _base_config(
            out_path="capture.json",
            split_quest_files=True,
            quest_out_dir="C:\\share\\frida",
            quest_out_prefix="gameplay_diff_capture.quest_",
            capture_profile="exhaustive_default",
            config_env_overrides=["CRIMSON_FRIDA_STATES", "CRIMSON_FRIDA_OUT_PATH"],
            log_mode="truncate",
            console_all_events=True,
            console_events=["start", "ready", "capture_shutdown"],
            include_caller=False,
        ),
    )
    _write_capture_stream_malformed(path, meta=meta, ticks=[_as_builtins_dict(tick)])

    capture = load_capture(path)

    assert capture.script == "gameplay_diff_capture"
    assert capture.config.out_path == "capture.json"
    assert capture.config.split_quest_files is True
    assert capture.config.quest_out_dir == "C:\\share\\frida"
    assert capture.config.quest_out_prefix == "gameplay_diff_capture.quest_"
    assert capture.config.capture_profile == "exhaustive_default"
    assert capture.config.config_env_overrides == ["CRIMSON_FRIDA_STATES", "CRIMSON_FRIDA_OUT_PATH"]
    assert capture.config.console_all_events is True
    assert capture.config.console_events == ["start", "ready", "capture_shutdown"]
    assert capture.config.include_caller is False
    assert len(capture.ticks) == 1


def test_load_capture_stream_rejects_unknown_config_fields(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = _capture_meta_dict(obj)
    config = _as_builtins_dict(
        _base_config(
            out_path="capture.json",
            log_mode="truncate",
        ),
    )
    config["future_knob"] = 12345
    meta["config"] = config
    _write_capture_stream_malformed(path, meta=meta, ticks=[_as_builtins_dict(tick)])

    with pytest.raises(CaptureError, match="invalid capture file"):
        load_capture(path)


def test_load_capture_stream_accepts_missing_hook_config_fields_with_defaults(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = _capture_meta_dict(obj)
    config = _as_builtins_dict(_base_config(out_path="capture.json", log_mode="truncate"))
    for key in (
        "bonus_sample_limit",
        "enable_input_hooks",
        "enable_rng_hooks",
        "enable_sfx_hooks",
        "enable_damage_hooks",
        "enable_effect_hooks",
        "creature_damage_projectile_only",
        "enable_spawn_hooks",
        "enable_creature_spawn_hook",
        "enable_creature_death_hook",
        "enable_bonus_spawn_hook",
    ):
        config.pop(key, None)
    meta["config"] = config
    _write_capture_stream_malformed(path, meta=meta, ticks=[_as_builtins_dict(tick)])

    capture = load_capture(path)

    assert capture.config.bonus_sample_limit == -1
    assert capture.config.enable_input_hooks is True
    assert capture.config.enable_rng_hooks is True
    assert capture.config.enable_sfx_hooks is True
    assert capture.config.enable_damage_hooks is True
    assert capture.config.enable_effect_hooks is True
    assert capture.config.creature_damage_projectile_only is True
    assert capture.config.enable_spawn_hooks is True
    assert capture.config.enable_creature_spawn_hook is True
    assert capture.config.enable_creature_death_hook is True
    assert capture.config.enable_bonus_spawn_hook is True


def test_load_capture_stream_rejects_truncated_last_line(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = _capture_meta_dict(obj)
    rows = [
        json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "tick", "tick": _as_builtins_dict(tick)}, separators=(",", ":"), sort_keys=True),
        '{"event":"tick","tick"',
    ]
    path.write_text("\n".join(rows), encoding="utf-8")

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_stream_rejects_legacy_capture_end_row(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    obj = _capture_obj(ticks=[tick])
    path = tmp_path / "capture.json"
    meta = _capture_meta_dict(obj)
    rows = [
        json.dumps({"event": "capture_meta", "capture": meta}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "tick", "tick": _as_builtins_dict(tick)}, separators=(",", ":"), sort_keys=True),
        json.dumps({"event": "capture_end", "reason": "manual_stop", "ticks_written": 1}, separators=(",", ":")),
    ]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_rejects_unknown_fields(tmp_path: Path) -> None:
    obj = capture_file_to_dict(_capture_obj(ticks=[_base_tick(tick_index=0, elapsed_ms=16)]))
    obj["unexpected"] = 1
    path = tmp_path / "capture.json"
    _write_capture_malformed(path, obj)

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_rejects_incomplete_sample_rows(tmp_path: Path) -> None:
    tick = _base_tick(tick_index=0, elapsed_ms=16)
    bad_creature = _as_builtins_dict(_sample_creature())
    del bad_creature["collision_flag"]
    obj = capture_file_to_dict(_capture_obj(ticks=[tick]))
    ticks_obj = obj["ticks"]
    assert isinstance(ticks_obj, list)
    assert ticks_obj
    tick0 = cast(dict[str, object], ticks_obj[0])
    assert isinstance(tick0, dict)
    samples = cast(dict[str, object], tick0["samples"])
    assert isinstance(samples, dict)
    samples["creatures"] = [bad_creature]
    samples["projectiles"] = []
    samples["secondary_projectiles"] = []
    samples["bonuses"] = []
    tick0["samples"] = samples
    path = tmp_path / "capture.json"
    _write_capture_malformed(path, obj)

    with pytest.raises(CaptureError):
        load_capture(path)


def test_load_capture_rejects_invalid_msgpack_zstd_payload(tmp_path: Path) -> None:
    path = tmp_path / "capture.msgpack.zst"
    path.write_bytes(zstd.compress(b"not-a-valid-capture-stream"))

    with pytest.raises(CaptureError):
        load_capture(path)
