from __future__ import annotations

import json
import re
from pathlib import Path

import msgspec

from ..replay.checkpoints import (
    FORMAT_VERSION as CHECKPOINT_FORMAT_VERSION,
)
from ..replay.checkpoints import (
    MAX_CHECKPOINTS_FILE_BYTES,
    MAX_CHECKPOINTS_PAYLOAD_BYTES,
    ReplayCheckpoint,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from ..replay.codec import MAX_REPLAY_FILE_BYTES, MAX_REPLAY_PAYLOAD_BYTES
from ..replay.types import REPLAY_FORMAT_VERSION, ReplayTick
from . import frida_finalize as frida_format
from .canonical_channels import (
    BonusEntitySample,
    CreatureEntitySample,
    EntitySamplesSnapshot,
    ProjectileEntitySample,
    ReplayInputSample,
    ReplayStepSnapshot,
    SecondaryProjectileEntitySample,
    SnapshotBonusTimers,
    SnapshotPlayer,
    SnapshotWeapon,
    TimingSampleRow,
)
from .frida_finalize import FRIDA_CAPTURE_FORMAT_VERSION, FRIDA_RUNTIME_VERSION
from .schema import TRACE_FORMAT_VERSION, TRACE_REQUIRED_CHANNELS, TRACE_SCHEMA_VERSION

_REPO_ROOT = Path(__file__).resolve().parents[3]
_TICK_BOUNDARY_FIELDS = ("dt", "inputs", "prelude", "postlude", "commands")


def _field_names(struct_type: type[msgspec.Struct]) -> tuple[str, ...]:
    return tuple(field.name for field in msgspec.structs.fields(struct_type))


def _capture_field_sets() -> dict[str, tuple[str, ...]]:
    tagged: dict[str, type[msgspec.Struct]] = {
        "session_start": frida_format._SessionStartRow,
        "run_start": frida_format._RunStartRow,
        "tick": frida_format._TickRow,
        "run_end": frida_format._RunEndRow,
        "run_error": frida_format._RunErrorRow,
        "error": frida_format._ErrorRow,
        "session_end": frida_format._SessionEndRow,
    }
    nested: dict[str, type[msgspec.Struct]] = {
        "session_start.config": frida_format._SessionConfigRow,
        "session_start.session_fingerprint": frida_format._SessionFingerprintRow,
        "run_start.settings": frida_format._RunSettingsRow,
        "run_start.settings.status": frida_format._CaptureGameStatusRow,
        "run_start.pool_residue[]": frida_format._CapturePoolResidueRow,
        "tick.evidence": frida_format._CaptureTickEvidence,
        "tick.evidence.checkpoint_private": frida_format._CaptureCheckpointEvidence,
        "tick.evidence.checkpoint_private.events": frida_format._CaptureCheckpointEventEvidence,
        "tick.evidence.clocks": frida_format._CaptureClockEvidence,
        "tick.channels": frida_format._TickChannels,
        "tick.channels.replay_step": ReplayStepSnapshot,
        "tick.channels.replay_step.inputs[]": ReplayInputSample,
        "tick.channels.checkpoint": ReplayCheckpoint,
        "tick.channels.checkpoint.players[]": ReplayPlayerCheckpoint,
        "tick.channels.checkpoint.deaths[]": ReplayDeathLedgerEntry,
        "tick.channels.checkpoint.perk": ReplayPerkSnapshot,
        "tick.channels.checkpoint.events": ReplayEventSummary,
        "tick.channels.sim_state": frida_format._CaptureSimStateSnapshot,
        "tick.channels.sim_state.gameplay": frida_format._CaptureSnapshotGameplay,
        "tick.channels.sim_state.gameplay.bonus_timers": SnapshotBonusTimers,
        "tick.channels.sim_state.players[]": SnapshotPlayer,
        "tick.channels.sim_state.players[].weapon": SnapshotWeapon,
        "tick.channels.entity_samples": EntitySamplesSnapshot,
        "tick.channels.entity_samples.creatures[]": CreatureEntitySample,
        "tick.channels.entity_samples.projectiles[]": ProjectileEntitySample,
        "tick.channels.entity_samples.secondary_projectiles[]": SecondaryProjectileEntitySample,
        "tick.channels.entity_samples.bonuses[]": BonusEntitySample,
        "tick.channels.rng_stream[]": frida_format._CaptureRngStreamRow,
        "tick.channels.timing_samples[]": TimingSampleRow,
        "tick.rng_outside_before": frida_format._OutsideRngBag,
        "tick.rng_outside_before.head[]": frida_format._OutsideRngHeadRow,
        "run_end.rng_outside_tail": frida_format._OutsideRngBag,
        "run_end.rng_outside_tail.head[]": frida_format._OutsideRngHeadRow,
    }
    return {
        **{path: ("event", *_field_names(struct_type)) for path, struct_type in tagged.items()},
        **{path: _field_names(struct_type) for path, struct_type in nested.items()},
    }


def _source_int(
    source: str,
    *,
    pattern: str,
    label: str,
    errors: list[str],
) -> int | None:
    match = re.search(pattern, source, flags=re.MULTILINE)
    if match is None:
        errors.append(f"{label} declaration is missing")
        return None
    return int(match.group(1))


def _zig_struct_fields(source: str, *, name: str, errors: list[str]) -> tuple[str, ...] | None:
    match = re.search(
        rf"^const {re.escape(name)} = struct \{{(?P<body>.*?)^\}};$",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        errors.append(f"Zig {name} declaration is missing")
        return None
    return tuple(re.findall(r"^\s{4}([a-z_][a-z0-9_]*):", match.group("body"), flags=re.MULTILINE))


def format_contract_errors() -> list[str]:
    """Return every current-format wiring mismatch across Python, Frida, and Zig."""

    errors: list[str] = []
    for label, struct_type in (
        ("Python ReplayTick", ReplayTick),
        ("Python ReplayStepSnapshot", ReplayStepSnapshot),
    ):
        fields = _field_names(struct_type)
        if fields != _TICK_BOUNDARY_FIELDS:
            errors.append(f"{label} fields are {fields!r}, expected {_TICK_BOUNDARY_FIELDS!r}")

    frida_source = (_REPO_ROOT / "scripts" / "frida" / "gameplay_diff_capture.js").read_text()
    frida_version = _source_int(
        frida_source,
        pattern=r"^const CAPTURE_FORMAT_VERSION = (\d+);$",
        label="Frida capture version",
        errors=errors,
    )
    if frida_version is not None and frida_version != int(FRIDA_CAPTURE_FORMAT_VERSION):
        errors.append(
            f"Frida capture version is {frida_version}, expected {int(FRIDA_CAPTURE_FORMAT_VERSION)}",
        )
    runtime_match = re.search(
        r'^const REQUIRED_FRIDA_VERSION = "([^"]+)";$',
        frida_source,
        flags=re.MULTILINE,
    )
    if runtime_match is None:
        errors.append("Frida runtime version declaration is missing")
    elif runtime_match.group(1) != FRIDA_RUNTIME_VERSION:
        errors.append(
            f"Frida runtime version is {runtime_match.group(1)!r}, expected {FRIDA_RUNTIME_VERSION!r}",
        )

    field_sets_match = re.search(
        r"// BEGIN CAPTURE_FIELD_SETS\nconst CAPTURE_FIELD_SETS = (?P<body>\{.*?\});\n// END CAPTURE_FIELD_SETS",
        frida_source,
        flags=re.DOTALL,
    )
    if field_sets_match is None:
        errors.append("Frida capture field-set manifest is missing")
    else:
        try:
            raw_field_sets = json.loads(field_sets_match.group("body"))
        except json.JSONDecodeError as exc:
            errors.append(f"Frida capture field-set manifest is invalid JSON: {exc}")
        else:
            expected_field_sets = _capture_field_sets()
            if set(raw_field_sets) != set(expected_field_sets):
                errors.append(
                    "Frida capture field-set paths differ: "
                    f"actual={sorted(raw_field_sets)!r}, expected={sorted(expected_field_sets)!r}",
                )
            for path in sorted(set(raw_field_sets) & set(expected_field_sets)):
                actual_fields = tuple(str(field) for field in raw_field_sets[path])
                expected_fields = expected_field_sets[path]
                if len(actual_fields) != len(set(actual_fields)) or set(actual_fields) != set(expected_fields):
                    errors.append(
                        f"Frida {path} fields are {actual_fields!r}, expected {expected_fields!r}",
                    )
    frida_step = re.search(
        r"replay_step:\s*\{(?P<body>.*?)^\s{8}\},$",
        frida_source,
        flags=re.MULTILINE | re.DOTALL,
    )
    if frida_step is None:
        errors.append("Frida replay_step declaration is missing")
    else:
        frida_fields = tuple(
            re.findall(
                r"^\s{10}(dt|inputs|prelude|postlude|commands):",
                frida_step.group("body"),
                flags=re.MULTILINE,
            ),
        )
        if frida_fields != _TICK_BOUNDARY_FIELDS:
            errors.append(f"Frida replay_step fields are {frida_fields!r}, expected {_TICK_BOUNDARY_FIELDS!r}")

    replay_source = (_REPO_ROOT / "crimson-zig" / "src" / "replay_codec.zig").read_text()
    cdt_source = (_REPO_ROOT / "crimson-zig" / "src" / "cdt_trace.zig").read_text()
    checkpoint_source = (_REPO_ROOT / "crimson-zig" / "src" / "checkpoint_diff_native.zig").read_text()
    dbg_verify_source = (_REPO_ROOT / "crimson-zig" / "src" / "dbg_verify_native.zig").read_text()

    comparisons = (
        (
            replay_source,
            r"^pub const replay_format_version: i32 = (\d+);$",
            "Zig replay format version",
            int(REPLAY_FORMAT_VERSION),
        ),
        (
            cdt_source,
            r"^pub const trace_format_version: u32 = (\d+);$",
            "Zig trace format version",
            int(TRACE_FORMAT_VERSION),
        ),
        (
            cdt_source,
            r"^pub const trace_schema_version: i32 = (\d+);$",
            "Zig trace schema version",
            int(TRACE_SCHEMA_VERSION),
        ),
        (
            checkpoint_source,
            r"^pub const checkpoints_format_version: i32 = (\d+);$",
            "Zig checkpoints format version",
            int(CHECKPOINT_FORMAT_VERSION),
        ),
        (
            dbg_verify_source,
            r"^pub const frida_capture_format_version: i32 = (\d+);$",
            "Zig Frida capture format version",
            int(FRIDA_CAPTURE_FORMAT_VERSION),
        ),
        (
            dbg_verify_source,
            r"^pub const frida_evidence_format_version: i32 = (\d+);$",
            "Zig Frida evidence format version",
            int(frida_format.FRIDA_EVIDENCE_FORMAT_VERSION),
        ),
    )
    for source, pattern, label, expected in comparisons:
        actual = _source_int(source, pattern=pattern, label=label, errors=errors)
        if actual is not None and actual != expected:
            errors.append(f"{label} is {actual}, expected {expected}")

    zig_runtime = re.search(
        r'^pub const frida_runtime_version = "([^"]+)";$',
        dbg_verify_source,
        flags=re.MULTILINE,
    )
    if zig_runtime is None:
        errors.append("Zig Frida runtime version declaration is missing")
    elif zig_runtime.group(1) != FRIDA_RUNTIME_VERSION:
        errors.append(
            f"Zig Frida runtime version is {zig_runtime.group(1)!r}, expected {FRIDA_RUNTIME_VERSION!r}",
        )

    size_comparisons = (
        (
            replay_source,
            r"^pub const max_replay_payload_bytes: usize = (\d+) \* 1024 \* 1024;$",
            "Zig replay payload MiB limit",
            int(MAX_REPLAY_PAYLOAD_BYTES // (1024 * 1024)),
        ),
        (
            replay_source,
            r"^pub const max_replay_file_bytes: usize = (\d+) \* 1024 \* 1024;$",
            "Zig replay file MiB limit",
            int(MAX_REPLAY_FILE_BYTES // (1024 * 1024)),
        ),
        (
            checkpoint_source,
            r"^pub const max_checkpoints_payload_bytes: usize = (\d+) \* 1024 \* 1024;$",
            "Zig checkpoints payload MiB limit",
            int(MAX_CHECKPOINTS_PAYLOAD_BYTES // (1024 * 1024)),
        ),
        (
            checkpoint_source,
            r"^pub const max_checkpoints_file_bytes: usize = (\d+) \* 1024 \* 1024;$",
            "Zig checkpoints file MiB limit",
            int(MAX_CHECKPOINTS_FILE_BYTES // (1024 * 1024)),
        ),
    )
    for source, pattern, label, expected in size_comparisons:
        actual = _source_int(source, pattern=pattern, label=label, errors=errors)
        if actual is not None and actual != expected:
            errors.append(f"{label} is {actual}, expected {expected}")

    for source, name in (
        (replay_source, "ReplayTickCurrentWire"),
        (cdt_source, "ReplayStepSnapshot"),
    ):
        fields = _zig_struct_fields(source, name=name, errors=errors)
        if fields is not None and fields != _TICK_BOUNDARY_FIELDS:
            errors.append(f"Zig {name} fields are {fields!r}, expected {_TICK_BOUNDARY_FIELDS!r}")

    zig_channels = re.search(
        r'^pub const trace_required_channels = "([^"]+)";$',
        cdt_source,
        flags=re.MULTILINE,
    )
    expected_channels = ",".join(TRACE_REQUIRED_CHANNELS)
    if zig_channels is None:
        errors.append("Zig required trace channel declaration is missing")
    elif zig_channels.group(1) != expected_channels:
        errors.append(f"Zig required trace channels are {zig_channels.group(1)!r}, expected {expected_channels!r}")

    return errors
