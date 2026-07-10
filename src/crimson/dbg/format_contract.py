from __future__ import annotations

import re
from pathlib import Path

import msgspec

from ..replay.checkpoints import FORMAT_VERSION as CHECKPOINT_FORMAT_VERSION
from ..replay.checkpoints import MAX_CHECKPOINTS_FILE_BYTES, MAX_CHECKPOINTS_PAYLOAD_BYTES
from ..replay.codec import MAX_REPLAY_FILE_BYTES, MAX_REPLAY_PAYLOAD_BYTES
from ..replay.types import REPLAY_FORMAT_VERSION, ReplayTick
from .canonical_channels import ReplayStepSnapshot
from .frida_finalize import FRIDA_CAPTURE_FORMAT_VERSION
from .schema import TRACE_FORMAT_VERSION, TRACE_REQUIRED_CHANNELS, TRACE_SCHEMA_VERSION

_REPO_ROOT = Path(__file__).resolve().parents[3]
_TICK_BOUNDARY_FIELDS = ("dt", "inputs", "prelude", "postlude", "commands")


def _field_names(struct_type: type[msgspec.Struct]) -> tuple[str, ...]:
    return tuple(field.name for field in msgspec.structs.fields(struct_type))


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
    )
    for source, pattern, label, expected in comparisons:
        actual = _source_int(source, pattern=pattern, label=label, errors=errors)
        if actual is not None and actual != expected:
            errors.append(f"{label} is {actual}, expected {expected}")

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
