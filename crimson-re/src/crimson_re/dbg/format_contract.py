from __future__ import annotations

import re
from pathlib import Path

import msgspec

from crimson.replay.checkpoints import (
    FORMAT_VERSION as CHECKPOINT_FORMAT_VERSION,
)
from crimson.replay.checkpoints import (
    MAX_CHECKPOINTS_FILE_BYTES,
    MAX_CHECKPOINTS_PAYLOAD_BYTES,
)
from crimson.replay.codec import MAX_REPLAY_FILE_BYTES, MAX_REPLAY_PAYLOAD_BYTES
from crimson.replay.types import REPLAY_FORMAT_VERSION

from .canonical_channels import ReplayStepSnapshot
from .schema import TRACE_FORMAT_VERSION, TRACE_REQUIRED_CHANNELS, TRACE_SCHEMA_VERSION

_REPO_ROOT = Path(__file__).resolve().parents[4]
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
    """Return every current-format wiring mismatch between Python and Zig."""

    errors: list[str] = []
    fields = _field_names(ReplayStepSnapshot)
    if fields != _TICK_BOUNDARY_FIELDS:
        errors.append(f"Python ReplayStepSnapshot fields are {fields!r}, expected {_TICK_BOUNDARY_FIELDS!r}")

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

    zig_step_fields = _zig_struct_fields(cdt_source, name="ReplayStepSnapshot", errors=errors)
    if zig_step_fields is not None and zig_step_fields != _TICK_BOUNDARY_FIELDS:
        errors.append(f"Zig ReplayStepSnapshot fields are {zig_step_fields!r}, expected {_TICK_BOUNDARY_FIELDS!r}")

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
