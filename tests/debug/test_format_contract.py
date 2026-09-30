from __future__ import annotations

import msgspec

from crimson.replay.checkpoints import FORMAT_VERSION as CHECKPOINT_FORMAT_VERSION
from crimson.replay.types import REPLAY_FORMAT_VERSION
from crimson_re.dbg.canonical_channels import ReplayStepSnapshot
from crimson_re.dbg.format_contract import format_contract_errors
from crimson_re.dbg.schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION


def _field_names(struct_type: type[msgspec.Struct]) -> tuple[str, ...]:
    return tuple(field.name for field in msgspec.structs.fields(struct_type))


def test_current_recording_format_matrix_is_explicit() -> None:
    assert (
        TRACE_FORMAT_VERSION,
        TRACE_SCHEMA_VERSION,
        REPLAY_FORMAT_VERSION,
        CHECKPOINT_FORMAT_VERSION,
    ) == (2, 19, 27, 6)


def test_cross_language_format_contract_is_wired() -> None:
    assert format_contract_errors() == []


def test_trace_tick_boundary_order_is_explicit() -> None:
    assert _field_names(ReplayStepSnapshot) == ("dt", "inputs", "prelude", "postlude", "commands")
