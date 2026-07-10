from __future__ import annotations

import re
from pathlib import Path

import msgspec

from crimson.dbg.canonical_channels import ReplayStepSnapshot
from crimson.dbg.format_contract import format_contract_errors
from crimson.dbg.frida_finalize import FRIDA_CAPTURE_FORMAT_VERSION, FRIDA_EVIDENCE_FORMAT_VERSION
from crimson.dbg.schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION
from crimson.replay.checkpoints import FORMAT_VERSION as CHECKPOINT_FORMAT_VERSION
from crimson.replay.types import REPLAY_FORMAT_VERSION, ReplayTick


def _field_names(struct_type: type[msgspec.Struct]) -> tuple[str, ...]:
    return tuple(field.name for field in msgspec.structs.fields(struct_type))


def test_current_recording_format_matrix_is_explicit() -> None:
    assert (
        TRACE_FORMAT_VERSION,
        TRACE_SCHEMA_VERSION,
        REPLAY_FORMAT_VERSION,
        CHECKPOINT_FORMAT_VERSION,
        FRIDA_CAPTURE_FORMAT_VERSION,
        FRIDA_EVIDENCE_FORMAT_VERSION,
    ) == (2, 14, 15, 5, 18, 1)


def test_cross_language_format_contract_is_wired() -> None:
    assert format_contract_errors() == []


def test_replay_and_trace_share_the_same_tick_boundary_order() -> None:
    expected = ("dt", "inputs", "prelude", "postlude", "commands")
    assert _field_names(ReplayTick) == expected
    assert _field_names(ReplayStepSnapshot) == expected


def test_frida_agent_uses_the_python_capture_format_version() -> None:
    source = (Path(__file__).parents[2] / "scripts" / "frida" / "gameplay_diff_capture.js").read_text()
    match = re.search(r"^const CAPTURE_FORMAT_VERSION = (\d+);$", source, flags=re.MULTILINE)

    assert match is not None
    assert int(match.group(1)) == FRIDA_CAPTURE_FORMAT_VERSION


def test_frida_agent_does_not_require_callable_rng_state_accessor_as_hook() -> None:
    source = (Path(__file__).parents[2] / "scripts" / "frida" / "gameplay_diff_capture.js").read_text()

    hook_names = re.search(
        r"^function requiredReplayHookNames\(\) \{(?P<body>.*?)^\}",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    function_names = re.search(
        r"^function requiredReplayFnNames\(\) \{(?P<body>.*?)^\}",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    validation = re.search(
        r"^function validateInstalledRequiredHooks\(\) \{(?P<body>.*?)^\}",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )

    assert hook_names is not None
    assert function_names is not None
    assert validation is not None
    assert '"crt_getptd"' not in hook_names.group("body")
    assert '"crt_getptd"' in function_names.group("body")
    assert "requiredReplayHookNames()" in validation.group("body")


def test_frida_agent_forwards_replay_boundaries_to_tick_contract() -> None:
    source = (Path(__file__).parents[2] / "scripts" / "frida" / "gameplay_diff_capture.js").read_text()
    finalize_tick = source.split("function finalizeTick() {", 1)[1].split(
        "function finalizeTickOrReport() {",
        1,
    )[0]

    assert "replay_prelude: tick.replay_prelude" in finalize_tick
    assert "replay_postlude: tick.replay_postlude" in finalize_tick
