from __future__ import annotations

from io import StringIO
import json

from crimson.oracle import OracleConfig, OutputMode, run_headless


def _collect(config: OracleConfig) -> list[dict[str, object]]:
    stream = StringIO()
    # `run_headless` emits one JSON object per line.
    import contextlib

    with contextlib.redirect_stdout(stream):
        run_headless(config)
    lines = [line.strip() for line in stream.getvalue().splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def test_oracle_summary_includes_command_hash() -> None:
    rows = _collect(
        OracleConfig(
            seed=0x1234,
            input_file=None,
            max_frames=3,
            frame_rate=60,
            sample_rate=1,
            output_mode=OutputMode.SUMMARY,
            preserve_bugs=False,
        )
    )
    assert rows
    for row in rows:
        command_hash = str(row.get("command_hash", ""))
        assert len(command_hash) == 16


def test_oracle_summary_is_deterministic_for_same_seed() -> None:
    config = OracleConfig(
        seed=0x1234,
        input_file=None,
        max_frames=4,
        frame_rate=60,
        sample_rate=1,
        output_mode=OutputMode.SUMMARY,
        preserve_bugs=False,
    )
    rows0 = _collect(config)
    rows1 = _collect(config)
    assert rows0 == rows1
