from __future__ import annotations

import msgspec

from .canonical_channels import RngStreamRow

_RNG_MARKS_EMPTY_VALUE = -1


def _decode_rng_stream_rows(rng_stream: object) -> list[RngStreamRow]:
    try:
        return msgspec.convert(rng_stream, type=list[RngStreamRow])
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise ValueError("rng_stream must be a valid list[RngStreamRow] payload") from exc


def canonical_rng_marks(
    *,
    rng_state: int,
    rng_stream: object,
) -> dict[str, int]:
    rows = _decode_rng_stream_rows(rng_stream)
    call_count = int(len(rows))
    inferred_count = 0
    for row in rows:
        if bool(row.inferred):
            inferred_count += 1

    first_value = _RNG_MARKS_EMPTY_VALUE
    last_value = _RNG_MARKS_EMPTY_VALUE
    first_state_before = _RNG_MARKS_EMPTY_VALUE
    last_state_after = _RNG_MARKS_EMPTY_VALUE
    if rows:
        first = rows[0]
        last = rows[-1]
        first_value = int(first.value_15)
        last_value = int(last.value_15)
        first_state_before = int(first.state_before_u32)
        last_state_after = int(last.state_after_u32)

    return {
        "calls_total": int(call_count),
        "inferred_total": int(inferred_count),
        "first_value_15": int(first_value),
        "last_value_15": int(last_value),
        "first_state_before_u32": int(first_state_before),
        "last_state_after_u32": int(last_state_after),
        "checkpoint_rng_state": int(rng_state),
    }
