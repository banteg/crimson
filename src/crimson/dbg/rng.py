from __future__ import annotations

from .canonical_channels import RngStreamRow

_RNG_MARKS_EMPTY_VALUE = -1


def canonical_rng_marks(
    *,
    rng_state: int,
    rng_stream: list[RngStreamRow],
) -> dict[str, int]:
    rows = list(rng_stream)
    call_count = int(len(rows))

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
        "first_value_15": int(first_value),
        "last_value_15": int(last_value),
        "first_state_before_u32": int(first_state_before),
        "last_state_after_u32": int(last_state_after),
        "checkpoint_rng_state": int(rng_state),
    }
