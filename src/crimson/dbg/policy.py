from __future__ import annotations

import msgspec


class ParityPolicy(msgspec.Struct, frozen=True):
    name: str
    float_abs_tol: float
    max_field_diffs: int
    ignore_field_prefixes: tuple[str, ...] = ()


_POLICIES: dict[str, ParityPolicy] = {
    "strict": ParityPolicy(
        name="strict",
        float_abs_tol=0.0,
        max_field_diffs=16,
    ),
}


def available_parity_policies() -> tuple[str, ...]:
    return tuple(sorted(_POLICIES))


def resolve_parity_policy(
    name: str,
    *,
    float_abs_tol: float | None = None,
    max_field_diffs: int | None = None,
) -> ParityPolicy:
    key = str(name).strip()
    if key not in _POLICIES:
        available = ", ".join(sorted(_POLICIES))
        raise ValueError(f"unknown parity policy {name!r}; available: {available}")
    policy = _POLICIES[key]
    if float_abs_tol is not None:
        policy = msgspec.structs.replace(policy, float_abs_tol=max(0.0, float(float_abs_tol)))
    if max_field_diffs is not None:
        policy = msgspec.structs.replace(policy, max_field_diffs=max(1, int(max_field_diffs)))
    return policy
