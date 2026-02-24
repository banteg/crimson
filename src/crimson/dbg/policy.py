from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True, slots=True)
class ParityPolicy:
    name: str
    float_abs_tol: float
    max_field_diffs: int
    include_hash_fields: bool
    include_rng_fields: bool
    normalize_unknown: bool
    unknown_events_wildcard: bool


_POLICIES: dict[str, ParityPolicy] = {
    "original_vs_python_default": ParityPolicy(
        name="original_vs_python_default",
        float_abs_tol=0.001,
        max_field_diffs=16,
        include_hash_fields=False,
        include_rng_fields=False,
        normalize_unknown=True,
        unknown_events_wildcard=True,
    ),
    "python_vs_rust_strict": ParityPolicy(
        name="python_vs_rust_strict",
        float_abs_tol=0.0,
        max_field_diffs=16,
        include_hash_fields=True,
        include_rng_fields=True,
        normalize_unknown=False,
        unknown_events_wildcard=False,
    ),
    "python_vs_rust_relaxed_float32": ParityPolicy(
        name="python_vs_rust_relaxed_float32",
        float_abs_tol=0.0001,
        max_field_diffs=16,
        include_hash_fields=True,
        include_rng_fields=True,
        normalize_unknown=False,
        unknown_events_wildcard=False,
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
        policy = replace(policy, float_abs_tol=max(0.0, float(float_abs_tol)))
    if max_field_diffs is not None:
        policy = replace(policy, max_field_diffs=max(1, int(max_field_diffs)))
    return policy

