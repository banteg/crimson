from __future__ import annotations


def resolve_weapon_sfx_ref(value: str) -> str:
    """Validate and return canonical weapon sound keys."""

    if value.startswith("sfx_"):
        return value

    raise ValueError(f"unsupported weapon sfx ref format: {value!r}")
