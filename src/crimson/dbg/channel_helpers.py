from __future__ import annotations

from .schema import TickRecord

ENTITY_SAMPLE_KINDS = ("creatures", "projectiles", "secondary_projectiles", "bonuses")


def as_object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    out: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(key, str):
            out[key] = item
    return out


def as_object_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def channel_list(row: TickRecord | None, channel_name: str) -> list[object]:
    if row is None:
        return []
    return as_object_list(row.channels.get(channel_name))


def channel_dict(row: TickRecord | None, channel_name: str) -> dict[str, object]:
    if row is None:
        return {}
    mapped = as_object_dict(row.channels.get(channel_name))
    if mapped is not None:
        return mapped
    return {}


def rng_row_key(row: object) -> tuple[object, object, object]:
    mapped = as_object_dict(row)
    if mapped is None:
        return (None, None, None)
    value_15 = mapped.get("value_15")
    if value_15 is None:
        value_15 = mapped.get("value")
    return (value_15, mapped.get("caller_static"), mapped.get("branch_id"))
