from __future__ import annotations

import msgspec

type BuiltinScalar = None | bool | int | float | str
type BuiltinValue = BuiltinScalar | list[BuiltinValue] | dict[str, BuiltinValue]
type BuiltinObject = dict[str, BuiltinValue]
type BuiltinRows = list[BuiltinObject]


def coerce_builtin_value(value: object, *, field: str) -> BuiltinValue:
    if value is None:
        return None
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return float(value)
    if isinstance(value, str):
        return str(value)
    if isinstance(value, list):
        return [coerce_builtin_value(item, field=f"{field}[]") for item in value]
    if isinstance(value, tuple):
        return [coerce_builtin_value(item, field=f"{field}[]") for item in value]
    if isinstance(value, dict):
        out: BuiltinObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{field} must use string keys, got {type(key).__name__}")
            out[str(key)] = coerce_builtin_value(item, field=f"{field}.{key}")
        return out
    raise TypeError(f"{field} must contain only builtin debug payload values, got {type(value).__name__}")


def to_builtin_value(value: object, *, field: str) -> BuiltinValue:
    return coerce_builtin_value(msgspec.to_builtins(value), field=field)


def to_builtin_object(value: object, *, field: str) -> BuiltinObject:
    built = to_builtin_value(value, field=field)
    if not isinstance(built, dict):
        raise TypeError(f"{field} must convert to a mapping payload")
    return built


def builtin_object_or_empty(value: BuiltinValue | None) -> BuiltinObject:
    if not isinstance(value, dict):
        return {}
    try:
        coerced = coerce_builtin_value(value, field="payload")
    except TypeError:
        return {}
    if isinstance(coerced, dict):
        return coerced
    return {}

