from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import cast

import msgspec


class FieldMismatch(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    path: str
    kind: str
    expected: object | None = None
    actual: object | None = None


def _path_or_root(path: str) -> str:
    return path if path else "<root>"


def _path_attr(path: str, name: str) -> str:
    return str(name) if not path else f"{path}.{name}"


def _path_index(path: str, index: int) -> str:
    return f"{path}[{int(index)}]" if path else f"[{int(index)}]"


def _path_key(path: str, key: object) -> str:
    if isinstance(key, str) and key.isidentifier():
        return _path_attr(path, key)
    key_text = json.dumps(key, sort_keys=True, default=repr)
    return f"{path}[{key_text}]" if path else f"[{key_text}]"


def _is_struct_instance(value: object) -> bool:
    fields = getattr(type(value), "__struct_fields__", None)
    return isinstance(fields, tuple)


def _struct_field_names(value: object) -> tuple[str, ...]:
    fields = getattr(type(value), "__struct_fields__", None)
    if isinstance(fields, tuple) and all(isinstance(name, str) for name in fields):
        return tuple(str(name) for name in fields)
    return ()


def _is_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview))


def _to_builtin(value: object) -> object:
    return msgspec.to_builtins(value)


def _append(
    out: list[FieldMismatch],
    *,
    path: str,
    kind: str,
    expected: object | None = None,
    actual: object | None = None,
) -> None:
    out.append(
        FieldMismatch(
            path=_path_or_root(path),
            kind=str(kind),
            expected=_to_builtin(expected) if expected is not None else None,
            actual=_to_builtin(actual) if actual is not None else None,
        ),
    )


def _collect(expected: object, actual: object, *, path: str, out: list[FieldMismatch]) -> None:
    if type(expected) is type(actual) and expected == actual:
        return

    if type(expected) is not type(actual):
        _append(out, path=path, kind="type_mismatch", expected=type(expected).__name__, actual=type(actual).__name__)
        return

    if _is_struct_instance(expected):
        for name in _struct_field_names(expected):
            _collect(
                getattr(expected, name),
                getattr(actual, name),
                path=_path_attr(path, name),
                out=out,
            )
        return

    if isinstance(expected, Mapping):
        expected_map = cast("Mapping[object, object]", expected)
        actual_map = cast("Mapping[object, object]", actual)
        keys = sorted(set(expected_map.keys()) | set(actual_map.keys()), key=lambda key: repr(key))
        for key in keys:
            key_path = _path_key(path, key)
            if key not in expected_map:
                _append(out, path=key_path, kind="missing_expected", actual=actual_map[key])
                continue
            if key not in actual_map:
                _append(out, path=key_path, kind="missing_actual", expected=expected_map[key])
                continue
            _collect(expected_map[key], actual_map[key], path=key_path, out=out)
        return

    if _is_sequence(expected):
        expected_seq = cast("Sequence[object]", expected)
        actual_seq = cast("Sequence[object]", actual)
        if len(expected_seq) != len(actual_seq):
            _append(out, path=path, kind="length_mismatch", expected=len(expected_seq), actual=len(actual_seq))
        shared_len = min(len(expected_seq), len(actual_seq))
        for index in range(shared_len):
            _collect(expected_seq[index], actual_seq[index], path=_path_index(path, index), out=out)
        for index in range(shared_len, len(expected_seq)):
            _append(out, path=_path_index(path, index), kind="missing_actual", expected=expected_seq[index])
        for index in range(shared_len, len(actual_seq)):
            _append(out, path=_path_index(path, index), kind="missing_expected", actual=actual_seq[index])
        return

    _append(out, path=path, kind="value_mismatch", expected=expected, actual=actual)


def strict_mismatches(expected: object, actual: object, *, root_path: str = "") -> list[FieldMismatch]:
    out: list[FieldMismatch] = []
    _collect(expected, actual, path=str(root_path), out=out)
    return out


def strict_mismatch_payload(expected: object, actual: object, *, root_path: str = "") -> tuple[list[dict[str, object]], int, str]:
    mismatches = strict_mismatches(expected, actual, root_path=root_path)
    payload = cast("list[dict[str, object]]", msgspec.to_builtins(mismatches))
    return payload, len(payload), json.dumps(payload, sort_keys=True, indent=2, default=repr)
