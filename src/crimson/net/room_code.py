from __future__ import annotations

from typing import Annotated

import msgspec

ROOM_CODE_LENGTH = 4

type RoomCode = Annotated[
    str,
    msgspec.Meta(
        min_length=ROOM_CODE_LENGTH,
        max_length=ROOM_CODE_LENGTH,
        pattern=rf"^[a-z0-9]{{{ROOM_CODE_LENGTH}}}$",
    ),
]


def parse_room_code(value: str) -> RoomCode:
    return msgspec.convert(str(value).strip().lower(), type=RoomCode)


def parse_optional_room_code(value: str | None) -> RoomCode | None:
    text = str(value or "").strip()
    if not text:
        return None
    return parse_room_code(text)


__all__ = ["ROOM_CODE_LENGTH", "RoomCode", "parse_optional_room_code", "parse_room_code"]
