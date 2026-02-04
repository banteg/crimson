from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path
from typing import Final, Iterable

from construct import Array, Byte, Bytes, Const, ConstructError, ConstError, Float32l, Int16sl, Int16ul, Int32ul
from construct import Padding, StreamError, Struct, Terminated, TerminatedError

from ..gameplay import PlayerInput

MAGIC: Final[bytes] = b"CRDEMO\x00"
VERSION: Final[int] = 1

FLAG_DEMO_MODE_ACTIVE: Final[int] = 1 << 0
FLAG_HARDCORE: Final[int] = 1 << 1
FLAG_PRESERVE_BUGS: Final[int] = 1 << 2
FLAG_PERK_PROGRESSION: Final[int] = 1 << 3
FLAG_AUTO_PICK_PERKS: Final[int] = 1 << 4


class DemoError(ValueError):
    pass


class ActionType:
    PERK_PICK = 1
    PERK_MENU_OPEN = 2


_MAGIC = Const(MAGIC)

_BASE_HEADER_V1 = Struct(
    "version" / Int16ul,
    "flags" / Int16ul,
    "game_mode" / Byte,
    "player_count" / Byte,
    "difficulty_level" / Int16sl,
    "world_size" / Float32l,
    "rng_state" / Int32ul,
    "detail_preset" / Byte,
    "fx_toggle" / Byte,
    Padding(2),
    "status_blob_len" / Int32ul,
    "frame_count" / Int32ul,
    "action_count" / Int32ul,
)

_PLAYER_INIT_V1 = Struct(
    "pos_x" / Float32l,
    "pos_y" / Float32l,
    "weapon_id" / Byte,
    Padding(1),
    Padding(2),
)

_INPUT_V1 = Struct(
    "move_x" / Float32l,
    "move_y" / Float32l,
    "aim_x" / Float32l,
    "aim_y" / Float32l,
    "buttons" / Byte,
    Padding(1),
    Padding(2),
)

_ACTION_V1 = Struct(
    "tick" / Int32ul,
    "action_type" / Byte,
    "player_index" / Byte,
    "payload_u16" / Int16ul,
    "payload_f32" / Float32l,
    Padding(4),
)


def _frame_v1(player_count: int) -> Struct:
    return Struct(
        "dt" / Float32l,
        "inputs" / Array(int(player_count), _INPUT_V1),
    )


@dataclass(frozen=True, slots=True)
class DemoHeader:
    flags: int
    game_mode: int
    player_count: int
    difficulty_level: int
    world_size: float
    rng_state: int
    detail_preset: int
    fx_toggle: int
    status_blob: bytes = b""
    player_inits: tuple["PlayerInit", ...] = ()

    def flag(self, mask: int) -> bool:
        return (int(self.flags) & int(mask)) != 0


@dataclass(frozen=True, slots=True)
class PlayerInit:
    pos_x: float
    pos_y: float
    weapon_id: int


@dataclass(frozen=True, slots=True)
class DemoFrame:
    dt: float
    inputs: tuple[PlayerInput, ...]


@dataclass(frozen=True, slots=True)
class DemoAction:
    tick: int
    action_type: int
    player_index: int
    payload_u16: int
    payload_f32: float


@dataclass(frozen=True, slots=True)
class Demo:
    header: DemoHeader
    frames: tuple[DemoFrame, ...]
    actions: tuple[DemoAction, ...] = ()


def loads(data: bytes) -> Demo:
    stream = io.BytesIO(data)

    try:
        _MAGIC.parse_stream(stream)
    except StreamError as exc:
        raise DemoError("unexpected EOF") from exc
    except ConstError as exc:
        raise DemoError("invalid magic") from exc

    try:
        header_raw = _BASE_HEADER_V1.parse_stream(stream)
    except ConstructError as exc:
        raise DemoError("unexpected EOF") from exc

    version = int(header_raw["version"])
    if version != VERSION:
        raise DemoError(f"unsupported demo version: {version}")

    player_count = int(header_raw["player_count"])
    if not (1 <= player_count <= 4):
        raise DemoError(f"unsupported player_count: {player_count}")

    try:
        status_blob_len = int(header_raw["status_blob_len"])
        status_blob = b"" if status_blob_len <= 0 else bytes(Bytes(status_blob_len).parse_stream(stream))

        player_inits_raw = Array(player_count, _PLAYER_INIT_V1).parse_stream(stream)

        frames_raw = Array(int(header_raw["frame_count"]), _frame_v1(player_count)).parse_stream(stream)
        actions_raw = Array(int(header_raw["action_count"]), _ACTION_V1).parse_stream(stream)

        Terminated.parse_stream(stream)
    except StreamError as exc:
        raise DemoError("unexpected EOF") from exc
    except TerminatedError as exc:
        raise DemoError("trailing data") from exc
    except ConstructError as exc:
        raise DemoError(str(exc)) from exc

    player_inits = tuple(
        PlayerInit(
            pos_x=float(entry["pos_x"]),
            pos_y=float(entry["pos_y"]),
            weapon_id=int(entry["weapon_id"]),
        )
        for entry in player_inits_raw
    )

    frames: list[DemoFrame] = []
    for frame in frames_raw:
        inputs: list[PlayerInput] = []
        for inp in frame["inputs"]:
            buttons = int(inp["buttons"])
            inputs.append(
                PlayerInput(
                    move_x=float(inp["move_x"]),
                    move_y=float(inp["move_y"]),
                    aim_x=float(inp["aim_x"]),
                    aim_y=float(inp["aim_y"]),
                    fire_down=(buttons & 0x01) != 0,
                    fire_pressed=(buttons & 0x02) != 0,
                    reload_pressed=(buttons & 0x04) != 0,
                )
            )
        frames.append(DemoFrame(dt=float(frame["dt"]), inputs=tuple(inputs)))

    actions = tuple(
        DemoAction(
            tick=int(entry["tick"]),
            action_type=int(entry["action_type"]),
            player_index=int(entry["player_index"]),
            payload_u16=int(entry["payload_u16"]),
            payload_f32=float(entry["payload_f32"]),
        )
        for entry in actions_raw
    )

    header = DemoHeader(
        flags=int(header_raw["flags"]),
        game_mode=int(header_raw["game_mode"]),
        player_count=player_count,
        difficulty_level=int(header_raw["difficulty_level"]),
        world_size=float(header_raw["world_size"]),
        rng_state=int(header_raw["rng_state"]),
        detail_preset=int(header_raw["detail_preset"]),
        fx_toggle=int(header_raw["fx_toggle"]),
        status_blob=status_blob,
        player_inits=player_inits,
    )

    return Demo(header=header, frames=tuple(frames), actions=actions)


def load(path: Path) -> Demo:
    return loads(path.read_bytes())


def dumps(demo: Demo) -> bytes:
    header = demo.header
    frames = demo.frames
    actions = demo.actions

    player_count = int(header.player_count)
    if len(header.player_inits) != player_count:
        raise DemoError("player init count mismatch")
    for frame in frames:
        if len(frame.inputs) != player_count:
            raise DemoError("frame input count mismatch")

    status_blob = bytes(header.status_blob or b"")

    header_raw = {
        "version": int(VERSION),
        "flags": int(header.flags),
        "game_mode": int(header.game_mode),
        "player_count": player_count,
        "difficulty_level": int(header.difficulty_level),
        "world_size": float(header.world_size),
        "rng_state": int(header.rng_state) & 0xFFFF_FFFF,
        "detail_preset": int(header.detail_preset) & 0xFF,
        "fx_toggle": int(header.fx_toggle) & 0xFF,
        "status_blob_len": len(status_blob),
        "frame_count": len(frames),
        "action_count": len(actions),
    }

    player_inits_raw = [
        {
            "pos_x": float(init.pos_x),
            "pos_y": float(init.pos_y),
            "weapon_id": int(init.weapon_id) & 0xFF,
        }
        for init in header.player_inits
    ]

    frames_raw = []
    for frame in frames:
        inputs_raw = []
        for inp in frame.inputs:
            buttons = 0
            if inp.fire_down:
                buttons |= 0x01
            if inp.fire_pressed:
                buttons |= 0x02
            if inp.reload_pressed:
                buttons |= 0x04
            inputs_raw.append(
                {
                    "move_x": float(inp.move_x),
                    "move_y": float(inp.move_y),
                    "aim_x": float(inp.aim_x),
                    "aim_y": float(inp.aim_y),
                    "buttons": int(buttons) & 0xFF,
                }
            )
        frames_raw.append({"dt": float(frame.dt), "inputs": inputs_raw})

    actions_raw = [
        {
            "tick": int(action.tick) & 0xFFFF_FFFF,
            "action_type": int(action.action_type) & 0xFF,
            "player_index": int(action.player_index) & 0xFF,
            "payload_u16": int(action.payload_u16) & 0xFFFF,
            "payload_f32": float(action.payload_f32),
        }
        for action in actions
    ]

    out = bytearray()
    out += MAGIC
    try:
        out += _BASE_HEADER_V1.build(header_raw)
        out += status_blob
        out += Array(player_count, _PLAYER_INIT_V1).build(player_inits_raw)
        out += Array(len(frames), _frame_v1(player_count)).build(frames_raw)
        out += Array(len(actions), _ACTION_V1).build(actions_raw)
    except ConstructError as exc:
        raise DemoError(str(exc)) from exc

    return bytes(out)


def dump(demo: Demo, path: Path) -> None:
    path.write_bytes(dumps(demo))


def build_header_flags(
    *,
    demo_mode_active: bool,
    hardcore: bool,
    preserve_bugs: bool,
    perk_progression_enabled: bool,
    auto_pick_perks: bool,
) -> int:
    flags = 0
    if demo_mode_active:
        flags |= FLAG_DEMO_MODE_ACTIVE
    if hardcore:
        flags |= FLAG_HARDCORE
    if preserve_bugs:
        flags |= FLAG_PRESERVE_BUGS
    if perk_progression_enabled:
        flags |= FLAG_PERK_PROGRESSION
    if auto_pick_perks:
        flags |= FLAG_AUTO_PICK_PERKS
    return int(flags)


def iter_actions_by_tick(actions: Iterable[DemoAction]) -> dict[int, list[DemoAction]]:
    out: dict[int, list[DemoAction]] = {}
    for action in actions:
        out.setdefault(int(action.tick), []).append(action)
    return out
