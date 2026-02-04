from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Final, Iterable

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


_BASE_HEADER_V1 = struct.Struct("<H H B B h f I B B H I I I")
_PLAYER_INIT_V1 = struct.Struct("<f f B B H")
_INPUT_V1 = struct.Struct("<f f f f B B H")
_FRAME_PREFIX_V1 = struct.Struct("<f")
_ACTION_V1 = struct.Struct("<I B B H f I")


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


def _read_exact(buf: memoryview, offset: int, size: int) -> tuple[memoryview, int]:
    end = offset + size
    if end > len(buf):
        raise DemoError("unexpected EOF")
    return buf[offset:end], end


def loads(data: bytes) -> Demo:
    buf = memoryview(data)
    offset = 0

    magic, offset = _read_exact(buf, offset, len(MAGIC))
    if bytes(magic) != MAGIC:
        raise DemoError("invalid magic")

    header_raw, offset = _read_exact(buf, offset, _BASE_HEADER_V1.size)
    (
        version,
        flags,
        game_mode,
        player_count,
        difficulty_level,
        world_size,
        rng_state,
        detail_preset,
        fx_toggle,
        _reserved,
        status_blob_len,
        frame_count,
        action_count,
    ) = _BASE_HEADER_V1.unpack(header_raw)

    if int(version) != VERSION:
        raise DemoError(f"unsupported demo version: {version}")

    player_count = int(player_count)
    if not (1 <= player_count <= 4):
        raise DemoError(f"unsupported player_count: {player_count}")

    status_blob = b""
    if int(status_blob_len) > 0:
        blob_raw, offset = _read_exact(buf, offset, int(status_blob_len))
        status_blob = bytes(blob_raw)

    player_inits: list[PlayerInit] = []
    for _ in range(player_count):
        init_raw, offset = _read_exact(buf, offset, _PLAYER_INIT_V1.size)
        pos_x, pos_y, weapon_id, _pad8, _pad16 = _PLAYER_INIT_V1.unpack(init_raw)
        _ = _pad8, _pad16
        player_inits.append(PlayerInit(pos_x=float(pos_x), pos_y=float(pos_y), weapon_id=int(weapon_id)))

    frames: list[DemoFrame] = []
    for _ in range(int(frame_count)):
        dt_raw, offset = _read_exact(buf, offset, _FRAME_PREFIX_V1.size)
        (dt,) = _FRAME_PREFIX_V1.unpack(dt_raw)
        inputs: list[PlayerInput] = []
        for _p in range(player_count):
            inp_raw, offset = _read_exact(buf, offset, _INPUT_V1.size)
            move_x, move_y, aim_x, aim_y, buttons, _pad8, _pad16 = _INPUT_V1.unpack(inp_raw)
            _ = _pad8, _pad16
            buttons = int(buttons)
            inputs.append(
                PlayerInput(
                    move_x=float(move_x),
                    move_y=float(move_y),
                    aim_x=float(aim_x),
                    aim_y=float(aim_y),
                    fire_down=(buttons & 0x01) != 0,
                    fire_pressed=(buttons & 0x02) != 0,
                    reload_pressed=(buttons & 0x04) != 0,
                )
            )
        frames.append(DemoFrame(dt=float(dt), inputs=tuple(inputs)))

    actions: list[DemoAction] = []
    for _ in range(int(action_count)):
        raw, offset = _read_exact(buf, offset, _ACTION_V1.size)
        tick, action_type, player_index, payload_u16, payload_f32, _reserved_u32 = _ACTION_V1.unpack(raw)
        _ = _reserved_u32
        actions.append(
            DemoAction(
                tick=int(tick),
                action_type=int(action_type),
                player_index=int(player_index),
                payload_u16=int(payload_u16),
                payload_f32=float(payload_f32),
            )
        )

    if offset != len(buf):
        raise DemoError("trailing data")

    header = DemoHeader(
        flags=int(flags),
        game_mode=int(game_mode),
        player_count=player_count,
        difficulty_level=int(difficulty_level),
        world_size=float(world_size),
        rng_state=int(rng_state),
        detail_preset=int(detail_preset),
        fx_toggle=int(fx_toggle),
        status_blob=status_blob,
        player_inits=tuple(player_inits),
    )
    return Demo(header=header, frames=tuple(frames), actions=tuple(actions))


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

    out = bytearray()
    out += MAGIC
    out += _BASE_HEADER_V1.pack(
        VERSION,
        int(header.flags),
        int(header.game_mode),
        player_count,
        int(header.difficulty_level),
        float(header.world_size),
        int(header.rng_state) & 0xFFFF_FFFF,
        int(header.detail_preset) & 0xFF,
        int(header.fx_toggle) & 0xFF,
        0,
        len(status_blob),
        len(frames),
        len(actions),
    )
    out += status_blob

    for init in header.player_inits:
        out += _PLAYER_INIT_V1.pack(float(init.pos_x), float(init.pos_y), int(init.weapon_id) & 0xFF, 0, 0)

    for frame in frames:
        out += _FRAME_PREFIX_V1.pack(float(frame.dt))
        for inp in frame.inputs:
            buttons = 0
            if inp.fire_down:
                buttons |= 0x01
            if inp.fire_pressed:
                buttons |= 0x02
            if inp.reload_pressed:
                buttons |= 0x04
            out += _INPUT_V1.pack(
                float(inp.move_x),
                float(inp.move_y),
                float(inp.aim_x),
                float(inp.aim_y),
                buttons,
                0,
                0,
            )

    for action in actions:
        out += _ACTION_V1.pack(
            int(action.tick) & 0xFFFF_FFFF,
            int(action.action_type) & 0xFF,
            int(action.player_index) & 0xFF,
            int(action.payload_u16) & 0xFFFF,
            float(action.payload_f32),
            0,
        )

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

