"""One-shot migration: convert v8 .crd replay fixtures to v9 format.

v8 layout:  {header, inputs: list[PackedTickInputs], dt: list[float], events: list[ReplayEvent]}
v9 layout:  {header, ticks: list[ReplayTick]}

Events are converted to per-tick commands:
  PerkPickEvent(tick_index=N, player_index=P, choice_index=C)
    -> PerkPickCommand(player_index=P, choice_index=C) on tick N
  PerkMenuOpenEvent(tick_index=N, player_index=P)
    -> PerkMenuOpenCommand(player_index=P) on tick N

Terminal events (tick_index >= len(inputs)) are dropped.
"""

from __future__ import annotations

import gzip
import io
import sys
from collections import defaultdict
from pathlib import Path

import msgspec

# -- raw v8 types for decoding --

class _V8Event(msgspec.Struct, tag_field="type"):
    tick_index: int = 0
    player_index: int = 0


class _V8PerkPickEvent(_V8Event, tag="perk_pick"):
    choice_index: int = 0


class _V8PerkMenuOpenEvent(_V8Event, tag="perk_menu_open"):
    pass


class _V8Replay(msgspec.Struct):
    header: msgspec.Raw
    inputs: list[list[list[float | int]]]
    dt: list[float]
    events: list[_V8PerkPickEvent | _V8PerkMenuOpenEvent]


# -- v9 command types (must match crimson.sim.input_providers) --

class PerkPickCommand(msgspec.Struct, tag="perk_pick", frozen=True):
    player_index: int
    choice_index: int


class PerkMenuOpenCommand(msgspec.Struct, tag="perk_menu_open", frozen=True):
    player_index: int


GameCommand = PerkMenuOpenCommand | PerkPickCommand


class ReplayTick(msgspec.Struct, frozen=True):
    inputs: list[list[float | int]]
    commands: tuple[GameCommand, ...] = ()
    dt: float | None = None


class _V9Replay(msgspec.Struct):
    header: msgspec.Raw
    ticks: list[ReplayTick]


def _migrate(v8_bytes: bytes) -> bytes:
    # Decompress if gzipped
    if v8_bytes[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(v8_bytes), mode="rb") as stream:
            v8_bytes = stream.read()

    v8 = msgspec.msgpack.decode(v8_bytes, type=_V8Replay)

    # Bump header version
    header_raw = msgspec.msgpack.decode(v8.header)
    assert isinstance(header_raw, dict)
    header_raw["replay_format_version"] = 9
    header_encoded = msgspec.msgpack.encode(header_raw)

    # Group events by tick
    events_by_tick: dict[int, list[GameCommand]] = defaultdict(list)
    tick_count = len(v8.inputs)
    for event in v8.events:
        if event.tick_index >= tick_count:
            # Terminal event — drop
            continue
        if isinstance(event, _V8PerkPickEvent):
            events_by_tick[event.tick_index].append(
                PerkPickCommand(player_index=event.player_index, choice_index=event.choice_index),
            )
        elif isinstance(event, _V8PerkMenuOpenEvent):
            events_by_tick[event.tick_index].append(
                PerkMenuOpenCommand(player_index=event.player_index),
            )

    # Build v9 ticks
    default_dt_val = 1.0 / 60.0
    ticks: list[ReplayTick] = []
    for i in range(tick_count):
        tick_inputs = v8.inputs[i]
        tick_dt_raw = v8.dt[i] if i < len(v8.dt) else default_dt_val
        # Store dt as None if it matches default
        tick_dt: float | None = float(tick_dt_raw) if abs(float(tick_dt_raw) - default_dt_val) > 1e-9 else None
        commands = tuple(events_by_tick.get(i, []))
        ticks.append(ReplayTick(inputs=tick_inputs, commands=commands, dt=tick_dt))

    v9 = _V9Replay(header=msgspec.Raw(header_encoded), ticks=ticks)
    raw = msgspec.msgpack.encode(v9)
    return gzip.compress(raw, compresslevel=9, mtime=0)


def main() -> None:
    fixture_dir = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "replays"
    crd_files = sorted(fixture_dir.glob("*.crd"))
    if not crd_files:
        print("No .crd files found in", fixture_dir)
        sys.exit(1)

    for crd_path in crd_files:
        print(f"Migrating {crd_path.name} ...")
        v8_data = crd_path.read_bytes()
        v9_data = _migrate(v8_data)
        crd_path.write_bytes(v9_data)
        print(f"  -> wrote {len(v9_data)} bytes")


if __name__ == "__main__":
    main()
