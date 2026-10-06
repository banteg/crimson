"""Write service/test/vectors.json: what the Python codec makes of the recorded fixtures and of corrupted payloads.

The service's TypeScript decoder must agree with the codec that records replays; its tests replay these vectors.
Run from the repository root: uv run python service/scripts/vectors.py
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path

import msgspec

from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.replay.codec import (
    ReplayCodecError,
    decode_replay_payload,
    dump_replay,
    encode_replay_payload,
    inflate_replay_payload,
)
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.replay.driver.setup import ReplayRunnerError
from crimson.replay.ranked import RankedTickMonitor, outcome_reasons, ranked_board, ranked_run_spec, unranked_reasons
from crimson.replay.types import REPLAY_FORMAT_VERSION, Replay, ReplayTick, current_recorder
from crimson.replay.versioning import current_replay_game_version
from crimson.sim.commands import PerkMenuOpenCommand, PerkPickCommand
from crimson.sim.run_result import PlayerRunResult, RunOutcome, RunResult

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "replays"
OUT = ROOT / "service" / "test" / "vectors.json"


def _core_transport():
    spec = importlib.util.spec_from_file_location("core_replay", ROOT / "crimson-core" / "checks" / "replay.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.encode


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture_vectors() -> list[dict]:
    encode = _core_transport()
    vectors = []
    for path in sorted(FIXTURES.glob("*.crd")):
        payload = inflate_replay_payload(path.read_bytes())
        replay = decode_replay_payload(payload)
        try:
            transport = _sha(encode(replay, len(replay.ticks)))
        except ValueError:
            transport = None
        vectors.append({
            "file": path.name,
            "payload_sha256": _sha(payload),
            "game_mode_id": int(replay.run.game_mode_id),
            "seed": replay.run.seed,
            "ticks": len(replay.ticks),
            "transport_sha256": transport,
            "board": ranked_board(replay.run),
            "unranked_reasons": unranked_reasons(replay.run),
            "outcome_reasons": outcome_reasons(replay.run, replay.result),
        })
    return vectors


def _base_replay() -> Replay:
    """A small valid ranked Survival replay; the codec checks its form, not its play."""
    ticks = [
        ReplayTick(inputs=[(0.0, 0.0, 512.0, 400.0, (1 << 8) | (1 << 12))]),
        ReplayTick(inputs=[(0.5, -0.25, 520.0, 410.5, (1 << 8) | (1 << 12) | 1)], commands=[PerkMenuOpenCommand(0)]),
        ReplayTick(inputs=[(0.0, 1.0, 530.0, 420.0, (1 << 8) | (1 << 12))], commands=[PerkPickCommand(0, 2)]),
    ]
    result = RunResult(
        outcome=RunOutcome.DEATH, elapsed_ms=50, kills=3, shots_fired=10, shots_hit=4, rng_state=0xDEADBEEF,
        pending_perks=0, quest_final_ms=None, players=(PlayerRunResult(experience=1234, health=-5.5, most_used_weapon_id=1),),
    )
    return Replay(
        format_version=REPLAY_FORMAT_VERSION,
        game_version=current_replay_game_version(),
        recorder=current_recorder(),
        run=ranked_run_spec(GameMode.SURVIVAL, seed=0x1234ABCD),
        result=result,
        ticks=ticks,
    )


class _Writer:
    """A msgpack writer with the canonical form by default and knobs for each non-canonical one."""

    def __init__(self, *, float32: bool = False, wide_ints: bool = False, wide_headers: bool = False) -> None:
        self.float32 = float32
        self.wide_ints = wide_ints
        self.wide_headers = wide_headers

    def encode(self, value) -> bytes:
        if value is None:
            return b"\xc0"
        if value is True:
            return b"\xc3"
        if value is False:
            return b"\xc2"
        if isinstance(value, int):
            return self._int(value)
        if isinstance(value, float):
            return b"\xca" + struct.pack(">f", value) if self.float32 else b"\xcb" + struct.pack(">d", value)
        if isinstance(value, str):
            data = value.encode()
            return self._header(len(data), 0xA0, 31, (0xD9, 0xDA, 0xDB)) + data
        if isinstance(value, list):
            return self._header(len(value), 0x90, 15, (None, 0xDC, 0xDD)) + b"".join(self.encode(v) for v in value)
        if isinstance(value, dict):
            body = b"".join(self.encode(k) + self.encode(v) for k, v in value.items())
            return self._header(len(value), 0x80, 15, (None, 0xDE, 0xDF)) + body
        raise TypeError(value)

    def _int(self, value: int) -> bytes:
        if self.wide_ints:
            return b"\xd3" + struct.pack(">q", value) if value < 0 else b"\xcf" + struct.pack(">Q", value)
        if 0 <= value <= 0x7F or -32 <= value < 0:
            return struct.pack(">b", value) if value < 0 else bytes([value])
        if value >= 0:
            for marker, fmt, top in ((0xCC, ">B", 0xFF), (0xCD, ">H", 0xFFFF), (0xCE, ">I", 0xFFFFFFFF)):
                if value <= top:
                    return bytes([marker]) + struct.pack(fmt, value)
            return b"\xcf" + struct.pack(">Q", value)
        for marker, fmt, low in ((0xD0, ">b", -0x80), (0xD1, ">h", -0x8000), (0xD2, ">i", -0x80000000)):
            if value >= low:
                return bytes([marker]) + struct.pack(fmt, value)
        return b"\xd3" + struct.pack(">q", value)

    def _header(self, length: int, fix: int, fix_max: int, markers) -> bytes:
        short, medium, long = markers
        if self.wide_headers:
            return bytes([long]) + struct.pack(">I", length)
        if length <= fix_max:
            return bytes([fix | length])
        if short is not None and length <= 0xFF:
            return bytes([short, length])
        if length <= 0xFFFF:
            return bytes([medium]) + struct.pack(">H", length)
        return bytes([long]) + struct.pack(">I", length)


def corrupted_vectors() -> tuple[str, list[dict]]:
    base = encode_replay_payload(_base_replay())
    wire = msgspec.msgpack.decode(base)
    assert _Writer().encode(wire) == base, "the vector writer must reproduce the canonical payload"

    def edit(change):
        copy = msgspec.msgpack.decode(base)
        change(copy)
        return _Writer().encode(copy)

    def reorder(w):
        run = w["run"]
        w["run"] = {"seed": run.pop("seed"), "game_mode_id": run.pop("game_mode_id"), **run}

    def set_input(index, value):
        return lambda w: w["ticks"][0][0][0].__setitem__(index, value)

    corrupted = {
        "float32 floats": _Writer(float32=True).encode(wire),
        "wide integers": _Writer(wide_ints=True).encode(wire),
        "wide headers": _Writer(wide_headers=True).encode(wire),
        "trailing byte": base + b"\x00",
        "missing key": edit(lambda w: w["run"].pop("friendly_fire")),
        "extra key": edit(lambda w: w["result"].__setitem__("bonus", 1)),
        "reordered keys": edit(reorder),
        "integer axis": edit(set_input(0, 1)),
        "float seed": edit(lambda w: w["run"].__setitem__("seed", 1.0)),
        "non-f32 axis": edit(set_input(2, 0.1)),
        "infinite axis": edit(set_input(2, float("inf"))),
        "unknown flag bit": edit(set_input(4, (1 << 8) | (1 << 12) | (1 << 30))),
        "inputs for two players": edit(lambda w: w["run"].__setitem__("player_count", 2)),
        "outcome of another mode": edit(lambda w: w["result"].__setitem__("outcome", "quest_completed")),
        "old format": edit(lambda w: w.__setitem__("format_version", REPLAY_FORMAT_VERSION - 1)),
        "perk choice out of range": edit(lambda w: w["ticks"][2][1][0].__setitem__("choice_index", 7)),
        "typo command in survival": edit(lambda w: w["ticks"][1][1].append({"type": "typo_submit", "player_index": 0})),
        "short weapon usage": edit(lambda w: w["run"]["status"]["weapon_usage_counts"].pop()),
        "quest level outside quests": edit(lambda w: w["run"].__setitem__("quest_level", {"major": 1, "minor": 1})),
        "no ticks": edit(lambda w: w.__setitem__("ticks", [])),
        "no recorder": edit(lambda w: w.pop("recorder")),
        "empty recorder platform": edit(lambda w: w["recorder"].__setitem__("platform", "")),
    }
    vectors = []
    for name, payload in corrupted.items():
        try:
            decode_replay_payload(payload)
        except ReplayCodecError:
            pass
        else:
            raise AssertionError(f"the codec accepted the {name} payload")
        vectors.append({"name": name, "payload": base64.b64encode(payload).decode("ascii")})
    return base64.b64encode(base).decode("ascii"), vectors


def ranked_run() -> tuple[str, str]:
    """A ranked Survival run that verifies: static movement, firing at a point circling the arena centre until the
    player dies, recorded through the run-down."""
    flags = 1 | (1 << 8) | (2 << 9) | (1 << 12)  # fire, static movement, mouse aim

    def tick(i: int) -> ReplayTick:
        angle = i * 0.02
        return ReplayTick(inputs=[(0.0, 0.0, f32(512.0 + 150.0 * math.cos(angle)), f32(512.0 + 150.0 * math.sin(angle)), flags)])

    def replay(ticks: list[ReplayTick], result: RunResult) -> Replay:
        return Replay(
            REPLAY_FORMAT_VERSION, current_replay_game_version(), current_recorder(),
            ranked_run_spec(GameMode.SURVIVAL, seed=0xC0FFEE), result, ticks,
        )

    provisional = RunResult(RunOutcome.INCOMPLETE, 0, 0, 0, 0, 0, 0, None, (PlayerRunResult(0, 0.0, 1),))
    long = replay([tick(i) for i in range(60 * 60 * 10)], provisional)
    driver = PlaybackDriver(long, version_mismatch_action=None)
    # The driver refuses the tick that ends the run-down when more follow: that tick is the recording's last.
    end = 0
    try:
        for end in range(len(long.ticks)):
            driver.step_tick(end)
    except ReplayRunnerError:
        pass
    ticks = long.ticks[: end + 1]
    result = PlaybackDriver(replay(ticks, provisional), version_mismatch_action=None).run()
    recorded = replay(ticks, result)
    monitor = RankedTickMonitor(replay=recorded)
    assert PlaybackDriver(recorded, version_mismatch_action=None).run(observer=monitor) == result
    assert not monitor.reasons and not unranked_reasons(recorded.run) and not outcome_reasons(recorded.run, result)
    print(f"ranked run: {len(ticks)} ticks, {result.players[0].experience} xp, {result.kills} kills")
    # The same run claiming more experience than it earned: well formed, and refused only by verification.
    inflated = msgspec.structs.replace(
        result, players=(msgspec.structs.replace(result.players[0], experience=result.players[0].experience + 100),),
    )
    return tuple(base64.b64encode(dump_replay(replay(ticks, claim))).decode("ascii") for claim in (result, inflated))


def terrain_vectors() -> list[dict]:
    """terrain_generate_random from seeds that reach each of its outcomes, and two quests' terrain_generate."""
    from crimson.quests.level import QuestLevel
    from crimson.sim.terrain_generate import terrain_generate, terrain_generate_random
    from crimson.terrain_slots import terrain_slots_for_quest
    from grim.rand import Crand

    def stamps(setup) -> list[str]:
        # One digest per layer over "rotation f32 bits,x,y" lines, which both languages print the same way.
        return [
            _sha("".join(f"{struct.pack('<f', rotation).hex()},{int(x)},{int(y)}\n" for rotation, x, y in layer).encode())
            for layer in (setup.layers.base, setup.layers.overlay, setup.layers.detail)
        ]

    vectors, outcomes = [], set()
    for seed in range(1000):
        setup = terrain_generate_random(Crand(seed), 50)
        if setup.terrain_slots in outcomes:
            continue
        outcomes.add(setup.terrain_slots)
        vectors.append({"seed": seed, "random": True, "slots": list(setup.terrain_slots), "layers": stamps(setup)})
        if len(outcomes) == 4:
            break
    for seed, (major, minor) in ((7, (2, 7)), (8, (5, 3))):
        slots = terrain_slots_for_quest(QuestLevel(major, minor))
        setup = terrain_generate(Crand(seed), slots)
        vectors.append({"seed": seed, "quest": [major, minor], "slots": list(slots), "layers": stamps(setup)})
    return vectors


def main() -> None:
    base, corrupted = corrupted_vectors()
    ranked, inflated = ranked_run()
    vectors = {
        "fixtures": fixture_vectors(), "valid_payload": base, "corrupted": corrupted, "ranked_run": ranked,
        "ranked_run_inflated": inflated,
        "unranked_run": base64.b64encode((FIXTURES / "rush-kills103.crd").read_bytes()).decode("ascii"),
        "terrain": terrain_vectors(),
    }
    OUT.write_text(json.dumps(vectors, indent=1) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
