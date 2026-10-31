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
from nacl.signing import SigningKey

from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.game_version import REPLAY_FORMAT_VERSION, REPLAY_RULES, current_replay_game_version
from crimson.math_parity import f32
from crimson.replay.codec import (
    ReplayCodecError,
    decode_replay_payload,
    dump_replay,
    encode_replay_payload,
    inflate_replay_payload,
    load_replay_file,
)
from crimson.replay.driver.playback_driver import PlaybackDriver, ReplayRunnerError
from crimson.replay.ranked import RankedTickMonitor, outcome_reasons, ranked_board, ranked_run_spec, unranked_reasons
from crimson.replay.types import Pilot, Replay, ReplayTick, current_recorder
from crimson.sim.commands import PerkMenuOpenCommand, PerkPickCommand
from crimson.sim.run_result import PlayerRunResult, RunOutcome, RunResult
from crimson.sim.run_spec import RunSpec
from crimson.sim.world_state import WorldState

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "replays"
OUT = ROOT / "service" / "test" / "vectors.json"


def _core_transport():
    spec = importlib.util.spec_from_file_location("core_replay", ROOT / "crimson-core" / "checks" / "replay.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.encode


# The seats' signing keys in the co-op vectors, from fixed seeds so the service's tests can sign as each seat.
SEAT_SEEDS = tuple(hashlib.sha256(f"crimson-vectors-seat-{seat}".encode()).digest() for seat in range(2))
SEAT_KEYS = tuple(bytes(SigningKey(seed).verify_key) for seed in SEAT_SEEDS)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_id(transport: bytes) -> str:
    """The service's id for a run (runIdentity in service/src/transport.ts): a one-player stream without its player
    count, a co-op one whole, neither with the config words after the weapon usage counts (rules, the legacy co-op
    reload and the build); a rules-2 run's tagged with its rules, and a run of another build than 1.9.93 tagged with
    its build too."""
    rules = int.from_bytes(transport[264:268], "little")
    build = int.from_bytes(transport[272:276], "little")
    transport = transport[:264] + transport[276:]
    if rules != 1:
        identity = b"crimson:run:rules\0" + rules.to_bytes(4, "little") + transport
    elif transport[48:52] != (1).to_bytes(4, "little"):
        identity = transport
    else:
        identity = transport[:48] + transport[52:]
    if build != ClBuild.V1_9_93:
        identity = b"crimson:run:build\0" + build.to_bytes(4, "little") + identity
    return _sha(identity)


def fixture_vectors() -> list[dict]:
    encode = _core_transport()
    vectors = []
    for path in sorted(FIXTURES.glob("*.crd")):
        payload = inflate_replay_payload(path.read_bytes())
        replay = decode_replay_payload(payload)
        try:
            transport = encode(replay, len(replay.ticks))
        except ValueError:
            transport = None
        vectors.append({
            "file": path.name,
            "payload_sha256": _sha(payload),
            "game_mode_id": int(replay.run.game_mode_id),
            "seed": replay.run.seed,
            "ticks": len(replay.ticks),
            "transport_sha256": None if transport is None else _sha(transport),
            "run_id": None if transport is None else _run_id(transport),
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
        rules=REPLAY_RULES,
        recorder=current_recorder(),
        pilot=None,
        seat_keys=SEAT_KEYS[:1],
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
        if isinstance(value, bytes):
            return self._header(len(value), None, -1, (0xC4, 0xC5, 0xC6)) + value
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
        if fix is not None and length <= fix_max:
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
        "a seat key per two players": edit(lambda w: w["seat_keys"].append(SEAT_KEYS[1])),
        "short seat key": edit(lambda w: w["seat_keys"].__setitem__(0, SEAT_KEYS[0][:-1])),
        "seat key as a string": edit(lambda w: w["seat_keys"].__setitem__(0, SEAT_KEYS[0].hex())),
        "seat keys as a map": edit(lambda w: w.__setitem__("seat_keys", {"0": SEAT_KEYS[0]})),
        "no seat keys": edit(lambda w: w.pop("seat_keys")),
        "no build": edit(lambda w: w["run"].pop("cl_build")),
        "unknown build": edit(lambda w: w["run"].__setitem__("cl_build", ClBuild.V1_9_93 - 1)),
        "1.9.8 rules under rules 1": edit(lambda w: w.update(rules=1, run={**w["run"], "cl_build": ClBuild.V1_9_8})),
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


# What both verifiers say of a pick on the run's first tick (service/test/worker/api.test.ts).
ILLEGAL_PICK = "tick 0: perk_pick without an open perk menu"


# Fire, static movement, mouse aim.
FIRING = 1 | (1 << 8) | (2 << 9) | (1 << 12)


def _circling(i: int, phase: float = 0.0) -> tuple[float, float, float, float, int]:
    """Firing, standing, at a point circling the arena centre."""
    angle = i * 0.02 + phase
    return (0.0, 0.0, f32(512.0 + 150.0 * math.cos(angle)), f32(512.0 + 150.0 * math.sin(angle)), FIRING)


def _hunting(ticks: list[ReplayTick], index: int, world: WorldState) -> None:
    """After tick `index`: player one, standing, fires at the nearest living creature, at a point kept inside the
    ranked view, and once a perk is pending opens the perk menu, then picks its first choice."""
    player = world.players[0].pos
    living = [creature.pos for creature in world.creatures.entries if creature.active and creature.hp > 0]
    if index + 1 < len(ticks):
        aim = min(living, key=lambda pos: (pos - player).length()) if living else None
        inputs = _circling(index + 1) if aim is None else (0.0, 0.0, f32(min(max(aim.x, 0.0), 1024.0)), f32(min(max(aim.y, 160.0), 864.0)), FIRING)
        ticks[index + 1] = msgspec.structs.replace(ticks[index + 1], inputs=[inputs])
    if world.state.perk_selection.pending_count and not ticks[index].commands and index + 2 < len(ticks):
        for at, command in ((index + 1, PerkMenuOpenCommand(0)), (index + 2, PerkPickCommand(0, 0))):
            ticks[at] = msgspec.structs.replace(ticks[at], commands=[command])


def _played(run: RunSpec, tick, limit: int, seat_keys: tuple[bytes, ...] | None = None, *, steer=None) -> Replay:
    """The run played with `tick`'s inputs until it ends, recorded through the run-down, with the result it reaches.
    `steer`, given the ticks, a tick's index and the world after it, may rewrite the ticks that follow (`_hunting`)."""

    def replay(ticks: list[ReplayTick], result: RunResult) -> Replay:
        return Replay(
            REPLAY_FORMAT_VERSION, current_replay_game_version(), REPLAY_RULES, current_recorder(), None, seat_keys, run, result, ticks,
        )

    provisional = RunResult(RunOutcome.INCOMPLETE, 0, 0, 0, 0, 0, 0, None, tuple(PlayerRunResult(0, 0.0, 1) for _ in range(run.player_count)))
    long = replay([tick(i) for i in range(limit)], provisional)
    driver = PlaybackDriver(long, version_mismatch_action=None)
    # The driver refuses the tick that ends the run-down when more follow: that tick is the recording's last.
    end = 0
    try:
        for end in range(len(long.ticks)):
            driver.step_tick(end)
            if steer is not None:
                steer(long.ticks, end, driver.world)
    except ReplayRunnerError:
        pass
    ticks = long.ticks[: end + 1]
    result = PlaybackDriver(replay(ticks, provisional), version_mismatch_action=None).run()
    return replay(ticks, result)


def ranked_run() -> tuple[str, str, str, str, str]:
    """A ranked Survival run that verifies: static movement, firing at a point circling the arena centre until the
    player dies, recorded through the run-down; the same run claiming more than it earned; declaring a pilot; and
    picking a perk no menu offered. Last, the run's id on the service."""
    recorded = _played(ranked_run_spec(GameMode.SURVIVAL, seed=0xC0FFEE), lambda i: ReplayTick(inputs=[_circling(i)]), 60 * 60 * 10)
    ticks, result = recorded.ticks, recorded.result

    def replay(ticks: list[ReplayTick], result: RunResult) -> Replay:
        return msgspec.structs.replace(recorded, ticks=ticks, result=result)

    monitor = RankedTickMonitor(replay=recorded)
    assert PlaybackDriver(recorded, version_mismatch_action=None).run(observer=monitor) == result
    assert not monitor.reasons and not unranked_reasons(recorded.run) and not outcome_reasons(recorded.run, result)
    print(f"ranked run: {len(ticks)} ticks, {result.players[0].experience} xp, {result.kills} kills")
    # The same run claiming more experience than it earned: well formed, and refused only by verification.
    inflated = msgspec.structs.replace(
        result, players=(msgspec.structs.replace(result.players[0], experience=result.players[0].experience + 100),),
    )
    # The same run again, declaring the bot that played it.
    piloted = msgspec.structs.replace(replay(ticks, result), pilot=Pilot(name="Astra", model="gpt-5", url="https://example.com/astra"))
    # The same run with a pick on its first tick, before any menu opened: Python refuses it as the core does.
    illegal = replay([msgspec.structs.replace(ticks[0], commands=[PerkPickCommand(0, 0)]), *ticks[1:]], result)
    refusal = None
    try:
        PlaybackDriver(illegal, version_mismatch_action=None).run()
    except ReplayRunnerError as error:
        refusal = str(error)
    assert refusal == ILLEGAL_PICK, refusal
    runs = (replay(ticks, result), replay(ticks, inflated), piloted, illegal)
    files = tuple(base64.b64encode(dump_replay(r)).decode("ascii") for r in runs)
    return (*files, _run_id(_core_transport()(recorded, None)))


def coop_runs() -> dict[str, object]:
    """Two players' runs on the ranked profile, each firing at its own point circling the arena centre: a co-op Survival
    run that ranks, played until both die, with its id and core stream digest; and a co-op custom quest both clear by
    firing at its one alien, which plays and verifies but does not rank (custom_quest_players), for the two-player
    quest time. Both record SEAT_KEYS, whose seeds sign them; the quest clear also comes without them."""
    from crimson.quests.dsl import build_custom_quest

    def both(i: int) -> ReplayTick:
        return ReplayTick(inputs=[_circling(i), _circling(i, math.pi)])

    survival = _played(ranked_run_spec(GameMode.SURVIVAL, seed=0xC0FFEE, player_count=2), both, 60 * 60 * 20, SEAT_KEYS)
    monitor = RankedTickMonitor(replay=survival)
    assert PlaybackDriver(survival, version_mismatch_action=None).run(observer=monitor) == survival.result
    assert not monitor.reasons and not unranked_reasons(survival.run) and not outcome_reasons(survival.run, survival.result)
    assert ranked_board(survival.run) == "survival-coop" and len(survival.result.players) == 2
    print(f"co-op run: {len(survival.ticks)} ticks, {survival.result.players[0].experience} xp, {survival.result.kills} kills")

    quest = build_custom_quest('quest "Pair Clear" version 1\nweapon shotgun\nat 500ms:\n    spawn alien.small_gray at (512, 420)\n')
    at_alien = ReplayTick(inputs=[(0.0, 0.0, 512.0, 420.0, FIRING)] * 2)
    cleared = _played(ranked_run_spec(GameMode.QUESTS, seed=0x1234ABCD, custom_quest=quest, player_count=2), lambda _: at_alien, 600, SEAT_KEYS)
    assert cleared.result.outcome == RunOutcome.QUEST_COMPLETED and unranked_reasons(cleared.run) == ["custom_quest_players"]
    transport = _core_transport()(survival, None)
    return {
        "file": base64.b64encode(dump_replay(survival)).decode("ascii"),
        "transport_sha256": _sha(transport),
        "run_id": _run_id(transport),
        "quest_file": base64.b64encode(dump_replay(cleared)).decode("ascii"),
        "unkeyed_quest_file": base64.b64encode(dump_replay(msgspec.structs.replace(cleared, seat_keys=None))).decode("ascii"),
        "seat_seeds": [seed.hex() for seed in SEAT_SEEDS],
        "seat_keys": [key.hex() for key in SEAT_KEYS],
    }


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


def run_terrain_vectors() -> list[dict]:
    """The terrain a ranked run starts on, from its seed: Survival seeds that reach each terrain_generate_random
    outcome, and two quests, whose terrain replaces the reset's."""
    from crimson.game_modes import GameMode
    from crimson.quests.level import QuestLevel
    from crimson.sim.run_init import initialize_run

    def stamps(setup) -> list[str]:
        return [
            _sha("".join(f"{struct.pack('<f', rotation).hex()},{int(x)},{int(y)}\n" for rotation, x, y in layer).encode())
            for layer in (setup.layers.base, setup.layers.overlay, setup.layers.detail)
        ]

    vectors, outcomes = [], set()
    for seed in range(1000):
        setup = initialize_run(ranked_run_spec(GameMode.SURVIVAL, seed=seed)).terrain
        if setup.terrain_slots in outcomes:
            continue
        outcomes.add(setup.terrain_slots)
        vectors.append({"seed": seed, "board": "survival", "quest": "", "slots": list(setup.terrain_slots), "layers": stamps(setup)})
        if len(outcomes) == 4:
            break
    # Quest 5.3's save (unlock 42) and its hardcore one (50) draw differently before the quest's terrain; a co-op pair
    # draws as one player does.
    for seed, (major, minor), hardcore, players in ((7, (2, 7), False, 1), (8, (5, 3), False, 1), (8, (5, 3), True, 1), (8, (5, 3), True, 2)):
        spec = ranked_run_spec(GameMode.QUESTS, seed=seed, quest_level=QuestLevel(major, minor), hardcore=hardcore, player_count=players)
        setup = initialize_run(spec).terrain
        board = ranked_board(spec)
        vectors.append({"seed": seed, "board": board, "quest": f"{major}.{minor}", "slots": list(setup.terrain_slots), "layers": stamps(setup)})
    return vectors


def custom_quest_payload() -> dict[str, object]:
    """A valid ranked custom quest replay that completes and verifies, plus its source, digest, and transport digest."""
    from crimson.quests.dsl import build_custom_quest

    source = (
        'quest "Quick Clear" version 1\n'
        'author "banteg"\n'
        'weapon shotgun\n'
        'terrain (2, 3, 2)\n'
        'fixed_weapon true\n'
        'at 500ms:\n'
        '    spawn alien.small_gray at (512, 420)\n'
    )
    quest = build_custom_quest(source)
    run = ranked_run_spec(GameMode.QUESTS, seed=0x1234ABCD, custom_quest=quest)
    flags = 1 | (1 << 8) | (2 << 9) | (1 << 12)
    tick = ReplayTick(inputs=[(0.0, 0.0, 512.0, 420.0, flags)])
    provisional = RunResult(RunOutcome.INCOMPLETE, 0, 0, 0, 0, 0, 0, None, (PlayerRunResult(0, 0.0, 1),))

    def build_replay(ticks: list[ReplayTick], result: RunResult) -> Replay:
        return Replay(
            REPLAY_FORMAT_VERSION,
            current_replay_game_version(),
            REPLAY_RULES,
            current_recorder(),
            None,
            None,
            run,
            result,
            ticks,
        )

    long = build_replay([tick] * 600, provisional)
    driver = PlaybackDriver(long, version_mismatch_action=None)
    end = 0
    try:
        for end in range(len(long.ticks)):
            driver.step_tick(end)
    except ReplayRunnerError:
        pass
    ticks = long.ticks[: end + 1]
    result = PlaybackDriver(build_replay(ticks, provisional), version_mismatch_action=None).run()
    recorded = build_replay(ticks, result)
    assert result.outcome == RunOutcome.QUEST_COMPLETED
    assert not unranked_reasons(recorded.run) and not outcome_reasons(recorded.run, result)
    payload = encode_replay_payload(recorded)
    assert decode_replay_payload(payload).run == run
    return {
        "payload": base64.b64encode(payload).decode("ascii"),
        "file": base64.b64encode(dump_replay(recorded)).decode("ascii"),
        "source": source,
        "digest": quest.digest(),
        "score": int(result.quest_final_ms or 0),
        "transport_sha256": _sha(transport := _core_transport()(recorded, None)),
        "run_id": _run_id(transport),
    }

def unranked_run() -> str:
    """A fresh, unfinished run under the historical Rush fixture's unranked configuration."""
    historical = decode_replay_payload(inflate_replay_payload((FIXTURES / "rush-kills103.crd").read_bytes()))
    replay = msgspec.structs.replace(
        _base_replay(), run=historical.run, seat_keys=None,
        ticks=[ReplayTick(inputs=[(0.0, 0.0, 512.0, 400.0, (1 << 8) | (1 << 12))])],
    )
    result = PlaybackDriver(replay, version_mismatch_action=None).run()
    return base64.b64encode(dump_replay(msgspec.structs.replace(replay, result=result))).decode("ascii")


def rules_1_9_8_run() -> dict[str, object]:
    """A ranked Survival run under the 1.9.8 rules that verifies: hunting the nearest creature until the player dies,
    picking the first perk its level-up offers. It ranks on 1.9.8's Survival board. 1.9.8 rolls perk offers from fewer
    perks, so the same ticks under 1.9.93's rules reach another result: only a verifier playing 1.9.8's rules takes it."""
    run = ranked_run_spec(GameMode.SURVIVAL, seed=0xC0FFEE, cl_build=ClBuild.V1_9_8)
    recorded = _played(run, lambda i: ReplayTick(inputs=[_circling(i)]), 60 * 60 * 10, steer=_hunting)
    monitor = RankedTickMonitor(replay=recorded)
    assert PlaybackDriver(recorded, version_mismatch_action=None).run(observer=monitor) == recorded.result
    assert not monitor.reasons and not unranked_reasons(recorded.run) and not outcome_reasons(recorded.run, recorded.result)
    as_1_9_93 = msgspec.structs.replace(recorded, run=msgspec.structs.replace(run, cl_build=ClBuild.V1_9_93))
    result_1_9_93 = PlaybackDriver(as_1_9_93, version_mismatch_action=None).run()
    assert result_1_9_93 != recorded.result
    result = recorded.result
    print(f"1.9.8 run: {len(recorded.ticks)} ticks, {result.players[0].experience} xp, {result.kills} kills")
    transport = _core_transport()(recorded, None)
    return {
        "file": base64.b64encode(dump_replay(recorded)).decode("ascii"),
        # The same ticks claimed under 1.9.93's rules with the result they reach there, as anyone holding the file
        # could: its play ends elsewhere, so only its ticks tell it for this run's copy.
        "as_1_9_93": base64.b64encode(dump_replay(msgspec.structs.replace(as_1_9_93, result=result_1_9_93))).decode("ascii"),
        "transport_sha256": _sha(transport),
        "run_id": _run_id(transport),
        "board": ranked_board(recorded.run),
        "score": result.players[0].experience,
        "unranked_reasons": unranked_reasons(recorded.run),
    }


def main() -> None:
    from quests import quest_dsl_tables

    base, corrupted = corrupted_vectors()
    ranked, inflated, piloted, illegal, ranked_id = ranked_run()
    vectors = {
        "fixtures": fixture_vectors(), "valid_payload": base, "corrupted": corrupted, "custom_quest_run": custom_quest_payload(), "ranked_run": ranked,
        "legacy_ranked_run": base64.b64encode((FIXTURES / "rules1-ranked-survival.crd").read_bytes()).decode(),
        "legacy_ranked_run_id": _run_id(_core_transport()(load_replay_file(FIXTURES / "rules1-ranked-survival.crd"), None)),
        "legacy_coop_run_id": _run_id(_core_transport()(load_replay_file(FIXTURES / "rules1-ranked-coop.crd"), None)),
        "legacy_coop_run": base64.b64encode((FIXTURES / "rules1-ranked-coop.crd").read_bytes()).decode(),
        "ranked_run_id": ranked_id, "ranked_run_inflated": inflated, "piloted_run": piloted, "illegal_command_run": illegal,
        "unranked_run": unranked_run(),
        "rules_1_9_8_run": rules_1_9_8_run(),
        "coop_run": coop_runs(),
        "terrain": terrain_vectors(),
        "run_terrain": run_terrain_vectors(),
        "quest_dsl": quest_dsl_tables(),
    }
    OUT.write_text(json.dumps(vectors, indent=1) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
