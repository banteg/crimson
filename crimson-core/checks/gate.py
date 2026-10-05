"""Whole-run agreement gate between Python and the recovered core.

Both implementations step the identical input/command stream. Each stream is
either an input-only `.rsi` from the bot corpus (`matrix.mjs`) or a recorded
`.crd` fixture converted with `replay.encode`. The gate compares a set of
per-tick fields to locate the first divergence, the first terminal tick and its
outcome, and the complete `RunResult` after the last tick both sides stepped.

Each stream's config carries its bug policy (`preserve_bugs`), and Python runs
under the same one: the bot corpus covers both, and recorded fixtures replay
under the rules they were recorded with, so their claimed results apply.
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import msgspec
from replay import encode

from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.quests.results import compute_quest_final_time
from crimson.replay.codec import load_replay_file
from crimson.replay.ticks import step_replay_tick
from crimson.replay.types import ReplayTick
from crimson.sim.commands import PerkMenuOpenCommand, PerkPickCommand
from crimson.sim.run_init import initialize_run
from crimson.sim.run_result import (
    PlayerRunResult,
    RunDown,
    RunOutcome,
    RunResult,
    build_run_result,
    run_result_mismatches,
)
from crimson.sim.run_spec import RunSpec, RunStatus
from crimson.sim.sessions import IllegalCommandError
from crimson.weapon_runtime import most_used_weapon_id_for_player
from crimson.weapons import WeaponId

CORE = Path(__file__).resolve().parents[1]
ROOT = CORE.parent
# `PortableConfig` in host/api.h: 12 uint32 settings, then the weapon usage counts.
CONFIG_BYTES = 260

# Native `game_state_pending` values that end a run (third_party/headers/crimsonland_types.h).
GAME_OVER, QUEST_RESULTS, QUEST_FAILED = 0x07, 0x08, 0x0C
TERMINAL_OUTCOMES = {
    GAME_OVER: RunOutcome.DEATH,
    QUEST_FAILED: RunOutcome.DEATH,
    QUEST_RESULTS: RunOutcome.QUEST_COMPLETED,
}
WEAPON_USAGE_SLOTS = 53


def _player(session):
    return session.world.players[0]


# Per-tick comparison: (label, core snapshot field, Python getter, f32?). Floats compare as F32 bits.
FIELDS: tuple[tuple[str, str, Callable, bool], ...] = (
    ("rng", "globals.rng", lambda s: s.world.state.rng.state, False),
    ("kills", "globals.creature_kill_count", lambda s: s.world.creatures.kill_count, False),
    ("pending_perks", "globals.perk_pending_count", lambda s: s.world.state.perk_selection.pending_count, False),
    ("shots_fired", "globals.highscore_record_shots_fired", lambda s: s.world.state.shots_fired, False),
    ("shots_hit", "globals.highscore_record_shots_hit", lambda s: s.world.state.shots_hit, False),
    ("reflex_boost", "globals.bonus_reflex_boost_timer", lambda s: s.world.state.bonuses.reflex_boost, True),
    ("freeze", "globals.bonus_freeze_timer", lambda s: s.world.state.bonuses.freeze, True),
    ("weapon_power_up", "globals.bonus_weapon_power_up_timer", lambda s: s.world.state.bonuses.weapon_power_up, True),
    ("energizer", "globals.bonus_energizer_timer", lambda s: s.world.state.bonuses.energizer, True),
    ("double_xp", "globals.bonus_double_xp_timer", lambda s: s.world.state.bonuses.double_experience, True),
    ("player.pos_x", "players[0].pos_x", lambda s: _player(s).pos.x, True),
    ("player.pos_y", "players[0].pos_y", lambda s: _player(s).pos.y, True),
    ("player.health", "players[0].health", lambda s: _player(s).health, True),
    ("player.death_timer", "players[0].death_timer", lambda s: _player(s).death_timer, True),
    ("player.heading", "players[0].heading", lambda s: _player(s).heading, True),
    ("player.aim_heading", "players[0].aim_heading", lambda s: _player(s).aim_heading, True),
    ("player.experience", "players[0].experience", lambda s: _player(s).experience, False),
    ("player.level", "players[0].level", lambda s: _player(s).level, False),
    ("player.ammo", "players[0].ammo", lambda s: _player(s).weapon.ammo, True),
    ("player.weapon_id", "players[0].weapon_id", lambda s: int(_player(s).weapon.weapon_id), False),
)
# Result-only fields read from the core's last compared snapshot.
RESULT_FIELDS = (
    "globals.game_state_pending",
    "globals.run_elapsed_ms",
    "globals.quest_spawn_timeline",
    *(f"globals.weapon_usage_time[{i}]" for i in range(WEAPON_USAGE_SLOTS)),
)


def _schema_index() -> dict[str, int]:
    schema = json.loads((CORE / "schema.json").read_text())
    names = [
        f"{group['name']}{f'[{i}]' if group['count'] > 1 else ''}.{field}"
        for group in schema
        for i in range(group["count"])
        for field in group["fields"]
    ]
    return {name: index for index, name in enumerate(names)}


def _bits(value, floating: bool) -> int:
    if floating:
        return struct.unpack("<I", struct.pack("<f", value))[0]
    return int(value) & 0xFFFFFFFF


def _from_bits(bits: int, floating: bool):
    return struct.unpack("<f", struct.pack("<I", bits))[0] if floating else bits


class Stream:
    """An input/command stream in the core's transport: its config and tick records."""

    def __init__(self, name: str, payload: bytes):
        self.name = name
        self.payload = payload
        self.config = struct.unpack_from(f"<{CONFIG_BYTES // 4}I", payload, 0)
        self.ticks: list[ReplayTick] = []
        offset = CONFIG_BYTES
        while offset < len(payload):
            mx, my, ax, ay, flags, count = struct.unpack_from("<4fII", payload, offset)
            offset += 24
            commands = []
            for _ in range(count):
                kind, argument = struct.unpack_from("<ii", payload, offset)
                offset += 8
                commands.append(
                    PerkPickCommand(player_index=0, choice_index=argument)
                    if kind == 1
                    else PerkMenuOpenCommand(player_index=0),
                )
            self.ticks.append(ReplayTick(inputs=[(mx, my, ax, ay, flags)], commands=commands))

    def run_spec(self) -> RunSpec:
        seed, mode, major, minor, unlock, unlock_full, detail, violence, friendly, hardcore, retry, preserve_bugs = (
            self.config[:12]
        )
        mode = GameMode(mode)
        return RunSpec(
            game_mode_id=mode,
            seed=seed,
            quest_level=QuestLevel(major, minor) if mode == GameMode.QUESTS else None,
            hardcore=bool(hardcore),
            preserve_bugs=bool(preserve_bugs),
            quest_fail_retry_count=retry,
            detail_preset=detail,
            violence_disabled=violence,
            friendly_fire=bool(friendly),
            status=RunStatus(
                quest_unlock_index=unlock,
                quest_unlock_index_hardcore=unlock_full,
                weapon_usage_counts=tuple(self.config[12 : 12 + WEAPON_USAGE_SLOTS]),
            ),
        )


def load_streams(rsi_dir: Path, fixtures_dir: Path) -> tuple[list[Stream], dict[str, str]]:
    streams = [Stream(path.name, path.read_bytes()) for path in sorted(rsi_dir.glob("*.rsi"))]
    unsupported = {}
    for path in sorted(fixtures_dir.glob("*.crd")):
        try:
            streams.append(Stream(path.name, encode(load_replay_file(path), None)))
        except ValueError as exc:
            unsupported[path.name] = str(exc)
    return streams, unsupported


def run_core(native: Path, stream: Stream, columns: list[int]) -> tuple[list[tuple[int, ...]], int, str]:
    """Selected snapshot columns after init and after every accepted tick, the exit code and stderr."""

    with tempfile.NamedTemporaryFile(delete=False) as fields:
        fields.write(struct.pack(f"<{len(columns)}I", *columns))
    try:
        proc = subprocess.run(
            [str(native), "--fields", fields.name],
            input=stream.payload,
            capture_output=True,
            check=False,
        )
    finally:
        os.unlink(fields.name)
    rows, data, offset = [], proc.stdout, 0
    while offset < len(data):
        (count,) = struct.unpack_from("<I", data, offset)
        rows.append(struct.unpack_from(f"<{count}I", data, offset + 4))
        offset += 4 + 4 * count
    return rows, proc.returncode, proc.stderr.decode()


def core_result(row: dict[str, int], mode: GameMode) -> RunResult:
    """The core does not export a RunResult yet; derive it from its state with Python's definitions."""

    state = row["globals.game_state_pending"]
    outcome = TERMINAL_OUTCOMES.get(state, RunOutcome.INCOMPLETE)
    elapsed = row["globals.quest_spawn_timeline"] if mode == GameMode.QUESTS else row["globals.run_elapsed_ms"]
    elapsed = struct.unpack("<i", struct.pack("<I", elapsed))[0]
    health = _from_bits(row["players[0].health"], True)
    pending = row["globals.perk_pending_count"]
    fired = struct.unpack("<i", struct.pack("<I", row["globals.highscore_record_shots_fired"]))[0]
    hit = struct.unpack("<i", struct.pack("<I", row["globals.highscore_record_shots_hit"]))[0]

    usage = SimpleNamespace(
        weapon_usage_time=[row[f"globals.weapon_usage_time[{i}]"] for i in range(WEAPON_USAGE_SLOTS)],
    )
    return RunResult(
        outcome=outcome,
        elapsed_ms=elapsed,
        kills=row["globals.creature_kill_count"],
        shots_fired=max(0, fired),
        shots_hit=max(0, min(hit, max(0, fired))),
        rng_state=row["globals.rng"],
        pending_perks=pending,
        quest_final_ms=(
            compute_quest_final_time(
                base_time_ms=elapsed,
                player_health_values=(health,),
                pending_perk_count=pending,
            ).final_time_ms
            if outcome == RunOutcome.QUEST_COMPLETED
            else None
        ),
        players=(
            PlayerRunResult(
                experience=row["players[0].experience"],
                health=health,
                most_used_weapon_id=most_used_weapon_id_for_player(
                    usage,
                    fallback_weapon_id=WeaponId(row["players[0].weapon_id"]),
                ),
            ),
        ),
    )


def compare(stream: Stream, native: Path) -> dict:
    index = _schema_index()
    names = [core for _, core, _, _ in FIELDS] + [name for name in RESULT_FIELDS if name not in {f[1] for f in FIELDS}]
    core_rows, exit_code, stderr = run_core(native, stream, [index[name] for name in names])

    spec = stream.run_spec()
    session = initialize_run(spec).session
    report: dict = {
        "preserve_bugs": spec.preserve_bugs,
        "ticks": len(stream.ticks),
        "core_ticks": len(core_rows) - 1,
        "core_exit": exit_code,
        "core_stderr": stderr.strip(),
    }
    first_divergence = None
    terminal = {"python": None, "core": None}
    python_ticks = 0
    python_error = None
    run_down = None
    run_down_over = None
    for tick_index in range(len(core_rows)):
        if tick_index:
            try:
                step = step_replay_tick(session, stream.ticks[tick_index - 1])
            except IllegalCommandError as exc:
                python_error = f"tick {tick_index - 1}: {type(exc).__name__}: {exc}"
                break
            python_ticks = tick_index
            if run_down is None and step.outcome is not None:
                run_down = RunDown(outcome=step.outcome, end_tick=tick_index - 1)
            if run_down is not None and run_down_over is None and run_down.tick(step.timing.frame_dt_ms_i32):
                run_down_over = tick_index
        row = dict(zip(names, core_rows[tick_index], strict=True))
        if terminal["python"] is None and session.terminal_outcome() is not None:
            terminal["python"] = {"tick": tick_index, "outcome": str(session.terminal_outcome())}
        if terminal["core"] is None and row["globals.game_state_pending"] in TERMINAL_OUTCOMES:
            terminal["core"] = {
                "tick": tick_index,
                "outcome": str(TERMINAL_OUTCOMES[row["globals.game_state_pending"]]),
            }
        if first_divergence is None:
            differences = {}
            for label, core_name, getter, floating in FIELDS:
                python_bits = _bits(getter(session), floating)
                if python_bits != row[core_name]:
                    differences[label] = {
                        "python": _from_bits(python_bits, floating),
                        "core": _from_bits(row[core_name], floating),
                    }
            if differences:
                first_divergence = {"snapshot": tick_index, "fields": differences}

    compared_tick = python_ticks
    row = dict(zip(names, core_rows[compared_tick], strict=True))
    expected = build_run_result(session, outcome=session.end_outcome())
    actual = core_result(row, spec.game_mode_id)
    mismatches = run_result_mismatches(expected, actual)
    report.update(
        python_ticks=python_ticks,
        python_error=python_error,
        result_tick=compared_tick,
        first_divergence=first_divergence,
        terminal=terminal,
        result_mismatches=mismatches,
        python_result=_result_json(expected),
        core_result=_result_json(actual),
    )
    # The core runs the whole stream, or rejects the tick after its run-down (exit 5), where Python's
    # `RunDown` ends too. Any other rejection is a failure, even when Python stopped at the same tick.
    stepped = len(core_rows) - 1
    core_finished = (exit_code == 0 and stepped == len(stream.ticks)) or (exit_code == 5 and run_down_over == stepped)
    report["agree"] = (
        core_finished
        and python_error is None
        and python_ticks == stepped
        and first_divergence is None
        and terminal["python"] == terminal["core"]
        and not mismatches
    )
    return report


def _result_json(result: RunResult) -> dict:
    return json.loads(msgspec.json.encode(result))


def _compare_job(args):
    stream, native = args
    return stream.name, compare(stream, native)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--native", type=Path, default=CORE / "build/native/core")
    parser.add_argument("--corpus", type=Path, default=CORE / "build/fixtures", help="Bot corpus from matrix.mjs")
    parser.add_argument("--fixtures", type=Path, default=ROOT / "tests/fixtures/replays")
    parser.add_argument("--out", type=Path, default=CORE / "build/gate.json")
    parser.add_argument("--only", action="append", default=[], help="Stream name to compare; repeat for several")
    parser.add_argument("--jobs", type=int, default=os.cpu_count())
    args = parser.parse_args()

    streams, unsupported = load_streams(args.corpus, args.fixtures)
    names = {stream.name for stream in streams}
    if args.only:
        if unknown := sorted(set(args.only) - names):
            parser.error(f"unknown streams: {', '.join(unknown)}")
        streams = [stream for stream in streams if stream.name in args.only]
    else:
        # The checked-in matrix results name every bot scenario; a partial corpus must not pass.
        cases = json.loads((CORE / "results/matrix.json").read_text())["cases"]
        if missing := sorted({case["name"] + ".rsi" for case in cases} - names):
            parser.error(f"{len(missing)} bot streams missing from {args.corpus}; run checks/matrix.mjs")
    jobs = [(stream, args.native) for stream in streams]
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        results = dict(pool.map(_compare_job, jobs))
    report = {
        "streams": dict(sorted(results.items())),
        "unsupported": unsupported,
        "agree": sum(r["agree"] for r in results.values()),
        "total": len(results),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    for name, result in report["streams"].items():
        where = result["first_divergence"]["snapshot"] if result["first_divergence"] else "-"
        status = "agree" if result["agree"] else "DIFFER"
        print(f"{status:7} {name:32} ticks {result['python_ticks']:6}/{result['ticks']:<6} first diff {where}")
    print(f"{report['agree']}/{report['total']} streams agree; {len(unsupported)} fixtures unsupported; {args.out}")
    sys.exit(0 if report["agree"] == report["total"] else 1)


if __name__ == "__main__":
    main()
