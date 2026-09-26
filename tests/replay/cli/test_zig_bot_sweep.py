"""Cross-port sweep: Python bot runs verified by the Zig replay verifier.

Slow (minutes), so opt-in: `CRIMSON_ZIG_BOT_SWEEP=1 uv run pytest tests/replay/cli/test_zig_bot_sweep.py`.
`CRIMSON_ZIG_BOT_SWEEP_SEEDS=3,4` picks the seeds.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from functools import partial
from pathlib import Path

import msgspec
import pytest

import crimson.dbg.record as dbg_record
from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.replay import Replay
from crimson.sim.run_spec import RunSpec

from ._helpers import record_bot_replay, write_replay

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not os.environ.get("CRIMSON_ZIG_BOT_SWEEP"),
        reason="set CRIMSON_ZIG_BOT_SWEEP=1 to run the Zig bot replay sweep",
    ),
]

_SEEDS = tuple(int(seed) for seed in os.environ.get("CRIMSON_ZIG_BOT_SWEEP_SEEDS", "1,2").split(","))
_QUEST_LEVELS = tuple(f"{major}.{minor}" for major in range(1, 6) for minor in range(1, 11))
_MAX_TICKS = 216_000


def _cases() -> dict[str, Callable[[], Replay]]:
    cases: dict[str, Callable[[], Replay]] = {}
    for seed in _SEEDS:
        for level in _QUEST_LEVELS:
            run = RunSpec(game_mode_id=GameMode.QUESTS, seed=seed, quest_level=QuestLevel.parse(level))
            cases[f"quest-{level}-s{seed}"] = partial(record_bot_replay, run, max_ticks=_MAX_TICKS)
        survival = RunSpec(game_mode_id=GameMode.SURVIVAL, seed=seed)
        cases[f"survival-s{seed}"] = partial(record_bot_replay, survival, max_ticks=_MAX_TICKS)
        cases[f"survival-2p-s{seed}"] = partial(
            record_bot_replay,
            RunSpec(game_mode_id=GameMode.SURVIVAL, seed=seed, player_count=2),
            max_ticks=_MAX_TICKS,
        )
        cases[f"survival-perk-s{seed}"] = partial(
            record_bot_replay, survival, max_ticks=_MAX_TICKS, pick_perk=True, tail_ticks=3000,
        )
        cases[f"rush-s{seed}"] = partial(
            record_bot_replay, RunSpec(game_mode_id=GameMode.RUSH, seed=seed), max_ticks=_MAX_TICKS,
        )
        cases[f"typo-s{seed}"] = partial(
            record_bot_replay, RunSpec(game_mode_id=GameMode.TYPO, seed=seed), max_ticks=3000, type_every=12,
        )
    return cases


_CASES = _cases()


@pytest.fixture(scope="module")
def zig_bin() -> Path:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)
    return dbg_record._ZIG_BIN


@pytest.mark.parametrize("case", sorted(_CASES))
def test_zig_verify_matches_python_bot_run(tmp_path: Path, zig_bin: Path, case: str) -> None:
    replay = _CASES[case]()
    replay_path = write_replay(tmp_path, replay=replay, name=f"{case}.crd")

    result = dbg_record._run_process(
        [str(zig_bin), "replay", "verify", str(replay_path), "--format", "json"],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["result"] == json.loads(msgspec.json.encode(replay.result))
