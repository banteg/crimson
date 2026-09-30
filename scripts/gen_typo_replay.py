"""Record a Typ-o replay fixture headlessly: a scripted typist plays until the creatures win.

Writes the replay and its per-tick checkpoint sidecar, as live play records them:

    uv run python scripts/gen_typo_replay.py tests/fixtures/replays/typo-<score>.crd
"""

from __future__ import annotations

import random
import string
import sys
from pathlib import Path

from crimson.game_modes import GameMode
from crimson.replay import ReplayRecorder, dump_replay_file, pack_tick
from crimson.replay.checkpoints import (
    DEFAULT_CHECKPOINT_SAMPLE_RATE,
    FORMAT_VERSION,
    ReplayCheckpoints,
    build_checkpoint,
    dump_checkpoints_file,
)
from crimson.replay.rng_call_order import RngCallOrder
from crimson.replay.ticks import step_replay_tick
from crimson.sim.commands import GameCommand, TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from crimson.sim.input import PlayerInput
from crimson.sim.run_init import initialize_run
from crimson.sim.run_result import build_run_result
from crimson.sim.run_spec import RunSpec
from crimson.sim.sessions import DeterministicSession
from grim.config import default_player_controls

SEED = 0x7E0
# Names from a local Typ-o score table, which late names draw from.
HIGHSCORE_NAMES = ("banteg", "Quick.Fox", "Zeta")
# The typist gives up after this long, and the creatures close in.
TYPING_TICKS = 15000


def _nearest_word(session: DeterministicSession) -> str:
    world = session.world
    player = world.players[0]
    alive = [creature.active and creature.hp > 0.0 for creature in world.creatures.entries]
    named = world.state.typo.names.active_entries(active_mask=alive)
    if not named:
        return ""
    _, name = min(named, key=lambda entry: (world.creatures.entries[entry[0]].pos - player.pos).length_sq())
    return name


class Typist:
    """A key a frame, going for the nearest creature, with the odd typo, fix and `reload`."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.word = ""

    def commands(self, session: DeterministicSession) -> list[GameCommand]:
        rng = self.rng
        text = session.world.state.typo.typing.text
        if not self.word:
            self.word = "reload" if rng.random() < 0.05 else _nearest_word(session)
        if not self.word or rng.random() < 0.15:
            return []
        if not self.word.startswith(text):
            return [TypoBackspaceCommand(player_index=0)]
        if text == self.word:
            self.word = ""
            return [TypoSubmitCommand(player_index=0)]
        ch = rng.choice(string.ascii_lowercase) if rng.random() < 0.03 else self.word[len(text)]
        return [TypoCharCommand(player_index=0, ch=ch)]


def main() -> None:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("artifacts/tests/typo_replay.crd")
    run = RunSpec(game_mode_id=GameMode.TYPO, seed=SEED, typo_highscore_names=HIGHSCORE_NAMES)
    session = initialize_run(run).session
    recorder = ReplayRecorder(run)
    controls = default_player_controls(0)
    idle = [
        PlayerInput(
            move_mode=controls.movement,
            aim_scheme=controls.aim_scheme,
            move_forward_pressed=False,
            move_backward_pressed=False,
            turn_left_pressed=False,
            turn_right_pressed=False,
        ),
    ]
    typist = Typist(random.Random(SEED))
    checkpoints = []
    rng_call_order = RngCallOrder()
    # Record like live play: stop on the tick that ends the run.
    outcome = None
    while outcome is None:
        commands = typist.commands(session) if recorder.tick_index < TYPING_TICKS else []
        tick = pack_tick(idle, commands)
        tick_index = recorder.record(tick)
        with rng_call_order.recording(session.world.state.rng):
            step = step_replay_tick(session, tick)
        if tick_index % DEFAULT_CHECKPOINT_SAMPLE_RATE == 0:
            checkpoints.append(
                build_checkpoint(
                    tick_index=tick_index,
                    world=session.world,
                    elapsed_ms=session.elapsed_ms,
                    rng_callers_crc32=rng_call_order.crc32(),
                    deaths=step.events.deaths,
                    events=step.events,
                ),
            )
        outcome = step.outcome
    result = build_run_result(session, outcome=outcome)
    replay = recorder.finish(result)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    dump_replay_file(out_path, replay)
    dump_checkpoints_file(
        out_path.with_name(f"{out_path.name}.chk"),
        ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=DEFAULT_CHECKPOINT_SAMPLE_RATE, checkpoints=checkpoints),
    )
    print(
        f"wrote {out_path} ticks={len(replay.ticks)} outcome={result.outcome} kills={result.kills} "
        f"score={result.players[0].experience} shots={result.shots_hit}/{result.shots_fired}",
    )


if __name__ == "__main__":
    main()
