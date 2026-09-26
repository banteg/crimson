from __future__ import annotations

from pathlib import Path

import msgspec
import zstandard as zstd

from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.replay import (
    REPLAY_TICK_DT,
    Replay,
    ReplayRecorder,
    ReplayTick,
    dump_replay,
    pack_tick_inputs,
    unpack_tick_inputs,
)
from crimson.replay.checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoints,
    default_checkpoints_path,
    dump_checkpoints_file,
)
from crimson.replay.driver.playback_driver import replay_with_simulated_result
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    GameCommand,
    PerkMenuOpenCommand,
    PerkPickCommand,
    TypoCharCommand,
    TypoSubmitCommand,
)
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec
from grim.geom import Vec2
from tests.support.replay_runner_helpers import _run_verify_playback, finish_replay


def build_replay(
    *,
    mode: GameMode,
    ticks: int,
    seed: int = 0xBEEF,
    player_count: int = 1,
    quest_level: str = "",
) -> Replay:
    parsed_level = QuestLevel.parse(quest_level) if str(quest_level).strip() else None
    recorder = ReplayRecorder(
        RunSpec(game_mode_id=mode, seed=int(seed), player_count=int(player_count), quest_level=parsed_level),
    )
    for _ in range(int(ticks)):
        recorder.record_tick(
            [PlayerInput(aim=Vec2(512.0, 512.0)) for _ in range(int(player_count))],
        )
    return finish_replay(recorder)


def build_typo_submit_replay(*, word: str = "reload", seed: int = 0xBEEF) -> Replay:
    recorder = ReplayRecorder(RunSpec(game_mode_id=GameMode.TYPO, seed=int(seed)))
    baseline = PlayerInput(aim=Vec2(512.0, 512.0))
    for ch in str(word):
        recorder.record_tick([baseline], commands=[TypoCharCommand(player_index=0, ch=ch)])
    recorder.record_tick([baseline], commands=[TypoSubmitCommand(player_index=0)])
    return finish_replay(recorder)


def claim_replay_stats(replay: Replay) -> Replay:
    return replay_with_simulated_result(replay)


def inject_tick_commands(replay: Replay, tick_index: int, commands: list[GameCommand]) -> None:
    old_tick = replay.ticks[tick_index]
    replay.ticks[tick_index] = msgspec.structs.replace(old_tick, commands=[*old_tick.commands, *commands])


def write_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(dump_replay(replay))
    return replay_path


def _write_current_payload(tmp_path: Path, *, payload: object, name: str) -> Path:
    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    raw = msgspec.msgpack.encode(payload)
    replay_path.write_bytes(zstd.ZstdCompressor(level=19).compress(raw))
    return replay_path


def _decoded_payload(replay: Replay) -> dict:
    return msgspec.msgpack.decode(zstd.ZstdDecompressor().decompress(dump_replay(replay)))


def write_current_typo_event_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    payload = _decoded_payload(replay)
    payload["ticks"][0][1] = [{"type": "typo_char", "player_index": 0, "ch": "x"}]
    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_unknown_command_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    payload = _decoded_payload(replay)
    payload["ticks"][0][1] = [{"type": "network_ping", "player_index": 0}]
    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_bad_event_player_index_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    payload = _decoded_payload(replay)
    payload["ticks"][0][1] = [{"type": "perk_menu_open", "player_index": payload["run"]["player_count"]}]
    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_missing_quest_level_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    payload = _decoded_payload(replay)
    payload["run"]["game_mode_id"] = int(GameMode.QUESTS)
    payload["run"]["quest_level"] = None
    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_mode_player_count_replay(
    tmp_path: Path,
    *,
    replay: Replay,
    name: str,
    mode: GameMode,
    player_count: int,
) -> Path:
    payload = _decoded_payload(replay)
    payload["run"]["game_mode_id"] = int(mode)
    payload["run"]["player_count"] = int(player_count)
    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_bad_tick_player_count_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    payload = _decoded_payload(replay)
    payload["ticks"][0][0] = []
    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_current_missing_perk_choice_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    payload = _decoded_payload(replay)
    payload["ticks"][0][1] = [{"type": "perk_pick", "player_index": 0}]
    return _write_current_payload(tmp_path, payload=payload, name=name)


def write_checkpoint_sidecar(
    replay_path: Path,
    replay: Replay,
    *,
    mutate_checkpoint: bool = False,
) -> Path:
    checkpoint_ticks = {0}
    checkpoints = []
    _run_verify_playback(replay, checkpoints_out=checkpoints, checkpoint_ticks=checkpoint_ticks)
    if mutate_checkpoint:
        checkpoints[0] = msgspec.structs.replace(
            checkpoints[0],
            score_xp=999999,
        )
    payload = ReplayCheckpoints(
        version=int(FORMAT_VERSION),
        sample_rate=1,
        checkpoints=list(checkpoints),
    )
    sidecar_path = default_checkpoints_path(replay_path)
    dump_checkpoints_file(sidecar_path, payload)
    return sidecar_path


run_verify_playback = _run_verify_playback


def record_bot_replay(
    run: RunSpec,
    *,
    max_ticks: int = 6000,
    fire: bool = True,
    pick_perk: bool = False,
    tail_ticks: int = 30,
    type_every: int = 0,
) -> Replay:
    """Record a run whose players aim at the nearest creature (and fire, if `fire`).

    Recording stops on the tick that ends the run, or after `max_ticks`. With
    `pick_perk`, the first pending perk is opened and picked, and recording
    stops `tail_ticks` ticks later. With `type_every`, every that many ticks the
    Typ-o player types and submits the name of the nearest creature.
    """

    session = initialize_run(run).session
    recorder = ReplayRecorder(run)
    picked_at: int | None = None
    for tick_index in range(int(max_ticks)):
        world = session.world
        targets = [creature for creature in world.creatures.entries if creature.active and creature.hp > 0.0]
        inputs = []
        for player in world.players:
            nearest = min(targets, key=lambda creature: (creature.pos - player.pos).length_sq(), default=None)
            aim = nearest.pos if nearest is not None else Vec2(player.pos.x + 100.0, player.pos.y)
            inputs.append(PlayerInput(aim=aim, fire_down=fire, fire_pressed=fire and tick_index % 2 == 0))
        # Step the same f32-quantized inputs the replay stores.
        inputs = unpack_tick_inputs(pack_tick_inputs(inputs))
        commands: list[GameCommand] = []
        if pick_perk and picked_at is None and world.state.perk_selection.pending_count > 0:
            commands = [PerkMenuOpenCommand(player_index=0), PerkPickCommand(player_index=0, choice_index=0)]
            picked_at = tick_index
        if type_every and tick_index % int(type_every) == 0:
            word = _typo_bot_word(world)
            if word:
                commands = [*(TypoCharCommand(player_index=0, ch=ch) for ch in word), TypoSubmitCommand(player_index=0)]
        recorder.record_tick(inputs, commands=commands)
        step = session.step_tick(dt=REPLAY_TICK_DT, inputs=inputs, commands=commands)
        if step.outcome is not None or (picked_at is not None and tick_index - picked_at >= int(tail_ticks)):
            break
    return finish_replay(recorder)


def _typo_bot_word(world) -> str:
    player = world.players[0]
    names = world.state.typo.names.names
    named = [
        (creature, names[index])
        for index, creature in enumerate(world.creatures.entries)
        if creature.active and creature.hp > 0.0 and names[index]
    ]
    nearest = min(named, key=lambda entry: (entry[0].pos - player.pos).length_sq(), default=None)
    return "" if nearest is None else nearest[1]


def with_idle_ticks(replay: Replay, count: int) -> Replay:
    """`replay` with `count` idle ticks appended; the recorded result is kept."""

    idle = ReplayTick(inputs=pack_tick_inputs([PlayerInput() for _ in range(replay.run.player_count)]), commands=[])
    return msgspec.structs.replace(replay, ticks=[*replay.ticks, *([idle] * int(count))])


def with_tick_commands(replay: Replay, tick_index: int, commands: list[GameCommand]) -> Replay:
    """`replay` with one tick's commands replaced; the recorded result is kept."""

    ticks = list(replay.ticks)
    ticks[tick_index] = msgspec.structs.replace(ticks[tick_index], commands=list(commands))
    return msgspec.structs.replace(replay, ticks=ticks)


def write_payload_bytes(tmp_path: Path, *, payload: bytes, name: str) -> Path:
    """Write raw msgpack payload bytes in the replay zstd envelope."""

    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(zstd.ZstdCompressor(level=19).compress(payload))
    return replay_path
