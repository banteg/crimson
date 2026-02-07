from __future__ import annotations

from grim.geom import Vec2

from ...game_modes import GameMode
from ...gameplay import PlayerInput, weapon_assign_player
from ...replay import Replay, UnknownEvent, unpack_packed_player_input, unpack_input_flags, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint, build_checkpoint
from ...replay.original_capture import (
    ORIGINAL_CAPTURE_BOOTSTRAP_EVENT_KIND,
    apply_original_capture_bootstrap_payload,
    original_capture_bootstrap_payload_from_event_payload,
)
from ...weapons import WeaponId
from ..sessions import RushDeterministicSession
from ..world_state import WorldState
from .common import (
    ReplayRunnerError,
    RunResult,
    build_damage_scale_by_type,
    build_empty_fx_queues,
    player0_most_used_weapon_id,
    player0_shots,
    reset_players,
    status_from_snapshot,
)

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE


def _enforce_rush_loadout(world: WorldState) -> None:
    for player in world.players:
        if int(player.weapon_id) != int(RUSH_WEAPON_ID):
            weapon_assign_player(player, int(RUSH_WEAPON_ID))
        # `rush_mode_update` forces weapon+ammo every frame; keep ammo topped up.
        player.ammo = float(max(0, int(player.clip_size)))


def run_rush_replay(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    trace_rng: bool = False,
    checkpoints_out: list[ReplayCheckpoint] | None = None,
    checkpoint_ticks: set[int] | None = None,
) -> RunResult:
    if int(replay.header.game_mode_id) != int(GameMode.RUSH):
        raise ReplayRunnerError(
            f"replay game_mode_id={int(replay.header.game_mode_id)} does not match rush={int(GameMode.RUSH)}"
        )

    if warn_on_version_mismatch:
        warn_on_game_version_mismatch(replay, action="verification")

    events_by_tick: dict[int, list[UnknownEvent]] = {}
    for event in replay.events:
        if isinstance(event, UnknownEvent) and str(event.kind) == ORIGINAL_CAPTURE_BOOTSTRAP_EVENT_KIND:
            events_by_tick.setdefault(int(event.tick_index), []).append(event)
            continue
        raise ReplayRunnerError("rush replay does not support events")

    tick_rate = int(replay.header.tick_rate)
    if tick_rate <= 0:
        raise ReplayRunnerError(f"invalid tick_rate: {tick_rate}")
    dt_frame = 1.0 / float(tick_rate)

    world_size = float(replay.header.world_size)
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=bool(replay.header.hardcore),
        difficulty_level=int(replay.header.difficulty_level),
        preserve_bugs=bool(replay.header.preserve_bugs),
    )
    reset_players(
        world.players,
        world_size=world_size,
        player_count=int(replay.header.player_count),
    )
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )
    world.state.rng.srand(int(replay.header.seed))

    _enforce_rush_loadout(world)

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    damage_scale_by_type = build_damage_scale_by_type()
    session = RushDeterministicSession(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        detail_preset=5,
        fx_toggle=0,
        game_tune_started=False,
        clear_fx_queues_each_tick=True,
        enforce_loadout=lambda: _enforce_rush_loadout(world),
    )

    inputs = replay.inputs
    tick_limit = len(inputs) if max_ticks is None else min(len(inputs), max(0, int(max_ticks)))

    for tick_index in range(tick_limit):
        state = world.state
        state.game_mode = int(GameMode.RUSH)
        state.demo_mode_active = False

        for event in events_by_tick.get(int(tick_index), []):
            payload = original_capture_bootstrap_payload_from_event_payload(list(event.payload))
            if payload is None:
                raise ReplayRunnerError(f"invalid bootstrap payload at tick={tick_index}")
            apply_original_capture_bootstrap_payload(payload, state=state, players=list(world.players))

        packed_tick = inputs[tick_index]
        player_inputs: list[PlayerInput] = []
        for packed in packed_tick:
            mx, my, ax, ay, flags = unpack_packed_player_input(packed)
            fire_down, fire_pressed, _reload_pressed = unpack_input_flags(int(flags))
            player_inputs.append(
                PlayerInput(
                    move=Vec2(float(mx), float(my)),
                    aim=Vec2(float(ax), float(ay)),
                    fire_down=fire_down,
                    fire_pressed=fire_pressed,
                    reload_pressed=False,
                )
            )

        tick = session.step_tick(
            dt_frame=float(dt_frame),
            inputs=player_inputs,
            trace_rng=bool(trace_rng),
        )
        step = tick.step
        events = step.events

        if checkpoints_out is not None and checkpoint_ticks is not None and int(tick_index) in checkpoint_ticks:
            checkpoints_out.append(
                build_checkpoint(
                    tick_index=int(tick_index),
                    world=world,
                    elapsed_ms=float(tick.elapsed_ms),
                    rng_marks=tick.rng_marks,
                    deaths=events.deaths,
                    events=events,
                    command_hash=str(step.command_hash),
                )
            )

        if not any(player.health > 0.0 for player in world.players):
            tick_index += 1
            break
    else:
        tick_index = tick_limit

    for event in events_by_tick.get(int(tick_index), []):
        payload = original_capture_bootstrap_payload_from_event_payload(list(event.payload))
        if payload is None:
            raise ReplayRunnerError(f"invalid bootstrap payload at tick={tick_index}")
        apply_original_capture_bootstrap_payload(payload, state=world.state, players=list(world.players))

    shots_fired, shots_hit = player0_shots(world.state)
    most_used_weapon_id = player0_most_used_weapon_id(world.state, world.players)
    score_xp = int(world.players[0].experience) if world.players else 0

    return RunResult(
        game_mode_id=int(GameMode.RUSH),
        tick_rate=tick_rate,
        ticks=int(tick_index),
        elapsed_ms=int(session.elapsed_ms),
        score_xp=score_xp,
        creature_kill_count=int(world.creatures.kill_count),
        most_used_weapon_id=int(most_used_weapon_id),
        shots_fired=int(shots_fired),
        shots_hit=int(shots_hit),
        rng_state=int(world.state.rng.state),
    )
