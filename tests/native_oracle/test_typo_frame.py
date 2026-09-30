"""`typo_gameplay_update_and_render` (0x004457c0) vs `typo_gameplay_update`, whole Typ-o runs from reset.

Each case resets the game natively (`gameplay_reset_state`) and in the port (`initialize_run`) from
one seed, then plays both frame by frame with random frame times and a scripted typist, and after
every frame compares the creature, projectile, sprite and effect pools, the player, the typing,
spawn and score state, the name table, the end of the run and the RNG. Only drawing is left out:
Grim does nothing, `fx_queue_render` just empties the decal queues, and the terrain and UI element
passes are stubbed. No score table is on disk, so the first highscore-name pick loads an empty one.
"""

from __future__ import annotations

import random
import string
import struct

from crimson.creatures.runtime import CreatureState
from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from crimson.math_parity import f32
from crimson.sim.commands import GameCommand, TypoBackspaceCommand, TypoCharCommand, TypoSubmitCommand
from crimson.sim.run_init import initialize_run
from crimson.sim.run_result import run_shot_counts
from crimson.sim.run_spec import RunSpec
from crimson.sim.sessions import DeterministicSession
from crimson.sim.state_types import PlayerState
from crimson.sim.timing import ftol_ms_i32
from tests.support.factories import player_input

from ._support import (
    CREATURE_LAYOUT,
    CREATURE_POOL_SLOTS,
    CREATURE_STRIDE,
    PROJECTILE_LAYOUT,
    PROJECTILE_STRIDE,
    SPRITE_LAYOUT,
    SPRITE_STRIDE,
    Mismatch,
    compare_effect_pool,
    compare_fields,
    install_fake_grim,
    mismatch_report,
    prepare_gameplay,
    python_sprite,
)
from .test_projectiles import _python_projectile

_ENTER_SCANCODE = 0x1C
_BACKSPACE = 8
_NAME_STRIDE = 64
# `highscore_active_record.score_xp`.
_SCORE_XP = 0x00487064
_FRAME_DTS = (f32(1.0 / 60.0), f32(1.0 / 60.0), f32(1.0 / 30.0), f32(0.016), f32(0.017))
_RUN_DOWN_FRAMES = 20

_CREATURE_FRAME_LAYOUT: dict[str, tuple[int, str]] = {
    **CREATURE_LAYOUT,
    "collision_flag": (0x09, "B"),
    "collision_timer": (0x0C, "f"),
    "target_heading": (0x30, "f"),
    "hit_flash_timer": (0x38, "f"),
    "force_target": (0x4C, "B"),
    "target_x": (0x50, "f"),
    "target_y": (0x54, "f"),
    "attack_cooldown": (0x60, "f"),
    "target_player": (0x70, "b"),
    "anim_phase": (0x94, "f"),
}
_PLAYER_FRAME_LAYOUT: dict[str, tuple[int, str]] = {
    "death_timer": (0x10, "f"),
    "pos_x": (0x14, "f"),
    "pos_y": (0x18, "f"),
    "health": (0x24, "f"),
    "size": (0x34, "f"),
    "aim_x": (0x50, "f"),
    "aim_y": (0x54, "f"),
    "move_phase": (0x94, "f"),
    "experience": (0xAC, "i"),
    "level": (0xB4, "i"),
    "spread_heat": (0x2B8, "f"),
    "weapon_id": (0x2C0, "i"),
    "clip_size": (0x2C4, "f"),
    "reload_active": (0x2C8, "B"),
    "ammo": (0x2CC, "f"),
    "reload_timer": (0x2D0, "f"),
    "shot_cooldown": (0x2D4, "f"),
    "reload_timer_max": (0x2D8, "f"),
    "muzzle_flash_alpha": (0x2FC, "f"),
    "aim_heading": (0x300, "f"),
}


class _Keys:
    """This frame's Enter state and polled key, as `grim_is_key_down` and `console_input_poll` report them."""

    def __init__(self) -> None:
        self.enter = False
        self.char = 0

    def take_char(self) -> int:
        char, self.char = self.char, 0
        return char


class _Typist:
    """Types creature names (or `reload`, or junk) a key a frame at a random pace, with typos and backspaces."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.word = ""
        self.pace = rng.choice((1, 1, 2, 3))
        # Then the typist gives up and the creatures win.
        self.frames = rng.randrange(600, 2000)

    def frame(self, session: DeterministicSession) -> tuple[bool, int]:
        rng = self.rng
        self.frames -= 1
        if self.frames < 0:
            return False, 0
        typo = session.world.state.typo
        text = typo.typing.text
        if not self.word:
            names = [name for index, name in typo.names.active_entries(active_mask=_alive(session))]
            roll = rng.random()
            if roll < 0.05:
                self.word = "reload"
            elif roll < 0.1 or not names:
                self.word = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randrange(1, 20)))
            else:
                self.word = rng.choice(names)
        if rng.randrange(self.pace):
            return False, 0
        if text and not self.word.startswith(text):
            return False, _BACKSPACE
        if text == self.word or len(text) >= len(self.word):
            self.word = ""
            # Enter reads before the polled key: a word may start the same frame.
            return True, ord(rng.choice(string.ascii_lowercase)) if rng.random() < 0.1 else 0
        if rng.random() < 0.05:
            return False, ord(rng.choice(string.ascii_lowercase))
        return False, ord(self.word[len(text)])


def _alive(session: DeterministicSession) -> list[bool]:
    return [creature.active and creature.hp > 0.0 for creature in session.world.creatures.entries]


def _commands(enter: bool, char: int) -> list[GameCommand]:
    commands: list[GameCommand] = [TypoSubmitCommand(player_index=0)] if enter else []
    if char == _BACKSPACE:
        commands.append(TypoBackspaceCommand(player_index=0))
    elif char:
        commands.append(TypoCharCommand(player_index=0, ch=chr(char)))
    return commands


def _python_creature(creature: CreatureState) -> dict[str, float | int | None]:
    return {
        "active": int(creature.active),
        "phase_seed": creature.phase_seed,
        "lifecycle_stage": creature.lifecycle_stage,
        "pos_x": creature.pos.x,
        "pos_y": creature.pos.y,
        "vel_x": creature.vel.x,
        "vel_y": creature.vel.y,
        "health": creature.hp,
        "max_health": creature.max_hp,
        "heading": creature.heading,
        "size": creature.size,
        "tint_r": creature.tint.r,
        "tint_g": creature.tint.g,
        "tint_b": creature.tint.b,
        "tint_a": creature.tint.a,
        "contact_damage": creature.contact_damage,
        "move_speed": creature.move_speed,
        "reward_value": creature.reward_value,
        "type_id": int(creature.type_id),
        "link_index": creature.link_index,
        "target_offset_x": None if creature.target_offset is None else creature.target_offset.x,
        "target_offset_y": None if creature.target_offset is None else creature.target_offset.y,
        "orbit_angle": creature.orbit_angle,
        "orbit_radius": creature.orbit_radius,
        "flags": int(creature.flags),
        "ai_mode": int(creature.ai_mode),
        "collision_flag": int(creature.plague_infected),
        "collision_timer": creature.collision_timer,
        "target_heading": creature.target_heading,
        "hit_flash_timer": creature.hit_flash_timer,
        "force_target": creature.force_target,
        "target_x": creature.target.x,
        "target_y": creature.target.y,
        "attack_cooldown": creature.attack_cooldown,
        "target_player": creature.target_player,
        "anim_phase": creature.anim_phase,
    }


def _python_player(player: PlayerState) -> dict[str, float | int]:
    return {
        "death_timer": player.death_timer,
        "pos_x": player.pos.x,
        "pos_y": player.pos.y,
        "health": player.health,
        "size": player.size,
        "aim_x": player.aim.x,
        "aim_y": player.aim.y,
        "move_phase": player.move_phase,
        "experience": player.experience,
        "level": player.level,
        "spread_heat": player.spread_heat,
        "weapon_id": int(player.weapon.weapon_id),
        "clip_size": float(player.weapon.clip_size),
        "reload_active": int(player.weapon.reload_active),
        "ammo": player.weapon.ammo,
        "reload_timer": player.weapon.reload_timer,
        "shot_cooldown": player.weapon.shot_cooldown,
        "reload_timer_max": player.weapon.reload_timer_max,
        "muzzle_flash_alpha": player.muzzle_flash_alpha,
        "aim_heading": player.aim_heading,
    }


def _c_string(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("latin-1")


def _pool_rows(oracle, symbol: str, stride: int, count: int, layout: dict[str, tuple[int, str]]) -> list[dict | None]:
    """One read of a native pool: each row's fields, or None for a row whose `active` byte is clear."""

    raw = oracle.read(symbol, stride * count)
    return [
        {name: struct.unpack_from(f"<{fmt}", raw, row + offset)[0] for name, (offset, fmt) in layout.items()}
        if raw[row]
        else None
        for row in range(0, stride * count, stride)
    ]


def _compare_pool(
    oracle, symbol: str, stride: int, layout: dict[str, tuple[int, str]], entries: list, to_python, label: str,
) -> list[Mismatch]:
    base = oracle.resolve(symbol)
    mismatches = []
    for index, (native, entry) in enumerate(zip(_pool_rows(oracle, symbol, stride, len(entries), layout), entries, strict=True)):
        if native is None and not entry.active:
            continue
        address = base + index * stride
        mismatches += compare_fields(
            f"{label}[{index}]", native or oracle.read_fields(address, layout), to_python(entry), address=address,
        )
    return mismatches


def _compare(
    oracle, session: DeterministicSession, *, run_started: bool, run_over: bool, effects: bool, case: str,
) -> list[Mismatch]:
    world = session.world
    state = world.state
    typo = state.typo
    creatures = world.creatures.entries
    mismatches = _compare_pool(
        oracle, "creature_pool", CREATURE_STRIDE, _CREATURE_FRAME_LAYOUT, creatures, _python_creature, f"{case} creature",
    )
    names = oracle.read("typo_target_name_table", _NAME_STRIDE * CREATURE_POOL_SLOTS)
    for index, creature in enumerate(creatures):
        native_name = _c_string(names[index * _NAME_STRIDE : (index + 1) * _NAME_STRIDE])
        if creature.active and native_name != typo.names.names[index]:
            mismatches.append(Mismatch(f"{case} {native_name!r} != {typo.names.names[index]!r}", f"name[{index}]", 0, 0, 0))
    mismatches += _compare_pool(
        oracle, "projectile_pool", PROJECTILE_STRIDE, PROJECTILE_LAYOUT, state.projectiles.entries, _python_projectile,
        f"{case} projectile",
    )
    mismatches += _compare_pool(
        oracle, "sprite_effect_pool", SPRITE_STRIDE, SPRITE_LAYOUT, state.sprite_effects.entries, python_sprite,
        f"{case} sprite",
    )
    if effects:
        mismatches += compare_effect_pool(oracle, state.effects, case)

    player_address = oracle.resolve("player_state_table")
    mismatches += compare_fields(
        f"{case} player", oracle.read_fields(player_address, _PLAYER_FRAME_LAYOUT), _python_player(world.players[0]),
        address=player_address,
    )

    shots_fired, shots_hit = run_shot_counts(state)
    native_globals = {
        "input": _c_string(oracle.read("typo_input_buffer", 0x80)),
        "submit_count": oracle.read_i32("typo_submit_count"),
        "match_count": oracle.read_i32("typo_match_count"),
        "shots_fired": oracle.read_i32("highscore_record_shots_fired"),
        "shots_hit": oracle.read_i32("highscore_record_shots_hit"),
        "target_world_x": oracle.read_f32("typo_target_world_x"),
        "target_world_y": oracle.read_f32("typo_target_world_y"),
        "spawn_cooldown": oracle.read_i32("survival_spawn_cooldown"),
        "highscore_names_loaded": oracle.read_u8("typo_word_highscore_cache_ready"),
        "score_xp": oracle.read_i32(_SCORE_XP),
        "elapsed_ms": oracle.read_i32("survival_elapsed_ms"),
        "kills": oracle.read_i32("creature_kill_count"),
        "shotgun_time": oracle.read_u32(oracle.resolve("weapon_usage_time") + 4 * 3),
        "pistol_time": oracle.read_u32(oracle.resolve("weapon_usage_time") + 4 * 1),
        "weapon_power_up": oracle.read_f32("bonus_weapon_power_up_timer"),
        "reflex_boost": oracle.read_f32("bonus_reflex_boost_timer"),
        "energizer": oracle.read_f32("bonus_energizer_timer"),
        "time_scale_active": oracle.read_u8("time_scale_active"),
        "camera_shake_timer": oracle.read_f32("camera_shake_timer"),
        "camera_shake_pulses": oracle.read_i32("camera_shake_pulses"),
        "aux_timer": oracle.read_f32("player_aux_timer"),
        "run_over": int(oracle.read_u32("game_state_pending") == GameStateId.GAME_OVER),
    }
    python_globals = {
        "input": typo.typing.text,
        "submit_count": typo.typing.submit_count,
        "match_count": typo.typing.match_count,
        "shots_fired": shots_fired,
        "shots_hit": shots_hit,
        "target_world_x": typo.target_world.x,
        "target_world_y": typo.target_world.y,
        "spawn_cooldown": typo.spawn_cooldown_ms,
        "highscore_names_loaded": int(typo.highscore_names.loaded),
        "score_xp": state.highscore_score_xp,
        "elapsed_ms": int(session.elapsed_ms),
        "kills": world.creatures.kill_count,
        "shotgun_time": state.weapon_usage_time[3],
        "pistol_time": state.weapon_usage_time[1],
        "weapon_power_up": state.bonuses.weapon_power_up,
        "reflex_boost": state.bonuses.reflex_boost,
        "energizer": state.bonuses.energizer,
        "time_scale_active": int(state.time_scale_active),
        "camera_shake_timer": state.camera_shake_timer,
        "camera_shake_pulses": state.camera_shake_pulses,
        "aux_timer": world.players[0].aux_timer,
        "run_over": int(run_over),
    }
    if not run_started:
        # Native sets its static aim point on the first frame.
        del native_globals["target_world_x"], native_globals["target_world_y"]
    for name, native_value in native_globals.items():
        if native_value != python_globals[name] and not (
            isinstance(native_value, float) and struct.pack("<f", native_value) == struct.pack("<f", python_globals[name])
        ):
            mismatches.append(Mismatch(case, name, native_value, python_globals[name], 0))  # ty: ignore[invalid-argument-type]
    if oracle.rand_state != state.rng.state:
        mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, state.rng.state, 0))
    return mismatches


def _setup_native(oracle, keys: _Keys) -> None:
    prepare_gameplay(oracle)
    oracle.write_u32("config_game_mode", int(GameMode.TYPO))
    oracle.call("register_core_cvars")
    install_fake_grim(
        oracle, {"grim_is_key_down": lambda call: int(keys.enter and (call.arg_u32(0) & 0xFF) == _ENTER_SCANCODE)},
    )
    oracle.stub("console_input_poll", lambda _call: keys.take_char())
    for name in ("sfx_play", "sfx_mute_all", "sfx_play_exclusive", "terrain_render", "ui_elements_update_and_render"):
        oracle.stub(name, 0)
    # No score table on disk.
    scores_path = oracle.alloc(0x20, data=b"scores.dat\0")
    oracle.stub("highscore_build_path", scores_path)
    oracle.stub("crt_fopen", 0)
    # The HUD timeline is in, so `creature_render_all` draws (and culls corpses).
    oracle.write_u32("ui_elements_timeline", 0x7FFF_FFFF)

    def fx_queue_render(_call) -> None:
        oracle.write_u32("fx_queue_count", 0)
        oracle.write_u32("fx_queue_rotated", 0)

    oracle.stub("fx_queue_render", fx_queue_render)


def test_typo_frame_matches_native(oracle) -> None:
    keys = _Keys()
    _setup_native(oracle, keys)
    pristine = oracle.snapshot()
    player_address = oracle.resolve("player_state_table")

    rng = random.Random(0x4457C0)
    mismatches: list[Mismatch] = []
    cases = frames = matched = deaths = table_loads = 0
    for _ in range(8):
        cases += 1
        seed = rng.getrandbits(32)
        experience = rng.choice((0, rng.randrange(0, 400)))
        typist = _Typist(rng)
        # Native's quirks: a Typ-o death leaves the trooper at exactly 0 health, the pain branch.
        session = initialize_run(RunSpec(game_mode_id=GameMode.TYPO, seed=seed, preserve_bugs=True)).session
        session.world.players[0].experience = experience

        oracle.restore(pristine)
        oracle.rand_state = seed
        oracle.call("gameplay_reset_state")
        # `game_frame_update`'s frame-end draw.
        oracle.call("crt_rand")
        oracle.write_u32("game_state_id", GameStateId.TYPO_GAMEPLAY)
        oracle.write_u32("game_state_pending", GameStateId.TYPO_GAMEPLAY)
        oracle.write_u32(player_address + _PLAYER_FRAME_LAYOUT["experience"][0], experience)

        case = f"seed=0x{seed:08x} experience={experience} pace={typist.pace}"
        case_mismatches = _compare(oracle, session, run_started=False, run_over=False, effects=True, case=f"{case} start")
        run_down = _RUN_DOWN_FRAMES
        frame = 0
        while not case_mismatches and frame < 3000 and run_down > 0:
            frame += 1
            frames += 1
            dt = rng.choice(_FRAME_DTS) if rng.random() < 0.9 else f32(rng.uniform(0.004, 0.05))
            keys.enter, keys.char = typist.frame(session)
            commands = _commands(keys.enter, keys.char)
            oracle.write_f32("frame_dt", dt)
            oracle.write_u32("frame_dt_ms", ftol_ms_i32(dt))
            oracle.call("typo_gameplay_update_and_render")
            oracle.call("crt_rand")
            tick = session.step_tick(dt=dt, inputs=[player_input()], commands=commands)
            if tick.outcome is not None:
                run_down -= 1
            case_mismatches = _compare(
                oracle,
                session,
                run_started=True,
                run_over=tick.outcome is not None,
                # The effect pool is large; a divergence there lasts.
                effects=frame % 16 == 0 or run_down == 0,
                case=f"{case} frame={frame} dt={dt!r}",
            )
        mismatches += case_mismatches
        matched += session.world.state.typo.typing.match_count
        deaths += int(run_down < _RUN_DOWN_FRAMES)
        table_loads += int(session.world.state.typo.highscore_names.loaded)
    assert not mismatches, mismatch_report(mismatches, total_cases=frames)
    assert matched > 5 * cases, f"only {matched} words hit over {cases} runs"
    assert deaths == cases, f"only {deaths} of {cases} runs ended"
    assert table_loads, "no run picked a highscore name"
