"""GOG 1.9.93 mode regressions for original bugs 61, 70 and 71."""

from __future__ import annotations

import pytest

from crimson.creatures.damage_types import CreatureDamageType
from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from crimson.projectiles.types import MAIN_PROJECTILE_POOL_SIZE

from ._support import CREATURE_LAYOUT, CREATURE_STRIDE, PROJECTILE_STRIDE, pool_rows, prepare_gameplay
from .test_typo_frame import _Keys, _setup_native


@pytest.mark.parametrize("freeze_at_ms", [4600, 5300], ids=["thaw-before-next-wave", "thaw-after-next-wave"])
def test_army_of_three_followers_check_the_replacement_leader(oracle, freeze_at_ms: int) -> None:
    prepare_gameplay(oracle)
    oracle.call("register_core_cvars")
    oracle.call("perks_init_database")
    oracle.stub("sfx_play", 0)
    oracle.call("player_reset_all")
    oracle.write_u32("config_game_mode", GameMode.QUESTS)
    oracle.write_u32("quest_stage_major", 5)
    oracle.write_u32("quest_stage_minor", 7)
    oracle.write_u8("run_active", 1)
    oracle.write_u8("scripted_burst_active", 1)  # Keep random kill drops out of the two cases.
    oracle.write_f32("frame_dt", 1 / 60)
    oracle.write_u32("frame_dt_ms", 16)
    oracle.rand_state = 123

    def living_slots() -> set[int]:
        rows = pool_rows(oracle, "creature_pool", CREATURE_STRIDE, 55, CREATURE_LAYOUT)
        return {i for i, row in enumerate(rows) if row is not None and row["health"] > 0}

    def kill_leader() -> None:
        oracle.call("creature_apply_damage", 0, 1600.0, CreatureDamageType.EXPLOSION, oracle.alloc_f32s(0, 0))

    oracle.call("quest_build_army_of_three", oracle.resolve("quest_spawn_table"), oracle.resolve("quest_spawn_count"))
    oracle.write_u32("quest_spawn_timeline", 501)
    oracle.call("quest_spawn_timeline_update")
    assert living_slots() == set(range(28))  # One leader and 27 followers.

    oracle.write_u32("quest_spawn_timeline", freeze_at_ms)
    oracle.write_f32("bonus_freeze_timer", 0.5)
    kill_leader()
    assert oracle.read_u8("creature_pool") == 0  # Freeze shatters the leader and frees slot zero immediately.
    assert living_slots() == set(range(1, 28))

    for _ in range(32):
        oracle.call("creature_update_all")
        oracle.call("quest_mode_update")
        oracle.call("bonus_update")
    assert oracle.read_f32("bonus_freeze_timer") == 0.0
    if freeze_at_ms == 4600:
        assert not living_slots()  # The original followers die when the empty leader slot is checked.
    else:
        # The 5.5-second wave reused slot zero. Both sets of followers now depend on it.
        assert living_slots() == set(range(55))
        kill_leader()
        oracle.call("creature_update_all")
        assert not living_slots()


def test_typo_accepts_a_dead_targets_name_until_the_body_disappears(oracle) -> None:
    keys = _Keys()
    _setup_native(oracle, keys)
    oracle.rand_state = 113
    oracle.call("gameplay_reset_state")
    oracle.call("crt_rand")  # Draw at the end of the reset frame.
    oracle.write_u32("game_state_id", GameStateId.TYPO_GAMEPLAY)
    oracle.write_u32("game_state_pending", GameStateId.TYPO_GAMEPLAY)

    def tick(char: str = "", *, enter: bool = False) -> None:
        keys.char = ord(char) if char else 0
        keys.enter = enter
        oracle.write_f32("frame_dt", 1 / 60)
        oracle.write_u32("frame_dt_ms", 16)
        oracle.call("typo_gameplay_update_and_render")
        oracle.call("crt_rand")

    def submit(word: str) -> None:
        for char in word:
            tick(char)
        tick(enter=True)

    def shot_counts() -> tuple[int, int, int]:
        pool = oracle.read("projectile_pool", MAIN_PROJECTILE_POOL_SIZE * PROJECTILE_STRIDE)
        return (
            oracle.read_i32("highscore_record_shots_hit"),
            oracle.read_i32("highscore_record_shots_fired"),
            sum(pool[::PROJECTILE_STRIDE]),
        )

    tick()
    target = oracle.resolve("creature_pool")
    health = target + CREATURE_LAYOUT["health"][0]
    assert oracle.read_f32(health) == 1.0
    assert oracle.read("typo_target_name_table", 5) == b"blue\0"
    for _ in range(190):  # Let the first spider come within shotgun range.
        tick()
    submit("blue")
    for _ in range(80):
        tick()
        if oracle.read_f32(health) <= 0:
            break
    assert oracle.read_f32(health) < 0
    assert oracle.read_u8(target) == 1
    assert shot_counts() == (1, 1, 12)

    submit("blue")
    assert shot_counts() == (2, 2, 24)

    for _ in range(180):
        tick()
        if not oracle.read_u8(target):
            break
    assert oracle.read_u8(target) == 0
    submit("blue")
    assert shot_counts() == (2, 3, 0)
    assert oracle.read_i32("creature_kill_count") == 1


@pytest.mark.parametrize(
    ("mode", "entry", "counter", "two_starts"),
    [
        (GameMode.TYPO, GameStateId.TYPO_GAMEPLAY, "mode_play_typo", [0, 0]),
        (GameMode.RUSH, GameStateId.GAMEPLAY, "mode_play_rush", [1, 2]),
    ],
    ids=["typo", "rush"],
)
def test_play_menu_counter_on_fresh_mode_starts(oracle, mode, entry, counter: str, two_starts: list[int]) -> None:
    _setup_native(oracle, _Keys())
    oracle.stub("ui_elements_reset_state", 0)
    oracle.write_u32("config_game_mode", mode)
    assert oracle.read_u32(counter) == 0
    for expected in two_starts:
        oracle.write_u8("run_active", 0)
        oracle.call("game_state_set", entry)
        assert oracle.read_u8("run_active") == 1
        assert oracle.read_u32(counter) == expected
