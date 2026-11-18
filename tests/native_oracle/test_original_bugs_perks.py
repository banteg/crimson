"""GOG 1.9.93 perk regressions for original bugs 64 through 67."""

from __future__ import annotations

import struct

import pytest

from crimson.bonuses.ids import BonusId
from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from crimson.perks import PerkId
from crimson.weapons import WeaponId

from ._support import PLAYER_STRIDE, install_fake_grim, prepare_gameplay

_MOUSE_LEFT = 0x100
_RIGHT_CTRL = 0x9D
_SPACE = 0x39
_RELOAD = 0x13
_DT = 1 / 60


def _prepare_perks(oracle, *, players=1):
    prepare_gameplay(oracle)
    oracle.call("register_core_cvars")
    oracle.call("perks_init_database")
    oracle.stub("sfx_play", 0)
    oracle.write_u32("config_player_count", players)
    oracle.call("player_reset_all")
    oracle.write_u32("current_player_index", 0)
    oracle.write_u8("input_primary_latch", 0)
    oracle.write_f32("frame_dt", _DT)
    oracle.write_u32("frame_dt_ms", 16)


@pytest.mark.parametrize(
    ("perk", "key", "opens"),
    [(False, _MOUSE_LEFT, True), (True, _MOUSE_LEFT, False), (True, _SPACE, True)],
)
def test_anxious_loader_consumes_level_up_click_with_full_clip(oracle, perk, key, opens):
    _prepare_perks(oracle)
    install_fake_grim(
        oracle,
        {
            "grim_is_mouse_button_down": lambda c: int(key == _MOUSE_LEFT and c.arg_u32(0) == 0),
            "grim_is_key_active": lambda c: int(key == _MOUSE_LEFT and c.arg_u32(0) == key),
            "grim_was_key_pressed": lambda c: int(key == _SPACE and c.arg_u32(0) == key),
            "grim_is_key_down": lambda _: 0,
        },
    )
    oracle.call("weapon_assign_player", 0, int(WeaponId.ASSAULT_RIFLE))
    if perk:
        oracle.call("perk_apply", int(PerkId.ANXIOUS_LOADER))
    oracle.write_u32("player_fire_key", _MOUSE_LEFT)
    oracle.write_u32("config_key_pick_perk", 0x101)
    oracle.write_u32("perk_pending_count", 1)
    oracle.write_u8("perk_choices_dirty", 0)
    oracle.write_u8("mouse_button_down", 0)
    oracle.write_u32("game_state_pending", int(GameStateId.GAMEPLAY))
    for axis in ("x", "y"):
        oracle.write_f32(f"ui_mouse_{axis}", 50.0)
        oracle.write_f32(f"perk_prompt_origin_{axis}", 0.0)
        oracle.write_f32(f"perk_prompt_bounds_min_{axis}", 0.0)
        oracle.write_f32(f"perk_prompt_bounds_max_{axis}", 100.0)

    requested = []
    oracle.stub("game_state_set", lambda c: requested.append(c.arg_u32(0)))
    assert oracle.read_f32("player_ammo") == oracle.read_f32("player_clip_size")
    assert oracle.read_f32("player_reload_timer") == 0.0
    oracle.call("player_update")
    # The pending-perk input block of gameplay_update_and_render, after player_update.
    oracle.run(0x0040B07D, 0x0040B1D3, regs={"ebx": 0, "esi": 1000})
    if key == _MOUSE_LEFT:
        assert oracle.read_u8("perk_prompt_hover_active") == 1
    assert requested == ([GameStateId.PERK_SELECTION] if opens else [])


@pytest.mark.parametrize(
    ("perk", "p1_alive", "expected"),
    [
        (True, True, (0.95 - _DT, 1.0 - _DT)),
        (False, True, (1.0 - _DT, 1.0 - _DT)),
        (True, False, (1.0, 0.95 - _DT)),
    ],
)
def test_player_two_fire_press_speeds_player_one_reload(oracle, perk, p1_alive, expected):
    _prepare_perks(oracle, players=2)
    install_fake_grim(
        oracle,
        {
            "grim_is_key_active": lambda c: int(c.arg_u32(0) == _RIGHT_CTRL),
            "grim_is_mouse_button_down": lambda _: 0,
            "grim_is_key_down": lambda _: 0,
        },
    )
    if perk:
        oracle.call("perk_apply", int(PerkId.ANXIOUS_LOADER))
    timers = [oracle.resolve("player_reload_timer") + seat * PLAYER_STRIDE for seat in range(2)]
    for seat, fire_key in enumerate((_MOUSE_LEFT, _RIGHT_CTRL)):
        oracle.call("weapon_assign_player", seat, int(WeaponId.ASSAULT_RIFLE))
        oracle.write_u32(oracle.resolve("player_fire_key") + seat * PLAYER_STRIDE, fire_key)
        oracle.write_f32(timers[seat], 1.0)
    if not p1_alive:
        oracle.write_f32("player_health", 0.0)
    for seat in range(2):
        oracle.write_u32("current_player_index", seat)
        oracle.call("player_update")
    assert [oracle.read_f32(timer) for timer in timers] == pytest.approx(expected)


@pytest.mark.parametrize(("prior_quest_minor", "first_choice"), [(4, PerkId.MONSTER_VISION), (3, PerkId.GRIM_DEAL)])
def test_hidden_evil_forces_monster_vision_in_next_survival_run(oracle, prior_quest_minor, first_choice):
    _prepare_perks(oracle)
    install_fake_grim(oracle)
    oracle.call("quest_database_init")
    oracle.stub("terrain_generate_random", 0)
    oracle.write_u32("quest_unlock_index", 23)
    oracle.write_u32("quest_stage_major", 3)
    oracle.write_u32("quest_stage_minor", prior_quest_minor)
    oracle.write_u32("config_game_mode", int(GameMode.SURVIVAL))
    oracle.call("gameplay_reset_state")
    assert (oracle.read_i32("quest_stage_major"), oracle.read_i32("quest_stage_minor")) == (3, prior_quest_minor)
    oracle.rand_state = 1
    oracle.call("perks_generate_choices")
    assert oracle.read_i32("perk_choice_ids") == first_choice


def test_ammo_maniac_skips_holstered_assault_rifle(oracle):
    _prepare_perks(oracle)
    held = set()
    install_fake_grim(oracle, {"grim_is_key_active": lambda c: int(c.arg_u32(0) in held)})
    oracle.write_u32("config_key_reload", _RELOAD)
    oracle.call("perk_apply", int(PerkId.ALTERNATE_WEAPON))
    oracle.call("weapon_assign_player", 0, int(WeaponId.ASSAULT_RIFLE))

    def swap():
        held.add(_RELOAD)
        oracle.call("player_update")
        held.clear()
        oracle.call("player_update")

    swap()
    assert (oracle.read_i32("player_weapon_id"), oracle.read_f32("player_clip_size")) == (WeaponId.PISTOL, 12)
    oracle.call("perk_apply", int(PerkId.AMMO_MANIAC))
    assert oracle.read_f32("player_clip_size") == 15
    swap()
    assert (oracle.read_i32("player_weapon_id"), oracle.read_f32("player_clip_size")) == (WeaponId.ASSAULT_RIFLE, 25)
    oracle.call("weapon_assign_player", 0, int(WeaponId.ASSAULT_RIFLE))
    assert oracle.read_f32("player_clip_size") == 31


@pytest.mark.parametrize("empty_frame", [False, True])
def test_telekinetic_charge_transfers_between_bonuses(oracle, empty_frame):
    _prepare_perks(oracle)
    install_fake_grim(oracle)
    oracle.call("perk_apply", int(PerkId.TELEKINETIC))
    oracle.write_u32("game_state_id", int(GameStateId.GAMEPLAY))
    oracle.write_f32("ui_transition_alpha", 1.0)
    oracle.write_f32("player_health", 50.0)
    oracle.write_f32("player_aim_y", 300.0)
    pool = oracle.resolve("bonus_pool")
    entry = struct.Struct("<IB3xffffi")
    for slot, (bonus, x) in enumerate(((BonusId.POINTS, 100.0), (BonusId.MEDIKIT, 400.0))):
        oracle.write(pool + slot * entry.size, entry.pack(bonus, 0, 5.0, 10.0, x, 300.0, 500 if slot == 0 else 0))

    oracle.write_f32("player_aim_x", 100.0)
    for _ in range(40):
        oracle.call("bonus_render")
    assert oracle.read_i32("telekinetic_bonus_hover_timer_ms") == 640
    if empty_frame:
        oracle.write_f32("player_aim_x", 250.0)
        oracle.call("bonus_render")
    oracle.write_f32("player_aim_x", 400.0)
    oracle.call("bonus_render")
    assert oracle.read_u8(pool + 4) == 0
    assert oracle.read_u8(pool + entry.size + 4) == int(not empty_frame)
    assert oracle.read_f32("player_health") == (50.0 if empty_frame else 60.0)
