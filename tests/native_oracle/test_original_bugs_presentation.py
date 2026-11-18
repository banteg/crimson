"""GOG 1.9.93 music and rendering regressions for original bugs 77 through 79."""

from __future__ import annotations

import pytest

from crimson.bonuses.ids import BonusId
from crimson.game_states import GameStateId
from crimson.projectiles.types import SecondaryProjectileTypeId

from ._support import SECONDARY_PROJECTILE_LAYOUT, install_fake_grim, prepare_gameplay


@pytest.mark.parametrize("quick_return", [True, False], ids=["half-second", "after-fade"])
def test_statistics_back_can_leave_the_main_menu_silent(oracle, quick_return: bool) -> None:
    theme, statistics = 2, 1
    oracle.write_u8("music_ready", 1)
    oracle.write("music_fade_out_flags", bytes([1]) * 128)
    oracle.write_f32("config_music_volume", 1.0)
    oracle.write_f32("frame_dt", 1 / 64)
    oracle.write_u32("music_track_crimson_theme_id", theme)
    oracle.write_u32("music_track_shortie_monk_id", statistics)
    oracle.write_u32("music_track_game_playlist", 4)

    # Supply two DirectSound streams. Native code selects, fades and stops them.
    table = oracle.resolve("music_entry_table")
    entry_size = 0x84
    playing = set()

    def start(call):
        playing.add((call.arg_u32(0) - table) // entry_size)

    def stop(call):
        playing.discard((call.arg_u32(0) - table) // entry_size)

    track_by_buffer = {}

    def get_status(call):
        track = track_by_buffer[call.arg_u32(0)]
        oracle.write_u32(call.arg_u32(1), int(track in playing))
        return 0

    get_status_addr = oracle.load_code(b"\xc2\x08\x00")
    oracle.stub(get_status_addr, get_status, pop=8)
    vtable = oracle.alloc(96)
    oracle.write_u32(vtable + 9 * 4, get_status_addr)
    for track in (theme, statistics):
        buffer = oracle.alloc(4)
        track_by_buffer[buffer] = track
        oracle.write_u32(buffer, vtable)
        oracle.write_u32(table + track * entry_size + 0x24, buffer)
        oracle.write_u32(table + track * entry_size + 0x74, 1)  # loaded Vorbis stream
    oracle.stub("sfx_entry_start_playback", start)
    oracle.stub("sfx_entry_stop", stop)
    oracle.stub("sfx_entry_resume", start)
    oracle.stub("sfx_entry_set_volume", 0)

    oracle.call("music_play_exclusive", theme)
    assert playing == {theme}
    oracle.call("ui_menu_main_click_statistics")
    assert oracle.read_u32("game_state_pending") == GameStateId.STATISTICS_MENU
    assert playing == {theme, statistics}
    for _ in range(32 if quick_return else 160):
        oracle.call("music_update_fades")
    theme_volume = oracle.resolve("music_track_volume") + theme * 4
    assert oracle.read_f32(theme_volume) == (0.75 if quick_return else 0.0)

    # Execute the activated Back button block inside statistics_menu_update.
    oracle.run(0x43FFEC, 0x44002A, regs={"ebx": 0})
    assert oracle.read_u32("game_state_pending") == GameStateId.MAIN_MENU
    for _ in range(160):
        oracle.call("music_update_fades")
    assert playing == (set() if quick_return else {theme})
    assert oracle.read_f32(theme_volume) == (0.0 if quick_return else 1.0)


def test_random_blood_stamp_is_centered_up_left_of_the_hit(oracle) -> None:
    quads = []

    def draw_quad(call):
        quads.append(tuple(call.arg_f32(i) for i in range(4)))
        return 0

    install_fake_grim(oracle, {"grim_draw_quad": draw_quad})
    oracle.write_f32("config_texture_scale", 1.0)
    oracle.write_u32("terrain_texture_width", 1024)
    oracle.write_u8("config_violence_disabled", 0)
    oracle.rand_state = 123
    oracle.call("fx_queue_add_random", oracle.alloc_f32s(500.0, 500.0))
    assert oracle.read_u32("fx_queue_count") == 1
    oracle.call("fx_queue_render")
    (quad,) = quads
    x, y, width, height = quad
    assert (width, height) == (39.0, 39.0)
    assert (x + width / 2, y + height / 2) == (480.5, 480.5)


@pytest.mark.parametrize(
    ("rocket", "nuke", "expected_pulses"),
    [(True, False, 4), (False, True, 20), (True, True, 4)],
    ids=["rocket-alone", "nuke-alone", "rocket-during-nuke"],
)
def test_rocket_sets_shake_pulses_without_starting_the_timer(oracle, rocket, nuke, expected_pulses) -> None:
    prepare_gameplay(oracle)
    oracle.write_f32("frame_dt", 1 / 64)
    if rocket:
        slot = oracle.call(
            "fx_spawn_secondary_projectile",
            oracle.alloc_f32s(400.0, 300.0),
            0.0,
            int(SecondaryProjectileTypeId.ROCKET),
        ).eax
        assert slot == 0
        for _ in range(128):  # Let the native two-second flight expire.
            oracle.call("projectile_update")
            oracle.call("camera_update")
        type_addr = oracle.resolve("secondary_projectile_pool") + SECONDARY_PROJECTILE_LAYOUT["type_id"][0]
        assert oracle.read_u32(type_addr) == SecondaryProjectileTypeId.DETONATION
    if nuke:
        bonus = oracle.resolve("bonus_pool")
        oracle.write_u32(bonus, int(BonusId.NUKE))
        oracle.call("bonus_apply", 0, bonus)
        assert oracle.read_u32("camera_shake_pulses") == 20
        assert oracle.read_f32("camera_shake_timer") == pytest.approx(0.2)

    oracle.call("projectile_update")
    assert oracle.read_u32("camera_shake_pulses") == expected_pulses
    if not nuke:
        assert oracle.read_f32("camera_shake_timer") == 0.0
    offset = oracle.resolve("camera_shake_offset")
    saw_camera_move = False
    for _ in range(40):
        oracle.call("camera_update")
        if oracle.read_f32(offset) or oracle.read_f32(offset + 4):
            saw_camera_move = True
        oracle.call("projectile_update")
    assert saw_camera_move == nuke
    # At 625 ms a Nuke alone still shakes. With the rocket its shake is already over.
    assert (oracle.read_f32("camera_shake_timer") > 0) == (nuke and not rocket)
