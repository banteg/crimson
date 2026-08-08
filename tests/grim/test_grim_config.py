from __future__ import annotations

from pathlib import Path

from grim import config as grim_config


def test_crimson_cfg_roundtrip_default() -> None:
    cfg = grim_config.default_crimson_cfg()
    blob = grim_config.encode_crimson_cfg(cfg)
    assert len(blob) == grim_config.CRIMSON_CFG_SIZE
    parsed = grim_config.CRIMSON_CFG_STRUCT.parse(blob)
    assert list(parsed["direction_arrow_flags"][:4]) == [1, 1, 1, 1]
    assert list(parsed["direction_arrow_flags"][4:]) == [0] * 6
    assert int(parsed["ten_tons_logging_completed"]) == 1
    assert int(parsed["sound_freq_adjustment_enabled"]) == 1
    assert int(parsed["ui_info_texts"]) == 1
    assert int(parsed["keybind_pick_perk"]) == 0x101
    assert int(parsed["keybind_reload"]) == 0x102
    assert float(parsed["mouse_sensitivity"]) == 0.5
    assert list(parsed["saved_name_order"]) == list(range(grim_config.SAVED_NAME_SLOT_COUNT))
    rebuilt = grim_config.CRIMSON_CFG_STRUCT.build(parsed)
    assert rebuilt == blob


def test_crimson_cfg_save_load(tmp_path: Path) -> None:
    cfg = grim_config.ensure_crimson_cfg(tmp_path)
    raw = cfg.path.read_bytes()
    loaded = grim_config.load_crimson_cfg(cfg.path)
    rebuilt = grim_config.encode_crimson_cfg(loaded)
    assert rebuilt == raw


def test_crimson_cfg_backfills_zero_keybinds(tmp_path: Path) -> None:
    cfg = grim_config.default_crimson_cfg()
    data = grim_config.CRIMSON_CFG_STRUCT.parse(grim_config.encode_crimson_cfg(cfg))
    data["input_config"][:2] = [
        {
            "move_forward": 0,
            "move_backward": 0,
            "turn_left": 0,
            "turn_right": 0,
            "fire": 0,
            "reserved_keys": [0, 0],
            "aim_left": 0,
            "aim_right": 0,
            "axis_aim_y": 0,
            "axis_aim_x": 0,
            "axis_move_y": 0,
            "axis_move_x": 0,
            "padding": [0, 0, 0],
        },
        {
            "move_forward": 0,
            "move_backward": 0,
            "turn_left": 0,
            "turn_right": 0,
            "fire": 0,
            "reserved_keys": [0, 0],
            "aim_left": 0,
            "aim_right": 0,
            "axis_aim_y": 0,
            "axis_aim_x": 0,
            "axis_move_y": 0,
            "axis_move_x": 0,
            "padding": [0, 0, 0],
        },
    ]
    path = tmp_path / grim_config.CRIMSON_CFG_NAME
    path.write_bytes(grim_config.CRIMSON_CFG_STRUCT.build(data))

    loaded = grim_config.ensure_crimson_cfg(tmp_path)
    defaults = grim_config.default_crimson_cfg(Path("<memory>")).controls
    assert loaded.controls.player(0) == defaults.player(0)
    assert loaded.controls.player(1) == defaults.player(1)


def test_player_keybind_roundtrip_for_players_three_and_four_uses_source_slots() -> None:
    cfg = grim_config.default_crimson_cfg(Path("<memory>"))
    cfg.controls.player(2).fire_code = 0x120
    cfg.controls.player(3).move_codes = (0x11F, 0x91, 0x8A, 0x97)

    blob = grim_config.encode_crimson_cfg(cfg)
    parsed = grim_config.CRIMSON_CFG_STRUCT.parse(blob)
    assert int(parsed["input_config"][2]["fire"]) == 0x120
    assert int(parsed["input_config"][3]["move_forward"]) == 0x11F
    assert list(parsed["input_config"][2]["reserved_keys"]) == [0x17E, 0x17E]
    assert list(parsed["input_config"][2]["padding"]) == [0x17E, 0x17E, 0x17E]
    assert blob[0x2C8:0x448] == bytes(0x180)

    loaded = grim_config.decode_crimson_cfg(Path("<memory>"), blob)
    assert loaded.controls.player(2).fire_code == 0x120
    assert loaded.controls.player(3).move_codes[0] == 0x11F


def test_direction_arrow_roundtrip_for_players_three_and_four_uses_source_slots() -> None:
    cfg = grim_config.default_crimson_cfg(Path("<memory>"))
    assert cfg.controls.player(2).show_direction_arrow
    assert cfg.controls.player(3).show_direction_arrow

    cfg.controls.player(2).show_direction_arrow = False
    cfg.controls.player(3).show_direction_arrow = True
    blob = grim_config.encode_crimson_cfg(cfg)
    parsed = grim_config.CRIMSON_CFG_STRUCT.parse(blob)
    assert list(parsed["direction_arrow_flags"][:4]) == [1, 1, 0, 1]

    loaded = grim_config.decode_crimson_cfg(Path("<memory>"), blob)
    assert not loaded.controls.player(2).show_direction_arrow
    assert loaded.controls.player(3).show_direction_arrow
