from __future__ import annotations

from pathlib import Path

from grim import config as grim_config


def test_crimson_cfg_roundtrip_default() -> None:
    cfg = grim_config.default_crimson_cfg()
    blob = grim_config.encode_crimson_cfg(cfg)
    assert len(blob) == grim_config.CRIMSON_CFG_SIZE
    parsed = grim_config.CRIMSON_CFG_STRUCT.parse(blob)
    assert int(parsed["unknown_08"]) == 0
    assert int(parsed["unknown_450"]) == 1
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
    data["keybinds"] = b"\x00" * grim_config.KEYBINDS_BLOB_SIZE
    path = tmp_path / grim_config.CRIMSON_CFG_NAME
    path.write_bytes(grim_config.CRIMSON_CFG_STRUCT.build(data))

    loaded = grim_config.ensure_crimson_cfg(tmp_path)
    assert loaded.controls.player(0).keybinds == grim_config.default_player_keybind_block(0)
    assert loaded.controls.player(1).keybinds == grim_config.default_player_keybind_block(1)


def test_player_keybind_roundtrip_for_extended_players_uses_reserved_gap_extension() -> None:
    cfg = grim_config.default_crimson_cfg(Path("<memory>"))
    cfg.controls.player(2).set_keybind(4, 0x120)
    cfg.controls.player(3).set_keybind(0, 0x11F)

    blob = grim_config.encode_crimson_cfg(cfg)
    parsed = grim_config.CRIMSON_CFG_STRUCT.parse(blob)
    assert list(parsed["extended_keybinds_p3"])[4] == 0x120
    assert list(parsed["extended_keybinds_p4"])[0] == 0x11F
    assert parsed["extended_reserved_gap"] == b"\x00" * len(parsed["extended_reserved_gap"])

    loaded = grim_config.decode_crimson_cfg(Path("<memory>"), blob)
    assert loaded.controls.player(2).keybind(4) == 0x120
    assert loaded.controls.player(3).keybind(0) == 0x11F


def test_direction_arrow_extension_roundtrip_for_players_three_and_four() -> None:
    cfg = grim_config.default_crimson_cfg(Path("<memory>"))
    assert cfg.controls.player(2).show_direction_arrow
    assert cfg.controls.player(3).show_direction_arrow

    cfg.controls.player(2).show_direction_arrow = False
    cfg.controls.player(3).show_direction_arrow = True
    blob = grim_config.encode_crimson_cfg(cfg)
    parsed = grim_config.CRIMSON_CFG_STRUCT.parse(blob)
    assert list(parsed["extended_direction_arrow_flags"]) == [
        grim_config.EXT_DIRECTION_ARROW_OFF,
        grim_config.EXT_DIRECTION_ARROW_ON,
    ]

    loaded = grim_config.decode_crimson_cfg(Path("<memory>"), blob)
    assert not loaded.controls.player(2).show_direction_arrow
    assert loaded.controls.player(3).show_direction_arrow
