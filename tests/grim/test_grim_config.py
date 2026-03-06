from __future__ import annotations

from grim import config as grim_config


def test_crimson_cfg_roundtrip_default() -> None:
    data = grim_config.default_crimson_cfg_data()
    assert int(data.get("keybind_pick_perk", 0)) == 0x101
    assert int(data.get("keybind_reload", 0)) == 0x102
    blob = grim_config.CRIMSON_CFG_STRUCT.build(data)
    assert len(blob) == grim_config.CRIMSON_CFG_SIZE
    parsed = grim_config.CRIMSON_CFG_STRUCT.parse(blob)
    rebuilt = grim_config.CRIMSON_CFG_STRUCT.build(parsed)
    assert rebuilt == blob


def test_crimson_cfg_save_load(tmp_path) -> None:
    cfg = grim_config.ensure_crimson_cfg(tmp_path)
    raw = cfg.path.read_bytes()
    loaded = grim_config.load_crimson_cfg(cfg.path)
    rebuilt = grim_config.CRIMSON_CFG_STRUCT.build(loaded.data)
    assert rebuilt == raw


def test_crimson_cfg_backfills_zero_keybinds(tmp_path) -> None:
    data = grim_config.default_crimson_cfg_data()
    data["keybinds"] = b"\x00" * 0x80
    path = tmp_path / grim_config.CRIMSON_CFG_NAME
    path.write_bytes(grim_config.CRIMSON_CFG_STRUCT.build(data))

    cfg = grim_config.ensure_crimson_cfg(tmp_path)
    assert cfg.data["keybinds"] == grim_config.default_crimson_cfg_data()["keybinds"]


def test_player_keybind_block_roundtrip_for_extended_players_preserves_unknown_bytes() -> None:
    data = grim_config.default_crimson_cfg_data()
    unknown = bytearray(data["unknown_248"])
    assert len(unknown) == grim_config.UNKNOWN_248_SIZE
    unknown[:] = b"\xA5" * len(unknown)
    data["unknown_248"] = bytes(unknown)

    grim_config.set_player_keybind_value(data, player_index=2, slot_index=4, value=0x120)
    grim_config.set_player_keybind_value(data, player_index=3, slot_index=0, value=0x11F)

    player3_block = grim_config.player_keybind_block(data, player_index=2)
    player4_block = grim_config.player_keybind_block(data, player_index=3)
    assert int(player3_block[4]) == 0x120
    assert int(player4_block[0]) == 0x11F

    unknown_after = bytes(data["unknown_248"])
    assert len(unknown_after) == grim_config.UNKNOWN_248_SIZE
    assert unknown_after[0x80:] == bytes([0xA5]) * (grim_config.UNKNOWN_248_SIZE - 0x80)


def test_hud_indicator_extension_roundtrip_for_players_three_and_four() -> None:
    data = grim_config.default_crimson_cfg_data()
    assert grim_config.hud_indicator_enabled_for_player(data, player_index=2)
    assert grim_config.hud_indicator_enabled_for_player(data, player_index=3)

    grim_config.set_hud_indicator_for_player(data, player_index=2, enabled=False)
    grim_config.set_hud_indicator_for_player(data, player_index=3, enabled=True)

    assert not grim_config.hud_indicator_enabled_for_player(data, player_index=2)
    assert grim_config.hud_indicator_enabled_for_player(data, player_index=3)
