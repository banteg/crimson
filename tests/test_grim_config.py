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
