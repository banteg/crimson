from __future__ import annotations

from pathlib import Path

from grim.config.defaults import default_crimson_cfg_data
from grim.config.model import CrimsonConfig
from grim.config.storage import load_crimson_cfg, save_crimson_cfg


def test_config_remembers_player_name_roundtrip(tmp_path: Path) -> None:
    cfg_path = tmp_path / "crimson.cfg"
    cfg = CrimsonConfig(path=cfg_path, data=default_crimson_cfg_data())
    cfg.set_player_name("banteg")
    save_crimson_cfg(cfg)

    loaded = load_crimson_cfg(cfg_path)
    assert loaded.player_name == "banteg"
    assert int(loaded.data.get("player_name_len", -1)) == 6


def test_config_player_name_trims_trailing_spaces(tmp_path: Path) -> None:
    cfg_path = tmp_path / "crimson.cfg"
    cfg = CrimsonConfig(path=cfg_path, data=default_crimson_cfg_data())
    cfg.set_player_name("abc   ")
    save_crimson_cfg(cfg)

    loaded = load_crimson_cfg(cfg_path)
    assert loaded.player_name == "abc"
    # The original mirrors the runtime input length to config, even if the saved name is trimmed.
    assert int(loaded.data.get("player_name_len", -1)) == 6
