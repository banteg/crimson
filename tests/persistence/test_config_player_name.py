from __future__ import annotations

from pathlib import Path

from grim.config import default_crimson_cfg, load_crimson_cfg


def test_config_remembers_player_name_roundtrip(tmp_path: Path) -> None:
    cfg_path = tmp_path / "crimson.cfg"
    cfg = default_crimson_cfg(cfg_path)
    cfg.profile.set_player_name_input("banteg")
    cfg.save()

    loaded = load_crimson_cfg(cfg_path)
    assert loaded.profile.player_name == "banteg"
    assert int(loaded.profile.player_name_input_len) == 6


def test_config_player_name_trims_trailing_spaces(tmp_path: Path) -> None:
    cfg_path = tmp_path / "crimson.cfg"
    cfg = default_crimson_cfg(cfg_path)
    cfg.profile.set_player_name_input("abc   ")
    cfg.save()

    loaded = load_crimson_cfg(cfg_path)
    assert loaded.profile.player_name == "abc"
    # The original mirrors the runtime input length to config, even if the saved name is trimmed.
    assert int(loaded.profile.player_name_input_len) == 6
