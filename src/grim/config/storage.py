from __future__ import annotations

from pathlib import Path

from .codec import CRIMSON_CFG_NAME, CRIMSON_CFG_SIZE, build_crimson_cfg, parse_crimson_cfg
from .defaults import default_crimson_cfg_data
from .model import CrimsonConfig


def save_crimson_cfg(config: CrimsonConfig) -> None:
    config.path.write_bytes(build_crimson_cfg(config.data))


def load_crimson_cfg(path: Path) -> CrimsonConfig:
    data = path.read_bytes()
    if len(data) != CRIMSON_CFG_SIZE:
        raise ValueError(f"{path} has unexpected size {len(data)} (expected {CRIMSON_CFG_SIZE})")
    parsed = parse_crimson_cfg(data)
    return CrimsonConfig(path=path, data=parsed)


def ensure_crimson_cfg(base_dir: Path) -> CrimsonConfig:
    path = base_dir / CRIMSON_CFG_NAME
    if path.exists():
        config = load_crimson_cfg(path)
        # Patch up configs produced by older revisions of this project.
        # `crimsonland.exe` expects player_count in [1..4], but our repo historically had 0 here.
        player_count = config.player_count
        if player_count < 1 or player_count > 4:
            config.player_count = 1
            save_crimson_cfg(config)
        if (
            config.detail_preset == 0
            and not config.fx_detail(level=0, default=False)
            and not config.fx_detail(level=1, default=False)
            and not config.fx_detail(level=2, default=False)
        ):
            config.set_fx_detail(level=0, enabled=True)
            config.set_fx_detail(level=1, enabled=True)
            config.set_fx_detail(level=2, enabled=True)
            config.detail_preset = 5
            save_crimson_cfg(config)
        # Patch up missing keybind defaults (older revisions left these as 0).
        keybind_patched = False
        if config.keybind_pick_perk == 0:
            config.keybind_pick_perk = 0x101
            keybind_patched = True
        if config.keybind_reload == 0:
            config.keybind_reload = 0x102
            keybind_patched = True
        if keybind_patched:
            save_crimson_cfg(config)
        # Patch up missing keybind defaults (older revisions left the entire keybind blob as 0).
        keybind_blob = config.keybinds
        default_keybinds = default_crimson_cfg_data()["keybinds"]
        patched = bytearray(keybind_blob)
        changed = False
        for offset in range(0, 0x80, 4):
            value = int.from_bytes(patched[offset : offset + 4], "little")
            if value != 0:
                continue
            patched[offset : offset + 4] = default_keybinds[offset : offset + 4]
            changed = True
        if changed:
            config.keybinds = bytes(patched)
            save_crimson_cfg(config)
        return config
    parsed = default_crimson_cfg_data()
    config = CrimsonConfig(path=path, data=parsed)
    save_crimson_cfg(config)
    return config
