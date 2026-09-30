from __future__ import annotations

from pathlib import Path

import msgspec

from grim.config import CrimsonConfig, ensure_crimson_cfg
from grim.console import ConsoleState, create_console, register_core_cvars

from .assets_fetch import download_missing_paqs


class RuntimeBoot(msgspec.Struct, frozen=True):
    config: CrimsonConfig
    console: ConsoleState
    width: int
    height: int


def boot_runtime(
    base_dir: Path,
    assets_dir: Path,
    *,
    width: int | None = None,
    height: int | None = None,
) -> RuntimeBoot:
    """Load crimson.cfg, build the console with its core cvars and fetch any missing .paq archives.

    `width`/`height` override the configured display size.
    """
    base_dir.mkdir(parents=True, exist_ok=True)
    config = ensure_crimson_cfg(base_dir)
    width = config.display.width if width is None else width
    height = config.display.height if height is None else height
    console = create_console(base_dir, assets_dir=assets_dir)
    register_core_cvars(console, width, height)
    download_missing_paqs(assets_dir, console)
    return RuntimeBoot(config=config, console=console, width=width, height=height)
