"""Checked sizeof expressions for named storage in matched freeware translation units."""
from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from . import match

_GAME = "decomp/1.4/crimson/crimson/"
_PERK_SIZES = {"1.0.2": 512, "1.3.0": 640, "1.4.0": 960}
_PI_SOURCES = {_GAME + "creatures/creature_update_all.cpp", _GAME + "player/player_update.cpp"}
_OFFSET_SYMBOLS = {
    "1.3.0": "_?offset@?CF@??game_frame_update@frame_update140@@YAEXZ@4Ueditor_point@2@A",
    "1.4.0": "_?offset@?CJ@??game_frame_update@frame_update140@@YAEXZ@4Ueditor_point@2@A",
}


def _assertion(version: str, source: str, symbol: str) -> tuple[str, int] | None:
    if version not in _PERK_SIZES:
        return None
    if source == _GAME + "perks/perk_meta.cpp" and symbol == "?perk_meta_table@@3PAVperk_meta_cpp_t@@A":
        return "perk_meta_table", _PERK_SIZES[version]
    if source == "decomp/1.4/crimson/level/brushes.cpp" and symbol == "_freeware_brushes" and version != "1.0.2":
        return "freeware_brushes", 16
    if source in _PI_SOURCES and symbol in {"_pi", "_half_pi"}:
        return symbol[1:], 4
    if source == _GAME + "projectiles/projectile_update.cpp" and symbol == "_half_pi":
        return "half_pi", 4
    if source == _GAME + "game/game_frame_update.cpp" and symbol == _OFFSET_SYMBOLS.get(version):
        # The decorated local static explicitly names its type and declaring namespace.
        return "frame_update140::editor_point", 8
    return None


def declared_size(version: str, source: str, symbol: str) -> int | None:
    assertion = _assertion(version, source, symbol)
    return assertion[1] if assertion else None


def verify_declared_sizes(version: str, config: match.ScratchConfig, symbols: Iterable[str]) -> None:
    """Refresh checks the size expressions in their own TU with the function's VC6 profile."""
    source = (config.directory / config.source).resolve()
    path = source.relative_to(match.REPO_ROOT).as_posix()
    checks = sorted({check for name in symbols if (check := _assertion(version, path, name)) is not None})
    if not checks:
        return
    code = match._apply_auto_inline_boundaries(source.read_bytes().decode("latin1"), config.auto_inline_off, source=source)
    checks_cpp = "\n".join(
        f"typedef char verified_extent_{i}[(sizeof({expression}) == {size}) ? 1 : -1];"
        for i, (expression, size) in enumerate(checks)
    )
    env = {**os.environ, "MSVC_VER": config.compiler, "CRIMSON_MATCH_SOURCE_INCLUDE": str(config.source_include_dir)}
    env.pop("CRIMSON_MATCH_INCLUDE_OVERLAY", None)
    if config.include_overlay:
        env["CRIMSON_MATCH_INCLUDE_OVERLAY"] = str(config.include_overlay.resolve())
    with tempfile.TemporaryDirectory(prefix="crimson-sizeof-") as scratch:
        temp = Path(scratch)
        (temp / source.name).write_bytes(f"{code}\n{checks_cpp}\n".encode("latin1"))
        command = list(match._scratch_compile_argv(config, match.DEFAULT_MATCH_ROOT))
        command.insert(-1, "/Zs")
        completed = match.run_compiler(command, cwd=temp, env=env, deadline=None)
    if completed.returncode:
        raise ValueError(f"{version} {path}: VC6 sizeof check failed:\n{completed.stdout}{completed.stderr}")
