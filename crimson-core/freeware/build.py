"""Build the source-recovered 1.4.0 freeware client with SDL3 or Emscripten."""

import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from adapter import x87

from .assets import prepare


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit(f"{name} is required for the freeware client build")
    return path


def game_sources(root: Path, stage: Path) -> list[Path]:
    core = root / "crimson-core"
    recovered = root / "decomp/1.4/crimson/crimson"
    particles = []
    for original in (
        recovered / "effects/fx_spawn_particle.cpp",
        root / "decomp/1.9/crimsonland/crimsonland/fx_spawn_particle_slow.cpp",
    ):
        # Reuse the Classic adapter for VC6's float x87 intrinsics on modern C++ hosts.
        translated = stage / original.name
        translated.write_text(x87(original, original.read_text()))
        particles.append(translated)
    return [
        *particles,
        *(
            core / "freeware" / name
            for name in (
                "menu.cpp",
                "survival.cpp",
                "career.cpp",
                "weapons.cpp",
                "perks.cpp",
                "scores.cpp",
                "particles.cpp",
                "console.cpp",
            )
        ),
        *(
            recovered / name
            for name in (
                "creatures/creature_spawn.cpp",
                "creatures/creature_find_nearest.cpp",
                "creatures/plaguebearer_spread_infection.cpp",
                "weapons/weapon_assign_player.cpp",
                "weapons/player_start_reload.cpp",
                "perks/perks_generate_choices.cpp",
                "weapons/weapon_name_get.cpp",
                "creatures/creature_alloc_slot.cpp",
                "creatures/creature_find_in_radius.cpp",
                "creatures/creature_reset_all.cpp",
                "player/player_heading_approach_target.cpp",
                "player/angle_approach.cpp",
                "projectiles/projectile_spawn.cpp",
                "effects/fx_spawn_secondary_projectile.cpp",
            )
        ),
    ]


def game_flags(root: Path) -> list[str]:
    return [
        "-std=c++17",
        "-O2",
        "-fms-extensions",
        "-Wno-ignored-attributes",
        "-fno-strict-aliasing",
        "-ffp-contract=off",
        "-DCL_BUILD=10400",
        "-I" + str(root / "tools/match/include"),
        "-I" + str(root / "third_party/headers"),
    ]


def build(root: Path, target: str, out: Path, install: Path | None) -> None:
    if install is None:
        git_dir = subprocess.check_output(
            [_tool("git"), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=root,
            text=True,
        ).strip()
        install = Path(git_dir).parent / "game_bins/crimsonland/1.4.0"
    if not (install / "sounds.paq").is_file():
        raise SystemExit("Supply an extracted Crimsonland 1.4.0 install with --game-dir.")
    assets = out / "assets"
    prepare(root, install, assets)
    core = root / "crimson-core"
    with tempfile.TemporaryDirectory() as stage:
        sources = [
            core / "freeware/client.cpp",
            core / "freeware/display.cpp",
            core / "freeware/hud.cpp",
            core / "freeware/music.cpp",
            *game_sources(root, Path(stage)),
        ]
        flags = game_flags(root)
        if target == "web":
            binary = out / "index.html"
            cmd = [
                _tool("em++"),
                *flags,
                *sources,
                "-sUSE_SDL=3",
                "-lidbfs.js",
                "-sEXPORTED_RUNTIME_METHODS=FS,IDBFS,addRunDependency,removeRunDependency",
                "-sALLOW_MEMORY_GROWTH",
                "--preload-file",
                f"{assets}@/assets",
                "--shell-file",
                core / "freeware/shell.html",
                "-o",
                binary,
            ]
        else:
            binary = out / "crimson"
            sdl = shlex.split(subprocess.check_output([_tool("pkg-config"), "--cflags", "--libs", "sdl3"], text=True))
            cmd = [_tool("clang++"), *flags, *sources, *sdl, "-o", binary]
        subprocess.run(cmd, check=True)
    print(binary)
