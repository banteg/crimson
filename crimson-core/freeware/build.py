"""Build the historical freeware clients with SDL3 or Emscripten."""

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
                "frame.cpp",
                "level.cpp",
                "survival.cpp",
                "career.cpp",
                "weapons.cpp",
                "perks.cpp",
                "scores.cpp",
                "console.cpp",
            )
        ),
        *(
            recovered / name
            for name in (
                "creatures/creature_spawn.cpp",
                "creatures/creature_spawn_random.cpp",
                "bonuses/bonus_spawn_at.cpp",
                "creatures/creature_update_all.cpp",
                "creatures/creature_handle_death.cpp",
                "creatures/creature_find_nearest.cpp",
                "creatures/plaguebearer_spread_infection.cpp",
                "weapons/weapon_assign_player.cpp",
                "weapons/player_start_reload.cpp",
                "perks/perks_generate_choices.cpp",
                "perks/player_check_level.cpp",
                "weapons/weapon_name_get.cpp",
                "creatures/creature_alloc_slot.cpp",
                "creatures/creature_find_in_radius.cpp",
                "creatures/creature_reset_all.cpp",
                "player/freeware_float_minmax.cpp",
                "player/player_heading_approach_target.cpp",
                "player/player_update.cpp",
                "player/player_reset_all.cpp",
                "level/move_with_collision.cpp",
                "game/game_frame_update.cpp",
                "render/projectile_render.cpp",
                "render/terrain_render.cpp",
                "render/terrain_generate.cpp",
                "../level/render_layer.cpp",
                "render/fx_queue_render.cpp",
                "render/creature_render_all.cpp",
                "render/player_render.cpp",
                "render/effect_render_all.cpp",
                "player/freeware_refill_clip.cpp",
                "ui/gameplay_render_hud.cpp",
                "ui/hud_set_row.cpp",
                "ui/overlay_begin.cpp",
                "ui/game_show_message.cpp",
                "ui/perk_selection_screen_update.cpp",
                "perks/wrap_text_to_width_alloc.cpp",
                "ui/game_credits_update.cpp",
                "ui/game_highscores_update.cpp",
                "player/angle_approach.cpp",
                "projectiles/projectile_spawn.cpp",
                "projectiles/projectile_update.cpp",
                "effects/fx_queue_add.cpp",
                "effects/fx_queue_add_random.cpp",
                "effects/fx_queue_add_rotated.cpp",
                "effects/fx_queue_add_shell.cpp",
                "effects/fx_spawn_sprite.cpp",
                "effects/fx_spawn_secondary_projectile.cpp",
            )
        ),
    ]


def game_flags(root: Path, edition: str = "1.4.0") -> list[str]:
    major, minor, patch = map(int, edition.split("."))
    return [
        "-std=c++17",
        "-O2",
        "-fms-extensions",
        "-Wno-ignored-attributes",
        "-fno-strict-aliasing",
        "-ffp-contract=off",
        # Recovered shared routines use the portable client's 1.4 record representation.
        "-DCL_BUILD=10400",
        f"-DFREEWARE_EDITION={major * 10000 + minor * 100 + patch}",
        "-DCRIMSON_FREEWARE_CLIENT",
        "-I" + str(root / "tools/match/include"),
        "-I" + str(root / "crimson-core/freeware"),
        "-I" + str(root / "third_party/headers"),
    ]


def build(root: Path, target: str, out: Path, install: Path | None, edition: str = "1.4.0") -> None:
    if install is None:
        git_dir = subprocess.check_output(
            [_tool("git"), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=root,
            text=True,
        ).strip()
        install = Path(git_dir).parent / "game_bins/crimsonland" / edition
    if not (install / "crimson.paq").is_file():
        raise SystemExit(f"Supply an extracted Crimsonland {edition} install with --game-dir.")
    assets = out / "assets"
    prepare(root, install, assets, edition)
    core = root / "crimson-core"
    with tempfile.TemporaryDirectory() as stage:
        sources = [
            core / "freeware/client.cpp",
            core / "freeware/display.cpp",
            core / "freeware/music.cpp",
            *game_sources(root, Path(stage)),
        ]
        flags = game_flags(root, edition)
        if target == "web":
            shell = Path(stage) / "shell.html"
            save_root = "/freeware" if edition == "1.4.0" else f"/freeware-{edition}"
            width = 1024 if edition == "1.4.0" else 640
            shell.write_text(
                (core / "freeware/shell.html")
                .read_text()
                .replace("@EDITION@", edition)
                .replace("@SAVE_ROOT@", save_root)
                .replace("@WIDTH@", str(width))
                .replace("@HEIGHT@", str(width * 3 // 4)),
            )
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
                shell,
                "-o",
                binary,
            ]
        else:
            binary = out / "crimson"
            sdl = shlex.split(subprocess.check_output([_tool("pkg-config"), "--cflags", "--libs", "sdl3"], text=True))
            cmd = [_tool("clang++"), *flags, *sources, *sdl, "-o", binary]
        subprocess.run(cmd, check=True)
    print(binary)
