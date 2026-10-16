"""Exercise the game module's actual adapted effect pool and overflow."""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
ROOT = CORE.parent
sys.path.insert(0, str(CORE))
import adapter
import game


def main():
    compiler = shutil.which("clang++")
    if not compiler:
        raise SystemExit("clang++ is required")
    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder)
        hunks = adapter.load_diffs(game.GAME_DIFFS)
        for path in (ROOT / "tools/match/include").glob("*.h"):
            text = adapter.apply_diffs(str(path.relative_to(ROOT)), path.read_text(), hunks)
            text = adapter.prototypes(path, text, adapter.PROTOTYPES)
            (out / path.name).write_text(game.game_header(path, text))
        sources = []
        for name in (
            "effect_spawn.cpp",
            "effect_free.cpp",
            "effect_init_entry.cpp",
            "effect_defaults_reset.cpp",
            "effects_update.cpp",
        ):
            path = ROOT / "decomp/1.9/crimsonland/effects" / name
            text = adapter.apply_diffs(str(path.relative_to(ROOT)), path.read_text(), hunks)
            text = game.adapt_game(path, adapter.adapt(path, text))
            source = out / (name + ".cpp")
            source.write_text(text)
            sources.append(str(source))
        subprocess.run(
            [
                compiler,
                "-std=c++17",
                "-O2",
                "-fms-extensions",
                "-fno-strict-aliasing",
                "-ffp-contract=off",
                "-Wno-ignored-attributes",
                "-Wno-unknown-attributes",
                "-Wno-write-strings",
                "-DCRIMSON_GAME",
                # The generated game data aliases these names to the same pool.
                "-Deffect_pool_pos_x=effect_pool",
                "-include",
                str(CORE / "host/hooks.h"),
                "-I" + str(CORE / "host"),
                "-I" + str(CORE / "game/include"),
                "-I" + str(out),
                "-I" + str(ROOT / "third_party/headers"),
                *sources,
                str(CORE / "game/effect_overflow.cpp"),
                str(CORE / "checks/effect_overflow.cpp"),
                "-o",
                str(out / "check"),
            ],
            check=True,
        )
        subprocess.run([str(out / "check")], check=True)


if __name__ == "__main__":
    main()
