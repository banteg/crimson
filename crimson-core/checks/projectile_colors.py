"""Capture head colors from the actual adapted projectile renderer, for both bug policies."""

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
        # Only graphics submission is doubled; compile the full adapted routine.
        (out / "grim2d_cpp.h").write_text('#include "projectile_colors_grim.h"\n')
        path = ROOT / "decomp/1.9/crimsonland/crimsonland/projectile_render.cpp"
        text = adapter.apply_diffs(str(path.relative_to(ROOT)), path.read_text(), hunks)
        text = game.adapt_game(path, adapter.adapt(path, text))
        (out / "projectile-under-test.cpp").write_text(text)
        subprocess.run(
            [
                compiler, "-std=c++17", "-O2", "-fms-extensions", "-fno-strict-aliasing", "-ffp-contract=off",
                "-Wno-ignored-attributes", "-Wno-unknown-attributes", "-Wno-write-strings", "-DCRIMSON_GAME",
                "-include", str(CORE / "host/hooks.h"),
                "-I" + str(CORE / "host"), "-I" + str(CORE / "game/include"),
                "-I" + str(CORE / "checks"), "-I" + str(out), "-I" + str(ROOT / "third_party/headers"),
                str(CORE / "checks/projectile_colors.cpp"), "-o", str(out / "check"),
            ],
            check=True,
        )
        subprocess.run([str(out / "check")], check=True)


if __name__ == "__main__":
    main()
