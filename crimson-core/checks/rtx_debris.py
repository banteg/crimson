"""Exercise the production debris budget and game hooks without a graphics context."""

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
    with tempfile.TemporaryDirectory(prefix="crimson-rtx-debris-") as folder:
        out = Path(folder)
        hunks = adapter.load_diffs(game.GAME_DIFFS)
        for path in (ROOT / "tools/match/include").glob("*.h"):
            text = adapter.apply_diffs(str(path.relative_to(ROOT)), path.read_text(), hunks)
            text = adapter.prototypes(path, text, adapter.PROTOTYPES)
            (out / path.name).write_text(game.game_header(path, text))
        binary = out / "check"
        subprocess.run([
            compiler, "-std=c++17", "-O2", "-fms-extensions", "-fno-strict-aliasing", "-ffp-contract=off",
            "-ffunction-sections", "-fdata-sections", "-Wno-ignored-attributes", "-Wno-unknown-attributes",
            "-Wno-write-strings", "-DCRIMSON_GAME", "-include", str(CORE / "host/hooks.h"),
            "-I" + str(CORE / "host"), "-I" + str(CORE / "game/include"), "-I" + str(out),
            "-I" + str(ROOT / "third_party/headers"), str(CORE / "checks/rtx_debris.cpp"),
            "-Wl,-dead_strip" if sys.platform == "darwin" else "-Wl,--gc-sections", "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
