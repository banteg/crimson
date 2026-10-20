"""Run real OpenGL renderer regression checks (SDL3; Linux needs Xvfb).

--web builds the same checks for a WebGL2 browser at build/renderer-check/index.html.
The game module and game assets are not needed.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]


def tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit(f"{name} is required")
    return path


def build(out: Path, web: bool) -> Path:
    filtering = (CORE.parent / "src/grim/filtering.glsl").read_text()
    (out / "filtering.h").write_text('R"GLSL(' + filtering + ')GLSL"\n')
    # Only wasm2c's scalar types are needed by the rendering imports.
    (out / "game.h").write_text(
        "#pragma once\n#include <stdint.h>\ntypedef uint8_t u8;\ntypedef uint32_t u32;\nstruct w2c_game;\n",
    )
    flags = (
        ["-sUSE_SDL=3", "-sMIN_WEBGL_VERSION=2", "-sMAX_WEBGL_VERSION=2", "-sALLOW_MEMORY_GROWTH"]
        if web
        else subprocess.check_output([tool("pkg-config"), "--cflags", "--libs", "sdl3"], text=True).split()
        + (["-framework", "OpenGL"] if sys.platform == "darwin" else ["-lGL"])
    )
    binary = out / ("index.html" if web else "renderer")
    subprocess.run(
        [
            tool("em++" if web else "clang++"),
            "-std=c++17",
            "-O2",
            "-I" + str(out),
            str(CORE / "checks/client_renderer.cpp"),
            *flags,
            "-o",
            str(binary),
        ],
        check=True,
    )
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web", action="store_true")
    args = parser.parse_args()
    if args.web:
        out = CORE / "build/renderer-check"
        out.mkdir(parents=True, exist_ok=True)
        print(build(out, True))
    else:
        with tempfile.TemporaryDirectory(prefix="crimson-renderer-") as folder:
            subprocess.run([str(build(Path(folder), False))], check=True)


if __name__ == "__main__":
    main()
