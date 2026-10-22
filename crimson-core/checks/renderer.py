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
sys.path.insert(0, str(CORE))

from adapter import adapt, apply_diffs, load_diffs
from game import GAME_DIFFS, adapt_game


def tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit(f"{name} is required")
    return path


def build(out: Path, web: bool, benchmark: str | None = None) -> Path:
    # Compile the actual adapted full-screen helpers over the test's small Grim
    # bridge, so hard-coded, pre-corrected test vertices cannot hide edge gaps.
    hunks = load_diffs(GAME_DIFFS)
    sources = []
    for name in ("draw_fullscreen_quad", "draw_fullscreen_color"):
        path = CORE.parent / f"decomp/1.9/grim/render/{name}.cpp"
        source = apply_diffs(str(path.relative_to(CORE.parent)), path.read_text(), hunks)
        source = adapt_game(path, adapt(path, source))
        sources.append("\n".join(line for line in source.splitlines() if not line.startswith("#include")))
    (out / "fullscreen.inc").write_text("\n".join(sources))
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
    if benchmark is not None:
        flags += ["-DRENDERER_BENCHMARK=" + str(["baseline", "bilinear", "cubic"].index(benchmark))]
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
    parser.add_argument("--benchmark", choices=["baseline", "bilinear", "cubic"])
    args = parser.parse_args()
    if args.web:
        out = CORE / "build" / ("renderer-check" + ("-" + args.benchmark if args.benchmark else ""))
        out.mkdir(parents=True, exist_ok=True)
        print(build(out, True, args.benchmark))
    else:
        with tempfile.TemporaryDirectory(prefix="crimson-renderer-") as folder:
            subprocess.run([str(build(Path(folder), False, args.benchmark))], check=True)


if __name__ == "__main__":
    main()
