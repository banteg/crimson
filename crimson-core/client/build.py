"""Build the native client: the game module through wasm2c, under an SDL3 host.

Requires the game module (build.py --target game), wabt's wasm2c and SDL3.
"""

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parent


def tool(name):
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"{name} is required")
    return path


def wasm2c_runtime():
    wasm2c = tool("wasm2c")
    prefix = Path(wasm2c).resolve().parent.parent
    runtime, include = prefix / "share/wabt/wasm2c", prefix / "include"
    if not (runtime / "wasm-rt-impl.c").exists() or not (include / "wasm-rt.h").exists():
        raise SystemExit(f"wasm2c runtime not found under {prefix}")
    return wasm2c, runtime, include


def pkg_config(*args):
    return subprocess.check_output([tool("pkg-config"), *args, "sdl3"], text=True).split()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=CORE / "build/app")
    parser.add_argument("--skip-game", action="store_true", help="Reuse the built game module")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not args.skip_game:
        subprocess.run([sys.executable, str(CORE / "build.py"), "--target", "game"], check=True)
    wasm2c, runtime, include = wasm2c_runtime()
    subprocess.run([wasm2c, str(CORE / "build/game/game.wasm"), "-n", "game", "-o", str(out / "game.c")], check=True)

    clang, clangxx = tool("clang"), tool("clang++")
    cflags = ["-O2", "-I" + str(out), "-I" + str(runtime), "-I" + str(include), "-I" + str(HERE)]
    cxxflags = [*cflags, "-std=c++17", *pkg_config("--cflags")]
    jobs = [
        [clang, *cflags, "-c", str(out / "game.c"), "-o", str(out / "game.o")],
        *(
            [clang, *cflags, "-c", str(runtime / f"{name}.c"), "-o", str(out / f"{name}.o")]
            for name in ("wasm-rt-impl", "wasm-rt-mem-impl")
        ),
        *(
            [clangxx, *cxxflags, "-c", str(source), "-o", str(out / f"host_{source.stem}.o")]
            for source in sorted(HERE.glob("*.cpp"))
        ),
    ]
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool:
        failures = [
            r
            for r in pool.map(lambda job: subprocess.run(job, capture_output=True, text=True, check=False), jobs)
            if r.returncode
        ]
    for failure in failures:
        print(failure.stderr)
    if failures:
        raise SystemExit(1)
    objects = [job[job.index("-o") + 1] for job in jobs]
    system = ["-framework", "OpenGL"] if sys.platform == "darwin" else ["-lGL"]
    subprocess.run([clangxx, *objects, *pkg_config("--libs"), *system, "-o", str(out / "crimson")], check=True)
    print(out / "crimson")


if __name__ == "__main__":
    main()
