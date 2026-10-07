"""Build the client: the game module through wasm2c, under the SDL3 host.

--target native links a desktop executable against SDL3 (build/app/crimson).
--target web builds the same host with Emscripten (build/web/index.html).
Requires the game module (build.py --target game) and wabt's wasm2c.
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


def compile_all(jobs):
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
    return [job[job.index("-o") + 1] for job in jobs]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["native", "web"], default="native")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--skip-game", action="store_true", help="Reuse the built game module")
    args = parser.parse_args()
    out = (args.out or CORE / "build" / {"native": "app", "web": "web"}[args.target]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not args.skip_game:
        subprocess.run([sys.executable, str(CORE / "build.py"), "--target", "game"], check=True)
    wasm2c, runtime, include = wasm2c_runtime()
    subprocess.run([wasm2c, str(CORE / "build/game/game.wasm"), "-n", "game", "-o", str(out / "game.c")], check=True)

    web = args.target == "web"
    cc, cxx = (tool("emcc"), tool("em++")) if web else (tool("clang"), tool("clang++"))
    cflags = ["-O2", "-I" + str(out), "-I" + str(runtime), "-I" + str(include), "-I" + str(HERE)]
    # The browser build has no threads; wasm2c then guards memory by bounds checks.
    cflags += ["-sUSE_SDL=3", "-DWASM_RT_USE_PTHREADS=0"] if web else []
    cxxflags = [*cflags, "-std=c++17", *([] if web else pkg_config("--cflags"))]
    objects = compile_all(
        [
            [cc, *cflags, "-c", str(out / "game.c"), "-o", str(out / "game.o")],
            *(
                [cc, *cflags, "-c", str(runtime / f"{name}.c"), "-o", str(out / f"{name}.o")]
                for name in ("wasm-rt-impl", "wasm-rt-mem-impl")
            ),
            *(
                [cxx, *cxxflags, "-c", str(source), "-o", str(out / f"host_{source.stem}.o")]
                for source in sorted(HERE.glob("*.cpp"))
            ),
        ],
    )
    if web:
        link = [
            cxx,
            *objects,
            "-O2",
            "-sUSE_SDL=3",
            "-sMIN_WEBGL_VERSION=2",
            "-sMAX_WEBGL_VERSION=2",
            "-sALLOW_MEMORY_GROWTH",
            "-sSTACK_SIZE=1048576",
            "-sEXIT_RUNTIME=0",
            "-sEXPORTED_RUNTIME_METHODS=FS,IDBFS,addRunDependency,removeRunDependency",
            "-lidbfs.js",
            "--shell-file",
            str(HERE / "web/shell.html"),
            "-o",
            str(out / "index.html"),
        ]
    else:
        system = ["-framework", "OpenGL"] if sys.platform == "darwin" else ["-lGL"]
        link = [cxx, *objects, *pkg_config("--libs"), *system, "-o", str(out / "crimson")]
    subprocess.run(link, check=True)
    print(out / ("index.html" if web else "crimson"))


if __name__ == "__main__":
    main()
