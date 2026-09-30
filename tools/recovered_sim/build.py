"""Compile recovered gameplay bodies with isolated platform glue."""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from adapter import adapt
from data import data_source

HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=HERE.parents[1])
    p.add_argument("--target", choices=["native", "wasm"], default="native")
    p.add_argument("--out", type=Path)
    a = p.parse_args()
    a.out = (a.out or HERE / "build" / a.target).resolve()
    a.out.mkdir(parents=True, exist_ok=True)
    headers = a.out / "include"
    headers.mkdir(exist_ok=True)
    for f in (a.root / "tools/match/include").glob("*.h"):
        text = f.read_text()
        if f.name == "grim2d_cpp.h":
            text = text.replace("(unsigned int)value", "(unsigned int)(uintptr_t)value")
            text = "#include <stdint.h>\n" + text
        (headers / f.name).write_text(text)
    (headers / "ogg").mkdir(exist_ok=True)
    (headers / "ogg/config_types.h").write_text(
        "#include <stdint.h>\ntypedef int16_t ogg_int16_t; typedef uint16_t ogg_uint16_t; typedef int32_t ogg_int32_t; typedef uint32_t ogg_uint32_t; typedef int64_t ogg_int64_t;\n",
    )
    (headers / "new.h").write_text("#include <new>\n")
    schema = json.loads((HERE / "schema.json").read_text())
    lines = []
    for group in schema:
        lines.append(f'trace_init("snapshot {group["name"]}");')
        if group["source"]:
            lines.append(f"for(int i=0;i<{group['count']};++i) {{const auto &s={group['source']}[i];")
            lines.extend(
                "put(portable_creature_index(s.owner));" if f == "owner_index" else f"put(s.{f});"
                for f in group["fields"]
            )
            lines.append("}")
        else:
            lines.extend(f"put({f});" for f in group["fields"])
    (headers / "snapshot.inc").write_text("\n".join(lines) + "\n")
    data_source(a.root, a.out)
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(a.out / "zig-global"), ZIG_LOCAL_CACHE_DIR=str(a.out / "zig-local"))
    zig = shutil.which("zig")
    if not zig or subprocess.check_output([zig, "version"], text=True).strip() != "0.16.0":
        raise SystemExit("The shared math adapter requires Zig 0.16.0")
    cc = ["clang++"] if a.target == "native" else [zig, "c++", "-target", "wasm32-wasi"]
    flags = [
        "-g",
        "-std=c++17",
        "-fms-extensions",
        "-fno-exceptions",
        "-fno-rtti",
        "-fno-strict-aliasing",
        "-fwrapv",
        "-ffp-contract=off",
        "-O2",
        "-Wno-ignored-attributes",
        "-Wno-write-strings",
        "-Wno-address-of-temporary",
        "-Wno-deprecated-register",
        "-Wno-int-to-pointer-cast",
        "-I" + str(HERE),
        "-I" + str(headers),
        "-I" + str(a.root / "third_party/headers"),
    ]
    if a.target == "native" and os.uname().sysname == "Darwin":
        flags.append("-mmacosx-version-min=11.0")
    sources = json.loads((HERE / "sources.json").read_text())
    fingerprints = json.loads((HERE / "provenance.json").read_text())
    for rel, expected in fingerprints.items():
        if hashlib.sha256((a.root / rel).read_bytes()).hexdigest() != expected:
            raise SystemExit(f"Recovered dependency changed; audit adapters before updating provenance: {rel}")

    def compile_one(rel):
        src = a.root / rel
        txt = src.read_text()
        txt = adapt(src, txt)
        dst = a.out / (src.stem + ".cpp")
        dst.write_text(f'#line 1 "{src}"\n' + txt)
        obj = a.out / (src.stem + ".o")
        proc = subprocess.run(
            cc + flags + ["-c", str(dst), "-o", str(obj)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode:
            return rel, proc.stderr
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        errors = [r for r in pool.map(compile_one, sources) if r]
    (a.out / "errors.txt").write_text("\n".join(f"{s}\n{e}" for s, e in errors))
    print(f"{len(sources) - len(errors)}/{len(sources)} compiled; errors: {a.out / 'errors.txt'}")
    if errors:
        raise SystemExit(1)
    for name in ["data.cpp", "host.cpp"]:
        src = a.out / name if name == "data.cpp" else HERE / name
        proc = subprocess.run(
            cc + flags + ["-c", str(src), "-o", str(a.out / (Path(name).stem + ".o"))],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode:
            print(proc.stderr)
            raise SystemExit(1)
    ziglib = Path(re.search(r'\.lib_dir = "([^"]+)"', subprocess.check_output([zig, "env"], env=env, text=True))[1])
    runtime = a.out / "runtime"
    if not runtime.exists():
        runtime.symlink_to(ziglib, target_is_directory=True)
    (a.out / "runtime_bridge.zig").write_text(
        'pub const sin = @import("runtime/compiler_rt/sin.zig");\npub const cos = @import("runtime/compiler_rt/cos.zig");\n',
    )
    mathcmd = [
        zig,
        "build-obj",
        "-O",
        "ReleaseFast",
        "-fno-omit-frame-pointer",
        "--dep",
        "rt",
        "-Mroot=" + str(HERE / "math.zig"),
        "-Mrt=" + str(a.out / "runtime_bridge.zig"),
        "-femit-bin=" + str(a.out / "math.o"),
    ]
    if a.target == "wasm":
        mathcmd[2:2] = ["-target", "wasm32-wasi"]
    elif os.uname().sysname != "Darwin":
        # Linux clang links PIE executables by default. The imported compiler
        # runtime must not optimize its memory loops into calls to themselves.
        mathcmd[2:2] = ["-fPIC", "-mcpu=baseline", "-fno-builtin"]
    elif os.uname().sysname == "Darwin":
        mathcmd[2:2] = ["-target", "aarch64-macos.11.0" if os.uname().machine == "arm64" else "x86_64-macos.11.0"]
    subprocess.run(mathcmd, env=env, check=True)
    objs = [str(a.out / (Path(f).stem + ".o")) for f in sources] + [
        str(a.out / "data.o"),
        str(a.out / "host.o"),
        str(a.out / "math.o"),
    ]
    link = (
        cc
        + (["-mmacosx-version-min=11.0"] if a.target == "native" and os.uname().sysname == "Darwin" else [])
        + objs
        + ["-o", str(a.out / ("core.wasm" if a.target == "wasm" else "core"))]
    )
    if a.target == "wasm":
        link += [
            "-mexec-model=reactor",
            "-Wl,--strip-debug",
            "-Wl,--export=portable_init",
            "-Wl,--export=portable_step",
            "-Wl,--export=portable_snapshot",
            "-Wl,--export=portable_input",
            "-Wl,--export=portable_config",
            "-Wl,--export=portable_output",
            "-Wl,--export=portable_commands",
            "-Wl,--export=portable_step_many",
            "-Wl,--export=portable_builder_probe",
            "-Wl,-z,stack-size=1048576",
        ]
    proc = subprocess.run(link, env=env, capture_output=True, text=True, check=False)
    (a.out / "link.log").write_text(proc.stderr)
    if proc.returncode:
        print(proc.stderr[-12000:])
    if a.target == "wasm" and "function signature mismatch" in proc.stderr:
        raise SystemExit("WASM ABI warning; see link.log")
    raise SystemExit(proc.returncode)


if __name__ == "__main__":
    main()
