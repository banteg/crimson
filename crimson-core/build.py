"""Compile recovered gameplay bodies with isolated platform glue."""

import argparse
import concurrent.futures
import difflib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from adapter import DIFFS, PROTOTYPES, adapt, apply_diffs, load_diffs, prototypes
from data import data_source
from game import (
    GAME_DIFFS,
    adapt_game,
    com_defaults,
    engine_globals,
    game_data,
    game_header,
    game_initializers,
    game_platform,
    game_sources,
    game_third_party,
    game_vendor_c,
    game_wrapped,
    object_name,
    simulation_names,
)

HERE = Path(__file__).resolve().parent
HOST = HERE / "host"


EXPORTS = (
    "portable_init",
    "portable_step",
    "portable_snapshot",
    "portable_input",
    "portable_config",
    "portable_output",
    "portable_commands",
    "portable_step_many",
    "portable_builder_probe",
    "portable_math_probe",
    "portable_player_x",
    "portable_player_y",
    "portable_player_health",
    "portable_shake_x",
    "portable_shake_y",
    "portable_probe",
    "portable_nearest_creature",
)
# An extern declaration of one name, optionally an array: the alignment a name really has goes before its `;`.
EXTERN = re.compile(r"(\bextern\b[^;{}()]*?\b(\w+)\s*(?:\[[^\]]*\])?)\s*;")
# Player one and the shake, for the service's ranked aim bound, and the nearest creature, for its input signals (host/api.h).
PROBE_READS = {
    "portable_nearest_creature",
    "portable_player_x",
    "portable_player_y",
    "portable_player_health",
    "portable_shake_x",
    "portable_shake_y",
}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=HERE.parent)
    p.add_argument("--target", choices=["native", "wasm", "game"], default="native")
    p.add_argument("--out", type=Path)
    p.add_argument(
        "--prepare",
        action="store_true",
        help="Write the adapted sources and adapted.diff, their changes from decomp/, without compiling",
    )
    a = p.parse_args()
    a.out = (a.out or HERE / "build" / a.target).resolve()
    a.out.mkdir(parents=True, exist_ok=True)
    headers = a.out / "include"
    headers.mkdir(exist_ok=True)
    if a.target == "game":
        game_data(a.root, a.out, engine_globals(a.root), simulation_names(a.root))
        alignments = {}
    else:
        alignments = data_source(a.root, a.out)

    def align_externs(text):
        return EXTERN.sub(
            lambda m: f"{m[1]} __attribute__((aligned({alignments[m[2]]})));" if m[2] in alignments else m[0],
            text,
        )

    hunks = load_diffs(GAME_DIFFS if a.target == "game" else DIFFS)
    adapted = {}  # repository-relative path: (decomp text, adapted text)
    for f in sorted((a.root / "tools/match/include").glob("*.h")):
        rel, raw = str(f.relative_to(a.root)), f.read_text()
        text = prototypes(f, apply_diffs(rel, raw, hunks), PROTOTYPES)
        if a.target == "game":
            text = game_header(f, text)
        adapted[rel] = (raw, align_externs(text))
        (headers / f.name).write_text(adapted[rel][1])
    (headers / "ogg").mkdir(exist_ok=True)
    (headers / "ogg/config_types.h").write_text(
        "#include <stdint.h>\ntypedef int16_t ogg_int16_t; typedef uint16_t ogg_uint16_t; typedef int32_t ogg_int32_t; typedef uint32_t ogg_uint32_t; typedef int64_t ogg_int64_t;\n",
    )
    (headers / "new.h").write_text("#include <new>\n")
    wasm = a.target != "native"
    if a.target == "game":
        com_defaults(a.root, headers)
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
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(a.out / "zig-global"), ZIG_LOCAL_CACHE_DIR=str(a.out / "zig-local"))
    zig = shutil.which("zig")
    if not zig or subprocess.check_output([zig, "version"], text=True).strip() != "0.17.0":
        raise SystemExit("The shared math adapter requires Zig 0.17.0")
    cc = [zig, "c++", "-target", "wasm32-wasi"] if wasm else ["clang++"]
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
        *(["-DCRIMSON_GAME", "-I" + str(HERE / "game/include")] if a.target == "game" else []),
        "-I" + str(HOST),
        "-I" + str(headers),
        "-I" + str(a.root / "third_party/headers"),
    ]
    if not wasm and os.uname().sysname == "Darwin":
        flags.append("-mmacosx-version-min=11.0")
    if a.target == "game":
        # The version, format and rules a replay names, as the Python port names its own (host/ranked.inc).
        from crimson.game_version import REPLAY_FORMAT_VERSION, REPLAY_RULES, current_replay_game_version

        flags += [
            f'-DCRIMSON_GAME_VERSION="{current_replay_game_version()}"',
            f"-DCRIMSON_REPLAY_FORMAT={REPLAY_FORMAT_VERSION}",
            f"-DCRIMSON_REPLAY_RULES={REPLAY_RULES}",
        ]
    sources = json.loads((HERE / "sources.json").read_text())
    if a.target == "game":
        sources += game_sources(a.root)
    name = object_name if a.target == "game" else lambda rel: Path(rel).stem

    # The game module compiles every source the verifier does, so every diff applies there; the verifier skips
    # the ones for files it leaves out.
    if a.target == "game" and (missing := sorted(set(hunks) - set(sources) - set(adapted))):
        raise SystemExit(f"Diffs for files outside the build: {', '.join(missing)}")
    wrapped = game_wrapped(a.root) if a.target == "game" else set()

    def compile_one(rel):
        src = a.root / rel
        raw = src.read_text()
        txt = align_externs(adapt(src, apply_diffs(rel, raw, hunks)))
        if a.target == "game":
            txt = adapt_game(src, txt, rel in wrapped)
        adapted[rel] = (raw, txt)
        dst = a.out / (name(rel) + ".cpp")
        dst.write_text(f'#line 1 "{src}"\n' + txt)
        if a.prepare:
            return None
        obj = a.out / (name(rel) + ".o")
        proc = subprocess.run(
            # Every recovered source sees what the edits to it call (host/hooks.h).
            cc + flags + ["-include", str(HOST / "hooks.h"), "-c", str(dst), "-o", str(obj)],
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
    if a.prepare:
        changed = {rel: texts for rel, texts in sorted(adapted.items()) if texts[0] != texts[1]}
        (a.out / "adapted.diff").write_text(
            "".join(
                line
                for rel, (old, new) in changed.items()
                for line in difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{rel}", f"b/{rel}")
            ),
        )
        print(f"{len(changed)}/{len(adapted)} files differ from decomp/: {a.out / 'adapted.diff'}")
        return
    (a.out / "errors.txt").write_text("\n".join(f"{s}\n{e}" for s, e in errors))
    print(f"{len(sources) - len(errors)}/{len(sources)} compiled; errors: {a.out / 'errors.txt'}")
    if errors:
        raise SystemExit(1)
    glue = [a.out / "data.cpp", HOST / "host.cpp", *(game_platform() if a.target == "game" else [])]
    if a.target == "game":
        game_initializers(a.root, a.out)
        glue.append(a.out / "initializers.cpp")
    third_party = game_third_party(a.root) if a.target == "game" else []
    for src in third_party:
        proc = subprocess.run(
            [
                zig,
                "cc",
                "-target",
                "wasm32-wasi",
                "-std=gnu89",
                "-O2",
                "-w",
                "-DHAVE_BOOLEAN",
                "-Dboolean=unsigned char",
                "-I" + str(HERE / "game/include"),
                "-I" + str(a.root / "third_party/headers"),
                "-c",
                str(src),
                "-o",
                str(a.out / f"third_party_{src.stem}.o"),
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode:
            print(proc.stderr)
            raise SystemExit(1)
    vendor = game_vendor_c() if a.target == "game" else []
    for src in vendor:
        proc = subprocess.run(
            [
                zig,
                "cc",
                "-target",
                "wasm32-wasi",
                "-std=c11",
                "-O2",
                "-w",
                "-c",
                str(src),
                "-o",
                str(a.out / f"vendor_{src.stem}.o"),
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode:
            print(proc.stderr)
            raise SystemExit(1)
    for src in glue:
        proc = subprocess.run(
            cc + flags + ["-c", str(src), "-o", str(a.out / (src.stem + ".o"))],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode:
            print(proc.stderr)
            raise SystemExit(1)
    ziglib = Path(re.search(r'\.lib_dir = "([^"]+)"', subprocess.check_output([zig, "env"], env=env, text=True))[1]).resolve()
    runtime = a.out / "runtime"
    # Relink every build, so a build directory from another Zig never keeps that Zig's runtime.
    runtime.unlink(missing_ok=True)
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
        "-Mroot=" + str(HOST / "math.zig"),
        "-Mrt=" + str(a.out / "runtime_bridge.zig"),
        "-femit-bin=" + str(a.out / "math.o"),
    ]
    if wasm:
        mathcmd[2:2] = ["-target", "wasm32-wasi"]
    elif os.uname().sysname != "Darwin":
        # Linux clang links PIE executables by default. The imported compiler
        # runtime must not optimize its memory loops into calls to themselves.
        mathcmd[2:2] = ["-fPIC", "-mcpu=baseline", "-fno-builtin"]
    elif os.uname().sysname == "Darwin":
        mathcmd[2:2] = ["-target", "aarch64-macos.11.0" if os.uname().machine == "arm64" else "x86_64-macos.11.0"]
    subprocess.run(mathcmd, env=env, check=True)
    objs = [str(a.out / (name(f) + ".o")) for f in sources] + [str(a.out / (src.stem + ".o")) for src in glue]
    objs += [str(a.out / f"third_party_{src.stem}.o") for src in third_party]
    objs += [str(a.out / f"vendor_{src.stem}.o") for src in vendor]
    objs.append(str(a.out / "math.o"))
    link = (
        cc
        + (["-mmacosx-version-min=11.0"] if not wasm and os.uname().sysname == "Darwin" else [])
        + objs
        + ["-o", str(a.out / {"native": "core", "wasm": "core.wasm", "game": "game.wasm"}[a.target])]
    )
    if wasm:
        link += [
            "-mexec-model=reactor",
            *(["-Wl,--strip-debug"] if a.target == "wasm" else []),
            *(
                f"-Wl,--export={name}"
                for name in EXPORTS
                # The verifier's probes serve its service and oracles, not the game module.
                if a.target == "wasm" or not (name.endswith("_probe") or name in PROBE_READS)
            ),
            "-Wl,-z,stack-size=1048576",
        ]
    proc = subprocess.run(link, env=env, capture_output=True, text=True, check=False)
    (a.out / "link.log").write_text(proc.stderr)
    if proc.returncode:
        print(proc.stderr[-12000:])
    if wasm and "function signature mismatch" in proc.stderr:
        raise SystemExit("WASM ABI warning; see link.log")
    raise SystemExit(proc.returncode)


if __name__ == "__main__":
    main()
