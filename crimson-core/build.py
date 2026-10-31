"""Compile recovered gameplay bodies with isolated platform glue."""

import argparse
import concurrent.futures
import difflib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

from adapter import (
    DIFFS,
    PROTOTYPES,
    adapt,
    apply_diffs,
    check_diffs,
    check_guards,
    check_rules,
    load_diffs,
    prototypes,
    wrap,
)
from data import data_source

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.build_identity import WASI_SDK_VERSION, runtime_identity, write_manifest

HERE = Path(__file__).resolve().parent
HOST = HERE / "host"


EXPORTS = (
    "portable_init",
    "portable_step",
    "portable_snapshot",
    "portable_input",
    "portable_config",
    "portable_quest",
    "portable_output",
    "portable_commands",
    "portable_step_many",
    "portable_refusal",
    "portable_builder_probe",
    "portable_math_probe",
    "portable_player_x",
    "portable_player_y",
    "portable_player_health",
    "portable_probe",
    "portable_nearest_creature",
    "portable_bakes",
)
# The recovered functions the verifier's host wraps (host/host.cpp), as the game module's are (game/sources.json):
# fx_queue_render, whose bakes it hands out, and music_play_exclusive, of which it keeps the simulation half.
CORE_WRAPPED = {
    "decomp/1.9/crimsonland/crimsonland/fx_queue_render.cpp",
    "decomp/1.9/crimsonland/audio/music_play_exclusive.cpp",
}
# An extern declaration of one name, optionally an array: the alignment a name really has goes before its `;`.
EXTERN = re.compile(r"(\bextern\b[^;{}()]*?\b(\w+)\s*(?:\[[^\]]*\])?)\s*;")
# Each player, for the service's ranked aim bound, the nearest creature, for its input signals, and each
# tick's bakes, for a run's ground (host/api.h).
PROBE_READS = {
    "portable_bakes",
    "portable_nearest_creature",
    "portable_player_x",
    "portable_player_y",
    "portable_player_health",
}


# The pinned wasi-sdk: WASI_SDK_PATH, else the main checkout's artifacts/wasi-sdk (which its worktrees share), else
# /opt/wasi-sdk.
def wasi_sdk() -> Path:
    if "WASI_SDK_PATH" in os.environ:
        candidates = [Path(os.environ["WASI_SDK_PATH"])]
    else:
        git = shutil.which("git") or "git"
        common = subprocess.check_output([git, "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=HERE, text=True).strip()
        candidates = [Path(common).parent / "artifacts/wasi-sdk", Path("/opt/wasi-sdk")]
    for sdk in candidates:
        if (sdk / "VERSION").is_file() and (sdk / "VERSION").read_text().split()[0] == WASI_SDK_VERSION:
            return sdk
    raise SystemExit(f"WASM targets require wasi-sdk {WASI_SDK_VERSION} at one of: {', '.join(map(str, candidates))}")


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
    wasm = a.target != "native"
    if wasm:
        sdk = wasi_sdk()
        c, cc = ([str(sdk / "bin" / tool), "--target=wasm32-wasip1"] for tool in ("clang", "clang++"))
    else:
        c, cc = ["clang"], ["clang++"]
    if a.target == "game":
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

        game_data(a.root, a.out, engine_globals(a.root), simulation_names(a.root))
        alignments = {}
    else:
        alignments = data_source(a.root, a.out, cc)

    def align_externs(text):
        return EXTERN.sub(
            lambda m: f"{m[1]} __attribute__((aligned({alignments[m[2]]})));" if m[2] in alignments else m[0],
            text,
        )

    hunks = load_diffs(GAME_DIFFS if a.target == "game" else DIFFS)
    # Every stale hunk at once, before anything compiles.
    check_diffs(a.root, hunks)
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
    if a.target == "game":
        com_defaults(a.root, headers)
    schema = json.loads((HERE / "schema.json").read_text())
    # The snapshot's words, and the indices of those only presentation reads (schema.json's `presentation`), which a
    # run inside the original may hold apart from the verifier's: a hash of its state leaves them out.
    lines, presentation, words = [], [], 0
    for group in schema:
        shown = [i for i, f in enumerate(group["fields"]) if f in group.get("presentation", [])]
        presentation += [words + n * len(group["fields"]) + i for n in range(group["count"]) for i in shown]
        words += group["count"] * len(group["fields"])
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
    (headers / "presentation.inc").write_text(",".join(map(str, presentation)) + "\n")
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
    build_identity = runtime_identity(a.target, a.root)
    versions = runpy.run_path(str(a.root / "src/crimson/game_version.py"))
    flags.append(f"-DCRIMSON_REPLAY_RULES={versions["REPLAY_RULES"]}")
    if a.target == "game":
        # The version, format and rules a replay names, as the Python port names its own (host/ranked.inc).
        flags += [
            f'-DCRIMSON_GAME_VERSION="{build_identity["version"]}"',
            f"-DCRIMSON_REPLAY_FORMAT={versions["REPLAY_FORMAT_VERSION"]}",
        ]
    sources = json.loads((HERE / "sources.json").read_text())
    if a.target == "game":
        sources += game_sources(a.root)
    # The guards between 1.9.8 and 1.9.93 that the diffs leave to the preprocessor must be the ones
    # editions/guards.json lists, each with its class, and the rules the sources name are the run's for this target.
    check_guards(a.root, hunks, sources)
    check_rules(a.root, cc, flags)
    name = object_name if a.target == "game" else lambda rel: Path(rel).stem

    # The game module compiles every source the verifier does, so every diff applies there; the verifier skips
    # the ones for files it leaves out.
    if a.target == "game" and (missing := sorted(set(hunks) - set(sources) - set(adapted))):
        raise SystemExit(f"Diffs for files outside the build: {', '.join(missing)}")
    wrapped = game_wrapped(a.root) if a.target == "game" else CORE_WRAPPED

    def compile_one(rel):
        src = a.root / rel
        raw = src.read_text()
        txt = align_externs(adapt(src, apply_diffs(rel, raw, hunks)))
        if a.target == "game":
            txt = adapt_game(src, txt, rel in wrapped)
        elif rel in wrapped:
            txt = wrap(src, txt)
        adapted[rel] = (raw, txt)
        dst = a.out / (name(rel) + ".cpp")
        dst.write_text(f'#line 1 "{src}"\n' + txt)
        if a.prepare:
            return None
        obj = a.out / (name(rel) + ".o")
        proc = subprocess.run(
            # Every recovered source sees what the edits to it call (host/hooks.h).
            cc + flags + ["-include", str(HOST / "hooks.h"), "-c", str(dst), "-o", str(obj)],
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
                *c,
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
                *c,
                "-std=c11",
                "-O2",
                "-w",
                "-c",
                str(src),
                "-o",
                str(a.out / f"vendor_{src.stem}.o"),
            ],
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
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode:
            print(proc.stderr)
            raise SystemExit(1)
    # The portable math (host/math.c over musl's sources) is C for the same compiler as everything else.
    subprocess.run(
        c
        + (["-mmacosx-version-min=11.0"] if not wasm and os.uname().sysname == "Darwin" else [])
        + ["-std=c11", "-O2", "-ffp-contract=off", "-fno-builtin", "-I" + str(HOST / "musl/shim")]
        + ["-I" + str(HOST / "musl/src/internal"), "-c", str(HOST / "math.c"), "-o", str(a.out / "math.o")],
        check=True,
    )
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
            # Without it wasi-libc's printf reports unsupported long doubles on stderr, a WASI import core.wasm
            # must not have.
            *(["-Wl,--strip-debug", "-lc-printscan-long-double"] if a.target == "wasm" else []),
            *(
                f"-Wl,--export={name}"
                for name in EXPORTS
                # The verifier's probes serve its service and oracles, not the game module.
                if a.target == "wasm" or not (name.endswith("_probe") or name in PROBE_READS)
            ),
            "-Wl,-z,stack-size=1048576",
        ]
    proc = subprocess.run(link, capture_output=True, text=True, check=False)
    (a.out / "link.log").write_text(proc.stderr)
    if proc.returncode:
        print(proc.stderr[-12000:])
    if wasm and "function signature mismatch" in proc.stderr:
        raise SystemExit("WASM ABI warning; see link.log")
    if proc.returncode == 0:
        binary = a.out / {"native": "core", "wasm": "core.wasm", "game": "game.wasm"}[a.target]
        write_manifest(binary.with_name(binary.name + ".build.json"), build_identity, [binary])
    raise SystemExit(proc.returncode)


if __name__ == "__main__":
    main()
