"""Compile recovered gameplay bodies with isolated platform glue."""

import argparse
import difflib
import json
import os
import re
import runpy
import shlex
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

from adapter import (
    DIFFS,
    GENERATED,
    PROTOTYPES,
    adapt,
    apply_diffs,
    check_diffs,
    check_guards,
    check_rules,
    load_diffs,
    prototypes,
    wrap,
    write_if_changed,
)
from data import data_source

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.build_identity import (
    WASI_SDK_VERSION,
    core_paths,
    file_hash,
    game_paths,
    runtime_identity,
    write_manifest,
)

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
        candidates = [Path(os.environ["WASI_SDK_PATH"]).resolve()]
    else:
        git = shutil.which("git") or "git"
        common = subprocess.check_output([git, "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=HERE, text=True).strip()
        candidates = [Path(common).parent / "artifacts/wasi-sdk", Path("/opt/wasi-sdk")]
    for sdk in candidates:
        if (sdk / "VERSION").is_file() and (sdk / "VERSION").read_text().split()[0] == WASI_SDK_VERSION:
            return sdk
    raise SystemExit(f"WASM targets require wasi-sdk {WASI_SDK_VERSION} at one of: {', '.join(map(str, candidates))}")


# A path in a build statement, where spaces, colons and dollars are Ninja's own syntax.
def ninja_path(path):
    return re.sub(r"[$ :]", lambda m: "$" + m[0], str(path))


# A command Ninja hands the shell: quoted for the shell, then with its dollars escaped for Ninja.
def ninja_command(args):
    return shlex.join(args).replace("$", "$$")


# The manifest beside a module, which the build writes once Ninja has linked it and the checks after the link pass.
def manifest(binary):
    return binary.with_name(binary.name + ".build.json")


# Whether a module is the one the build last linked and checked from these inputs: Ninja keeps any module newer than
# its objects, whatever its bytes.
def recorded(binary, fingerprint):
    if not (binary.exists() and manifest(binary).exists()):
        return False
    result = json.loads(manifest(binary).read_text())
    return result["fingerprint"] == fingerprint and result["artifacts"] == {binary.name: file_hash(binary)}


# A module the build cannot vouch for goes, and its manifest with it, which stands only beside a module the build
# linked and checked: Ninja links it again.
def discard(binary):
    binary.unlink(missing_ok=True)
    manifest(binary).unlink(missing_ok=True)


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
    # What this run generates, for the pruning below.
    GENERATED.clear()
    # Ninja runs in the output directory, where what the build writes goes by its relative name; everything else goes
    # by its absolute path, which Ninja's depfiles must be able to spell: they split a path at these characters.
    a.root = a.root.resolve()
    for path in (HERE, a.root):
        if re.search(r"[|;<>*^`\\\x00-\x1f\x7f]", str(path)):
            raise SystemExit(f"Ninja cannot track files under {path}, which holds | ; < > * ^ ` \\ or a control character")
    a.out = (a.out or HERE / "build" / a.target).resolve()
    # The build overwrites and prunes in its output directory and hashes its inputs into its identity: an output
    # directory holding files git tracks would lose them, and one among the inputs would change the identity every run.
    git = shutil.which("git")
    if git and a.out.is_dir() and subprocess.run([git, "ls-files"], cwd=a.out, capture_output=True, check=False).stdout:
        raise SystemExit(f"The output directory {a.out} holds files git tracks")
    inside = f"{a.out.relative_to(a.root).as_posix()}/" if a.out.is_relative_to(a.root) else ""
    if any(inside.startswith(p) for p in (game_paths if a.target == "game" else core_paths)(a.root) if p.endswith("/")):
        raise SystemExit(f"The output directory {a.out} lies among the build's inputs")
    a.out.mkdir(parents=True, exist_ok=True)
    headers = a.out / "include"
    headers.mkdir(exist_ok=True)
    # The generated sources, apart from the objects and logs, so their quoted includes, which look beside them first,
    # find nothing the build did not generate.
    source_dir = a.out / "src"
    source_dir.mkdir(exist_ok=True)
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
            heat_heads_header,
            object_name,
            simulation_names,
        )

        game_data(a.root, source_dir, engine_globals(a.root), simulation_names(a.root))
        alignments = {}
    else:
        alignments = data_source(a.root, source_dir, cc)

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
        write_if_changed(headers / f.name, adapted[rel][1])
    (headers / "ogg").mkdir(exist_ok=True)
    write_if_changed(
        headers / "ogg/config_types.h",
        "#include <stdint.h>\ntypedef int16_t ogg_int16_t; typedef uint16_t ogg_uint16_t; typedef int32_t ogg_int32_t; typedef uint32_t ogg_uint32_t; typedef int64_t ogg_int64_t;\n",
    )
    write_if_changed(headers / "new.h", "#include <new>\n")
    if a.target == "game":
        com_defaults(a.root, headers)
        write_if_changed(headers / "rtx_heat_heads.h", heat_heads_header(a.root))
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
    write_if_changed(headers / "snapshot.inc", "\n".join(lines) + "\n")
    write_if_changed(headers / "presentation.inc", ",".join(map(str, presentation)) + "\n")
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
        "-I" + str(headers.relative_to(a.out)),
        "-I" + str(a.root / "third_party/headers"),
    ]
    darwin = ["-mmacosx-version-min=11.0"] if not wasm and os.uname().sysname == "Darwin" else []
    flags += darwin
    build_identity = runtime_identity(a.target, a.root)
    versions = runpy.run_path(str(a.root / "src/crimson/game_version.py"))
    flags.append(f"-DCRIMSON_REPLAY_RULES={versions["REPLAY_RULES"]}")
    if a.target == "game":
        # The version, format and rules a replay names, as the Python port names its own (host/ranked.inc). The
        # version holds the source fingerprint, which any edit changes, so a header brings it to the files that name
        # it (host/host.cpp, game/changes/version.patch) and every other object stays compiled.
        flags.append(f"-DCRIMSON_REPLAY_FORMAT={versions["REPLAY_FORMAT_VERSION"]}")
        write_if_changed(headers / "game_version.h", f'#define CRIMSON_GAME_VERSION "{build_identity["version"]}"\n')
    sources = json.loads((HERE / "sources.json").read_text())
    if a.target == "game":
        sources += game_sources(a.root)
    # The guards between 1.9.8 and 1.9.93 that the diffs leave to the preprocessor must be the ones
    # editions/guards.json lists, each with its class, and the rules the sources name are the run's for this target.
    check_guards(a.root, hunks, sources)
    # From the output directory, where the compiles run and the flags' relative include resolves.
    check_rules(a.root, cc, flags, cwd=a.out)
    name = object_name if a.target == "game" else lambda rel: Path(rel).stem

    # The game module compiles every source the verifier does, so every diff applies there; the verifier skips
    # the ones for files it leaves out.
    if a.target == "game" and (missing := sorted(set(hunks) - set(sources) - set(adapted))):
        raise SystemExit(f"Diffs for files outside the build: {', '.join(missing)}")
    wrapped = game_wrapped(a.root) if a.target == "game" else CORE_WRAPPED

    for rel in sources:
        src = a.root / rel
        raw = src.read_text()
        txt = align_externs(adapt(src, apply_diffs(rel, raw, hunks)))
        if a.target == "game":
            txt = adapt_game(src, txt, rel in wrapped)
        elif rel in wrapped:
            txt = wrap(src, txt)
        adapted[rel] = (raw, txt)
        write_if_changed(source_dir / (name(rel) + ".cpp"), f'#line 1 "{src}"\n' + txt)
    if a.target == "game":
        game_initializers(a.root, source_dir)
    # Whatever sits among the generated headers and sources that this run did not generate goes (one it no longer
    # generates, or a stray), or the includes that found it would go on finding it.
    for path in [*headers.rglob("*"), *source_dir.rglob("*")]:
        if path.is_file() and path not in GENERATED:
            path.unlink()
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
    glue = [source_dir / "data.cpp", HOST / "host.cpp", *(game_platform() if a.target == "game" else [])]
    if a.target == "game":
        glue.append(source_dir / "initializers.cpp")
    third_party = game_third_party(a.root) if a.target == "game" else []
    vendor = game_vendor_c() if a.target == "game" else []
    # Each object's rule, source and name, in link order.
    objects = [("recovered", source_dir / (name(rel) + ".cpp"), name(rel) + ".o") for rel in sources]
    objects += [("glue", src, src.stem + ".o") for src in glue]
    objects += [("third_party", src, f"third_party_{src.stem}.o") for src in third_party]
    objects += [("vendor", src, f"vendor_{src.stem}.o") for src in vendor]
    objects.append(("math", HOST / "math.c", "math.o"))
    rules = {
        # Every recovered source sees what the edits to it call (host/hooks.h).
        "recovered": [*cc, *flags, "-include", str(HOST / "hooks.h")],
        "glue": [*cc, *flags],
        "third_party": [
            *c,
            "-std=gnu89",
            "-O2",
            "-w",
            "-DHAVE_BOOLEAN",
            "-Dboolean=unsigned char",
            "-I" + str(HERE / "game/include"),
            "-I" + str(a.root / "third_party/headers"),
        ],
        "vendor": [*c, "-std=c11", "-O2", "-w"],
        # The portable math (host/math.c over musl's sources) is C for the same compiler as everything else.
        "math": [
            *c,
            *darwin,
            "-std=c11",
            "-O2",
            "-ffp-contract=off",
            "-fno-builtin",
            "-I" + str(HOST / "musl/shim"),
            "-I" + str(HOST / "musl/src/internal"),
        ],
    }
    binary = a.out / {"native": "core", "wasm": "core.wasm", "game": "game.wasm"}[a.target]
    link_flags = []
    if wasm:
        link_flags += [
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
    # Ninja knows a compiler by its command, which stays the same when another compiler takes its path: every
    # object and the link also read what the compilers say they are.
    toolchain = a.out / "toolchain.txt"
    write_if_changed(toolchain, "".join(subprocess.check_output([*tool, "--version"], text=True) for tool in (c, cc)))
    # Depfiles name the headers an object read, not the ones its includes would find now, which a file added to or
    # removed from a directory they search changes: each rule's objects also read the names of the files under its -I
    # directories and its sources' own, except the generated sources', which hold nothing else. No include names a
    # dot-file, which Finder and editors leave about, and a searched directory holding the output directory leaves
    # out the build's own files there.
    searched = {}
    for rule, command in rules.items():
        dirs = {a.out / arg[2:] for arg in command if arg.startswith("-I")}
        dirs |= {src.parent for r, src, _ in objects if r == rule} - {source_dir}
        files = [
            path
            for d in sorted(dirs)
            for path in sorted(d.rglob("*"))
            if path.is_file()
            and not any(part.startswith(".") for part in path.relative_to(d).parts)
            and (d.is_relative_to(a.out) or not path.is_relative_to(a.out))
        ]
        searched[rule] = a.out / f"search_{rule}.txt"
        write_if_changed(searched[rule], "".join(f"{path}\n" for path in files))

    # Ninja runs in the output directory, so what lands there goes by its name in it, and the output directory never
    # reaches Ninja's syntax or its depfiles.
    def node(path):
        return ninja_path(path.relative_to(a.out) if path.is_relative_to(a.out) else path)

    lines = []
    for rule, command in rules.items():
        lines += [
            f"rule {rule}",
            f"  command = {ninja_command(command)} -MMD -MF $out.d -c $in -o $out",
            "  depfile = $out.d",
            "  deps = gcc",
        ]
    lines += [
        "rule link",
        f"  command = {ninja_command([*cc, *darwin])} $in -o $out {ninja_command(link_flags)} 2> link.log",
    ]
    lines += [
        f"build {ninja_path(obj)}: {rule} {node(src)} | {node(toolchain)} {node(searched[rule])}"
        for rule, src, obj in objects
    ]
    names = " ".join(ninja_path(obj) for *_, obj in objects)
    lines += [
        f"build objects: phony {names}",
        # The linker's warnings, which the ABI check below reads, come out of the link with the module.
        f"build {node(binary)} | link.log: link {names} | {node(toolchain)}",
        f"default {node(binary)}",
    ]
    write_if_changed(a.out / "build.ninja", "\n".join(lines) + "\n")
    # The locked Ninja, beside the interpreter running the build, before any other.
    ninja = [shutil.which("ninja", path=f"{sysconfig.get_path('scripts')}{os.pathsep}{os.environ['PATH']}") or "ninja"]
    ninja += ["-C", str(a.out), "--quiet", "-k", "0"]
    # Every object before the link, so every compile error comes at once.
    proc = subprocess.run([*ninja, "objects"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    (a.out / "errors.txt").write_text(proc.stdout)
    print(f"{len(objects) - proc.stdout.count('FAILED: ')}/{len(objects)} compiled; errors: {a.out / 'errors.txt'}")
    if proc.returncode:
        raise SystemExit(1)
    if not recorded(binary, build_identity["fingerprint"]):
        discard(binary)
    proc = subprocess.run(ninja, capture_output=True, check=False)
    log = (a.out / "link.log").read_text()
    if proc.returncode:
        print(log[-12000:])
    abi = wasm and "function signature mismatch" in log
    # Nothing loads a module that failed to link or the check, and the next build links it again.
    if proc.returncode or abi:
        discard(binary)
        raise SystemExit("WASM ABI warning; see link.log" if abi else proc.returncode)
    write_manifest(manifest(binary), build_identity, [binary])


if __name__ == "__main__":
    main()
