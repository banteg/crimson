"""Measure VC6 C1XX frontend record ids (the C2 fe symbol +0x28 id) per declaration kind.

C1XX numbers its symbols with one counter for the whole translation unit and writes each global record into the
`gl` stream (function-scope records into `sy`) as `<class byte> ... <id> <subkind byte> <name NUL>`. C2's
`p2symtab_10741b6d` 0x10741b6d reads the id with `il_read_id` 0x107416cd: two bytes little-endian, or, when bit 7
of the second byte is set, four bytes `b0 | (b1 & 0x7f) << 8 | (b2 << 16 | b3 << 24) >> 1`. The call operand hash
(`hash_operand` 0x1070db59, kind 4) folds this id of the callee.

This tool compiles C++ probe translation units with the pinned msvc6.5 driver and the `/B2` capture wrapper
(tools/match/c2/capture.c; unmodified C2 still runs), then decodes the id of every named record. A probe function
`int F(int);` placed after a prefix shows how many ids the prefix consumed.

    # ids of every named record in a source file (the file's directory is added to the include path)
    python scripts/c2/fe_id_probe.py ids scratch.cpp [--cflags "/O2 /G5 /W3 /IZ:/path/include"]
    # ids consumed by a prefix (a header, or #include lines): F's id after it minus F's id alone
    python scripts/c2/fe_id_probe.py measure prefix.h [--cflags ...]
    # built-in declaration kinds: F's id with N copies of the kind in front of it
    python scripts/c2/fe_id_probe.py sweep [--kind enumerator --kind typedef ...] [--counts 0,1,2,5]
    python scripts/c2/fe_id_probe.py kinds

Run with the Crimson environment (`uv run python ...` in a Crimson checkout). Intermediate files go to --work
(default: a temporary directory). See tools/match/c2/compiler/frontend-ids.md.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from itertools import pairwise
from pathlib import Path

from crimson import match
from crimson import match_c2_replay as replay

CAPTURE = match.DEFAULT_MATCH_ROOT / "c2/capture.c"
CFLAGS = "/O2 /G5 /W3"
NAME = re.compile(rb"([?_A-Za-z][\x21-\x7e]*)\x00")
PROBE = "int F(int);\nint probe(int a) { return F(a); }\n"
PROBE_NAME = "?F@@YAHH@Z"


def build_capture(work: Path) -> Path:
    helper = work / "helper"
    dll = helper / "capture.dll"
    if not dll.exists():
        helper.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(CAPTURE, helper / "capture.c")
        replay.compile_driver(helper, "capture.c", "capture.obj")
        replay.link(helper, "capture.dll", "capture.obj", dll=True)
    return dll


def compile_streams(source: str, directory: Path, dll: Path, cflags: str) -> dict[str, bytes]:
    """Compile `source` as C++ and return the captured frontend streams by suffix."""
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    (directory / "probe.cpp").write_text(source)
    env = dict(
        os.environ,
        CRIMSON_IL_CAPTURE_DIR=replay.windows_path(directory),
        CRIMSON_IL_BACKEND=replay.windows_path(replay.COMPILER / "Bin/C2.DLL"),
    )
    arguments = [match.DEFAULT_MATCH_ROOT / "cl.sh", "/c", *cflags.split(), f"/B2{replay.windows_path(dll)}"]
    result = subprocess.run(
        [str(a) for a in (*arguments, "/Foprobe.obj", "probe.cpp")],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode or not (directory / "arguments.bin").exists():
        raise RuntimeError(f"compile failed in {directory}:\n{result.stdout}{result.stderr}")
    _, streams = replay.read_arguments(directory)
    return {suffix: path.read_bytes() for suffix, path in streams.items()}


def id_before(data: bytes, end: int) -> int | None:
    """Decode the `il_read_id` value that ends at `end` (exclusive), preferring the four-byte form."""
    if end >= 4 and data[end - 3] & 0x80:
        b0, b1, b2, b3 = data[end - 4 : end]
        return b0 | (b1 & 0x7F) << 8 | (b2 << 16 | b3 << 24) >> 1
    if end >= 2 and not data[end - 1] & 0x80:
        return data[end - 2] | data[end - 1] << 8
    return None


def records(data: bytes) -> list[tuple[int, str]]:
    """(id, name) for each NUL-terminated name preceded by `<id> <subkind byte>`.

    Heuristic scan, not a full stream parser: source-file records (class 0x12) are `<0x12> <id> <name>` without
    the subkind byte, so their names decode to junk ids, as can other strings. Symbol names (decorated `?...`,
    locals, parameters) are reliable.
    """
    return [(value, m.group(1).decode()) for m in NAME.finditer(data) if (value := id_before(data, m.start() - 1))]


def fe_ids(source: str, directory: Path, dll: Path, cflags: str = CFLAGS) -> dict[str, int]:
    streams = compile_streams(source, directory, dll, cflags)
    ids: dict[str, int] = {}
    for suffix in ("gl", "sy"):
        for value, name in records(streams[suffix]):
            ids.setdefault(name, value)
    return ids


def probe_id(prefix: str, directory: Path, dll: Path, cflags: str) -> int:
    return fe_ids(prefix + PROBE, directory, dll, cflags)[PROBE_NAME]


# kind -> (head, unit, tail). The text before PROBE is head + N copies of unit + tail, with `@` in the unit
# replaced by the copy index so that every name is unique.
FN_HEAD = (
    "struct P { int a; };\nint g(int);\nvoid s(const char *);\nint arr[8];\nint f(int v, P *p, float fv, char c) { P q;"
)
FN_TAIL = " return v + q.a + c; }\n"
KINDS = {
    # enums, typedefs, tags
    "enumerator": ("enum E { e_", ", e@", " };\n"),
    "enum_type_1": ("", "enum E@ { e@ };\n", ""),
    "enum_type_empty": ("", "enum E@ { };\n", ""),
    "typedef": ("", "typedef int T@;\n", ""),
    "typedef_redecl": ("", "typedef int T;\n", ""),
    "typedef_fnptr_2param": ("", "typedef int (*T@)(int, float);\n", ""),
    "struct_forward": ("", "struct S@;\n", ""),
    "struct_forward_redecl": ("", "struct S;\n", ""),
    "struct_empty": ("", "struct S@ { };\n", ""),
    "struct_1member": ("", "struct S@ { int a; };\n", ""),
    "union_1member": ("", "union U@ { int a; };\n", ""),
    "typedef_struct_tag_2names": ("", "typedef struct tagX@ { int a; } X@, *PX@;\n", ""),
    "anonymous_union_member": ("", "struct S@ { union { int a; float b; }; };\n", ""),
    # class members
    "data_member": ("struct S {", " int m@;", " };\n"),
    "bitfield_member": ("struct S {", " int m@ : 1;", " };\n"),
    "fnptr_member_2param": ("struct S {", " int (*m@)(int, int);", " };\n"),
    "static_data_member": ("struct S {", " static int m@;", " };\n"),
    "method_void": ("struct S { int x;", " void m@();", " };\n"),
    "method_1param": ("struct S { int x;", " int m@(int);", " };\n"),
    "method_2param": ("struct S { int x;", " int m@(int, int);", " };\n"),
    "method_overload": ("struct S { int x;", " int m(char (*)[@ + 1]);", " };\n"),
    "inline_method_0param": ("struct S { int x;", " int m@() { return x; }", " };\n"),
    "inline_method_1param": ("struct S { int x;", " int m@(int v) { return x + v; }", " };\n"),
    "out_of_line_method": ("", "struct S@ { int x; int m(int); };\nint S@::m(int v) { return x + v; }\n", ""),
    "virtual_method": ("struct S { int x;", " virtual int m@(int);", " };\n"),
    "nested_struct_1member": ("struct S {", " struct N@ { int a; };", " };\n"),
    "class_user_default_ctor": ("", "struct S@ { S@(); int a; };\n", ""),
    "class_user_ctor_1param": ("", "struct S@ { S@(int); int a; };\n", ""),
    "class_user_copy_ctor": ("", "struct S@ { S@(const S@ &); int a; };\n", ""),
    "class_user_assign": ("", "struct S@ { S@ &operator=(const S@ &); int a; };\n", ""),
    "class_user_dtor": ("", "struct S@ { ~S@(); int a; };\n", ""),
    "class_virtual_dtor": ("", "struct S@ { virtual ~S@(); int a; };\n", ""),
    "class_member_with_dtor": ("struct A { ~A(); };\n", "struct S@ { A a; };\n", ""),
    "class_derived_polymorphic": ("struct B { virtual int s(int); };\n", "struct D@ : B { int a; };\n", ""),
    # functions
    "fn_void": ("", "void f@();\n", ""),
    "fn_void_void": ("", "void f@(void);\n", ""),
    "fn_1param": ("", "int f@(int);\n", ""),
    "fn_1param_named": ("", "int f@(int x);\n", ""),
    "fn_2param": ("", "int f@(int, int);\n", ""),
    "fn_4param": ("", "int f@(int, int, int, int);\n", ""),
    "fn_default_arg": ("", "int f@(int x = 3);\n", ""),
    "fn_ellipsis": ("", "int f@(const char *, ...);\n", ""),
    "fn_fnptr_param": ("", "int f@(int (*cb)(int, int));\n", ""),
    "fn_extern_c_stdcall": ("", 'extern "C" int __stdcall f@(int);\n', ""),
    "fn_redecl": ("", "int f(int);\n", ""),
    "fn_overload": ("", "int f(char (*)[@ + 1]);\n", ""),
    "fn_inline_decl": ("", "inline int f@(int);\n", ""),
    "fn_def_1param": ("", "int f@(int v) { return v + 1; }\n", ""),
    "fn_inline_def_1param": ("", "inline int f@(int v) { return v + 1; }\n", ""),
    "fn_def_empty": ("", "void f@() { }\n", ""),
    "fn_decl_then_def": ("", "int f@(int);\nint f@(int v) { return v; }\n", ""),
    "template_fn": ("", "template <class T> T t@(T v) { return v; }\n", ""),
    "template_class": ("", "template <class T> struct TS@ { T v; T get() { return v; } };\n", ""),
    # variables
    "extern_var": ("", "extern int v@;\n", ""),
    "extern_var_redecl": ("", "extern int v;\n", ""),
    "global_var": ("", "int v@;\n", ""),
    "global_var_init": ("", "int v@ = 5;\n", ""),
    "global_fnptr_var_2param": ("", "int (*v@)(int, int);\n", ""),
    "global_string_init": ("", 'const char *v@ = "s@";\n', ""),
    # preprocessor and scopes
    "define": ("", "#define M@ 5\n", ""),
    "namespace_empty": ("", "namespace ns@ { }\n", ""),
    "using_decl": ("namespace ns { int f(int); }\n", "using ns::f;\n", ""),
    # function bodies (the body is emitted; inline bodies that are never called give the same counts)
    "local_var": (FN_HEAD, " int t@ = v;", FN_TAIL),
    "static_local": (FN_HEAD, " static int t@; v += t@;", FN_TAIL),
    "string_literal_distinct": (FN_HEAD, ' s("x@");', FN_TAIL),
    "string_literal_same": (FN_HEAD, ' s("x");', FN_TAIL),
    "call_same_fn": (FN_HEAD, " g(1);", FN_TAIL),
    "expression_stmt": (FN_HEAD, " v = v * 3 + p->a; arr[v] += (v < 4) ? !v : c;", FN_TAIL),
    "cast_explicit": (FN_HEAD, " v = (int)v;", FN_TAIL),
    "sizeof_type": (FN_HEAD, " v = sizeof(P);", FN_TAIL),
    "if": (FN_HEAD, " if (v) v = 2;", FN_TAIL),
    "if_else": (FN_HEAD, " if (v) v = 2; else v = 3;", FN_TAIL),
    "if_and": (FN_HEAD, " if (v && p->a) v = 2;", FN_TAIL),
    "if_or": (FN_HEAD, " if (v || p->a) v = 2;", FN_TAIL),
    "while": (FN_HEAD, " while (v) v--;", FN_TAIL),
    "do_while": (FN_HEAD, " do v--; while (v);", FN_TAIL),
    "for_decl": (FN_HEAD, " { for (int j = 0; j < v; j++) p->a += j; }", FN_TAIL),
    "switch_2cases": (FN_HEAD, " switch (v) { case 1: v = 3; break; case 2: v = 4; break; }", FN_TAIL),
    "switch_case": (FN_HEAD + " switch (v) { case 0: v = 1;", " case @ + 1: v = 3;", " }" + FN_TAIL),
    "user_label": (FN_HEAD, " l@: v++;", FN_TAIL),
}


def expand(kind: str, n: int) -> str:
    head, unit, tail = KINDS[kind]
    return head + "".join(unit.replace("@", str(i)) for i in range(n)) + tail


def run_sweep(work: Path, kinds: list[str], counts: list[int], cflags: str, jobs: int) -> None:
    dll = build_capture(work)
    tasks = [(kind, n) for kind in kinds for n in counts]

    def one(task):
        kind, n = task
        return task, probe_id(expand(kind, n), work / "runs" / f"{kind}-{n}", dll, cflags)

    with ThreadPoolExecutor(jobs) as pool:
        results = dict(pool.map(one, tasks))
    for kind in kinds:
        values = [results[kind, n] for n in counts]
        points = list(zip(counts, values, strict=True))
        steps = [(b - a) / (m - n) for (n, a), (m, b) in pairwise(points)]
        # The first copy can differ (first function body, first overload, first virtual); report it apart.
        later = f"{steps[-1]:g}" if len(set(steps[1:])) == 1 else "nonlinear"
        pairs = " ".join(f"N={n}:{v:#x}" for n, v in points)
        print(f"{kind:28} {pairs}  first={steps[0]:g} then={later}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--work", type=Path, help="working directory (default: temporary)")
    parser.add_argument("--cflags", default=CFLAGS, help="compiler flags, e.g. with /IZ:<include dir>")
    sub = parser.add_subparsers(dest="command", required=True)
    ids = sub.add_parser("ids", help="print the fe id of every named record")
    ids.add_argument("source", type=Path)
    measure = sub.add_parser("measure", help="ids consumed by a prefix file placed before F")
    measure.add_argument("source", type=Path)
    sweep = sub.add_parser("sweep", help="F's id against N copies of each declaration kind")
    sweep.add_argument("--kind", action="append", choices=sorted(KINDS))
    sweep.add_argument("--counts", default="0,1,2,5")
    sweep.add_argument("--jobs", type=int, default=8)
    sub.add_parser("kinds", help="list the built-in kinds with N=2")
    args = parser.parse_args()
    if args.command == "kinds":
        for kind in KINDS:
            print(f"{kind}:\n  " + expand(kind, 2).rstrip("\n").replace("\n", "\n  "))
        return
    work = args.work or Path(tempfile.mkdtemp(prefix="feid"))
    work.mkdir(parents=True, exist_ok=True)
    if args.command == "sweep":
        counts = [int(x) for x in args.counts.split(",")]
        run_sweep(work, args.kind or list(KINDS), counts, args.cflags, args.jobs)
        return
    dll = build_capture(work)
    cflags = f"/I{replay.windows_path(args.source.parent)} {args.cflags}"
    if args.command == "ids":
        for name, value in fe_ids(args.source.read_text(), work / "ids", dll, cflags).items():
            print(f"{value:#07x} {name}")
    else:
        alone = probe_id("", work / "alone", dll, cflags)
        after = probe_id(args.source.read_text() + "\n", work / "after", dll, cflags)
        print(f"F alone {alone:#x}, after prefix {after:#x}: prefix consumed {after - alone} ids")


if __name__ == "__main__":
    main()
