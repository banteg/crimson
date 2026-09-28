"""Pinned, preserving C2 observations. Trace comparisons are diagnostics, never match credit."""

from __future__ import annotations

import json
import os
import shutil
import struct
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

from . import match
from . import match_c2_replay as replay

ASSETS = match.DEFAULT_MATCH_ROOT / "c2"
NODE_WORDS = 742
MAX_NODES = 16384


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


@contextmanager
def compiler_environment():
    values = {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(replay.COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(replay.WIBO),
        "CRIMSON_IL_BACKEND": replay.windows_path(replay.COMPILER / "Bin/C2.DLL"),
    }
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def load_profile() -> dict[str, Any]:
    profile = json.loads((ASSETS / "profile.json").read_text())
    require(profile["schema_version"] == 1, "Unsupported C2 profile")
    require(
        replay.sha((replay.COMPILER / "Bin/C2.DLL").read_bytes()) == profile["c2_sha256"],
        "C2 binary does not match the pinned observer profile; no hooks installed",
    )
    return profile


def observer_source(profile: dict[str, Any]) -> str:
    """Generate callsite wrappers from the checked-in profile, without editing compiler files."""
    hooks = profile["hooks"]
    declarations = [
        f"#define HOOK_COUNT {len(hooks)}",
        f"#define INVOKE_RVA {profile['invoke_rva']}",
        f"#define MAX_NODES {MAX_NODES}",
    ]
    wrappers = []
    for index, hook in enumerate(hooks):
        slot = index * 4
        before = f"""__declspec(naked) static void phase_{index}(void) {{
 __asm {{
 pushfd
 pushad
 mov eax,esp
 push eax
 push {index}
 call observe
 add esp,8
 popad
 popfd
"""
        if hook["return"]:
            before = before.removesuffix(" popad\n popfd\n")
            before += f""" cmp dword ptr [active+{slot}],0
 jne recursive_call
 mov dword ptr [active+{slot}],1
 popad
 popfd
 push eax
 mov eax,dword ptr [esp+4]
 mov dword ptr [returns+{slot}],eax
 mov dword ptr [esp+4],offset after_call
 pop eax
 jmp dword ptr [targets+{slot}]
 after_call:
 pushfd
 pushad
 mov eax,esp
 push eax
 push {index + 100}
 call observe
 add esp,8
 mov dword ptr [active+{slot}],0
 popad
 popfd
 jmp dword ptr [returns+{slot}]
 recursive_call:
 push 83
 call ExitProcess
"""
        else:
            before += f" jmp dword ptr [targets+{slot}]\n"
        wrappers.append(before + " }\n}\n")
    arrays = "\n".join(
        [
            "static unsigned long sites[] = {" + ",".join(str(h["site"]) for h in hooks) + "};",
            "static unsigned long offsets[] = {" + ",".join(str(h["target"]) for h in hooks) + "};",
            "static void (*hooks[])(void) = {" + ",".join(f"phase_{i}" for i in range(len(hooks))) + "};",
        ],
    )
    template = (ASSETS / "observer.c.in").read_text()
    return (
        "\n".join(declarations)
        + "\n"
        + template.replace(
            "/* GENERATED_PROFILE */",
            "",
        ).replace("/* GENERATED_HOOKS */", "\n".join(wrappers) + arrays)
    )


def decode_trace(data: bytes, profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Reject truncated/unknown records; keep identities scoped to their observed event."""
    require(len(data) >= 12, "Truncated C2 trace header")
    magic, version, c2_base = struct.unpack_from("<3I", data)
    require(magic == 0x43325431 and version == 1, "Unsupported C2 trace format")
    offset = 12
    snapshots = []
    function_ordinal = -1
    while offset < len(data):
        require(len(data) - offset >= 12, "Truncated C2 event header")
        phase, function, count = struct.unpack_from("<3I", data, offset)
        offset += 12
        index = phase - 100 if phase >= 100 else phase
        require(index < len(profile["hooks"]), "Unknown C2 hook")
        hook = profile["hooks"][index]
        require(phase < 100 or hook["return"], "Unexpected return event")
        require(count <= MAX_NODES, "C2 node limit exceeded")
        require(len(data) - offset >= count * NODE_WORDS * 4, "Truncated C2 node records")
        nodes = []
        for _ in range(count):
            words = struct.unpack_from(f"<{NODE_WORDS}I", data, offset)
            offset += NODE_WORDS * 4
            node: dict[str, Any] = {"id": words[0], "op": words[1], "line": words[2], "flags": words[3]}
            for side, name in enumerate(("src", "dst")):
                start = 4 + side * 369
                require(words[start] <= 16, "C2 operand chain limit exceeded")
                operands = []
                for k in range(words[start]):
                    at = start + 1 + k * 23
                    raw = list(words[at : at + 7])
                    operands.append({"raw": raw, "kind": raw[2] & 255, "temp_words": list(words[at + 7 : at + 23])})
                node[name] = operands
            nodes.append(node)
        if phase == 0:
            function_ordinal += 1
        require(function_ordinal >= 0, "Trace starts after function entry")
        ordinal = function_ordinal
        snapshots.append(
            {
                "event": len(snapshots),
                "function_ordinal": ordinal,
                "function_address": function,
                "c2_base": c2_base,
                "phase": phase,
                "site_rva": hook["site"],
                "target_rva": hook["target"],
                "boundary": "return" if phase >= 100 else "entry",
                "nodes": nodes,
            },
        )
    require(bool(snapshots), "Empty C2 trace")
    return snapshots


def summarize(snapshots: list[dict[str, Any]], line: int | None = None) -> list[dict[str, Any]]:
    """Describe selected nodes and their current temporary users, without assuming stable arena IDs."""
    rows = []
    for event in snapshots:
        nodes = event["nodes"]
        selected = [node for node in nodes if line is None or node["line"] == line]
        temps = {op["raw"][6] for n in selected for side in ("src", "dst") for op in n[side] if op["kind"] == 1}
        users = []
        for temp in sorted(temps):
            occurrences = [
                {"node": n["id"], "line": n["line"], "op": n["op"], "side": side, "words": op["temp_words"]}
                for n in nodes
                for side in ("src", "dst")
                for op in n[side]
                if op["kind"] == 1 and op["raw"][6] == temp
            ]
            words = occurrences[0]["words"]
            users.append(
                {
                    "address": temp,
                    "occurrences": occurrences,
                    "descriptor": {
                        "flags_raw": words[1],
                        "priority_raw": words[3],
                        "register_descriptor_rva": words[4] - event["c2_base"] if words[4] else None,
                        "count_raw": words[9],
                        "cost_raw": words[15],
                    },
                },
            )
        rows.append(
            {k: v for k, v in event.items() if k != "nodes"}
            | {
                "node_count": len(nodes),
                "selected_nodes": selected,
                "temporaries": users,
            },
        )
    return rows


def compare(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> dict[str, Any]:
    """Find observable shape divergence at aligned hook occurrences, not semantic/value equivalence."""

    def keyed(events):
        seen: Counter = Counter()
        result = {}
        for e in events:
            base = (e["function_ordinal"], e["phase"])
            key = (*base, seen[base])
            seen[base] += 1
            result[key] = e
        return result

    def shape(event):
        # Alpha-renaming is event-local: do not connect recycled arena addresses
        # across events, or compare raw addresses from separate compiler runs.
        names = {}

        def operand(op):
            kind = op["kind"]
            if kind == 7:
                return (kind, op["raw"][6])
            if kind != 1:
                return (kind,)
            temp = op["raw"][6]
            ordinal = names.setdefault(temp, len(names))
            phase = event["phase"] % 100
            if phase < 12:
                return (kind, ordinal)
            words = op["temp_words"]
            register = words[4]
            register_rva = register - event["c2_base"] if register else None
            return (kind, ordinal, words[1], words[3], register_rva, words[9], words[15])

        return [
            (
                n["op"],
                n["line"],
                n["flags"],
                tuple(operand(op) for op in n["src"]),
                tuple(operand(op) for op in n["dst"]),
            )
            for n in event["nodes"]
        ]

    a, b = keyed(left), keyed(right)
    deltas = []
    for key in dict.fromkeys([*a, *b]):
        x, y = a.get(key), b.get(key)
        if x is None or y is None or shape(x) != shape(y):
            deltas.append(
                {
                    "function_ordinal": key[0],
                    "phase": key[1],
                    "occurrence": key[2],
                    "left_event": x["event"] if x else None,
                    "right_event": y["event"] if y else None,
                    "left_nodes": len(x["nodes"]) if x else None,
                    "right_nodes": len(y["nodes"]) if y else None,
                },
            )
    return {
        "kind": "c2-shape-comparison",
        "first_shape_difference": deltas[0] if deltas else None,
        "differences": deltas,
        "limitations": "Pairs function ordinals and hook occurrences. Compares opcode, line, flags, operand kinds, kind-7 payloads, event-local temporary relationships and selected descriptor fields (+04,+0c,+10,+24,+3c) only at the allocation callsites (hook indices 12+). Other operands remain opaque. Equal signatures do not establish semantic equivalence; descriptor field meanings are phase-dependent. Arena IDs may be recycled even within one trace.",
    }


def trace(scratch: Path, out: Path, *, passes_only: bool = False) -> dict[str, Any]:
    profile = load_profile()
    if passes_only:
        profile = {**profile, "hooks": profile["hooks"][:12]}
    config = match.load_scratch_config(scratch.resolve())
    require(config.compiler == "msvc6.5", "Only the pinned msvc6.5 profile is supported")
    require(not out.exists(), "Output directory must be new, to exclude stale traces and objects")
    out = out.resolve()
    replay.windows_path(out / "captured-source" / config.source)
    # Copy local includes as well as source; retain shared include-overlay configuration.
    require(not out.is_relative_to(config.directory.resolve()), "Output must be outside the scratch directory")
    out.mkdir(parents=True)
    (out / "profile.json").write_text(json.dumps(profile, indent=2) + "\n")
    source = out / "source"
    shutil.copytree(config.directory, source, ignore=shutil.ignore_patterns("build", "__pycache__", ".git"))
    captured_source = out / "captured-source"
    shutil.copytree(source, captured_source)
    folders = {name: out / name for name in ("helper", "capture", "replay", "observed", "missing-stream")}
    for directory in folders.values():
        directory.mkdir()
    frozen = replace(config, directory=source)
    with compiler_environment():
        helper = folders["helper"]
        shutil.copyfile(ASSETS / "capture.c", helper / "capture.c")
        replay.compile_driver(helper, "capture.c", "capture.obj")
        replay.link(helper, "capture.dll", "capture.obj", dll=True)
        normal = match.compile_scratch(frozen, force=True)
        wrapped_config = replace(
            frozen,
            directory=captured_source,
            cflags=config.cflags + f' /B2"Z:{helper / "capture.dll"}" /Bd',
        )
        old_capture = os.environ.get("CRIMSON_IL_CAPTURE_DIR")
        os.environ["CRIMSON_IL_CAPTURE_DIR"] = replay.windows_path(folders["capture"])
        try:
            wrapped = match.compile_scratch(wrapped_config, force=True)
        finally:
            if old_capture is None:
                os.environ.pop("CRIMSON_IL_CAPTURE_DIR", None)
            else:
                os.environ["CRIMSON_IL_CAPTURE_DIR"] = old_capture
        arguments, streams = replay.read_arguments(folders["capture"])
        hashes = {name: replay.sha(path.read_bytes()) for name, path in streams.items()}
        replay.build_replay(folders["replay"], arguments)
        replay.run([replay.WIBO, "replay.exe"], folders["replay"])
        observed = folders["observed"]
        shutil.copyfile(folders["replay"] / "replay_settings.h", observed / "replay_settings.h")
        (observed / "observer.c").write_text(observer_source(profile))
        replay.compile_driver(observed, "observer.c", "observer.obj")
        replay.link(observed, "observer.exe", "observer.obj")
        replay.run([replay.WIBO, "observer.exe"], observed)
        objects = [normal, wrapped, folders["replay"] / "replay.obj", observed / "replay.obj"]
        normalized = replay.normalized_coff(normal)
        require(
            all(replay.normalized_coff(p) == normalized for p in objects),
            "Observation changed the whole COFF object",
        )
        metrics = replay.function_metrics(frozen, normal)
        require(all(replay.function_metrics(frozen, p) == metrics for p in objects), "Replay matcher metrics differ")
        missing = streams["ex"]
        backup = missing.with_suffix(".withheld")
        missing.rename(backup)
        try:
            rejected = replay.run(
                [replay.WIBO, folders["replay"] / "replay.exe"],
                folders["missing-stream"],
                check=False,
            )
            require(
                rejected.returncode != 0 and not (folders["missing-stream"] / "replay.obj").exists(),
                "Missing-stream negative control did not reject replay",
            )
        finally:
            backup.rename(missing)
        require(
            hashes == {name: replay.sha(path.read_bytes()) for name, path in streams.items()},
            "Captured streams changed",
        )
    snapshots = decode_trace((observed / "phases.bin").read_bytes(), profile)
    (out / "snapshots.json").write_text(json.dumps(snapshots) + "\n")
    inputs = [
        *ASSETS.iterdir(),
        Path(__file__),
        Path(replay.__file__),
        replay.WIBO,
        *(
            replay.COMPILER / "Bin" / name
            for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL", "MSPDB60.DLL", "LINK.EXE")
        ),
        *replay.import_inputs(),
    ]
    result = {
        "schema_version": 1,
        "kind": "preserving-c2-trace",
        "profile": profile["name"],
        "function": config.function,
        "cflags": config.cflags,
        "source_sha256": replay.sha((source / config.source).read_bytes()),
        "build_key": json.loads((normal.parent / "scratch-build.json").read_text())["key"],
        "input_hashes": {str(p): replay.sha(p.read_bytes()) for p in inputs if p.is_file()},
        "stream_hashes": hashes,
        "whole_coff_equal_except_timestamp": True,
        "normalized_coff_sha256": replay.sha(normalized),
        "missing_stream_rejected": True,
        "compiler_decisions_modified": False,
        "passes_only": passes_only,
        "metrics": metrics,
        "events": len(snapshots),
        "object_paths": [str(p.relative_to(out)) for p in objects],
        "profile_sha256": replay.sha((out / "profile.json").read_bytes()),
        "trace_sha256": replay.sha((observed / "phases.bin").read_bytes()),
        "snapshots_sha256": replay.sha((out / "snapshots.json").read_bytes()),
    }
    (out / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def read_verified(directory: Path) -> list[dict[str, Any]]:
    record = json.loads((directory / "manifest.json").read_text())
    data = (directory / "snapshots.json").read_bytes()
    require(
        record.get("schema_version") == 1 and record.get("whole_coff_equal_except_timestamp") is True,
        "Not a verified preserving trace",
    )
    require(replay.sha(data) == record["snapshots_sha256"], "Snapshot digest mismatch")
    require(
        record.get("kind") == "preserving-c2-trace"
        and record.get("compiler_decisions_modified") is False
        and record.get("missing_stream_rejected") is True,
        "Trace preservation controls missing",
    )
    profile_bytes = (directory / "profile.json").read_bytes()
    require(replay.sha(profile_bytes) == record["profile_sha256"], "Profile digest mismatch")
    raw = (directory / "observed/phases.bin").read_bytes()
    require(replay.sha(raw) == record["trace_sha256"], "Raw trace digest mismatch")
    for relative in record["object_paths"]:
        path = (directory / relative).resolve()
        require(path.is_relative_to(directory.resolve()), "Object path escapes trace directory")
        require(
            replay.sha(replay.normalized_coff(path)) == record["normalized_coff_sha256"],
            "Preserved object digest mismatch",
        )
    snapshots = json.loads(data)
    require(snapshots == decode_trace(raw, json.loads(profile_bytes)), "Decoded snapshots differ from raw trace")
    return snapshots
