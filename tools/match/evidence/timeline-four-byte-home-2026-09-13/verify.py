"""Reproduce a four-byte dead pointer store and its guard-elimination history.

These sources are diagnostic controls, not proposed recovered game code.
"""

import argparse
import difflib
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from crimson import match
from crimson import match_c2 as c2

HERE = Path(__file__).resolve().parent
BASE_SHA = "a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9"
COPY = """int *selected = &entry->template_id;
            int *copied;
            for (unsigned int k = 0; k < sizeof copied; ++k)
                ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k];
            int *template_id = selected;
            if (copied != selected && entry->count <= 0) return;"""
TRIPLET = [
    "lea edi, dword [esi+0xc]",
    "mov dword [esp+0x10], edi",
    "mov dword [esp+0x10], ebx",
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sources(base):
    witness = base.replace("int *template_id = &entry->template_id;", COPY).replace(
        "entry->heading", "((float *)template_id)[-1]",
    )
    guard = "if (copied != selected && entry->count <= 0) return;"
    loop = """for (unsigned int k = 0; k < sizeof copied; ++k)
                ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k];"""
    hoisted = witness.replace("        int spawn_index = 0;\n", "").replace(
        "    do {\n        quest_timeline", "    int spawn_index = 0;\n    do {\n        quest_timeline",
    ).replace("        entry_count = quest_spawn_count;", "        spawn_index = 0;\n        entry_count = quest_spawn_count;")
    hoisted = hoisted.replace("entry->count = 0;", "entry->count = spawn_index;").replace(
        "creatures_any_active_flag = 0;", "creatures_any_active_flag = spawn_index;",
    )
    return {
        "canonical": base,
        "positive": witness,
        "reversed": witness.replace(guard, "if (entry->count <= 0 && copied != selected) return;"),
        "dead": witness.replace(guard, ""),
        "read": witness.replace(guard, "").replace("int *template_id = selected;", "int *template_id = copied;"),
        "null-guard": witness.replace("copied != selected", "copied == 0"),
        "count-equals-zero": witness.replace("entry->count <= 0", "entry->count == 0"),
        "memcpy": "#include <string.h>\n" + witness.replace(loop, "memcpy(&copied, &selected, sizeof copied);"),
        "assignment": witness.replace(loop, "copied = selected;"),
        "counter-lifetime": hoisted,
    }


def build(config, directory, source):
    directory.mkdir(parents=True)
    (directory / "scratch.cpp").write_text(source)
    (directory / "scratch.conf").write_bytes((config.directory / "scratch.conf").read_bytes())
    cfg = replace(config, directory=directory)
    obj = match.compile_scratch(cfg, force=True)
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    result = match.run_match(obj_path=obj, function=cfg.function, symbol_name=cfg.symbol, reference_aliases=cfg.reference_aliases)
    lines = [x.text for x in result.candidate_disassembly]
    native = [x.text for x in result.target_disassembly]
    (directory / "candidate.asm").write_text("\n".join(lines) + "\n")
    (directory / "native-diff.txt").write_text("\n".join(difflib.unified_diff(native, lines, fromfile="native", tofile="candidate")) + "\n")
    row = {
        "source_sha256": sha(source.encode()),
        "body_sha256": sha(body.data),
        "normalized_coff_sha256": sha(c2.replay.normalized_coff(obj)),
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
        "instructions": len(result.candidate_lines),
        "target_instructions": len(result.target_lines),
        "prefix": result.prefix_instructions,
        "ratio": result.ratio,
        "refs": [result.masked_operand_audit.ok_count, result.masked_operand_audit.unresolved_count, result.masked_operand_audit.mismatch_count],
        "frame": next(x for x in lines if x.startswith("sub esp,")),
        "native_pointer_triplet": any(lines[i:i + 3] == TRIPLET for i in range(len(lines) - 2)),
        "shared_zero_tests_and_clears": all(x in lines for x in [
            "cmp dword [eax+0x4], ebx", "cmp eax, ebx", "mov dword [esi+0x14], ebx", "mov byte [ADDR], bl",
        ]),
    }
    assert not row["exact"] and not row["body_byte_exact"]
    return row


def global_profile():
    stock = c2.load_profile()
    # Read from the pinned C2 0x130cb disassembly; all call opcodes/targets are
    # checked by the observer before hooking. Original entry hook saves ECX.
    calls = [
        (0x13143, 0x117D0), (0x1315A, 0x11AFA), (0x13189, 0x11209),
        (0x131DE, 0x08F28), (0x13375, 0x0A547), (0x134E9, 0x450D7),
        (0x13415, 0x0B571), (0x1341C, 0x0B471), (0x13476, 0x08F28),
        (0x1366C, 0x0A547), (0x13673, 0x0B9AB), (0x1367C, 0x0789C),
        (0x13683, 0x06BD0), (0x13706, 0x0789C), (0x1370D, 0x06BD0),
        (0x136F2, 0x43190), (0x136FB, 0x0789C),
        (0x13722, 0x43190), (0x1372B, 0x0789C), (0x1369A, 0x061C8),
    ]
    return {**stock, "hooks": stock["hooks"][:12] + [
        {"site": site, "target": target, "return": True} for site, target in calls
    ]}


def analyze(directory, label):
    events = c2.read_verified(directory)
    first = events[0]["nodes"]
    source = (directory / "source/scratch.cpp").read_text().splitlines()
    start = next(i for i, line in enumerate(source) if "void quest_spawn_timeline_update" in line)
    copy_line = next(i for i, line in enumerate(source) if "((unsigned char *)&copied)[k]" in line) - start
    # Follow the original byte store's destination address definition to its
    # symbol; never guess which of the two adjacent LEAs is the destination.
    byte_stores = [n for n in first if n["line"] == copy_line and n["op"] == 0x15B and n["dst"] and n["dst"][0]["kind"] == 6]
    assert len(byte_stores) == 1
    byte_store = byte_stores[0]
    address = byte_store["src"][-1]["raw"][6]
    definition = next(n for n in first if any(o["kind"] == 1 and o["raw"][6] == address for o in n["dst"]))
    symbol = next(o["raw"][5] for o in definition["src"] if o["kind"] == 3)
    line = byte_store["line"]
    history = []
    previous = None
    for event in events:
        nodes = event["nodes"]
        intrinsics = [n for n in nodes if n["op"] == 0x190 and n["line"] == line]
        reads = [n for n in nodes if any(o["kind"] == 2 and o["raw"][5] == symbol for o in n["src"])]
        addresses = [n for n in nodes if any(o["kind"] == 3 and o["raw"][5] == symbol for o in n["src"])]
        stores = [n for n in nodes if n["op"] == 1 and any(o["kind"] == 2 and o["raw"][5] == symbol for o in n["dst"])]
        state = [len(intrinsics), len(reads), len(addresses), len(stores)]
        if state != previous:
            history.append({
                "event": event["event"], "site": hex(event["site_rva"]), "target": hex(event["target_rva"]),
                "boundary": event["boundary"], "state": state,
                "intrinsics": intrinsics, "reads": reads, "addresses": addresses, "stores": stores,
            })
            previous = state
    if label == "positive":
        assert [(h["target"], h["boundary"], h["state"]) for h in history] == [
            ("0x130cb", "entry", [0, 1, 1, 0]),
            ("0x450d7", "return", [1, 1, 1, 0]),
            ("0xb571", "return", [1, 2, 1, 0]),
            ("0xb9ab", "return", [1, 1, 1, 0]),
            ("0x43190", "return", [1, 0, 1, 0]),
            ("0x296de", "entry", [0, 0, 0, 1]),
        ]
        lowered = next(e for e in events if e["target_rva"] == 0x296DE)
        stores = [n for n in lowered["nodes"] if n["op"] == 1 and any(o["kind"] == 2 and o["raw"][5] == symbol for o in n["dst"])]
        assert len(stores) == 1
        node_id = stores[0]["id"]
        for event in events[lowered["event"]:]:
            store = next(n for n in event["nodes"] if n["id"] == node_id)
            assert store["op"] == 1 and store["dst"][0]["kind"] == 2 and store["dst"][0]["raw"][5] == symbol
            assert not any(o["kind"] == 2 and o["raw"][5] == symbol for n in event["nodes"] for o in n["src"])
    else:
        assert history[-1]["state"] == [0, 0, 0, 0]
        if label == "reversed":
            assert history[-2]["target"] == "0x8f28" and history[-2]["state"] == [1, 0, 1, 0]
            assert history[-1]["target"] == "0x6bd0" and history[-1]["boundary"] == "return"
        else:
            assert len(history) == 2 and history[-1]["target"] == "0x450d7"
    return {"copied_symbol": symbol, "history": history}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    base = (config.directory / config.source).read_text()
    assert sha(base.encode()) == BASE_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    rows = {name: build(config, out / "sources" / name, source) for name, source in sources(base).items()}
    positive = rows["positive"]
    assert positive["instructions"] == 115 and positive["prefix"] == 14 and positive["refs"] == [12, 0, 0]
    assert positive["native_pointer_triplet"] and positive["frame"] == "sub esp, 0x1c"
    for name in ["reversed", "dead", "memcpy", "assignment"]:
        assert rows[name]["body_sha256"] == rows["canonical"]["body_sha256"]
    for name in ["null-guard", "count-equals-zero"]:
        assert rows[name]["body_sha256"] == positive["body_sha256"]
    assert rows["read"]["frame"] == "sub esp, 0x1c" and not rows["read"]["native_pointer_triplet"]
    assert rows["counter-lifetime"]["frame"] == "sub esp, 0x1c"
    assert rows["counter-lifetime"]["native_pointer_triplet"] and rows["counter-lifetime"]["shared_zero_tests_and_clears"]
    profile = global_profile()
    traces = {}
    with patch.object(c2, "load_profile", lambda: profile):
        for name in ["positive", "reversed", "dead"]:
            directory = out / "traces" / name
            receipt = c2.trace(out / "sources" / name, directory)
            assert receipt["source_sha256"] == rows[name]["source_sha256"]
            obj = directory / receipt["object_paths"][0]
            body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), config.symbol)
            assert sha(body.data) == rows[name]["body_sha256"]
            traces[name] = {
                "source_sha256": receipt["source_sha256"],
                "whole_coff_equal_except_timestamp": receipt["whole_coff_equal_except_timestamp"],
                "missing_stream_rejected": receipt["missing_stream_rejected"],
                "compiler_decisions_modified": receipt["compiler_decisions_modified"],
                "normalized_coff_sha256": receipt["normalized_coff_sha256"],
                "profile_sha256": receipt["profile_sha256"],
                "stream_hashes": receipt["stream_hashes"],
                "trace_sha256": receipt["trace_sha256"],
                "snapshots_sha256": receipt["snapshots_sha256"],
                **analyze(directory, name),
            }
            print(name, "whole COFF preserved; copy history verified", flush=True)
    (out / "results.json").write_text(json.dumps({
        "verifier_sha256": sha(Path(__file__).read_bytes()), "c2_sha256": profile["c2_sha256"],
        "source_controls": rows, "traces": traces,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
