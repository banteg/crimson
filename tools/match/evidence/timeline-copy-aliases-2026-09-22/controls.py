"""Reproduce bounded source controls for the timeline copy's implicit aliases."""

import argparse
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
BASE_SHA = "a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9"
WITNESS_SHA = "aba4e7736bbf47507b4476c976548626257f47a9bf7bd065e9bd1e537929c03f"
TRIPLET = [
    "lea edi, dword [esi+0xc]",
    "mov dword [esp+0x10], edi",
    "mov dword [esp+0x10], ebx",
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probes = load("timeline_probes", HERE.parent / "vc6-timeline-consumers-2026-09-11/probes.py")


def sources():
    cfg = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    base = (cfg.directory / cfg.source).read_text()
    assert sha(base.encode()) == BASE_SHA
    assert cfg.compiler == "msvc6.5" and cfg.cflags == "/O2 /GB /W3 /GR-"
    witness = (HERE / "witness.cpp").read_text()
    assert sha(witness.encode()) == WITNESS_SHA
    result = {
        "canonical": base,
        "pair": (HERE.parent / "vc6-timeline-pointer-home-2026-09-12/witness.cpp").read_text(),
        "guard": (HERE.parent / "timeline-four-byte-home-2026-09-13/witness.cpp").read_text(),
        "end-pointer": witness,
    }
    expression = "out - (unsigned char*)&copied - sizeof copied"
    for name, replacement in {
        "end-equality": "out != (unsigned char*)&copied + sizeof copied",
        "end-rebase": "(out - sizeof copied) - (unsigned char*)&copied",
        "end-integer-difference": "(unsigned long)out - (unsigned long)&copied - sizeof copied",
    }.items():
        result[name] = witness.replace(expression, replacement)
    start = witness.index("            int *copied;")
    end = witness.index("            do {", start)
    block = witness[start:end].replace("            int spread;\n\n", "")
    result["closed-scope"] = (
        witness[:start] + "            int spread;\n            {\n" + block + "            }\n" + witness[end:]
    )
    result["closed-scope-rebased"] = result["closed-scope"].replace(
        expression,
        "out - ((unsigned char*)&copied + sizeof copied)",
    )
    for name, helper, typ in [
        ("end-struct-pointer", "struct pointer_word { int *value; };\n", "pointer_word"),
        ("end-union-pointer", "union pointer_word { int *value; unsigned char bytes[4]; };\n", "pointer_word"),
        ("end-integer", "", "unsigned long"),
        ("end-float", "", "float"),
    ]:
        result[name] = witness.replace('extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;').replace(
            "int *copied;",
            typ + " copied;",
        )
    result["separate-input"] = witness.replace(
        "int *template_id=&entry->template_id;",
        "int *selected=&entry->template_id; int *template_id=selected;",
    ).replace("in=(const unsigned char*)&template_id", "in=(const unsigned char*)&selected")
    return cfg, result


def build(name, out):
    cfg, cases = sources()
    row, candidate, obj = probes.build(cfg, out, name, cases[name])
    shutil.copyfile(cfg.directory / "scratch.conf", candidate.directory / "scratch.conf")
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    lines = (candidate.directory / "candidate.asm").read_text().splitlines()
    row.update(
        body_sha256=sha(body.data),
        frame=int(next(line.split(", ")[1] for line in lines if line.startswith("sub esp,")), 0),
        native_pointer_triplet=any(lines[i : i + 3] == TRIPLET for i in range(len(lines) - 2)),
    )
    assert not row["body_byte_exact"] and row["reference_problems"] == 0
    return row, candidate, obj


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    rows = {name: build(name, args.out)[0] for name in sources()[1]}
    end = rows["end-pointer"]
    assert end["frame"] == 32 and not end["native_pointer_triplet"]
    assert rows["guard"]["frame"] == 28 and rows["guard"]["native_pointer_triplet"]
    assert rows["pair"]["frame"] == 32 and rows["pair"]["native_pointer_triplet"]
    for name in (
        "end-rebase",
        "end-integer-difference",
        "end-struct-pointer",
        "end-union-pointer",
        "end-integer",
        "end-float",
    ):
        assert rows[name]["normalized_coff_sha256"] == end["normalized_coff_sha256"]
    for name in ("closed-scope", "closed-scope-rebased"):
        assert rows[name]["normalized_coff_sha256"] == rows["end-equality"]["normalized_coff_sha256"]
        assert rows[name]["frame"] == 28 and not rows[name]["native_pointer_triplet"]
    result = {"kind": "timeline-copy-alias-controls", "verified": True, "controls": rows}
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Verified {len(rows)} stock source builds; no new exact body")


if __name__ == "__main__":
    main()
