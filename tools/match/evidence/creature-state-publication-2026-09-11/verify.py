"""Replay bounded creature-update recovery against the original x86 function.

Requires optional unicorn==2.1.4 and local JIT permission. This records finite
caller evidence under explicit callback models, not whole-game equivalence.
"""

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import replace
from pathlib import Path

import unicorn
from execute import ENGINE_PATH, Comparison, match
from fixtures import check_layout, scenarios
from recover import stages

HERE = Path(__file__).resolve().parent
FUNCTION = "creature_update_all"
BEFORE_SHA256 = "854a1dcf34a2b8e21695af7dfa23ade204da4172a3004ad4cd8adcd44636cb17"
IMAGE_SHA256 = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
KEYS = ("state", "players", "slots", "scalars", "writes", "model_writes", "calls")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def serialize(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=lambda item: item.hex()).encode()


def observation(value):
    return sha(serialize({key: sha(serialize(value[key])) for key in KEYS}))


def first_difference(a, b):
    if isinstance(a, dict):
        return {key: [a.get(key), b.get(key)] for key in a.keys() | b.keys() if a.get(key) != b.get(key)}
    index = next((index for index, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    return {"index": index, "lengths": [len(a), len(b)],
            "native": a[max(0, index - 1):index + 2], "candidate": b[max(0, index - 1):index + 2]}


def build(config, out, name, source):
    directory = out / name
    directory.mkdir(exist_ok=True)
    (directory / "scratch.cpp").write_text(source)
    return Comparison(replace(config, directory=directory))


def metric(comparison):
    p = comparison.program
    r = p.result
    return {"ratio": r.ratio, "native_instructions": len(r.target_disassembly),
            "candidate_instructions": len(r.candidate_disassembly),
            "normalized_exact": r.exact, "body_byte_exact": r.body_byte_exact,
            "references": [r.masked_operand_audit.ok_count, r.masked_operand_audit.unresolved_count,
                           r.masked_operand_audit.mismatch_count],
            "object_sha256": sha(p.object_path.read_bytes()), "body_sha256": sha(p.body.data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--candidate-source", type=Path, help="Pre-promotion source to verify instead of the canonical scratch")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA256
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == BEFORE_SHA256
    sources = stages(before)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / FUNCTION)
    candidate_source = args.candidate_source or config.directory / config.source
    assert candidate_source.read_text() == sources["recovered"], "Candidate differs from the replayable recovery"
    layout = check_layout(config, out)
    before_program = build(config, out, "before", before)
    after_program = build(config, out, "recovered", sources["recovered"])
    assert after_program.program.result.ratio >= before_program.program.result.ratio
    assert after_program.program.result.masked_operand_audit.mismatch_count == 2
    assert not after_program.program.result.exact and not after_program.program.result.body_byte_exact
    cases = scenarios()
    (out / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
    rows, witnesses = [], []
    before_differences = Counter()
    native_coverage, candidate_coverage = set(), set()
    callback_counts = Counter()
    for index, case in enumerate(cases):
        native = after_program.run(True, case)
        current = after_program.run(False, case)
        old = before_program.run(False, case)
        wrong = [key for key in KEYS if native[key] != current[key]]
        if wrong:
            failure = {"index": index, "case": case, "differences": {
                key: first_difference(native[key], current[key]) for key in wrong}}
            (out / "failure.json").write_bytes(serialize(failure))
            raise AssertionError(f"Recovered mismatch in {case['name']}: {wrong}; see {out / 'failure.json'}")
        changed = [key for key in KEYS if native[key] != old[key]]
        before_differences.update(changed)
        if changed and len(witnesses) < 12:
            witnesses.append({"case": index, "name": case["name"], "differences": {
                key: first_difference(native[key], old[key]) for key in changed}})
        rows.append({"case": index, "name": case["name"], "native": observation(native),
                     "before": observation(old), "recovered": observation(current),
                     "before_differences": changed, "calls": len(native["calls"]), "writes": len(native["writes"])})
        native_coverage.update(native["coverage_offsets"])
        candidate_coverage.update(current["coverage_offsets"])
        callback_counts.update(call[0] for call in native["calls"])
        if index % 200 == 0:
            print(f"Verified {index + 1}/{len(cases)} cases", flush=True)
    assert before_differences["writes"] and before_differences["state"] and before_differences["calls"]
    controls = []
    defects = [
        ("omit-last-slot", "creature_index < 384", "creature_index < 383", "last-slot-frozen-pc07f"),
        ("wrong-contact-damage", "creature_pool[creature_index].contact_damage);",
         "creature_pool[creature_index].contact_damage * 2.0f);", "contact-19.999-40-0-pc07f"),
    ]
    for name, old, new, case_name in defects:
        assert sources["recovered"].count(old) == 1
        wrong_source = sources["recovered"].replace(old, new)
        comparison = build(config, out, name, wrong_source)
        case = next(case for case in cases if case["name"] == case_name)
        native, candidate = after_program.run(True, case), comparison.run(False, case)
        changed = [key for key in KEYS if native[key] != candidate[key]]
        assert changed, f"Negative control {name} was not detected"
        controls.append({"name": name, "source_sha256": sha(wrong_source.encode()),
                         "case": case_name, "detected": changed})
    intermediate = {}
    # Record the separately reconstructible intermediate static states. The
    # final comparison above, rather than their score, gates promotion.
    for name in ("publication", "movement"):
        comparison = build(config, out, name, sources[name])
        intermediate[name] = metric(comparison)
    p = after_program.program
    native_instructions = {i.offset for i in p.result.target_disassembly}
    candidate_instructions = {i.offset for i in p.result.candidate_disassembly}
    assert native_instructions - native_coverage == {1017, 1018, 1021, 4189, 4190, 4193}
    assert candidate_instructions - candidate_coverage == {976, 977, 980, 4005, 4006, 4009}
    manifest = match.load_function_manifest(scope="all")
    record = {
        "schema_version": 1, "function": FUNCTION, "unicorn": unicorn.__version__,
        "image_sha256": IMAGE_SHA256, "native_body_sha256": sha(p.image.function_bytes(p.native_start, p.native_end)),
        "source_sha256": {name: sha(text.encode()) for name, text in sources.items()},
        "harness_sha256": {name: sha((HERE / name).read_bytes()) for name in ("verify.py", "execute.py", "fixtures.py", "recover.py")},
        "engine_sha256": sha(ENGINE_PATH.read_bytes()), "matcher_sha256": sha(Path(match.__file__).read_bytes()),
        "compiler": config.compiler, "cflags": config.cflags,
        "compiler_files_sha256": {name: sha((match.DEFAULT_MATCH_ROOT / "compilers" / config.compiler / "Bin" / name).read_bytes())
                                  for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL")},
        "layout": layout, "cases": len(cases), "cases_sha256": sha((out / "cases.json").read_bytes()),
        "before": metric(before_program), "recovered": metric(after_program), "intermediate": intermediate,
        "before_differences": dict(before_differences), "recovered_differences": {},
        "native_instruction_coverage": {"covered": len(native_coverage), "total": len(native_instructions),
                                        "uncovered_offsets": sorted(native_instructions - native_coverage)},
        "candidate_instruction_coverage": {"covered": len(candidate_coverage), "total": len(candidate_instructions),
                                           "uncovered_offsets": sorted(candidate_instructions - candidate_coverage)},
        "coverage_limit": "Six instructions on each side handle negative rand() remainders; the shared rand model returns 0..32767.",
        "native_helpers": {name: {"address": entry, "instruction_count": len(pcs),
                                  "body_sha256": sha(p.image.function_bytes(entry, match.resolve_function(manifest, name)[2]))}
                           for name, (entry, pcs) in after_program.native_helpers.items()},
        "callback_counts": dict(callback_counts), "relocations": p.relocations,
        "witnesses": witnesses, "negative_controls": controls, "rows": rows,
        "scope": "Bounded caller execution with native angle/vector/ftol helpers and shared callback models. No whole-game or exact-match claim.",
    }
    (out / "results.json").write_text(json.dumps(record, indent=2, default=lambda item: item.hex()) + "\n")
    print(f"Verified {len(cases)} cases; before differences: {dict(before_differences)}; recovered differences: zero", flush=True)


if __name__ == "__main__":
    main()
