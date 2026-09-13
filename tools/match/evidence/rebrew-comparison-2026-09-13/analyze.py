"""Run Rebrew's unmodified near-diag core; no project migration or GA search."""

import argparse
import importlib.metadata
import json
import shutil
import subprocess
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--rebrew", type=Path, required=True)
parser.add_argument("--cases", type=Path, required=True)
args = parser.parse_args()
sys.path.insert(0, str(args.rebrew / "src"))
from rebrew.near_diag import analyze

controls = {
    "identical": ("31c0c3", "31c0c3"),
    "alternate-mov-encoding": ("89d8c3", "8bc3c3"),
    "different-return-constant": ("31c0c3", "b801000000c3"),
    "different-return-register": ("89d8c3", "89d9c3"),
    "changed-immediate": ("b801000000c3", "b802000000c3"),
    "changed-call-target": ("e800100000c3", "e800200000c3"),
    "stack-slot": ("8b442404c3", "8b442408c3"),
    "same-call-shifted": ("90e8fa0f0000c3", "6690e8f90f0000c3"),
}
result = {
    "rebrew_commit": subprocess.check_output([shutil.which("git"), "-C", str(args.rebrew), "rev-parse", "HEAD"], text=True).strip(),
    "interface": "rebrew.near_diag.analyze; no relocation masking; independently materialized candidate references",
    "dependencies": {n: importlib.metadata.version(n) for n in ("capstone", "lief", "typer", "rich", "tomlkit")},
    "controls": {name: analyze(bytes.fromhex(a), bytes.fromhex(b), set(), 0x1000) for name, (a, b) in controls.items()},
    "functions": {},
}
for directory in sorted(args.cases.iterdir()):
    if not directory.is_dir():
        continue
    metadata = json.loads((directory / "inputs.json").read_text())
    a = (directory / "target.bin").read_bytes()
    b = (directory / "candidate-resolved.bin").read_bytes()
    result["functions"][directory.name] = {
        "input_evidence": metadata,
        "self_control": analyze(a, a, set(), metadata["va"]),
        "diagnosis": analyze(a, b, set(), metadata["va"]),
    }
assert result["controls"]["identical"]["verdict"] == "MATCH"
assert result["controls"]["alternate-mov-encoding"]["verdict"].startswith("ENCODING-ONLY")
assert result["controls"]["different-return-constant"]["verdict"].startswith("EQUIVALENT")
assert result["controls"]["different-return-register"]["verdict"].startswith("EFFECTIVE")
for row in result["functions"].values():
    assert row["self_control"]["verdict"] == "MATCH"
    assert not row["input_evidence"]["unresolved"]
assert result["functions"]["statistics_update_check_worker"]["diagnosis"]["verdict"] == "MATCH"
(args.cases.parent / "rebrew.json").write_text(json.dumps(result, indent=2) + "\n")
for name, row in result["functions"].items():
    print(name, row["diagnosis"]["verdict"], row["diagnosis"]["first_mismatch"])
