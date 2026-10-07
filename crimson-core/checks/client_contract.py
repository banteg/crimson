"""Test instrumentation and the known initialization blocker, not client parity."""

import json
import shutil
import subprocess
import sys

from client_evidence import CORE, sha256
from gate import core_result

from crimson.game_modes import GameMode
from crimson.sim.run_result import run_result_mismatches


def main():
    out = CORE / "build/client/contract"
    out.mkdir(parents=True, exist_ok=True)
    artifacts = {"native": CORE / "build/native/core", "wasm": CORE / "build/wasm/core.wasm"}
    before = {name: sha256(path) for name, path in artifacts.items()}
    hashes = out / "before.json"
    hashes.write_text(json.dumps(before))
    subprocess.run([sys.executable, str(CORE / "build.py"), "--target", "client"], check=True)
    proc = subprocess.run(
        [sys.executable, str(CORE / "checks/client_evidence.py"), "--out", str(out), "--before", str(hashes)],
        check=False,
    )
    report = json.loads((out / "replay.json").read_text())
    probes = json.loads((out / "probes.json").read_text())
    if proc.returncode != 1 or report["client_snapshots"] != 0 or report["client_result"] is not None:
        raise RuntimeError("Expected blocked initialization, not successful replay")
    if len(report["blockers"]) != 1 or report["blockers"][0]["caller"] != "gameplay_reset_state":
        raise RuntimeError("Initialization blocker changed; review the session contract")
    if report["blockers"][0]["event"] != "rand_outside_tick" or not probes["agree"]:
        raise RuntimeError("Client recording/guard control failed")
    if report["claimed_result_mismatches"]:
        raise RuntimeError("Verifier reference differs from the recording claim")
    after = {name: sha256(path) for name, path in artifacts.items()}
    if before != after:
        raise RuntimeError("The client build or evidence run modified a verifier executable")
    control_file = out / "control.json"
    subprocess.run(
        [
            shutil.which("node"),
            str(CORE / "checks/client_compare.mjs"),
            str(out / "quest-1.1.rsi"),
            str(artifacts["native"]),
            str(artifacts["wasm"]),
            str(control_file),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    control = json.loads(control_file.read_text())
    mismatches = run_result_mismatches(
        core_result(control["verifier_final"], GameMode.QUESTS),
        core_result(control["client_final"], GameMode.QUESTS),
    )
    if not control["full_state_agree"] or mismatches:
        raise RuntimeError("Comparator control failed for native/WASM verifier state or full result")
    summary = {
        "artifact_preservation": before == after,
        "expected_blocker": True,
        "probes": probes,
        "control_ticks": control["compared_ticks"],
        "control_fields": control["fields_per_snapshot"],
        "control_full_result_mismatches": mismatches,
    }
    (out / "contract.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("Client instrumentation controls passed; actual client replay remains blocked before tick 0")


if __name__ == "__main__":
    main()
