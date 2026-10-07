"""Record a strict client replay attempt, including aborts and unavailable results.

Build the client first. This never rebuilds, patches or relaxes the verifier.
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

from gate import Stream, _result_json, core_result
from replay import encode

from crimson.replay.codec import load_replay_file
from crimson.sim.run_result import run_result_mismatches

CORE = Path(__file__).resolve().parents[1]
ROOT = CORE.parent


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, default=CORE / "build/client/client")
    parser.add_argument("--wasm", type=Path, default=CORE / "build/wasm/core.wasm")
    parser.add_argument("--native", type=Path, default=CORE / "build/native/core")
    parser.add_argument("--replay", type=Path, default=ROOT / "tests/fixtures/replays/quest-1.1-completed.crd")
    parser.add_argument("--out", type=Path, default=CORE / "build/client/evidence")
    parser.add_argument("--before", type=Path, help="Previously captured artifact hashes")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    replay = load_replay_file(args.replay)
    payload = encode(replay, None)
    input_file = args.out / "quest-1.1.rsi"
    input_file.write_bytes(payload)
    stream = Stream(args.replay.name, payload, replay)
    result_file = args.out / "replay.json"
    result_file.unlink(missing_ok=True)
    proc = subprocess.run(
        [
            shutil.which("node"),
            str(CORE / "checks/client_compare.mjs"),
            str(input_file),
            str(args.client),
            str(args.wasm),
            str(result_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if not result_file.exists():
        raise RuntimeError(proc.stderr or proc.stdout)
    report = json.loads(result_file.read_text())
    verifier_result = core_result(report.pop("verifier_final"), stream.run_spec().game_mode_id)
    report["verifier_result"] = _result_json(verifier_result)
    client_final = report.pop("client_final", None)
    client_result = core_result(client_final, stream.run_spec().game_mode_id) if report["complete_stream"] else None
    report["client_result"] = _result_json(client_result) if client_result else None
    report["result_mismatches"] = run_result_mismatches(verifier_result, client_result) if client_result else None
    report["full_result_agree"] = report["full_state_agree"] and report["result_mismatches"] == []
    report["claimed_result_mismatches"] = run_result_mismatches(replay.result, verifier_result)
    report["run_result_comparison"] = "compared" if client_result else "blocked: client stream incomplete"
    report["input"] = args.replay.name
    report["replay_sha256"] = sha256(args.replay)
    report["rsi_sha256"] = sha256(input_file)
    report["hashes_after"] = {"native": sha256(args.native), "wasm": sha256(args.wasm), "client": sha256(args.client)}
    if args.before:
        report["hashes_before"] = json.loads(args.before.read_text())
        report["verifier_byte_identity"] = {
            kind: report["hashes_before"][kind] == report["hashes_after"][kind] for kind in ("native", "wasm")
        }
    # Keep the trace separate, but put observed slot coverage and return-use flags in the summary.
    events = [json.loads(line) for line in Path(str(result_file) + ".jsonl").read_text().splitlines()]
    report["observed_slots"] = sorted({event["slot"] for event in events if event["event"] == "grim"})
    report["grim_calls"] = sum(event["event"] == "grim" for event in events)
    report["compiler"] = subprocess.check_output([shutil.which("clang++"), "--version"], text=True).splitlines()[0]
    report["zig"] = subprocess.check_output([shutil.which("zig"), "version"], text=True).strip()
    result_file.write_text(json.dumps(report, indent=2) + "\n")
    inventory = json.loads((args.client.parent / "inventory.json").read_text())
    # Inventory all recovered callers too: unlinked routines are coverage gaps, not runtime discoveries.
    all_rand = []
    for source in sorted((ROOT / "decomp/1.9/crimsonland").rglob("*")):
        if source.suffix not in {".c", ".cpp"}:
            continue
        lines = [
            i for i, line in enumerate(source.read_text().splitlines(), 1) if "crt_rand()" in line or "rand()" in line
        ]
        if lines:
            all_rand.append(
                {
                    "source": str(source.relative_to(ROOT)),
                    "lines": lines,
                    "linked": str(source.relative_to(ROOT)) in inventory["sources"],
                },
            )
    inventory["all_recovered_rand_callers"] = all_rand
    (args.out / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    # Probe the recording implementation independently; do not bypass session initialization.
    probe_file = args.out / "grim-probe.jsonl"
    probe = subprocess.run(
        [str(args.client), "--client-grim-probe"],
        env=dict(os.environ, CRIMSON_CLIENT_TRACE=str(probe_file)),
        capture_output=True,
        check=False,
        timeout=10,
    )
    probe_events = [json.loads(line) for line in probe_file.read_text().splitlines()]
    expected = {site["slot"] for site in inventory["grim_sites"]}
    actual = {event["name"] for event in probe_events}
    probe_report = {
        "exit": probe.returncode,
        "slots": len(actual),
        "expected_slots": len(expected),
        "agree": probe.returncode == 0 and actual == expected and len(probe_events) == len(expected),
    }
    controls = []
    for name, argv, payload_override, reason in [
        ("rand-outside-tick", ["--client-rand-probe"], b"", "rand_outside_tick"),
        ("unsupported-grim-slot", ["--client-unsupported-probe"], b"", "grim:grim_init_system"),
        ("survival", [], payload[:4] + struct.pack("<I", 1) + payload[8:], "session:only-quest-1.1"),
        ("quest-1.2", [], payload[:12] + struct.pack("<I", 2) + payload[16:], "session:only-quest-1.1"),
    ]:
        control_trace = args.out / f"{name}.jsonl"
        control = subprocess.run(
            [str(args.client), *argv],
            input=payload_override,
            env=dict(os.environ, CRIMSON_CLIENT_TRACE=str(control_trace)),
            capture_output=True,
            check=False,
            timeout=10,
        )
        control_events = [json.loads(line) for line in control_trace.read_text().splitlines()]
        observed = control_events[-1] if control_events else {}
        controls.append(
            {
                "name": name,
                "exit": control.returncode,
                "observed": observed,
                "agree": control.returncode < 0
                and (observed.get("reason") == reason or observed.get("event") == reason),
            },
        )
    probe_report["controls"] = controls
    probe_report["agree"] = probe_report["agree"] and all(control["agree"] for control in controls)
    (args.out / "probes.json").write_text(json.dumps(probe_report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "replay": report["run_result_comparison"],
                "blockers": report["blockers"],
                "probe": probe_report,
                "identity": report.get("verifier_byte_identity"),
            },
            indent=2,
        ),
    )
    raise SystemExit(0 if report["full_result_agree"] and probe_report["agree"] else 1)


if __name__ == "__main__":
    main()
