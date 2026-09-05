---
tags:
  - frida
  - differential-testing
  - workflow
---

# Differential Playbook

Use this when an agent is given a new capture run artifact (typically
`artifacts/frida/share/gameplay_diff_capture.survival*.cdt` + `.crd`,
`artifacts/frida/share/gameplay_diff_capture.rush*.cdt` + `.crd`, or
`artifacts/frida/share/gameplay_diff_capture.quest_*_*.cdt` + `.crd`) and needs to
continue cross-implementation investigation.

This runbook is updated for the decoupled `dbg` trace suite which unifies telemetry
difﬁng for Original vs Python vs Zig.

## 1) Identify the capture artifact

Frida host capture now finalizes directly to `.cdt` traces plus matching `.crd` replay sidecars.
If only raw JSONL exists, finalize it offline (no game process needed):

```bash
uv run --with frida==17.15.4 python scripts/frida/gameplay_diff_capture_host.py \
  --finalize-only \
  --raw-path artifacts/frida/share/gameplay_diff_capture.jsonl \
  --output-dir analysis/frida/traces
```

Then check health of the finalized trace:

```bash
uv run crimson dbg health analysis/frida/traces/gameplay_diff_capture.survival.run<k>.cdt
```

Record the SHA256 of the `.cdt` trace first. Session tracking is by capture SHA family.

## 2) Record rewrite candidate trace from matching `.crd`

```bash
uv run crimson dbg record \
  analysis/frida/traces/gameplay_diff_capture.<run>.crd \
  --impl python \
  --out analysis/frida/traces/gameplay_diff_capture.<run>.py.cdt
```

```bash
uv run crimson dbg record \
  analysis/frida/traces/gameplay_diff_capture.<run>.crd \
  --impl zig \
  --out analysis/frida/traces/gameplay_diff_capture.<run>.zig.cdt
```

`dbg record` always emits full traces; there is no profile mode or tick-cap mode.

## 3) Record the investigation

Keep the SHA-keyed investigation record beside its artifacts under `analysis/`;
see [evidence records](../verification/evidence-ledger/index.md) for required
provenance, commands and outcomes. Reuse the record for the same native capture,
and distinguish each candidate implementation commit.

Run `dbg health` on the candidate trace as well as the native trace. Both must be
parity-ready before comparing. Do not assume a new playthrough reproduces the
same absolute tick timeline; use event and RNG anchors across captures.

## 4) Baseline triage commands

Run the strict trace comparison after recording the candidate:

```bash
uv run crimson dbg diff \
  analysis/frida/traces/capture_<sha8>.cdt \
  analysis/frida/traces/capture_<sha8>_zig.cdt
```

Capture the first divergence plus its surrounding focus window:

```bash
uv run crimson dbg bisect \
  analysis/frida/traces/capture_<sha8>.cdt \
  analysis/frida/traces/capture_<sha8>_zig.cdt \
  --window-before 12 \
  --window-after 6 \
  --json-out analysis/frida/reports/capture_<sha8>_bisect.json
```

For surgical detail at exactly the focus mismatch tick, inspect the state across both traces in lockstep:

```bash
uv run crimson dbg focus \
  analysis/frida/traces/capture_<sha8>.cdt \
  analysis/frida/traces/capture_<sha8>_zig.cdt \
  --tick <focus_tick>
```

## 5) Consult the live address-keyed analysis

Resolve the native function first:

```bash
just analysis-function <name-or-address>
```

Consult Binary Ninja first with the printed `bn decompile` command, then use the
same address in IDA and Ghidra. Do not cite generated decompile line numbers;
record the canonical function name, function address, and any instruction
address relevant to the probe.

Recovered hotspot notes are preserved in
`analysis/annotations/functions.json`. Ghidra-specific presentation names are
preserved in `analysis/overlays/ghidra_local_renames.json`.

## 6) Common mismatch classes

- For position drift, compare `replay_step` first, then movement state and
  integration. Matching inputs do not rule out a reset or precision error.
- For XP/score timing differences, inspect death and presentation boundaries.
  Agreement on the next tick does not excuse an earlier mismatch.
- RNG shortfall lead near focus tick: investigate missing branch/caller path
  before tuning downstream gameplay behavior.

## 7) Completion checklist

1. Add targeted tests for every replay/trace-finalization behavior change.
2. Run `just check`.
3. Update the investigation record beside its artifacts with:
   - SHA
   - exact baseline commands
   - first mismatch progression
   - landed changes
   - next probe
4. Commit with conventional commits style.
