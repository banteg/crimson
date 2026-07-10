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

## 3) Decide session bookkeeping

Search for the SHA in the differential sessions index and session files:
`docs/frida/differential-sessions.md` and `docs/frida/differential-sessions/session-*.md`.

Quick lookup:

```bash
rg "<sha256>" docs/frida/differential-sessions.md docs/frida/differential-sessions/session-*.md
```

- If SHA exists: append to that session file.
- If SHA is new: create a new session file and add it to the index.

Do not assume you can re-record the same gameplay timeline. Use event and RNG
anchors, not exact absolute tick equality across different recordings.

## 4) Baseline triage commands

Unlike the legacy process, `dbg` diffing is extremely fast because playback and difﬁng are decoupled. Run the strict trace-based reports:

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

## 5) Use refactored decompiled hotspot sources first

Static/native references for differential probes should now prefer the refactored
hotspot packs under `analysis/ghidra/derived/hotspots/`:

- Start from `analysis/ghidra/derived/hotspots/<target>/README.md` for target
  scope, extracted function list, and direct callgraph.
- Use `analysis/ghidra/derived/hotspots/<target>/functions/*.c` as the immutable
  extracted baseline for citations.
- Use `analysis/ghidra/derived/hotspots/<target>/work/*.work.c` for local
  renames and annotations while preserving address/branch labels.
- Fall back to `analysis/ghidra/raw/crimsonland.exe_decompiled.c` only when a
  needed function is not yet covered by a hotspot pack.

## 6) Common mismatch classes

- Early position drift (`players[0].pos.*`): usually input reconstruction quality.
- XP/score-only one-tick blips: often timing/bridge artifacts; verify whether it
  self-heals on the next tick.
- RNG shortfall lead near focus tick: investigate missing branch/caller path
  before tuning downstream gameplay behavior.

## 7) Completion checklist

1. Add targeted tests for every replay/trace-finalization behavior change.
2. Run `just check`.
3. Update differential session docs (`docs/frida/differential-sessions.md` index
   plus the relevant `docs/frida/differential-sessions/session-*.md` file) with:
   - SHA
   - exact baseline commands
   - first mismatch progression
   - landed changes
   - next probe
4. Commit with conventional commits style.
