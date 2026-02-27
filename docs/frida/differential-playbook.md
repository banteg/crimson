---
tags:
  - frida
  - differential-testing
  - workflow
---

# Differential Playbook

Use this when an agent is only given a new capture file (typically
`artifacts/frida/share/gameplay_diff_capture.msgpack.zst` or a quest-split file like
`artifacts/frida/share/gameplay_diff_capture.quest_1_1.msgpack.zst`) and needs to
continue cross-implementation investigation.

This runbook is updated for the decoupled `dbg` trace suite which unifies telemetry
difﬁng for Original vs Python vs Zig.

## 1) Identify the capture artifact

Convert the original Native Frida capture into a uniform `dbg` trace first:

```bash
uv run crimson dbg import-capture \
  artifacts/frida/share/gameplay_diff_capture.msgpack.zst \
  --out analysis/frida/traces/capture_<sha8>.cdt
```

Then check the health of the capture:

```bash
uv run crimson dbg health analysis/frida/traces/capture_<sha8>.cdt
```

Record the SHA256 of the trace (or the original messagepack) first. Session tracking is by capture SHA family.

## 2) Convert capture to replay and record candidate trace

Generate the replay payload:

```bash
uv run crimson replay convert-capture \
  artifacts/frida/share/gameplay_diff_capture.msgpack.zst \
  analysis/frida/replays/capture_<sha8>.crd.chk
```

Then record the rewrite execution via your target implementation (`python` or `zig`) to generate a candidate `dbg` trace:

```bash
uv run crimson dbg record \
  analysis/frida/replays/capture_<sha8>.crd \
  --impl zig \
  --out analysis/frida/traces/capture_<sha8>_zig.cdt
```
*(Use `--impl python` to test the Python path).*

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

Unlike the legacy process, `dbg` diffing is extremely fast because playback and difﬁng are decoupled. Run the standard trace-based reports:

Find the first structural divergence depending on the exact policy (`original_vs_python_default` vs `python_vs_zig_core`):

```bash
uv run crimson dbg diff \
  analysis/frida/traces/capture_<sha8>.cdt \
  analysis/frida/traces/capture_<sha8>_zig.cdt \
  --policy python_vs_zig_core \
  --float-abs-tol 1e-3
```

Extract a focused trace repro bundle spanning across the first divergence point:

```bash
uv run crimson dbg bisect \
  analysis/frida/traces/capture_<sha8>.cdt \
  analysis/frida/traces/capture_<sha8>_zig.cdt \
  --policy python_vs_zig_core \
  --window-before 12 \
  --window-after 6 \
  --out analysis/frida/traces/capture_<sha8>_repro.cdt
```

For surgical detail at exactly the focus mismatch tick, inspect the state across both traces in lockstep:

```bash
uv run crimson dbg focus \
  analysis/frida/traces/capture_<sha8>.cdt \
  analysis/frida/traces/capture_<sha8>_zig.cdt \
  --tick <focus_tick> \
  --policy python_vs_zig_core
```

For visual context and movement trajectory overlaps, use the visualizer:

```bash
uv run crimson dbg viz \
  analysis/frida/traces/capture_<sha8>.cdt \
  analysis/frida/traces/capture_<sha8>_zig.cdt
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

1. Add targeted tests for every replay/conversion behavior change.
2. Run `just check`.
3. Update differential session docs (`docs/frida/differential-sessions.md` index
   plus the relevant `docs/frida/differential-sessions/session-*.md` file) with:
   - SHA
   - exact baseline commands
   - first mismatch progression
   - landed changes
   - next probe
4. Commit with conventional commits style.