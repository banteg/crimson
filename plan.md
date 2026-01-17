# Agent Loop Plan (Crimsonland RE)

Goal: keep a looped agent quickly oriented and making steady, verifiable progress on
reverse engineering Crimsonland.

This plan is designed to be fed repeatedly to a single‑turn agent. Each run should
complete one focused unit of work and leave a clear trail in docs or artifacts.

## Ground rules

- Do one primary task per iteration; avoid spreading across subsystems.
- Prefer evidence-backed changes (add callsite lines, addresses, or direct outputs).
- Treat `source/decompiled/` as read-only except when regenerating via Ghidra.
- For any Python tool/script, use `uv run ...`.
- If you commit, use Conventional Commits. Otherwise, do not commit.

## Progress tracking (required)

- This plan is static. Track progress in `plan_progress.log` (append only).
- Each run must append a single line:
  `DONE | <short summary> | FILES: <comma list> | NEXT: <single focus>`
- If blocked, append:
  `BLOCKED | <reason> | NEXT: <single focus>`

## Fast context (read on first run or after a long gap)

1. `docs/index.md` for overall scope and known formats.
2. `docs/metrics.md` for current coverage and last regen date.
3. `docs/detangling.md` for current naming targets and evidence.
4. `docs/entrypoint.md`, `docs/atlas.md`, `docs/weapon-table.md`, `docs/pipeline.md`.
5. `source/README.md` for canonical Ghidra regeneration workflow.

## How to choose work (per run)

Pick one narrow, evidence-friendly task that moves the Crimsonland RE forward.
Typical choices: naming a hotspot function with evidence, updating a doc section
with new extracted data, or refreshing a single artifact via a script.

## Command cookbook

### Ghidra regen (full, classic exe)
```
./.codex/skills/ghidra/scripts/ghidra-analyze.sh \
  --script-path scripts/ghidra_scripts \
  -s ImportThirdPartyHeaders.java -a source/headers/third_party \
  -s ApplyWinapiGDT.java -a source/ghidra/winapi_32.gdt \
  -s ApplyNameMap.java -a source/ghidra/name_map.json \
  -s ExportAll.java \
  -o source/decompiled \
  game/crimsonland.exe
```

Repeat for `game/grim.dll` when needed.

### Hotspot naming targets
```
uv run python scripts/function_hotspots.py --top 12 --only-fun
```

### Entrypoint trace refresh
```
uv run python scripts/entrypoint_trace.py --depth 2 --skip-external
```

### Atlas usage scan
```
uv run python scripts/atlas_scan.py
```

### Weapon table extract
```
uv run python scripts/extract_weapon_table.py
```

### Asset extraction (pipeline sanity)
```
uv run paq extract game assets
```

## Artifacts to update (pick the ones tied to your task)

- `source/ghidra/name_map.json` for new names/signatures.
- `docs/detangling.md` for new evidence and next targets.
- `docs/entrypoint.md` for init flow changes.
- `docs/atlas.md`, `docs/weapon-table.md`, `docs/pipeline.md` for format/system progress.
- `docs/metrics.md` if Ghidra outputs were regenerated.

## Output contract (for the bash loop)

At the end of each run, output:
- `STATUS: <one line>`
- `FILES: <comma-separated list>`
- `NEXT: <single recommended focus>`

Only output `DONE` if verification passed, there are no remaining
"Status: In progress" sections, and the user explicitly asks to stop the loop.
