# decompile hotspot extraction

This folder is analysis-only and does not alter runtime code.

- source: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
- extracted functions: `4`
- requested targets: `effect_spawn_splitter_hit_burst`
- resolved targets: `effect_spawn_splitter_hit_burst`
- call depth: `1`
- name map: `analysis/ghidra/maps/name_map.json`
- local renames: `analysis/ghidra/derived/hotspots/effect_spawn_splitter_hit_burst/work/local_renames.json`
- direct callgraph: `callgraph.txt`

## Files

- `analysis/ghidra/derived/hotspots/effect_spawn_splitter_hit_burst/functions/0042e120_effect_spawn.c` (0x0042e120)
- `analysis/ghidra/derived/hotspots/effect_spawn_splitter_hit_burst/functions/0042f3f0_effect_spawn_splitter_hit_burst.c` (0x0042f3f0)
- `analysis/ghidra/derived/hotspots/effect_spawn_splitter_hit_burst/functions/00461054___ftol.c` (0x00461054)
- `analysis/ghidra/derived/hotspots/effect_spawn_splitter_hit_burst/functions/00461746_crt_rand.c` (0x00461746)

## Suggested workflow

- Keep `functions/` as the immutable extraction baseline.
- Use `work/` for variable renames and comments (safe to edit).
- Start with `work/renaming_guide.md` for consistent first-pass renames.
- Keep address labels and branch ids intact when annotating parity-sensitive logic.
