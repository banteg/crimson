# Ghidra analysis

This directory holds structured Ghidra artifacts and supporting files we keep
under version control. Whole-program decompiles are intentionally not checked
in; consult functions by canonical name/address as described in
`analysis/README.md`.

Layout:

- `raw/` — structured Ghidra exports (treat as read-only).
- `derived/` — compact recovered datasets derived from earlier investigations.
- `scripts/` — custom Ghidra scripts.
- `maps/` — name/data maps and WinAPI GDT.

External inputs:

- `third_party/headers/` — header pack for type recovery.
- `analysis/ghidra/projects/` — persistent headless projects and provenance
  records (gitignored).

## Regenerating

1. Re-run Ghidra analysis with headers in `third_party/headers/` added to the
   C parser include paths. We use `analysis/ghidra/scripts/ImportThirdPartyHeaders.java`
   to parse codec headers before exporting. The default flow reuses the
   persistent project and is wrapped by the justfile shortcuts:

   ```bash
   just ghidra-exe
   ```

   For Grim2D exports:

   ```bash
   just ghidra-grim
   ```

   Each run verifies the input binary hash plus the Ghidra version and
   installation fingerprint, processes the existing program, reapplies maps,
   and saves the updated project. The first run imports the binary and creates
   the project. `FinalizeAnalysis.java` runs a whole-program post-map pass when
   creating a project, then limits later refreshes to analysis queued by current
   map changes so generated names do not drift between exports.

   Use the explicit rebuild commands for a clean reproducibility baseline or
   after intentionally changing the binary/tool:

   ```bash
   just ghidra-rebuild-exe
   just ghidra-rebuild-grim
   ```

   Rebuilds move the previous project and provenance into
   `analysis/ghidra/projects/backups/` before importing cleanly.

## WSL regen + Windows sync

If the primary workspace is on Windows and Ghidra runs in WSL, use the sync
helper so outputs land in the Windows repo without leaving WSL dirty:

```bash
just ghidra-sync
```

This runs `ghidra-exe` and `ghidra-grim` in WSL, copies
`analysis/ghidra/raw/` and `analysis/ghidra/derived/` back to Windows, then
cleans the WSL outputs so `git pull` remains clean.

Override the Windows repo path if needed:

```bash
CRIMSON_WIN_REPO=/mnt/c/dev/crimson just ghidra-sync
```

Override the game directory when needed:

   ```bash
   just game_dir=game_bins/crimsonland/1.9.93-gog ghidra-exe
   ```

The header pack includes DirectX/DirectSound headers as references, and the
import script parses codec headers (JPEG/zlib/ogg/vorbis) plus the
`png_struct_stub.h` shim used for grim.dll’s libpng 1.0.5-era layout. The full
libpng public headers (`png.h`, `pngconf.h`, `pngasmrd.h`) are kept for
reference but skipped in headless parsing due to Ghidra C parser limitations
with unnamed callback parameters.

   The WinAPI .gdt is kept in `analysis/ghidra/maps/winapi_32.gdt`; override it
   via `CRIMSON_WINAPI_GDT` or the `ApplyWinapiGDT.java` script arg if needed.
   The name/data maps can be overridden via `CRIMSON_NAME_MAP` and
   `CRIMSON_DATA_MAP`.

2. For custom persistent analyses, pass `--persistent`, an explicit project
   directory, and a stable project name:

   ```bash
   ./analysis/ghidra/tooling/ghidra-analyze.sh \
     --persistent \
     --project-dir analysis/ghidra/projects \
     --project-name crimsonland_exe \
     --script-path analysis/ghidra/scripts \
     -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
     -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
     -s FinalizeAnalysis.java \
     -s ExportAll.java \
     -o analysis/ghidra/raw \
     game_bins/crimsonland/1.9.93-gog/crimsonland.exe
   ```

   Use `--project-name grim_dll` with
   `game_bins/crimsonland/1.9.93-gog/grim.dll` for Grim2D exports, and run
   the vtable helper before applying the name map so vtable entries are created
   as functions:

   ```bash
   ./analysis/ghidra/tooling/ghidra-analyze.sh \
     --persistent \
     --project-dir analysis/ghidra/projects \
     --project-name grim_dll \
     --script-path analysis/ghidra/scripts \
     -s CreateGrim2DVtableFunctions.java \
     -s CreateConfigDialogProc.java \
     -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
     -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
     -s FinalizeAnalysis.java \
     -s ExportAll.java \
     -o analysis/ghidra/raw \
     game_bins/crimsonland/1.9.93-gog/grim.dll
   ```

3. The wrapper automatically switches from `-import` to `-process` after the
   project is created. If operating the raw headless analyzer directly, the
   equivalent repeated-run command is:

   ```bash
   GHIDRA_OUTPUT_DIR=analysis/ghidra/raw \
     /opt/ghidra/support/analyzeHeadless \
     analysis/ghidra/projects grim_dll \
     -process grim.dll \
     -scriptPath "/workspace/analysis/ghidra/scripts;/workspace/analysis/ghidra/tooling/ghidra_scripts" \
     -postScript CreateGrim2DVtableFunctions.java \
     -postScript CreateConfigDialogProc.java \
     -postScript ApplyNameMap.java analysis/ghidra/maps/name_map.json \
     -postScript ApplyDataMap.java analysis/ghidra/maps/data_map.json \
     -postScript FinalizeAnalysis.java \
     -postScript ExportAll.java
   ```
