# Source artifacts

This directory stores source inputs and decompiled outputs that we want under
version control.

Layout:

- `headers/` — third‑party headers for better Ghidra type recovery.
- `decompiled/` — raw Ghidra output (treat as read‑only).
- `clean/` — hand‑refactored C, renamed symbols, notes, etc.

Regenerating:

1. Re-run Ghidra analysis with headers in `source/headers/` added to the
   C parser include paths. We use `scripts/ghidra_scripts/ImportThirdPartyHeaders.java`
   to parse codec headers before exporting:

   ```bash
   ./scripts/ghidra-analyze.sh \
     --script-path scripts/ghidra_scripts \
     -s ImportThirdPartyHeaders.java -a source/headers/third_party \
     -s ApplyWinapiGDT.java -a source/ghidra/winapi_32.gdt \
     -s ExportAll.java \
     -o source/decompiled \
     game/crimsonland.exe
   ```

   The header pack includes DirectX/DirectSound headers as references, but the
   import script only parses codec headers (JPEG/zlib/ogg/vorbis). The full
   `png.h` header is kept for reference but skipped in headless parsing due to
   Ghidra C parser limitations with unnamed callback parameters.

   The WinAPI .gdt is kept in `source/ghidra/winapi_32.gdt`; override it via
   `CRIMSON_WINAPI_GDT` or the `ApplyWinapiGDT.java` script arg if needed.

   For faster iterations, keep the headless project around and re-run with the
   same project name. We store these under `output/ghidra_project/`:

   ```bash
   ./scripts/ghidra-analyze.sh \
     --keep-project \
     --project-dir output/ghidra_project \
     --project-name crimsonland_exe \
     --script-path scripts/ghidra_scripts \
     -s ApplyNameMap.java -a source/ghidra/name_map.json \
     -s ExportAll.java \
     -o source/decompiled \
     game/crimsonland.exe
   ```

   Use `--project-name grim_dll` with `game/grim.dll` for Grim2D exports, and
   run the vtable helper before applying the name map so vtable entries are
   created as functions:

   ```bash
   ./scripts/ghidra-analyze.sh \
     --keep-project \
     --project-dir output/ghidra_project \
     --project-name grim_dll \
     --script-path scripts/ghidra_scripts \
     -s CreateGrim2DVtableFunctions.java \
     -s ApplyNameMap.java -a source/ghidra/name_map.json \
     -s ExportAll.java \
     -o source/decompiled \
     game/grim.dll
   ```
2. Copy fresh outputs into `source/decompiled/`.
3. Only edit files in `source/clean/`.
