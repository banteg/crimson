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
     -s ExportAll.java \
     -o source/decompiled \
     game/crimsonland.exe
   ```

   The header pack includes DirectX/DirectSound headers as references, but the
   import script only parses codec headers (JPEG/zlib/ogg/vorbis). The full
   `png.h` header is kept for reference but skipped in headless parsing due to
   Ghidra C parser limitations with unnamed callback parameters.
2. Copy fresh outputs into `source/decompiled/`.
3. Only edit files in `source/clean/`.
