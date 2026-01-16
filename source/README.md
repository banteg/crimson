# Source artifacts

This directory stores source inputs and decompiled outputs that we want under
version control.

Layout:

- `headers/` — third‑party headers for better Ghidra type recovery.
- `decompiled/` — raw Ghidra output (treat as read‑only).
- `clean/` — hand‑refactored C, renamed symbols, notes, etc.

Regenerating:

1. Re-run Ghidra analysis with headers in `source/headers/` added to the
   C parser include paths.
2. Copy fresh outputs into `source/decompiled/`.
3. Only edit files in `source/clean/`.
