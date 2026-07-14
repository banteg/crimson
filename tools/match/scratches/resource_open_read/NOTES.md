# resource_open_read

When a pack is enabled, this scans its NUL-terminated entry table after a
four-byte header. Each entry is a name, a native-endian 32-bit size, then raw
data. A case-insensitive name match leaves the shared stream positioned at that
data; misses seek over it. Exhausting the pack closes it and falls back to the
standalone path.

Standalone files are measured with `fseek`/`ftell` and rewound. The helper
returns only success/failure and keeps the successful stream in `resource_fp`.

The recovered source is an exact 88/88-instruction match with all 21 native
references aligned. MSVC naturally reuses the dead `size_out` argument slot for
the current packed-entry size after preserving the output pointer in `EBX`.
