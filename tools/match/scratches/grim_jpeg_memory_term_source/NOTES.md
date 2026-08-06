# `grim_jpeg_memory_term_source`

Native target: `grim.dll` at `0x1003ab00`, one byte.

Binary Ninja shows a single `ret`, and the cross-references identify it as the
terminal callback used by Grim's in-memory IJG source manager. Its context is
caller-owned, so termination intentionally performs no work.
