# `grim_jpeg_memory_src`

Native target: `grim.dll` at `0x1003a990`, 122 bytes.

This scratch selects the installer from the canonical recovered IJG 6a
provider translation unit. It allocates the custom memory source manager and
4 KiB buffer on first use, installs all five source callbacks, and resets the
caller-provided input window. The provider recipe independently requires this
same symbol to match before publishing its deterministic archive.
