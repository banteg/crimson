# `dx_get_version`

Native target: `crimsonland.exe` at `0x0041ccb0` (251 bytes).

Live Binary Ninja evidence recovers the complete DirectX version wrapper. It
first queries `IDxDiagProvider` through `dx_get_version_from_dxdiag`, falls back
to system-file version resources, lowercases the optional version letter, and
packs `(major, minor, letter)` into `major << 16 | minor << 8 | letter_index`.
It can also emit a bounded `major.minor` or `major.minor<letter>` string and
always terminates the caller's final byte.

The primary callee name is backed by its COM CLSID/IID flow and queries for
`DxDiag_SystemInfo`, `dwDirectXVersionMajor`, `dwDirectXVersionMinor`, and
`szDirectXVersionLetter`. No dummy references, inline assembly, volatile
ordering constraints, or dead expressions are used.
