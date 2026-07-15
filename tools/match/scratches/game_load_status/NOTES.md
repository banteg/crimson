# `game_load_status`

Native target: `crimsonland.exe` at `0x00412c10` (420 bytes).

Live Binary Ninja evidence identifies a 0x26c-byte file contract, inverse byte
transform over the 0x268-byte status blob, signed-byte checksum validation, and
separate missing-file, invalid-size, and invalid-checksum paths. The C++
frontend is source-shape evidence: with otherwise identical source, VC6 C
coalesces three caller-cleanup sites that the native code keeps separate.

Verified exact with `crimson match scratch`: 134/134 normalized instructions
and all 43 references.
