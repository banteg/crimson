# game_is_full_version

The DRM-free native build returns constant true in `al`. Live Binary Ninja
callsites consistently consume only that byte, so the recovered return type is
`unsigned char`, not the previous `int` annotation. IDA had also classified the
three-byte body as a library function; the manifest now records it as
game-owned code so this heavily used predicate is measured by the matcher.
