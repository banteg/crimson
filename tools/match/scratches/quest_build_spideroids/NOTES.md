# `quest_build_spideroids`

Native target: `crimsonland.exe` at `0x004373c0` (224 bytes).

Live Binary Ninja evidence recovers three unconditional splitter entries at
`(1088, 512)`/1000 ms, `(-64, 512)`/3000 ms, and `(1088, 256)`/6000 ms. When
the byte currently named `config_hardcore` is nonzero, the builder adds
`(1088, 762)` and `(512, 1088)` at 9000 ms. It then adds `(-64, 762)` at
9000 ms when there are at least two players or that same byte is nonzero.
Every entry uses template `0x01` and count 1, producing 3, 4, 5, or 6 entries
according to those branches.

The direct fixed-entry source reproduces the native shared constants, branch
shape, scaled final-entry address, early-pop return path, and all 62
instructions. It scores 98.39%. The sole residual is a scheduling swap: VC6
loads the shared integer constant 1 immediately before the first x-coordinate
store in the candidate and immediately after it in the target. The clean
source is retained without adding an artificial ordering constraint.
