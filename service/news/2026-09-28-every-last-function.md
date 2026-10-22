# Every Last Function

All 858 game and engine functions in `crimsonland.exe` and `grim.dll` now come from recovered C/C++ source that Visual C++ 6 compiles back to the original machine code, instruction for instruction. That's called a matching decompilation, and for 1.9.93, the Crimsonland Classic build on GOG, it is now complete.

Why bother, when the Python port already plays the same? Because there's no more guessing. If the source compiles to the same bytes, it *is* the game.

Older versions are measured against the same source on [decomp.dev](https://decomp.dev/banteg/crimson). Next up: compiling it for things Visual C++ 6 never dreamed of.
