# Recovered crimsonland.exe source layout

This tree is the canonical home for recovered game source of `crimsonland.exe`
in the 1.9 build family (canonical build 1.9.93; see
[../../README.md](../../README.md)). It covers all 679 game functions,
`0x401030`–`0x452ee1`, in 576 source files. Matcher scratch directories keep
their `scratch.conf`, notes and experiments, and their `SOURCE` fields point
here.

## Translation units

Each directory is one inferred translation unit: a contiguous range of native
code that one original source file compiled to. The boundaries come from link
order:

- the static-initializer table (`.CRT$XCU`) lists global constructors in link
  order, and most units open with the initializer of the globals defined at the
  top of their file;
- file statics of neighbouring screens interleave in `.bss`, which ties those
  screens to one object;
- the 29 multi-function objects proven in
  `tools/native/translation_units/crimsonland.exe.json` never cross a boundary.

Directory names are a plausible reconstruction, not a claim about the original
file names. `layout.json` records each unit's code range and evidence; the
native-link tests check that every function lies inside its unit.

The Rich headers of 1.9.1 and 1.9.8 separate game objects from runtime objects
by compiler build. They link 23 and 24 game C++ objects and no C objects, and
1.9.93's 34 C++ objects fit 24 game objects plus the same 10 runtime objects.
So one directory probably still spans two original files, and the game was all
C++: the `.c` files here are a matching convenience.

## Files

Inside a unit every function is still its own file and compile object, so each
function matches independently. The exception is the 29 proven multi-function
objects: each is one file named after its lifecycle, such as
`gameplay/quest_meta.cpp`, which holds the quest metadata table with its
constructor, `atexit` registration and destructor. Each member's scratch
selects its own symbol from that shared file.

Merging a unit's files into one source file is the next step. A merge counts
only when every function in the unit still compiles exactly.
