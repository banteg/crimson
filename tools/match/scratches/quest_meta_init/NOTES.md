# quest_meta_init

Native target: `crimsonland.exe` at `0x00412190` (25 bytes).

The named provider placement-constructs a 50-entry wrapper over the external
quest metadata array. The static array is necessarily non-null; expressing
that invariant lets VC6 emit the original guarded vector-construction helper,
including the 0x2c stride and the entry destructor used for exception
unwinding.

The object now defines `_quest_meta_init` directly rather than the
compiler-local `_$E1` identity. It still matches all seven instructions, full
prefix, with all four references aligned.
