# perk_meta_table_init

Native target: `crimsonland.exe` at `0x0042faa0` (28 bytes).

The named provider placement-constructs a 128-entry wrapper over the external
perk metadata array. The static array is necessarily non-null; expressing
that invariant lets VC6 emit the original guarded vector-construction helper
with its native 0x14 stride.

The object now defines `_perk_meta_table_init` directly rather than the
compiler-local `_$E1` identity. It still matches all seven instructions, full
prefix, with all four references aligned.
