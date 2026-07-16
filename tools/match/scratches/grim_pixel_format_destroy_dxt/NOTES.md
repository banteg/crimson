# `grim_pixel_format_destroy_dxt`

Native target: `grim.dll` at `0x10016c3c` (160 bytes).

The virtual destructor walks every cached depth slice and four-row DXT block,
releases each owned 4x4 RGBA staging buffer, frees the row-state and cache-entry
arrays, and finally invokes the shared pixel-format/converter base destructor.

The candidate recovers the complete ownership and loop structure. Its remaining
codegen delta is VC6 register allocation: native uses EBX for the depth loop and
EDI for the row loop, while this natural nested-loop source assigns them in the
opposite order and retains two extra save/load instructions. The local-label
alias names only the compiler-generated EH handler; it adds no source-level call
or codegen constraint.
