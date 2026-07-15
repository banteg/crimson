# `config_load_presets`

Native target: `crimsonland.exe` at `0x0041f1a0` (653 bytes).

Live Binary Ninja evidence identifies the default two-player key bindings, the
0x480-byte `crimson.cfg` contract, binding transfer into runtime player state,
conditional Grim configuration propagation, and player-name/reset behavior.

The recovered C++ source matches 88.20% (67-instruction exact prefix, 178 target
and candidate instructions). Everything outside the two-player binding-copy
loop is instruction-identical. The remaining mismatch is confined to VC6's
choice of induction anchors: the native uses `config_p1_axis_move_x` and the
runtime backward-key field, while the reconstructed aggregate loop is rebased
to each record's turn-left field. Pointer, struct, indexed, frontend, and honest
optimizer-profile variants either preserve that rebasing or regress the exact
surrounding code, so the scratch remains explicitly WIP rather than masking the
difference.
