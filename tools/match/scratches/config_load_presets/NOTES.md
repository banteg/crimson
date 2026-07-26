# `config_load_presets`

Native target: `crimsonland.exe` at `0x0041f1a0` (653 bytes).

Live Binary Ninja evidence identifies the default two-player key bindings, the
0x480-byte `crimson.cfg` contract, binding transfer into runtime player state,
conditional Grim configuration propagation, and player-name/reset behavior.

The file-side copy now uses `player_input_config_t` records directly. This
preserves the persisted Y/X analog-axis ordering while making the transfer into
the runtime `player_input_t` layout explicit.

The recovered C++ source matches 88.20% (67-instruction exact prefix, 178 target
and candidate instructions). Everything outside the two-player binding-copy
loop is instruction-identical. The remaining mismatch is confined to VC6's
choice of induction anchors: the native uses `config_p1_axis_move_x` and the
runtime backward-key field, while the reconstructed aggregate loop is rebased
to each record's turn-left field. Pointer, struct, indexed, frontend, and honest
optimizer-profile variants either preserve that rebasing or regress the exact
surrounding code, so the scratch retains the natural source rather than masking
the compiler residual.

## Recovery classification audit

Binary Ninja accounts for the complete defaults, file contract, binding
transfer, Grim propagation, names, and reset policy. Candidate and native each
have 178 instructions. The address-level audit is `50/0/3`: all three
mismatches are the same two-record copy rebased from native field anchors to
the candidate aggregate bases, not unknown data or incorrect offsets.
Everything outside that single localized loop is exact, so recovery is
`semantic-complete` with a `compiler` residual.
