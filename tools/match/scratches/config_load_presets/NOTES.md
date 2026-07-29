# `config_load_presets`

Native target: `crimsonland.exe` at `0x0041f1a0` (653 bytes).

Live Binary Ninja evidence identifies the default two-player key bindings, the
0x480-byte `crimson.cfg` contract, binding transfer into runtime player state,
conditional Grim configuration propagation, and player-name/reset behavior.

The file-side copy now uses `player_input_config_t` records directly and binds
an interior cursor to the evidenced `axis_move_x` field. This preserves the
persisted Y/X analog-axis ordering while making the transfer into the runtime
`player_input_t` layout explicit.

The recovered C++ source matches 88.76% (67-instruction exact prefix, 178 target
and candidate instructions). Everything outside the two-player binding-copy
loop is instruction-identical. The remaining mismatch is confined to VC6's
choice of induction anchors: the native uses `config_p1_axis_move_x` and the
runtime backward-key field. Binding the source to `axis_move_x` advances the
candidate's normalized source anchor from turn-left to backward-key and raises
the weighted match by 3.67 bytes, but the compiler still rebases both induction
registers differently from native.

Three recorded mutation sweeps cover 11 variants of the binding loop:
field-identity aliases, typed/raw source anchors, and source/destination
induction-pointer forms. The `axis_move_x` source anchor is the sole winner.
Making it the actual loop induction variable regresses 12.60-34.55 weighted
bytes; the pointer-bound forms remove one relocation mismatch only by adding an
instruction and losing 12.60 weighted bytes. Those tradeoffs are rejected, so
the scratch retains the simplest evidenced interior cursor.

## Recovery classification audit

Binary Ninja accounts for the complete defaults, file contract, binding
transfer, Grim propagation, names, and reset policy. Candidate and native each
have 178 instructions. The address-level audit is `50/0/3`: all three
mismatches are the same two-record copy rebased from native field anchors to
the candidate compiler-selected anchors, not unknown data or incorrect
offsets.
Everything outside that single localized loop is exact, so recovery is
`semantic-complete` with a `compiler` residual.
