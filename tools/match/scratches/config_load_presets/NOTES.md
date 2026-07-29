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

## Shared member-boundary audit

The same binding-copy residual appears in `crimsonland_main`, making a
translation-unit-local row method or assignment operator a plausible shared
source constraint. Three recorded plans now bound that hypothesis:

- `binding-member-boundary-mutations.json` (SHA-256
  `ed19614167fc34a2a1e5f05bc2e5b686bcda24d6d7c0279612e8fd2b4a53c143`)
  tests six local runtime-owned, persisted-owned, assignment, and
  axis-relative member forms. VC6 leaves the member body out of line, removing
  23 instructions from the target function; all six produce the same
  155-instruction result.
- `binding-forceinline-member-mutations.json` (SHA-256
  `e4edd8b87f036a62709e31960f10619ddbd1eb48352311f69b69a39ddebd68f0`)
  confirms that applying `__forceinline` to those local-class methods does not
  change that lowering.
- `binding-global-member-mutations.json` (SHA-256
  `b4cedb31cd1581996e4c26eccd1b09b5a95a2242d0fd3a0dd12774dcd9d7e559`)
  moves the member types to file scope. Forced inlining restores the
  178-instruction body, but the persisted-owned direction loses 3.6685
  weighted bytes and the runtime-owned method and assignment forms each lose
  36.6854. None improves the three-reference induction-anchor audit.

The ordinary free-helper, raw/interior cursor, and member/operator source
menus are therefore all closed. Replaying the member forms in
`crimsonland_main` would test the same compiler decision in a noisier caller
and is not justified by the smaller function's complete negative matrix.
