# `config_load_presets`

Native target: `crimsonland.exe` at `0x0041f1a0` (653 bytes).

Live Binary Ninja evidence identifies the default two-player key bindings, the
0x480-byte `crimson.cfg` contract, binding transfer into runtime player state,
conditional Grim configuration propagation, and player-name/reset behavior.

The file-side copy now names both aggregate identities directly through
`config_blob.input_config[player_index]` and
`player_state_table[player_index].input`. This preserves the persisted Y/X
analog-axis ordering while making the transfer into the runtime
`player_input_t` layout explicit.

The recovered C++ source now matches 100%: 653/653 bytes, all 178 instructions,
and all 53 audited references. A typed persisted-row pointer preserves the
field identities, while an ordinary pointer to its `axis_move_x` member owns
the first and final field accesses. VC6 then selects the native
`config_p1_axis_move_x` induction base and exact loop-end identity without
changing any copied value or the direct destination aggregate.

Three earlier mutation sweeps cover 11 variants of the binding loop:
field-identity aliases, typed/raw source anchors, and source/destination
induction-pointer forms. The `axis_move_x` source anchor was the sole winner in
that earlier matrix.
Making it the actual loop induction variable regresses 12.60-34.55 weighted
bytes; the pointer-bound forms remove one relocation mismatch only by adding an
instruction and losing 12.60 weighted bytes. Those tradeoffs remain rejected;
the later direct-aggregate recovery supersedes the interior-cursor source.

## Recovery classification audit

Binary Ninja accounts for the complete defaults, file contract, binding
transfer, Grim propagation, names, and reset policy. Candidate and native each
have 178 instructions. The final address-level audit is `53/0/0`, and the
entire 653-byte function is exact. No recovery residual remains.

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

## 2026-08-09 aggregate-identity recovery

The exact duplicate binding copy in `crimsonland_main` uses direct source and
destination aggregate expressions. Transferring that identity boundary here
raises the whole-function match from 88.7640449% to 92.6966292%, or from
579.629213 to 605.308989 fuzzy-weighted bytes. It preserves 178/178
instructions and the 67-instruction prefix while improving the reference audit
from `50/0/3` to `51/0/2`.

Live native disassembly at `0x0041f2bd..0x0041f322` confirms the reason: the
destination induction register is based at runtime `move_key_backward` in both
native and the revised candidate. Native still bases the source induction at
`config_p1_axis_move_x` and ends at `0x004805c0`; the candidate naturally
rebases those same field accesses to persisted `move_key_backward`. Giving the
first `move_key_forward` load a named local, as in `crimsonland_main`, is
byte-neutral, so the simpler direct publication is retained. The retained
source SHA-256 is
`a7041f8bce90003abaea9fc5fd575e36d948eb27ac7dd1f5956e285437305643`.

## Exact source-induction recovery (2026-08-11)

The direct-aggregate pass left the source loop anchored at persisted
`move_key_backward`, even though all effective field addresses were correct.
The older cursor sweeps changed both source and destination ownership and did
not cover a hybrid with the recovered direct destination aggregate.

`binding-hybrid-source-anchor-mutations.json` evaluates five such hybrids.
Keeping a typed `player_input_config_t *bindings` for the named fields, plus an
`int *binding_cursor = &bindings->axis_move_x` for the first and final fields,
is the sole winner. It raises the function from 92.6966% to **100%**, extends
the prefix from 67 to all 178 instructions, and improves references from
`51/0/2` to **`53/0/0`**. The other axis-relative spellings are byte-neutral or
regressive. The scratch is now classified exact.
