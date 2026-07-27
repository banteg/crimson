# demo_trial_overlay_render

High-value recovery for the 2,413-byte demo-expiry overlay at `0x004047c0`.
Live Binary Ninja control-flow, stack-slot, string, and callsite evidence
recovers the complete panel, time formatter, message policy, local-static
buttons, purchase action, and return-to-menu action.

## Recovered source shape

- renders the 512x256 warning panel, logo, header, and three native message
  layouts for the Quest tier limit, exhausted trial, and Quest-only grace time;
- preserves the native integer time decomposition, including the manual
  minute remainder that produces VC6's three multiply-high divisions;
- formats single-digit seconds with the evidenced `"0%d"` literal and
  centiseconds with the native one-digit zero prefix;
- retains the empty formatted line and the extra unused time argument passed
  to the grace-period lead sentence;
- reconstructs the shared three-bit local-static guard in Maybe later,
  Purchase, and unused Already paid order;
- opens `http://buy.crimsonland.com` and latches quit after Purchase; and
- returns to the main menu, resets the render transition, and switches music
  after Maybe later.

## Static-object evidence

The VC6 object relocation table maps `$E2` to the Maybe later destructor at
`0x00405150`, `$E3` to Purchase at `0x00405140`, and `$E4` to Already paid at
`0x00405130`. Live Binary Ninja disassembly proves all three callbacks are a
single `ret`. The decorated guard/object aliases and pooled empty literal now
pass the strict reference audit at `171/0/0`.

## Remaining mismatch

The natural source is a 94.25% semantic reconstruction: 616 candidate
instructions against 636 native instructions, with the first 205 instructions
exact and the native `0x124` stack frame reproduced. VC6 still tail-merges a
repeated two-line text suffix that the native keeps distinct. In the button
tail it assigns the long-lived row origin to the body vector's dead `+0x10`
slot and the short Purchase coordinate to `+0x1c`; native uses those two slots
in the opposite roles and retains the shared y coordinate between them. Scoped
vectors, constructor and assignment forms, `set`, `operator+`, `operator+=`,
and separate scalar anchors either preserved those artifacts or materially
worsened the long text-body register allocation. No union, volatile state,
dead expression, fake reference, or artificial register constraint is used.

## Recovery classification audit

A fresh focused `--regions` run is unchanged before and after classification:
**94.25%**, 616/636 candidate/native instructions, prefix 205, and `171/0/0`
references. Live Binary Ninja on `crimsonland.exe.bndb` confirms all three
message arms, their exact strings and Y increments, the shared final sentence,
all three guarded local-static buttons, the purchase URL action, and the
return-to-menu/audio action. The 20-instruction count delta is the documented
repeated-suffix tail merge; the later diffs are label displacement and
temporary-slot scheduling induced by that merge, not missing behavior.

The full compiler/flag sweep found no exact profile flip, with stock VC6.5
`/O2 /GB` remaining best. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## 2026-07-27 mutation audit

A fresh live Binary Ninja comparison localized the 20-instruction deficit more
precisely. Native keeps separate, otherwise instruction-identical upgrade tails
for the Quest arm (`0x00404c6c..0x00404cb9`) and expired arm
(`0x00404d55..0x00404da2`), including an `add esp, 0x10` after each text call.
VC6.5 merges both tails at candidate offset `0x55a`. Structured nesting,
explicit `goto` exits, and fixed-string inline/force-inline wrappers all
normalized back to the same 616-instruction candidate, establishing that this
is an optimizer tail-merge rather than missing source behavior.

The native button tail also confirms the Purchase coordinate at `esp+0x10`,
the long-lived row origin at `esp+0x1c`, and shared y at `esp+0x18`
(`0x00405047..0x004050d6`). Extending the body-position lifetime to reuse the
Purchase slot produced 631 instructions but regressed fuzzy-weighted bytes by
205.95 and introduced six reference mismatches. Declaration-order variants
were neutral; direct and copy-initialized constructors were neutral; y-first
field assignment regressed by 3.85 bytes. No source change was retained.

Five exhaustive, non-truncated mutation sweeps are recorded in
`experiments.jsonl` (28 variants total). A narrow flag check found `/Ox` raised
the raw ratio to 95.25% but created 33 unresolved references, so the
reference-clean `/O2 /GB` baseline remains canonical at **94.25%**,
2274.23/2413 fuzzy-weighted bytes, 616/636 instructions, prefix 205, and
`171/0/0` references.
