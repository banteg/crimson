# `quest_build_frontline_assault`

Native target: `crimsonland.exe` at `0x00437e10` (285 bytes).

Live Binary Ninja evidence recovers waves 2 through 21. Every wave emits a
bottom-center alien at `(terrain_width / 2, 1088)`. Waves 2-4 use template
`0x26`, waves 5-9 use `0x1a`, and later waves return to `0x26`. Waves above
four add a template `0x26` alien at `(-64, -64)`; waves above ten also add one
at `(1088, -64)`. Wave ten uniquely adds two template `0x29` AlienBigGray creatures at the
right and left edge midpoints. All counts are one.

Each wave trigger is `wave * step - 5000`. The step starts at 2500, decreases
by 50, and clamps to 1800. The special wave-ten trigger retains the native
spelling `(step * 5 - 2500) * 2`. The result contains 50 entries.

The candidate preserves the native cursor/count/step/wave registers, signed
terrain halving, conditional entry policy, trigger arithmetic, clamp, and
output count. Recovering the same cursor/count builder object used by adjacent
quest constructors keeps the bottom-edge Y store beside the converted X store,
extends the exact prefix from 10 to 18 instructions, and prevents VC6 from
folding the two wave-ten count advances into one `+= 2`. It resolves the
terrain-width reference. Ordering the second template test as `wave >= 10`
with the late gray arm before the blue fallback reproduces the native three
template stores and both unconditional exits. This raises the score from the
previous 87.27% to 96.43%, extends the exact prefix from 18 to 29 instructions,
and emits the exact native count of 84 instructions with the reference still
resolved.

The residual is now limited to three instructions in two regions. The candidate
uses `sub eax, 5000` where the native function uses `add eax, -5000`, then uses
`eax` rather than `ecx` for the final output-count pointer load and store. The
template ladder itself is exact, and the fuzzy gap falls from 36.27 to 10.18
bytes. `pos.set(x, y)` and `msvc6.5pp` do not improve the result. Dummy
dependencies, volatile barriers, or semantically distinct fake template values
are not used to preserve the native control-flow spelling.

An address-keyed Binary Ninja local type now preserves the second wave-ten
cursor after VC6 advances it. Both midpoint AlienBigGray creatures render as named
`quest_spawn_entry_t` fields; the remaining negative trigger/count access is a
real induction-pointer artifact, not an unknown structure member.

The compiler-facing builder uses the canonical `quest_spawn_entry_t` directly.
Its cursor/count aggregate now also agrees with the repeatedly evidenced quest
builder source idiom without changing the record view or introducing a
code-generation-only wrapper.

## Recorded mutation evidence

Three earlier complete sweeps add 53 variants around the dominant compiler
residual.
`bottom-entry-shape-mutations.json` evaluates eight nested, independent,
defaulted, switch, and repeated-entry forms. The greater-first nesting is
byte-neutral, while duplicating the complete entry construction regresses
sharply; none restores the native unfused pale/blue/pale ladder. Its SHA-256 is
`ef601c16d6e7ab3cd54bf575c83d0e99f09eca650a464d073eaaa6cf21f63faa`.
The retained late-gray-first comparator ordering is distinct from that sweep's
global default-and-middle-override form and recovers the complete ladder.

`arithmetic-epilogue-mutations.json` exhausts all 11 single-site and 30
two-site combinations of equivalent negative-trigger spellings and output
pointer forms. All 41 are byte-identical to the baseline, ruling out AST
spelling and their interaction as controls for the native `add -5000` and
final `ecx` allocation. Its SHA-256 is
`8b841b0ad44299e42ec85d1fcab0525d074b829331f4aeb42b0bee81821f2e34`.

`template-condition-lifetime-mutations.json` tests four named-boolean forms
around the pale/blue/pale template ladder. Naming the early and late bounds,
separately or together, is byte-neutral; naming the complete middle range
regresses to 64.74% and shortens the exact prefix to seven instructions. The
complete four-variant sweep has SHA-256
`e07cc77e1f691b983c51bb30214917f83dc472ed677b479b2524c1dc5623b0cc`.
VC6's equal-arm folding is therefore not controlled by an elided condition
temporary.

## Native template-arm ordering

Live Binary Ninja disassembly at `0x00437e47` shows the exact missing sequence:
an early gray store and jump, a `wave >= 10` gray store and jump, then the blue
fallback. Spelling the second source condition as `wave >= 10` is sufficient
for VC6 to retain all three stores and both jumps. An inlined whole-selector
helper and an independent later-wave `if/else` both fall back to the older
84.34%, 82-instruction form and are rejected.

## Recovery classification audit

Fresh Binary Ninja HLIL confirms the complete wave range, template ladder,
off-screen additions, wave-ten midpoint pair, trigger arithmetic, clamp, and
output count. The candidate emits 84 instructions against 84 native instructions
and its sole masked reference resolves. The localized differences are one
equivalent negative-offset opcode choice and the final output-pointer register
allocation; recovery is `semantic-complete` with a `compiler` residual.
