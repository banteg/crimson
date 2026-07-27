# `creature_render_type`

Native target: `crimsonland.exe` at `0x00418b60` (2834 bytes).

Live Binary Ninja evidence recovers the complete per-type creature sprite
renderer. The function binds the selected creature texture, configures its
atlas, and performs up to three 384-entry pool walks:

- An optional detail pass runs when the first effects-detail flag is enabled
  and Monster Vision is absent. It starts from the creature tint at 40% alpha,
  applies lifecycle fading, rotates the sprite by `heading - pi/2`, expands
  its size by 1.07, and offsets each half-extent by another 0.7.
- The main pass either blends low-max-health creatures toward a bright blue
  Energizer tint or copies their normal tint. Its sprite is drawn at the
  creature's native size. Creatures whose lifecycle has fallen below -10 are
  retired; ping-pong creatures also clear their spawn-slot owner.
- The violence-configured pass draws positive hit flashes twice in white. Its
  alpha is `min(hit_flash_timer * 5, 1)` before transition-alpha scaling.

All passes reproduce the two native atlas paths. Ping-pong animation uses
`(int)(anim_phase + 0.5) % 16`, reflects frames above seven, and adds the type's
base frame plus 16. The other path uses the lifecycle countdown below 16,
otherwise rounds the animation phase, reflects long type animations above
frame 15, and adds 32 for ranged-attack shock creatures. Transition alpha,
batch boundaries, render-state changes, camera offset, tint clamps, and all
four quad submissions are accounted for.

The current honest VC6.5 result is 78.45% with the exact native 0x3c-byte stack
frame, 757 candidate instructions versus 765 target instructions, a
25-instruction exact prefix, and references `136/0/5`. The adjacent camera
coordinates are the two fields of the native aggregate `camera_offset`;
recording that proven object-level alias resolves the eight formerly
unresolved aligned references without masking any address disagreement.
Repeating the natural
`size * 0.5` expression in both vector-constructor arguments is significant:
VC6 performs the same common-subexpression lowering as native and restores the
0x3c-byte frame; a named half-size local changes both scheduling and layout.
The native-backed `creature_max_health` field cursor and guarded `do` loop also
keep Energizer initialization on its own branch and improve the best result.
That induction cursor is now converted back to its containing `creature_t`
with `offsetof(creature_t, max_health)`. This preserves the exact VC6 output
while replacing every Energizer-path byte offset and float-index alias with
the recovered `active`, `type_id`, tint, animation, position, size, lifecycle,
flags, and spawn-link fields. A shadow probe verified no change to the score,
instruction counts, exact prefix, or reference agreement.

The five native callsites each push a creature type followed by the same
transition-alpha value. Recovering the missing second parameter in Binary
Ninja changes all four internal stack reads from `arg_8` to
`transition_alpha`. In the violence pass, the remaining
`lifecycle_stage[10]` alias lands at creature offset `0x38`, exactly the
recovered `hit_flash_timer` field. Replacing it with that field and dropping
the obsolete cursor is also byte-identical under the matcher.

The remaining mismatch is allocator residue rather than missing behavior.
Native anchors its four walks at lifecycle stage, max health, animation phase,
and lifecycle stage respectively. VC6 rebases the middle walks to type id and
the flash walk to hit-flash timer. Native also keeps each tint pointer in `ebp`
through the corresponding draw, whereas the candidate folds those addresses
into the induction pointer; this removes the native pointer reloads and
explains the eight-instruction length difference.

Natural indexed, pointer, `for`, `while`, and `do` loop shapes were checked,
including the proven lifecycle/max-health/animation symbols and direct flag
reload at retirement. VC6.6 emits the same best backend shape; `msvc6.5pp`
materially regresses the stack frame and floating-point comparisons. No
volatile fields, dummy expressions, fake references, hard-coded addresses, or
artificial register constraints are used, so this remains an evidence-backed
semantic WIP rather than a fakematch.

## Binary Ninja type and control-flow recovery

This 2,834-byte renderer was still timeout-skipped. The durable name-map policy
now restores its 124-block LLIL, MLIL, and HLIL, and its prototype includes the
second `float transition_alpha` argument independently proven by all five
callers and the matching source.

Native anchors its four pool walks at lifecycle stage, max health, animation
phase, and lifecycle stage. Two 0x98-byte Binary Ninja stride views now model
the first, second, and fourth cursors without lying about their interior
addresses. Forward accesses therefore read as `type_id`, `flags`, `tint_*`,
`heading`, `size`, `hit_flash_timer`, and `anim_phase`; the only remaining
negative offsets are fields genuinely located before the native cursor, such
as `active`, position, and lifecycle in the max-health pass. Pointer increments
also decompile as one record because both presentation views retain the proven
0x98 stride.

The analysis/type recovery does not affect code generation: the honest match
remains 78.45%, 757/765 instructions, prefix 25, and `136/0/5` references.

## Flash base-frame shape sweep

A fresh live Binary Ninja read from target
`3023:2:9499448411019345244` bounds a localized violence-pass mismatch to the
ping-pong frame join at native `0x004194eb..0x0041957d`. Native materializes
the Grim interface and vtable alongside the type's base frame before forming
`base_frame + reflected_frame + 16`, then joins the shared atlas-frame call.
The candidate computes the same frame but folds the base-frame load into the
expression and delays the interface load until that join.

The schema-1 spec `flash-base-frame-mutations.json` tests five ordinary
spellings of that base-frame lifetime and addition order. Spec SHA-256 is
`7e5c69cfa8dc086ab187656c9f3029fa3128ea3992a82d8244a50fb90d511d98`;
the tested source SHA-256 is
`8764235bae69d4c6e5601f075daf937b8db7b1fcc5d0c9e2a56ecf431a04412c`.
The recorded sweep evaluated all 5/5 one-site variants without truncation.
Four were byte-identical to the 78.4494% baseline, 757/765 instructions,
prefix 25, and `136/0/5` references. Hoisting the base-frame local before
animation rounding added one instruction and regressed by 0.05151 percentage
points and 1.46 fuzzy-weighted bytes. No single mutation improved, so no
interaction sweep was warranted and the compact current expression remains.

## Semantic-completion audit

Fresh live Binary Ninja HLIL and disassembly confirm all four native pool
cursors and every detail, Energizer, lifecycle-retirement, spawn-owner, and
hit-flash branch. Address-matched IDA and Ghidra snapshots independently agree
on the two-argument signature and the only two direct callees,
`perk_count_get` and `__ftol`. The five aligned-reference mismatches carry no
unresolved target.

Hoisting the tint pointer to function scope and replacing each pointer copy
with a direct aggregate copy both reproduced the exact same 78.45%,
757/765-instruction candidate and `136/0/5` reference audit. The alternate
`msvc6.5pp` profile regressed to 59.67%. These no-op natural source variants
and the already exact `0x3c` frame isolate the remaining eight-instruction
delta to VC6 register allocation and aligned-reference scheduling. The scratch
is therefore classified `semantic-complete` with a `compiler` residual. The
five visible audit mismatches are different induction anchors within the same
proven creature records; no address is hidden with an alias and no independent
source-reference debt remains.

## Cursor-reference audit refresh

A fresh masked-reference audit still has exactly five aligned mismatches, at
native `0x00418eb0`, `0x00419171`, `0x004193d1`, `0x0041945e`, and
`0x00419638`, with no unresolved reference. The first is representative:
native initializes `esi` to `creature_max_health` at `0x0049bf60`, then reads
the active byte at `esi-0x28`, type id at `esi+0x44`, and max health at
`esi`. The current source is already written around that typed max-health
cursor, but the candidate object rebases the same record to
`creature_max_health+0x44`; it consequently uses `esi-0x6c`, `esi`, and
`esi-0x44` for those same three fields.

The other four audit entries are the analogous compiler-selected animation,
hit-flash, and loop-end anchors documented above. Since the candidate object
resolves each address into the same proven `0x98`-byte creature record, and
the existing pointer/index/loop sweeps already reject or reproduce the natural
alternatives, no new source or alias mutation is justified. Metrics remain
78.4494087%, 757/765 instructions, prefix 25, and `136/0/5` references.
