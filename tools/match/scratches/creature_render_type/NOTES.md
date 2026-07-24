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
