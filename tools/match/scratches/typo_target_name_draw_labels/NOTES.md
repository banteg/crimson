# typo_target_name_draw_labels

Native target: `crimsonland.exe` at `0x00445600` (434 bytes, 111
instructions).

MSVC 6.5 `/O2 /GB` reproduces the function exactly:

```txt
match=100.00% prefix=111/111 target_insns=111 candidate_insns=111 refs=20/0/0
```

## Recovered source shape

- Rendering begins with opaque white text color and Grim config slot 24 set to
  `0.5f`.
- Parallel pointers walk all 384 creature records and 64-byte Typ-o name slots.
  Only active creature records are rendered.
- Label alpha is `1.0f` for nonnegative lifecycle stages. Negative stages use
  `(stage + 10.0f) * 0.1f`, clamped to `[0, 1]`.
- Text is centered on `camera_offset + creature.position`; its baseline is 50
  pixels above the creature. The black background begins four pixels left of
  the text, is eight pixels wider than the measured label, is 15 pixels high,
  and uses `alpha * 0.67f`.
- The foreground text is white with the unclipped label alpha.

The loop retains the native lifecycle-field induction cursor, but now derives
its containing `creature_t` with `offsetof(creature_t, lifecycle_stage)`.
Named `active`, `pos_x`, and `pos_y` accesses replace the former cursor-relative
cast and float indices. A shadow probe confirmed that the recovered type view
still emits the exact 111/111 instructions with all 20 references aligned.

Two local vector values are essential source evidence. One retains the centered
text position while the other receives the background origin through its
ordinary `set` method. Modeling x and y as unrelated scalar locals lets VC6
reuse the measured-width stack slot and retain y on the x87 stack, producing a
109-instruction equivalent. The paired vector objects recover the native stack
layout and copies exactly.

Likewise, assigning lifecycle alpha with a conditional expression before the
upper/lower clamp recovers the native float store/reload and shared `1.0f`
block. Directly nesting the clamp inside the negative-stage branch is
semantically equivalent but folds one x87 instruction. No volatile state,
dummy work, artificial dependencies, or forced addresses are used.

## Port parity

The Python and Zig renderers already preserve the centered label position,
50-pixel vertical offset, four/eight-pixel background padding, 15-pixel height,
0.67 background multiplier, and lifecycle fade. They intentionally skip empty
or effectively transparent labels and apply runtime viewport/entity scaling;
those are presentation-safe generalizations of the fixed-resolution native
renderer, so no port edit is required.
