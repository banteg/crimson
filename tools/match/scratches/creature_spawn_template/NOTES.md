# creature_spawn_template WIP

Initial scope:

- shared root creature initialization
- random heading sentinel handling
- formation ids `0x11..0x19`
- spawn-slot controller ids `0x07..0x0e`, `0x10`
- random/stat template ids `0x03..0x06`, `0x1a..0x20`, `0x2e`,
  `0x31..0x36`, `0x3d`, `0x41`
- fixed-stat/special ids `0x00`, `0x01`, `0x0f`, `0x21..0x2d`,
  `0x2f`, `0x30`, `0x37..0x3c`, `0x3e..0x40`, `0x42`, `0x43`
- unhandled-template fallback for `0x11` and `0x13`
- shared post-dispatch tail modifiers

Known missing work:

- tighter local/field ordering in the dispatch ladder
- the `0x13` chain formation is now in the native ladder slot, but its body
  still differs in local ordering
- tail modifier ordering/codegen still diverges after the large dispatch

Keep tracking prefix, not just total match percent. This scratch is expected to
be low percentage until more template families are added.

Current local score:

```txt
match=59.31% prefix=23/3159 target_insns=3159 candidate_insns=2719 refs=315/0/2
first_target=lea esi, dword [ebp+edx*2]
first_candidate=mov dword [esp+0x14], edi
```

Frame/prefix notes:

- The source now reproduces the native `0x48`-byte stack frame.
- Moving the saved position pointer below the random-heading sentinel improved
  the prefix from `1/3159` to `20/3159`.
- The first blocker is now root-slot address arithmetic versus reloading `pos`
  from the stack.
- The Wibo-backed compile path makes this scratch practical enough to iterate
  on medium-size case families; the random-stat block added a large body match
  without moving the prefix.
- Moving the `0x13` chain formation ahead of the grid/fixed-stat ladder improved
  total body alignment from `55.06%` to `57.28%`; the prefix remains blocked at
  the same root-slot address arithmetic mismatch.
- In all four trigonometric child-spawn loops, materializing the allocated
  creature pointer before declaring the angle keeps the angle live on x87
  across the paired `cos`/`sin`, as native does. This removes six candidate
  instructions, raises the score from `58.09%` to `58.42%`, and improves the
  masked-reference audit from `308/1/2` to `311/1/2` without changing behavior.
- The five grid-spawn loops use the native inclusive vertical-offset guard
  `offset <= 0x100`. Replacing the equivalent `< 0x101` spelling recovers the
  native compare/branch tokens and raises the score from `58.42%` to `58.59%`.
- Native clamps the four tint components with the direct two-sided shape
  `if (x < 0) x = 0; else if (x > 1) x = 1`. Recovering that spelling across
  the three randomized template families fixes twelve clamp sites, removes six
  candidate instructions, raises the score to `59.06%`, and improves the
  reference audit to `314/1/2`.
- Binary Ninja and the IDA string inventory both identify `0x00477758` as the
  `"Unhandled creatureType.\n"` diagnostic. Naming that data object in the
  curated map replaces the address-derived scratch placeholder and resolves
  the remaining unknown masked reference (`315/0/2`).
- Binary Ninja's native stack view and the normalized listing show two adjacent
  16-byte tint values: the first formation root uses `[esp+0x38..0x44]`, while
  its child tint occupies `[esp+0x48..0x54]`. Modeling those as contiguous RGBA
  aggregates preserves the exact `0x48`-byte frame. Recovering the first root's
  whole-value assignment adds nine native-shaped construction/copy instructions
  and raises the score from `59.06%` to `59.31%` without changing the prefix or
  reference audit. The later fixed-template ladder also constructs tint values
  at `[esp+0x48..0x54]`, but a broad POD aggregate conversion schedules the
  copies in the wrong order and regresses the score, so that extrapolation is
  intentionally left unresolved.
