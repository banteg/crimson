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
match=58.59% prefix=23/3159 target_insns=3159 candidate_insns=2716 refs=311/1/2
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
