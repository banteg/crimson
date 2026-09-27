# Plague draw scheduling without the ID pad

The [earlier ID/window experiment](../projectile-id-window-2026-09-28/README.md)
isolated K9, but tested its fixes on an artificial ID pad. The scheduling
correction also works independently on the canonical source. Parenthesizing
all ten initial-plague draw coordinates and both stored trig expressions
raises `projectile_render` from **97.746852% to 97.846256%**. It remains
non-exact: 3,015/3,021 instructions, prefix 1,322, frame 412 bytes, and
544/0/0 references. No pad or compiler intervention is retained.

The additional FROUND nodes move C2's 81-node scheduling boundary, as established
by the earlier trace. The remaining `push 62.0f; push ecx` pair now precedes
`fld st(0); fsin`, matching native. The corresponding sine spill uses `[esp+0x20]`
instead of `[esp+0x18]` because those arguments are already on the stack.

## Verification

[verify.py](verify.py) freshly compiles the source at `39f6d6465` and the retained
source, using the unmodified MSVC 6.5 profile. [results.json](results.json) records:

- Only the 24-byte candidate interval `+0x2510..+0x2528` changes. Every byte and
  relocation outside that interval is identical between the two compilations.
- That interval matches native `0x42518c..0x4251a4` byte for byte after resolving
  its single verified DIR32 reference to `camera_offset.y`. Its location is
  12 bytes early because the ion arc is still short by six instructions.
- The old schedule, wrong stack displacement, and wrong relocation identity
  are rejected by the same comparison.
- All **192 native/before/after execution cases** agree on complete call
  arguments, pool state and writes. Cases cover both x87 precisions, initial
  and fading plague lifetimes, pool endpoints, inactive/noncanonical active
  bytes, mixed conventional draws, alpha values and glow settings. The shared
  harness checks stack, callee-saved registers, x87 state and allowed writes.

These are finite caller-level checks with recording external-call contracts;
they do not establish GPU output or arbitrary-input equivalence.

The uniform coordinate-only control regresses to 97.614314%; adding parentheses
to all angle definitions gives 97.680583%. Coordinates plus stored trig values
give the retained result; including all angle parentheses as well emits the
same retained body. This supports the window-boundary explanation rather than
a change to the arithmetic itself.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/projectile-plague-schedule-2026-09-28/verify.py \
  --out /tmp/projectile-plague-proof
```

K6/K7's ion operand ordering and K8's resulting scheduling difference remain.
`quest_spawn_timeline_update` and `player_update` are unchanged.
