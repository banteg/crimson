# `fx_queue_render`

Native target: `crimsonland.exe` at `0x00427920` (2076 bytes).

Live Binary Ninja evidence recovers the terrain FX queue consumer. When the
terrain render target is available, it draws queued ground decals into that
target, renders corpse shadows and color sprites in separate blend passes,
clears both queues, and restores the backbuffer. If terrain rendering failed,
only the corpse queue is drawn directly in camera space. That fallback returns
without clearing either queue; the source preserves this native asymmetry.

The four `render_scratch_f*` stores are real shared globals, not artificial
ordering aids. Their exact source shape is two adjacent 2D vector temporaries:
native copies the atlas origin into the first, constructs the opposite corner
with the vector `operator+`, and reuses the first vector for shadow positions.
The same small value-type constructor/operator idiom independently produces an
exact match in `effect_spawn`, and other overlay render paths reference this
same address range.

The recovered source is an exact `msvc6.5 /O2 /GB` match: 543/543 instructions,
2076/2076 bytes, and 162/0/0 audited references. The validator accepts the
source without volatile accesses, artificial references, dead expressions, or
register/order constraints.

## Freeware

In 1.0.2 and 1.3.0, safe mode returns before drawing. In the terrain pass,
shells are drawn before the two corpse passes, which write 0.5 and 0.99 back
to the queue's alpha field. The generic impact pass first appears in 1.3.0.
1.4.0 adds screen-space corpses in safe mode, draws terrain corpses before
shells, and preserves the queued alpha for the color pass.

The blood decal subtracts a two-component half-size from its position.
Constructing the two atlas corner coordinates as a vector value also
reproduces VC6's stores to the shared drawing scratch.
