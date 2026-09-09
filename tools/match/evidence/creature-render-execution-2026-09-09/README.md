# Bounded creature-render execution audit

The 130 recorded scenarios produce identical native/candidate Grim2D observations
and identical writes to creature active flags and spawn-slot owners. Together,
they execute all 765 native and 760 candidate instructions. Four deliberately
incorrect temporary candidates are detected. No matching source changes follow
from this audit: `creature_render_type` remains **79.74%**, `139/0/5` references,
and neither normalized-exact nor encoded-body-exact.

[verify.py](verify.py) executes the original Windows x86 body and the current VC6
COFF candidate in separate Unicorn instances. Both start from the same mapped PE,
fixture data, stack contents, and x87 control word. Candidate references are
relocated from COFF records: defined symbols address their own loaded sections;
external symbols must resolve uniquely through the existing reference catalog.
The loader does not translate candidate instructions into native instructions or
use fuzzy alignment to drive execution.

The observer records every invoked Grim2D operation in order. Float arguments
are compared as their exact 32-bit words, with no tolerance; color pointers are
read at the call. Configuration IDs 19 and 20 compare the ID and first value word,
which are the fields consumed by the exact
[`grim_set_config_var`](../../scratches/grim_set_config_var/scratch.cpp) branches.
The other three value words are uninitialized by the recovered constructor and
are not read by those branches. Virtual calls model the recovered `__thiscall`
stack cleanup and overwrite caller-saved integer registers and flags. The perk
query records its argument and returns the scenario's specified count. The
original 39-byte `crt_ftol` executes unchanged, including its rounding-mode
save and restore.

The fixture covers the combinations of shadows, flash rendering, Monster Vision,
type animation flags, four Energizer levels, and 24-bit/64-bit x87 precision.
Each of the 128 main scenarios contains 66 records covering animation flag
combinations, lifecycle boundaries, health and flash thresholds, inactive and
other-type filtering, and the final pool slot. Two additional negative-phase
cases exercise the signed-remainder paths; those inputs are diagnostic and do
not establish that normal gameplay produces negative animation phases.

Fixture offsets and sizes are independently compiled from the current shared
headers before execution. Setup values are checked after all writes, preventing
an overlapping fixture from silently changing a requested scenario. During
execution, writes outside the stack, creature active bytes, or 32 spawn-slot
owner fields fail the audit. Unknown virtual slots, unexpected execution,
instruction/time limits, changed x87 control words, unbalanced stacks, and
clobbered callee-saved registers also fail.

The four negative controls verify that the observer notices different kinds of
errors:

| Temporary defect | Detected difference |
| --- | --- |
| Shadow opacity changed from 0.4 to 0.41 | Drawing argument bits |
| Last pool slot omitted | Drawing call sequence |
| Spawn-slot release removed | Global writes |
| Second flash draw removed | Drawing call sequence |

This is finite behavioral evidence, not a proof of equivalence or a new exact
match. Instruction coverage does not cover every path, input, interleaving, or
floating-point value. The modeled observers do not execute the GPU, full Grim2D
state machine, or actual perk-table lookup. The remaining static byte and
reference differences are still unresolved.

## Reproduce

From the repository root, with optional `unicorn==2.1.4` available:

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/creature-render-execution-2026-09-09/verify.py \
  --out /private/tmp/crimson-creature-render-audit
```

On macOS the process needs permission to allocate executable memory for Unicorn;
a sandbox that forbids JIT memory can terminate it during `mem_map`, before any
emulated game instruction executes. The dependency need not be added to the
project's dependency declarations.

[results.json](results.json) records the image, source, object body, verifier,
compiler-file and generated-case hashes; compiled fixture layout; complete
instruction coverage; relocated object references; per-scenario observation
hashes; and negative-control outcomes. The generated `cases.json` in the output
directory contains every concrete scenario. The Unicorn Python API follows the
[upstream tutorial](https://www.unicorn-engine.org/docs/tutorial.html).
