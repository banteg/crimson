# Reusable C2 trace validation

The generalized commands preserve whole COFF objects for a timeline residual,
an exact C function, and an exact C++ network worker. Repeating the same source
produces equal comparison signatures, and a source-expression variant produces
a detected difference. No new source match is claimed.

| Frozen input | Events | Whole COFF preserved | Native acceptance |
| --- | ---: | --- | --- |
| `quest_spawn_timeline_update` | 116 | Yes | Partial, 13 clean references |
| Same timeline source, separate capture | 116 | Yes | Same partial |
| `plaguebearer_spread_infection` (C) | 74 | Yes | Exact encoded body |
| `statistics_update_check_worker` (C++) | 296 | Yes | Exact encoded body |
| C control plus separate integer helper | 102 | Yes | Original C body remains exact |
| Timeline with relative heading expression | 116 | Yes | Diagnostic variant |

The changed expression replaces `entry->heading` with
`((float *)template_id)[-1]` on the same source line. Its first observed signature
difference is at hook 0, before C2 routine RVA `0x130cb`, with 154 nodes on each
side. Equal node counts alone would miss the operand/temporary difference.
This locates an observation, not a unique causal explanation of the native gap.

Every successful run checks ordinary compilation, wrapped compilation, standalone
replay, and observed replay for whole-object equality except the timestamp,
and checks native metrics independently. A missing expression stream must fail
without producing an object. A deliberately wrong first CALL destination is
rejected with exit code 95 before backend execution and produces no replay object.
A separate C control appends an externally visible integer helper and exercises
two emitted functions in one trace; function ordinals and per-hook occurrences
keep their events separate.

The initial repeat test exposed address noise: temporary descriptor `+0x0c`
contains an arena pointer at early passes, before its later priority role.
The comparison now excludes descriptor values before the allocation hooks;
raw early words remain available for inspection. The recorded successful repeat
includes separate captured streams and processes, rather than self-comparing
the same JSON file.

```sh
uv run python tools/match/evidence/c2-trace-generalization-2026-09-13/verify.py \
  --out /private/tmp/c2-validation
```

[results.json](results.json) contains each run's provenance/metrics and both
comparisons. Full raw traces, frozen sources, helper executables, and objects
are generated under the chosen output directory; they are not checked into Git.
The test suite additionally rejects malformed binary records, digest changes,
unknown layouts, changed constant payloads, changed temporary relationships and
allocation costs; it checks address rebasing and recycled function addresses.

See [the reusable tracing guide](../../c2/README.md) for coverage and limitations.
