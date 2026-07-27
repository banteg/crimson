# highscore_load_table

The recovered loader initializes all 100 records with the native light-reset
sentinels, reads and validates records from the mode-specific path, applies the
Quest hardcore marker and score-load gates, and implements the daily, weekly,
and monthly date filters with the native integer promotions. At capacity it
replaces the mode-specific worst record, sorts all 100 slots with the native
comparator, and promotes the loaded flags either wholesale or by choosing the
best same-name record.

The same-name promotion loop compares every inner record against the fixed
outer record's name, while separately tracking the best score index. Comparing
against the moving best record is behaviorally equivalent because a best record
can only be selected after a successful same-name comparison, but it lets VC6
coalesce the outer and best byte offsets. Restoring the fixed outer name
naturally recovers the native fourth stack local and exact `0x58` frame.

## Native-grounded mutation sweep

Fresh Binary Ninja output for `highscore_load_table` at `0x0043afa0` confirms
five separate 72-byte copies at `0x0043b205`, `0x0043b249`, `0x0043b276`,
`0x0043b299`, and `0x0043b2b8`. The old source SHA-256
`28a1685a07e931f9e477e7dd4f62d1deb46e5f483d074ebb0eb54e17a6424d99`
tail-merged four of those copies and matched 77.08%, with 344/354 instructions,
a 67-instruction prefix, and `55/0/0` references.

`copy-exit-mutations.json` records seven complete native-shaped singles:

- direct append with a precomputed published count: 82.37%, 355 instructions,
  67-prefix, `56/0/0`;
- scoped duplicate pointer, capacity `else if`, and scoped append pointer:
  byte-neutral at 77.08%;
- scoped worst pointers: 76.97%;
- zero-first duplicate `if`/`else`: 76.79%;
- capacity `switch`: 58.17% and one reference mismatch.

Because the direct append single improved, the same plan evaluated all 16
two-site interactions. The aggregate winner combined the zero-first duplicate
branch with the append rewrite and scored 87.17% with a 159-instruction prefix,
but it was rejected after localized inspection: VC6 inverted the native
`je 0x0043b20c`, laid the duplicate copy after the Rush arm, and reduced clean
references from 55 to 52. The append-only shape instead preserved the native
lookup branch and restored all five copies in their native order.

`append-order-mutations.json` then evaluated four complete singles against that
82.37% baseline. Copy-then-count and postincrement-then-publish tied at 96.33%,
354/354 instructions, a 261-instruction prefix, and `57/0/0` references.
Postincrement with an early published count was byte-neutral at 82.37%;
preincrement tail-merged the copies again and regressed to 77.08%. The source
retains the clearer tied winner:

```c
highscore_table[count] = stored;
count++;
highscore_table_count = count;
```

The retained source SHA-256 is
`0c3842a90f4b05f5359b81b17731195e0803342a5ffb10c25de170ed2c81f739`.
The mutation-plan SHA-256 values are
`d4e1e864403fbc49aa43b3b16b15af4117b2ec8bed255863e7c3744614df99fc`
and
`db2faf5dbba854f620a30af9bf9111f112d3cb9bbee17dfddd03b06019b1300d`;
the three complete records are in `experiments.jsonl`, whose SHA-256 is
`37ce30f56841ace59bee924d6ed334f3770a8a93cfb492ccb35f642e690224c6`.

The scratch remains `semantic-complete` with a `compiler` residual. The only
two mismatch regions now begin at native `0x0043b340` and `0x0043b3a5`, inside
the already recovered same-name promotion loop. They are register/lifetime and
instruction-scheduling differences: the target uses `edx`/`ebp` for the inner
index/byte offset while the candidate uses `ebp`/`edi`. No volatile state,
byte-offset locals, or artificial dependencies were added to force those
compiler choices.

## Same-name loop exact match

Live native IL shows the initial best-record index being saved before either
outer-record flag test. `same-name-loop-lifetime-mutations.json` evaluated that
ordering, split and compound gate spellings, declaration ordering, and their
interactions. Moving only `best = index` before the existing compound gate is
exact: 1198/1198 bytes, 354/354 instructions, and `59/0/0` references.
Reordering the declarations alone was byte-neutral. The retained move is
behavior-preserving because skipped records never consume `best`.
