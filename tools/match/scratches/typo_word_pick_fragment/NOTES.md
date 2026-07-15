# typo_word_pick_fragment

Native target: `crimsonland.exe` at `0x00444f70` (356 bytes, 117
instructions).

MSVC 6.5 `/O2 /GB` reproduces the function exactly:

```txt
match=100.00% prefix=117/117 target_insns=117 candidate_insns=117 refs=54/0/0
```

## Recovered source shape

- The normal word pool has 51 entries. A nonzero argument expands the random
  modulus to 52 and makes the final `"the"` entry reachable.
- One `rand()` draw is reduced with signed remainder and dispatched through a
  dense switch table.
- Cases 0 through 38 and 40 through 51 return the recovered literal table in
  order. Index 39 intentionally has no case and reaches the default
  `"nerd"`; out-of-range remainders share that default.
- The full ordered table is `lamb`, `gun`, `head`, `tail`, `leg`, `nose`,
  `road`, `stab`, `high`, `low`, `hat`, `pie`, `hand`, `jack`, `cube`, `ice`,
  `cow`, `king`, `lord`, `mate`, `mary`, `dick`, `bill`, `cat`, `harry`,
  `tom`, `fly`, `call`, `shot`, `gate`, `quick`, `brown`, `fox`, `jumper`,
  `over`, `lazy`, `dog`, `zeta`, `unique`, `nerd`, `earl`, `sleep`, `onyx`,
  `mill`, `blue`, `below`, `scape`, `reap`, `damo`, `break`, `boom`, `the`.

The direct switch recovers the native prologue, modulus selection, jump table,
case ordering, literal references, and return blocks without layout helpers or
artificial constructs.

## Port parity

Python and Zig already use this exact ordered table, select modulus 51 or 52
from the prefix-capable flag, tag the single random draw at this call site, and
preserve the explicit index-39 `"nerd"` fallback. No port edit is required.
