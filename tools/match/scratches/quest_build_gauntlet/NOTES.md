# `quest_build_gauntlet`

Native target: `crimsonland.exe` at `0x004369a0` (614 bytes).

Live Binary Ninja evidence recovers three phases and a temporary hardcore-mode
state adjustment. Hardcore mode adds four to the global player count before
building and subtracts four again on every return path. The phases are:

- `player_count + 9` template `0x0a` nests on a radius-158 ring centered at
  (512, 512), with triggers starting at 0 and advancing by 200 ms;
- `player_count + 9` four-entry template `0x41` waves at the right, left,
  bottom, and top edge midpoints, in that order. Triggers start at 4000 ms and
  advance by 5500 ms, while counts start at 2 and advance by one per wave;
- `player_count + 17` template `0x0a` nests on a radius-258 ring centered at
  (512, 512), with triggers starting at 42500 ms and advancing by 500 ms.

Both rings use `index * 6.28318548 / active_count`; separate cosine and sine
field assignments reproduce the native x87 strategy of retaining the numerator
while reloading and dividing by the global count twice. The four edge entries
recompute the signed integer width midpoint for every coordinate and use
`width + 64` and -64 as the outer bounds. Heading is left untouched throughout.

The candidate reproduces the exact 182-instruction body, the complete prologue
and hardcore restore paths, and all 26 audited references, scoring 98.35% with
a 120-instruction exact prefix. Separate indexed record expressions recover the
native x87/store schedule throughout all three phases. The only residual is the
middle wave's loop comparison: native and candidate compute the same two values
in the same order but exchange EAX and EBP for three instructions.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## 2026-07-27 focused family pass

Live Binary Ninja reconfirmed both rings, every four-edge wave, and the
hardcore player-count restore paths. MSVC 6.0, 6.5, 6.5 Processor Pack, and
6.6 tie at 80.21978021978022%; 7.0 regresses to 75.06849315068493%.
`/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tie, while `/G6` falls to
79.12087912087912% and shortens the prefix.

`phase-metadata-shape-mutations.json` (SHA-256
`a656d52650447f821bad3097d938fc70364515e55c33386ea0f630a5481d17c2`)
recorded all 21 single and pair sibling-shape variants. Ring setters and
direct fields for every edge entry are all byte-identical, including their
pair interactions. No source change is justified. Validation remains
492.54945054945057/614 weighted bytes, a 121.45054945054943 gap,
182/182 instructions, prefix 31, and references 25/0/0.

## Ring count-advance audit

The first native ring advances its entry induction value inside the x87
window, so `ring-count-advance-mutations.json` (SHA-256
`ae6651814bd7ce51b368bccdddfc4703a808e09fc13447c34174f8897f587e73`)
tested moving the semantic count update before metadata in either ring and in
combination. The inner change lost 129.196 weighted bytes and 21 prefix
instructions; the outer change lost 48.451 weighted bytes; the pair lost
130.189. These are decisive negatives, so the source remains at 80.2198%.

## 2026-07-29 indexed-record and loop-schedule pass

The syntax-terror recovery exposed the missing source distinction: retaining a
record pointer lets VC6 hoist metadata stores into x87 conversion windows,
whereas separate `spawns[entry_count]` expressions delay them until each
coordinate pair is complete.

`indexed-ring-record-mutations.json` (SHA-256
`68264d00ea59540bc62ad0bfe6afe78a9b4568e0e359c487402c4b5231b3125e`)
evaluated both rings independently and together. The pair raised the score from
80.2198% to 85.7143% and extended the exact prefix from 31 to 66 instructions.
`indexed-edge-wave-record-mutations.json` (SHA-256
`59c9d787519882dd6d416aa6af3eac01dc4e1854ea6360b215c6bcdde1662c23`)
then tested both setter and direct-metadata forms for all four edge records.
They are byte-identical and raise the score to 97.2527%, with a 120-instruction
exact prefix.

The outer ring needed one independent source-order correction.
`remaining-loop-shape-mutations.json` (SHA-256
`ee6aee3c60e1743bdc59593b4c6363c427bed97d8e9883f63274c36c29cfca4a`)
exhausted all six orders of the entry, ring, and trigger advances. Advancing the
entry and ring indices before the trigger recovers the complete outer ring and
raises the retained score to 98.3516%.

Only three operand bytes remain different at the edge-wave backedge. The target
emits `lea ebp,[edx+9]; lea eax,[edi-2]; cmp eax,ebp`; the candidate emits the
same operations with EAX and EBP exchanged. The following recorded families
bound this as register allocation rather than missing semantics:

- `wave-condition-register-mutations.json` (SHA-256
  `1d6be3fb864ba79420063b709206bcc35906069b2103c8c269bb8252f2f2469e`)
  evaluated 59 algebra, relation, and following-local declaration variants;
- `wave-loop-control-mutations.json` (SHA-256
  `6d44ff8a6cd79a88e4c308d1ff41cfaa8c5ed441e03d2861c08a28c126ec9cce`)
  evaluated 17 structured bottom-check variants;
- `wave-condition-local-mutations.json` (SHA-256
  `c51169eb2f62a4e8fdcbabfc221f9e622c2570f0662089bc1a68b070e5974cdd`)
  evaluated 14 named-limit/index declaration and assignment variants;
- `wave-condition-increment-mutations.json` (SHA-256
  `442686d6756bc31db51df90c0b915a02e9e6ee88fcd0ea47c5ff285c96fbb19c`)
  evaluated five preincrement, postincrement, and comma-update forms;
- `wave-goto-backedge-mutations.json` (SHA-256
  `62fd933e8cebcf425bcab1aaf9d55005364abd57c6fdd81efc73b5ea9ab4e7d4`)
  evaluated the equivalent explicit labeled backedge;
- `indexed-ring-metadata-mutations.json` (SHA-256
  `a4da624fc5bcf999c1df4ec97654aa581cef9041748c28a317adbd06a796fb8c`)
  confirmed both ring setter forms are byte-neutral.

None changes the remaining three instructions. MSVC 6.0, 6.5, and 6.6 also
remain byte-identical at 98.3516%; `/GB`, `/G5`, `/G7`, `/Ox`, `/Ob1`, `/Ob2`,
`/Og`, and `/Ot` tie, while the processor-pack, `/G6`, `/Os`, and VC7 profiles
regress. The retained source therefore stops before artificial dependencies or
register forcing.
