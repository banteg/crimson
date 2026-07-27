# `highscore_sync_worker`

Native target: `crimsonland.exe` at `0x0042d0e0` (1970 bytes).

Work in progress: 66.99% normalized match, 26/519-instruction exact prefix,
517 candidate instructions, and 107/0/0 reference audit. The candidate also
reproduces the native `0x160`-byte frame.

Live Binary Ninja evidence recovers the complete upload/download worker:

- it snapshots and later restores the active `0x48`-byte high-score record,
  drives `online_sync_status`, reloads the table around synchronization, and
  preserves the native 20 ms batch / 300 ms interactive delays;
- it builds the `42 48 f3 85` binary request header, selected-name/full-version
  gate, quest and mode bytes, and appends eligible packed `0x40`-byte records;
- it posts the native octet-stream header to
  `scores.crimsonland.com/scoring_v2_7.php` using the 10-entry MIME list,
  guest credentials, WinINet flags, and context `0x1289`;
- it reads in `0x400`-byte chunks with the native `0x8000` overflow guard and
  reports both Win32 and WinINet response errors on failure;
- it accepts response magic `0x15`, adds the two count bytes, validates exactly
  `count * 0x44` payload bytes, marks each received record active, stamps its
  hardcore marker, and saves it with the preserved native tail sentinels;
- invalid magic logs response diagnostics but still follows the native success
  path, whereas a read error or invalid record length follows failure cleanup;
- every request, connection, and session handle is closed after deleting the
  response buffer, and all terminal console/status transitions are present.

The remaining mismatch is compiler shape rather than missing behavior. The
native frame places the reused 64-byte host/path slot below the MIME array,
lowers both strings into individual stores, field-anchors the submit iterator,
keeps `InternetReadFile` results in `EAX`, and tail-merges several failure
messages. MSVC gives the typed candidate the opposite array-slot order, literal
block copies, a base-anchored record iterator, and different scalar stack-slot
reuse. Natural initializer, scoped-buffer, pointer-loop, read-loop, branch, and
declaration-order variants were tested; the retained source has the exact body
instruction count and best honest score without byte-spelled literals,
volatility, padding, fake references, or artificial register constraints.

## Recorded record-cursor mutation sweep

Fresh evidence came from live Binary Ninja target
`3023:2:9499448411019345244`. The complete native disassembly has SHA-256
`ba9d4e6ad1222ac5eabd912d7cb69fade344a46e23b4b76d02fdc96b97ef0b3c`;
the corresponding decompilation has SHA-256
`b791395bf0964966d477a05b889c39062695e8903ee49191a345b0be5e0ba238`.
The baseline source SHA-256 is
`77fcf23d24c9742dc5cf070eb58a0c810cb714d00e59e158ea1ea39aedf5bb86`
and reproduces **60.6936%**, gap `774.3353`, 519/519 instructions, prefix
19, and references `102/0/0`.

`record-cursor-mutations.json` is a schema-1, two-site specification covering
three submit-record cursor forms and four received-record destination or
decrement forms. Its SHA-256 is
`f03344176b4b46b86c0a57eaf6da54862cdd82a64452a2ca2ccad69b94d4f047`.
A recorded `--max-changes 1 --max-variants 7` sweep evaluated all 7/7 singles
without truncation:

| rank | source shape | match | gap | candidate/native | prefix | refs |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | branch-local flags pointer | 60.6936% | 774.3353 | 519/519 | 19 | `102/0/0` |
| 2-5 | receive reference, predecrement, and inside/outside pointers | 60.6936% | 774.3353 | 519/519 | 19 | `102/0/0` |
| 6 | submit record-pointer induction | 60.5010% | 778.1310 | 519/519 | 19 | `102/0/0` |
| 7 | submit record plus flags induction | 60.5010% | 778.1310 | 519/519 | 19 | `102/0/0` |

The complete record is in `experiments.jsonl`, whose SHA-256 is
`d2acf2e74207bc00fd9d3cacef20c3469f904d2617ca4e50f46a225b5cfc209d`.
No single improved, so no interaction sweep was run.

Native submit iteration at `0x0042d31c..0x0042d3b2` is explicitly anchored
at `&highscore_table[0].flags`: it loads the byte through `[edi]`, recovers the
owner with `lea esi, [edi-0x44]`, and advances the field cursor by the proven
`0x48` record size. Merely naming a branch-local flags pointer optimizes back
to the current candidate byte-for-byte. The two natural pointer-induction
forms still lower as base-record iteration and each loses 3.7958
fuzzy-weighted bytes, so neither supplies the native owner-recovery shape.

Native receive iteration at `0x0042d6df..0x0042d72e` computes the stack record
address before the 17-dword copy, pushes that address, performs `rep movsd`,
sets the two tail bytes, and calls `highscore_save_record`. Named pointer and
reference spellings, including declaration inside or before the loop, all
compile identically to the retained source; folding the decrement into the
condition is also byte-neutral. These are decisive compiler-shape negatives,
not missing semantics. The scratch therefore retains its original source and
remains `semantic-complete` with a `compiler` residual, without raw owner
offsets, dummy aliases, volatility, fake arithmetic, assembly, or register
forcing.

## Follow-up request/receive stopping audit

After the HUD and Quest priority passes reached stopping points, a bounded
live Binary Ninja audit revisited the largest worker mismatch region at
`0x0042d3cc..0x0042d5eb`. Native retains the `InternetOpenA`,
`InternetConnectA`, `HttpOpenRequestA`, and `HttpSendRequestA` sequence, the
bytewise `scores.crimsonland.com` and `/scoring_v2_7.php` setup, and the
`InternetReadFile` loop with `0x400` chunks and the `0x8000` response guard.
The source already contains the same request and receive behavior; its natural
string initializers and stack-slot order account for the localized compiler
shape. No new source discrepancy or honest mutation site was found, so the
scratch remains unchanged at `1195.664739884393/1970` weighted bytes
(`60.69364161849711%`), gap `774.3352601156071`, 519/519 instructions, prefix
19, and `102/0/0` references.

## Native correction and bounded mutation wave

The next live Binary Ninja pass kept target
`3023:2:9499448411019345244` at `0x0042d0e0` and inspected the native startup
(`0x0042d120..0x0042d1c7`), submit loop
(`0x0042d304..0x0042d3b2`), request/read block
(`0x0042d3c8..0x0042d648`), response-save loop
(`0x0042d655..0x0042d798`), and cleanup
(`0x0042d7a1..0x0042d89c`). The native disassembly and decompilation hashes
remain
`ba9d4e6ad1222ac5eabd912d7cb69fade344a46e23b4b76d02fdc96b97ef0b3c`
and
`b791395bf0964966d477a05b889c39062695e8903ee49191a345b0be5e0ba238`.

Three complete recorded sweeps produced retained, natural source changes:

- `scalar-declaration-order-mutations.json` moved the already-computed HTTP
  header length after the other scalar declarations. This recovered
  `11.387283236994335` weighted bytes, extended the exact prefix from 19 to
  26 instructions, and moved the first mismatch from byte `0x48` to `0x63`.
- `read-loop-control-flow-mutations.json` changed the chunk reader to the
  native-shaped conjunctive loop. The retained form tests the `0x8000` bound
  before the zero-byte stop, as native does at `0x0042d5a1..0x0042d5d7`.
  This recovered another `14.006687176976357` weighted bytes and four audited
  references. The two natural condition orders compile byte-identically.
- `received-hardcore-marker-lifetime-mutations.json` exposed a real semantic
  imprecision. The port had snapshotted `config_hardcore` once before saving
  all received scores, but native reloads it at the loop target
  `0x0042d6e6` for every record. Moving the typed marker computation into the
  loop before the copy both restores native behavior if configuration changes
  concurrently and recovers `98.61310437345105` weighted bytes. All four
  per-iteration forms improved by at least `94.81001557036234`; the retained
  form follows native statement order.

The resulting source SHA-256 is
`1522a2a7f83539d750664c6252e41b49ea4e413483d5b485c1b48e46a37b7441`.
It produces `1319.6718146718147/1970` weighted bytes
(`66.98841698841699%`), gap `650.3281853281853`, 517/519 instructions,
prefix 26, and references `107/0/0`. Against the wave baseline this is
`+124.00707478742174` weighted bytes (`+6.294775369919881` percentage
points), with the gap reduced by the same `124.00707478742174` bytes.

All 12 mutation plans were recorded in a 12-line `experiments.jsonl`
(SHA-256
`0638ddca4ebd454771ff3a0b32817d9570235480a2aaafbab21b01d420f81e48`).
The complete 134-variant evidence is:

| plan | variants | result | SHA-256 |
| --- | ---: | --- | --- |
| `record-cursor-mutations.json` | 7 | neutral or worse | `f03344176b4b46b86c0a57eaf6da54862cdd82a64452a2ca2ccad69b94d4f047` |
| `network-buffer-init-mutations.json` | 15 | all zero/copy forms worse | `ebbf713860d4f8234a94245d2dd06a9aa5d89954571440eb95731b0e0e49d30a` |
| `scalar-declaration-order-mutations.json` | 12 | retained improvement | `35c689bc5b19047149a485413d5d1376415f848072728427623056c70cbd7189` |
| `accept-array-lifetime-mutations.json` | 5 | neutral; removal invalid | `ab1f052c1da135055c8eb42b66a783767949bccbc7b9bc4ccde93b44fa87a954` |
| `network-failure-tail-mutations.json` | 63 | no win; shared labels rejected by C++ initialization rules | `a5fba65376ab97e1e01521e31ba55a40eb875bd82ce3b4599209c3144d5ed073` |
| `handle-initialization-shape-mutations.json` | 5 | byte-neutral | `b26fb025ef82cd2e53272f0628ab516768f5e57340b7a968a5513ff0bbade3e3` |
| `score-count-lifetime-mutations.json` | 5 | valid pairs neutral | `2f7b50f3861125386c8ce34b07bd1f7d7294b1b0720f389a578439643c4aa050` |
| `server-address-lifetime-mutations.json` | 5 | neutral or worse | `74e287f51b3e0fe5e4abd470e47f1dd53d8eaeb24df4b2447ec3f4370cd3bc3d` |
| `read-loop-control-flow-mutations.json` | 3 | retained improvement | `41dccc90a6b3164c04559336c51f902bd494e562022c1e1ab3f7914e25531b24` |
| `received-hardcore-marker-lifetime-mutations.json` | 4 | retained native correction | `7abc770630ff899c41194623f7dbe0c1c6e0c939e79ec4162263785e72856f01` |
| `cleanup-state-order-mutations.json` | 5 | byte-neutral | `5aee7720dbc89590b677a38e0a1cc2df6789b011eabe47a12502eb896840a561` |
| `received-loop-local-order-mutations.json` | 5 | byte-neutral | `e261301f6dfe17311fea0a70784fb7ac3b8e33910198e80166ca9de5d9704247` |

A compiler/profile matrix also confirmed MSVC 6.5 `/O2 /GB` remains best:
`/G5` and `/Ob1` are identical, `/G6` and 6.5pp regress, the 6.6 alias is
identical, and 7.0 does not compile this scratch. The remaining gap is
localized compiler shape: MIME/host-path stack-slot allocation, bytewise
string lowering, the native field-anchored submit cursor, scalar-slot reuse,
and shared failure tails. The bounded natural forms above either compile
identically or regress, so no artificial aliases, volatility, raw owner
offsets, fake references, padding, or register forcing are retained.
