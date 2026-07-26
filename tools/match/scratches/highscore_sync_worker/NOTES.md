# `highscore_sync_worker`

Native target: `crimsonland.exe` at `0x0042d0e0` (1970 bytes).

Work in progress: 60.69% normalized match, 19/519-instruction exact prefix,
519 candidate instructions, and 102/0/0 reference audit. The candidate also
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
