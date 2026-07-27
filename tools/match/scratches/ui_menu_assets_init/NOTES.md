# `ui_menu_assets_init`

Native target: `crimsonland.exe` at `0x00419dd0` (551 bytes).

Live Binary Ninja evidence recovers the three JAZ resources and placements,
the 0xe8-byte template copy topology, slot duplication, UV bands, vertical
offsets, and the eight-slot horizontal translation. Modeling the translation as
the inlined C++ `vec2 += (-84, 0)` operation reproduces the native loop,
including its otherwise-surprising `y` self-copy.

The six contiguous 0xe8-byte subtemplates are modeled as one array view, and
the slot type retains the empty user-defined constructor established by
`ui_menu_template_pool_init`. That ordinary object model prevents VC6 from
hoisting the first `-100` calculation across the block-01-to-block-02 copy.
The candidate now aligns all 110 normalized instructions with a 110-instruction
prefix and scores 100.00%.

This remains an honest WIP because two static references still differ
(`refs=64/0/2`). For the first two `+124` adjustments, native reloads copied
destination slots 4 and 5 (`0x0048fdec`, `0x0048fe08`), while VC6 propagates
the equal source values from slots 3 and 2 (`0x0048fdd0`, `0x0048fdb4`). The
full-vector `+= (0, 124)` spelling forces the native references but emits eight
non-native x self-copies; `memmove` forces the references but emits calls.
Neither is retained, and no volatile or artificial dependency is used.

An address-level audit confirms that every other masked reference resolves.
The two differing loads are the compiler's equal-value propagation described
above, not wrong globals or record offsets, so recovery is classified
`semantic-complete` with a `compiler` residual. MSVC 6.5 `/GX` and `/Ob1`
variants are byte-identical; MSVC 6.5pp, `/Oy-`, `/G6`, `/O1`, and MSVC 7.0
profiles all regress the instruction match without resolving the pair.

## Bounded residual audit (2026-07-27)

The two mismatches are now pinned to native instructions 67 and 70, at
`0x00419f1c` and `0x00419f2e`. Native loads copied destinations
`0x0048fdec` and `0x0048fe08`; the candidate loads the equal source fields at
`0x0048fdd0` and `0x0048fdb4`. The surrounding instructions and all 64 other
masked references agree.

`alias_lifetime_mutations.json` tests six natural spellings around only the two
copies and adjustments:

- destination references created before and after the copy, destination
  pointers, and a base-slot pointer all compile identically to the baseline;
- interleaving each copy with its adjustment and mutating the assignment-result
  lvalue both regress to 97.27%, move the first mismatch to instruction 63, and
  increase reference mismatches from two to five.

The complete sweep is recorded in `experiments.jsonl`; it has four neutral and
two degrading variants, with no improving winner. Reproduce it with:

```sh
uv run crimson match mutate tools/match/scratches/ui_menu_assets_init \
  --spec tools/match/scratches/ui_menu_assets_init/alias_lifetime_mutations.json \
  --max-variants 6 --jobs 6
```

A five-profile matrix closes the remaining installed compiler gap. VC6 builds
8168 (`msvc6.0`), 8966 (`msvc6.5`), and 9782 (`msvc6.6`) all produce the same
110-instruction, `refs=64/0/2` result. The Processor Pack and VC7 regress.
In particular, build 9782 is the exact compiler family supported by the EXE's
Rich records, so the residual is not explained by having tested only the
default 8966 backend. Further work needs a different recovered type/TU
constraint or the missing historical source context, not another generic flag
or alias sweep.
