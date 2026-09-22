# Timeline copy aliases and stack sharing

An unused copy's extent alone does not determine whether it can share the
spread slot. A new four-byte copy witness retains implicit references from
pointer loads and the spawn call; those references prevent sharing. Removing
only that alias membership during stack allocation reproduces the graph and
28-byte frame of the earlier guard witness. This is compiler evidence, not a
new match or a proposed source recovery.

The [September 13 guard witness](../timeline-four-byte-home-2026-09-13/README.md)
already produced the native pointer/zero triplet with a 28-byte frame using
stock VC6. The present result explains an additional failing route and compares
it with that known positive control. Canonical source, flags, 113/115
instructions, prefix 51, 13 clean references, and non-exact status are unchanged.

## Source control and actual owner

[witness.cpp](witness.cpp) replaces the pointer declaration with a byte copy
whose end pointer is consumed in the zero-valued spread initializer:

```cpp
int *template_id = &entry->template_id;
int *copied;
unsigned char *out = (unsigned char *)&copied;
const unsigned char *in = (const unsigned char *)&template_id;
for (unsigned k = sizeof copied; k; --k)
    *out++ = *in++;
int spread;
spread = out - (unsigned char *)&copied - sizeof copied;
```

The copied value is unused. The pointer subtraction is within the same
four-byte object representation, including its one-past position. This is an
intentional diagnostic construction; no original-game evidence supports it.
Heading is read as `((float *)template_id)[-1]`, following the existing copy
witnesses. In the verified layout, heading is at entry+8 and template ID at
entry+12: EDI points at the ID, `[edi-4]` reads heading, and `[edi]` reads ID.

The stock compiler emits separate slots, in this order:

```asm
lea edi, dword [esi+0xc]
mov dword [esp+0x10], ebx
mov dword [esp+0x14], edi
```

Its frame is 32 bytes. The explicit local-use trace sees just one store to
`copied`; that count misses implicit alias uses. The source/COFF identities and
native metrics are retained in [controls.json](controls.json).

## Preserving alias and allocation observations

[verify.py](verify.py) extends the existing complete-operand observer and
stack-allocation model. Every normal/captured/replayed/observed whole COFF
comparison passes, excluding only timestamps. All four missing-stream
controls reject replay. Twenty individual allocation offsets are checked
against the observed descriptors, and frame sizes against emitted code.

The read-only [alias observer](aliases.c.in) follows `C2+0x3686`: it resolves
the handle through the primary table or secondary 12-byte records, then walks
definition lists and their kind-12 groups. Kind-6 operands store their alias
handle at +0x1c, beyond the seven common words in the generic trace; kind-11
call effects use +0x14. A nonnegative definition index at +0x38 identifies an
allocated local. Bounds, depth, symbol identity, and complete operand coverage
are checked. Arena identities are compared only within each replay.

| Stock source | Copy size | Implicit operands containing copy | Shares spread | Frame |
|---|---:|---:|---|---:|
| Earlier pair | 8 | 0 | Yes | 32 |
| Earlier guard | 4 | 0 | Yes | 28 |
| End-pointer witness | 4 | 4 | No | 32 |
| Separate copy input, live pointer derived from it | 4 | 4 | No | 32 |

For the end-pointer witness, the two kind-6 pointer loads and both kind-11
spawn-call effects include `copied` and the position local. Separating the
copy's input from the live pointer removes position from the two load alias
sets, but leaves the copy in all four operands. That change does not enable
stack sharing. The copied owner's descriptor flag word is `0x20604`, versus
`0x20204` in the older guard/pair controls. The meaning of that 0x400 bit is
not inferred from this correlation.

The copied four-byte local conflicts with every local in the end-pointer
witness. In the guard witness its conflict set excludes itself and spread.
The reused greedy grouping model reproduces all slots in both cases, rather
than fitting only the total frame size. [compiler-results.json](compiler-results.json)
retains the full graphs, source bindings, alias memberships, replay receipts,
and 24 rejecting corruption controls.

## Causal intervention and its limits

[diagnostic.py](diagnostic.py) adds a callsite-checked hook immediately before
`0x33c7e -> 0x4ac4c`, the stack dataflow builder. With pruning enabled it
removes the copied definition from one shared alias-list link. It preserves
the explicit copy store, symbol extent, IR operands, and all other definitions
in that list. The changed link remains absent during `0x4b107` conflict
construction and is restored, with readback checks, before `0x4b617` groups
locals. An otherwise identical disabled-pruning replay preserves whole COFF.

The pruned graph has the same copy/spread sharing and other conflict sets as
the guard witness. All five predicted offsets agree with compiler output;
the frame becomes 28 bytes and the emitted stores are correctly ordered:

```asm
lea edi, dword [esi+0xc]
mov dword [esp+0x10], edi
mov dword [esp+0x10], ebx
```

The two stores are adjacent, full-width, and have no intervening read. The
verifier checks their order; a frame-size improvement alone would not establish
this. However, argument scheduling also changes: both position stores precede
the argument pushes, where stock output interleaves them. Zero sharing and
other native differences remain. The diagnostic is 115/115 instructions,
prefix 14, 12 clean references, 82.608696% agreement, and non-exact. No runtime
equivalence is claimed. [diagnostic-results.json](diagnostic-results.json)
records both emitted windows and every graph/offset check.

## Bounded source controls and stopping point

[controls.py](controls.py) retains 14 fresh stock builds, including the three
established controls. Four-byte struct, union, integer, and float destinations,
integer address subtraction, and rebased pointer subtraction preserve the
end-pointer witness's whole COFF except timestamps. Closing the copy's scope
before the spawn loop or testing its end pointer for equality removes the
copy; their emitted bodies agree with each other. Separating the input changes
some addressing but preserves the alias obstruction. None is promoted.

The next useful question is when a credible copy consumer loses its last use
without leaving its destination in implicit alias sets. A four-byte owner,
one explicit use, or a 28-byte frame is insufficient evidence on its own.
The existing guard establishes a mechanism; its deliberate redundant condition
still lacks evidence as original source. Native zero lifetimes, registers,
addressing, and argument scheduling remain separate requirements.

## Reproduce

Run from the repository root with new output directories:

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/timeline-copy-aliases-2026-09-22/controls.py \
  --out /tmp/timeline-copy-alias-controls
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/timeline-copy-aliases-2026-09-22/verify.py \
  --out /tmp/timeline-copy-alias-observer
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/timeline-copy-aliases-2026-09-22/diagnostic.py \
  --verified /tmp/timeline-copy-alias-observer \
  --out /tmp/timeline-copy-alias-diagnostic
```

The pinned backend is MSVC 6.5 C2 SHA-256
`d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`.
Raw traces, generated sources, assembly, objects, and replay settings remain
in the chosen output directories. The checked-in JSON files summarize those
reproducible runs; they do not install diagnostic objects into the build.
