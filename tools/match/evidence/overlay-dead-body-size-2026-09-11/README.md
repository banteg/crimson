# Dead-player body size ownership

The dead-player body draw now reloads its width and height into the existing
`sprite_size` scalar. The prior source passed the two field loads directly,
causing VC6 to use an unnamed argument temporary at entry-relative slot -40.
Native uses slot -36, the candidate's existing sprite-size home.

The linked candidate changes at exactly two instructions: the store and load
at function offsets 1095 and 1105, corresponding to native addresses
`0x4287d7` and `0x4287e1`. Only their ESP displacements change. Instruction
addresses, sizes, operations, registers and all other operands are unchanged.
The observed entry-relative homes now agree with native at both accesses;
no other paired access changes. This restores two of the six displaced body
argument accesses documented by the preceding
[size-ownership proof](../overlay-size-ownership-2026-09-11/README.md).

Normalized alignment rises from **94.773519% to 94.947735%**, gaining
**7.982578 fuzzy-weighted bytes** and leaving a **231.494774-byte** weighted
gap. Instructions remain **1,148/1,148**, prefix remains nine, and all
**331 references** remain clean. Whole-function normalized and encoded
exactness remain false. This is a small instruction recovery, with no
demonstrated runtime defect in the preceding source and no new whole-function
match credit.

## Machine evidence

[verify.py](verify.py) reuses the preceding proof's unchanged fixtures,
guarded machine runner, source-listing join and read-only ESP observer.
All **851 native/before/current cases** agree on ordered call arguments,
permitted global writes, stored targeting-line distance bits, and complete
player/creature storage. The original 239 call hashes are checked again.
All 199 unambiguous paired stack accesses are exercised. Mismatched stack
accesses fall from **28 to 26**; the three non-frame EBP accesses and one
ambiguous pairing retain the preceding proof's explicit exclusions.

The ordinary runner and stack observer agree on all returned fields in
753 additional observation controls. All 2,553 observed executions preserve
the x87 control word `0x037f` and empty x87 stack. The parent also checks
stack balance, saved registers, admitted instructions and permitted writes.
[results.json](results.json) records program and parent identities, static
instruction changes, actual stack maps and per-case observation hashes.

The source before this change is retained as [before.cpp](before.cpp), SHA-256
`893863b7f9421b1aef6bd0e72818a4f024c49d4190543f0534e5fa84427dd484`.
The recovered source SHA-256 is
`df048c95f7ba8cd30ab5b8ac3a4a9ad1ab46b658eea1ff7b6a6e3b1ae24fef2b`.
Native image SHA-256 remains
`771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4`.

## Compiler observation and controls

Fresh [before](stack-before.json) and [current](stack-current.json) traces
use the unchanged stock-C2 observer from the preceding package. Each source
has 45 allocation symbols, 43 checked local descriptors, seven groups and a
44-byte frame. The scoped allocation model predicts every descriptor offset.
Normal, captured, replayed and observed whole COFF objects agree within each
source build except for timestamps. Withheld-stream, truncated-trace and
corrupted-offset controls remain active. Compiler data and on-disk binaries
are not modified.

The sprite-size use count rises from six to eight while its -36 home remains
unchanged. The unnamed body-size temporary falls from six to four uses and
keeps its -40 group. The two dead-body instructions now access the named
sprite-size owner. This explains the candidate emission without claiming
unique original variable names or lexical scope.

[source-controls.json](source-controls.json) retains 23 reconstructible,
hash-checked compiling controls: the baseline and all seven subsets of the
three direct body draws reusing `sprite_size`; six shield/muzzle offset
ownership controls; six targeting-line vector-scope controls; and three
controls directly constructing local shield/muzzle offsets. Among the body
draw subsets, only the dead-body subset improves alignment without adding instructions or changing
reference counts. Extending reuse to living-body draws does not reproduce
their remaining native stack homes. Relative to the retained source, direct
shield-offset construction is neutral; direct muzzle-offset construction adds two instructions and reduces
alignment. The other offset and targeting-line controls also add instructions
and reduce alignment. [verify_controls.py](verify_controls.py) reproduces the
recorded metrics in [control-results.json](control-results.json). These are
bounded negatives, not exhaustion claims.

## Scope and reproduction

The parent retains its explicit Grim2D recording callbacks, perk model and
D3DX normalization model. The native CRT conversion helper executes, but
external graphics/audio backends do not. This proof uses PC=64 rendering
fixtures and does not establish PC=24, arbitrary-input or pixel equivalence.
No matching rule, reference alias, waiver, Python or Zig source changes are
part of this recovery.

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/overlay-dead-body-size-2026-09-11/verify.py \
  --out /tmp/crimson-overlay-dead-body-proof
uv run python \
  tools/match/evidence/overlay-dead-body-size-2026-09-11/verify_controls.py \
  --out /tmp/crimson-overlay-dead-body-controls
uv run python \
  tools/match/evidence/overlay-size-ownership-2026-09-11/verify_stack.py \
  --source tools/match/evidence/overlay-dead-body-size-2026-09-11/before.cpp \
  --out /tmp/crimson-overlay-dead-body-stack-before
uv run python \
  tools/match/evidence/overlay-size-ownership-2026-09-11/verify_stack.py \
  --out /tmp/crimson-overlay-dead-body-stack-current
```

The stock VC6 toolchain and Unicorn JIT permission are required locally.
