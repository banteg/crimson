# Native linker artifacts

This directory contains deterministic reports for the classic Win32/x86
linker track. Regenerate the Grim pilot with:

```bash
just native-audit grim.dll
```

Each image directory contains:

- `objects.json`: the canonical function-to-translation-unit selection,
  generated data-definition objects, compiler profile, matching state, and
  source/config/object hashes;
- `objects.txt`: the same object files in ascending reference-address order;
- `exports.def`: explicit reference-export name/ordinal mappings to decorated
  object symbols;
- `closure.json`: exact decorated COFF definitions and references, duplicate
  definitions, PE exports/imports, linker directives, and unresolved-symbol
  categories;
- `data.json`: the curated data-map rows joined to reference-image sections,
  explicit data-definition evidence, and unresolved linker fan-in.

Object files remain ignored compiler-cache outputs. The manifest records their
repository-relative paths and hashes so a build can be reproduced and audited
without checking generated COFF files into Git.

The audit forcibly recompiles every selected object and the ABI assertion unit
in an isolated temporary directory instead of trusting an existing cache
entry. It snapshots the compiler, system headers, wrapper, and Wibo before and
after that build and aborts if they change.

VC6 writes compile time into the COFF header. Object hashes zero only those
four `TimeDateStamp` bytes before hashing; the normalization is declared in
`objects.json`. Source/config/header inputs, the compiler bundle's material
`Bin` and `Include` trees, Wibo, selection/catalog maps, and the reference
image retain ordinary SHA-256 fingerprints. A shared `audit_digest` ties the
three JSON reports together, while the object list and export definition have
component hashes.

The audit is intentionally strict:

- canonical identity is `(image, resolved native address)`;
- missing, duplicate, malformed, or non-canonical scratches are errors;
- every recovered function remains isolated unless an explicit
  `tools/native/translation_units/<image>.json` cluster binds compiler-local
  members emitted by one source translation unit;
- every cluster member must preserve its canonical byte ratio and reference
  audit, and each physical cluster object appears once in the link list;
- symbol closure uses exact decorated COFF names;
- the reference PE export must have an unambiguous `.def` mapping;
- no unresolved symbol is hidden behind a generated stub.

Fully specified, currently referenced data definitions are emitted into one
deterministic i386 COFF object after the function-object pass discovers their
exact requested symbol names. Overlapping ranges share storage, so C and C++
decorated names and interior fields can alias the same bytes without inventing
duplicate globals. Sparse ranges remain separate sections; the emitter does
not fill unknown gaps or derive extents from neighboring symbols.
Initializers may be recorded literally as `initializer_hex` or compactly as a
single-byte `initializer_fill`; both forms are checked byte-for-byte against
the pinned reference image before an object is emitted.
Definition groups share the same size, alignment, initializer, and provenance
across an explicit sorted list of `[address, name]` members. Each member's
expected data-map type is validated before expansion, so groups reduce repeated
manifest text without widening which symbols qualify for emission. A `null`
expected type deliberately restricts a group to currently untyped map entries;
the group's size and alignment sources must then record the independent type or
storage-width evidence used for those members.
Groups whose members have different literal values may instead set
`member_initializer_hex` and list `[address, name, initializer_hex]` members.
The group still owns the common initializer provenance, size, alignment, and
type checks, while each member's literal is independently length-checked and
compared byte-for-byte with the pinned reference image.
An unresolved catalog name whose address falls inside one of those explicit
ranges is emitted as an `interior-alias` binding. The alias records its own
mapped address and name, but its section storage remains owned by the smallest
containing explicit definition; no independent size or initializer is inferred.

The three Crimsonland metadata lifecycle clusters are the first modeled
exception. Their natural global-array definitions emit exact
`$E4/$E1/$E3/$E2` initializer, constructor, registrar, and finalizer
functions. Co-location keeps the registrar-to-finalizer relocation COFF-local
instead of inventing an external callback provider. `function_count`
therefore remains the owned function count while `object_count` is the number
of physical linker inputs.

`function_closure` means there are no unresolved in-scope game functions and
no duplicate strong definitions. `game_owned_closure` additionally requires
all mapped game data and unclassified externals to resolve.
`all_references_closed` is stricter still and includes imports, excluded
functions, and toolchain/library dependencies. Game-owned closure is expected
to remain false until real data definitions exist.

`summary.game_function_debt` keeps the function gate actionable without
weakening exact linker identity. `emitted_name_mismatch` means an object emits
one or more same-display-name candidates, but none has the exact decorated
name requested by the reference. `missing_definition` means no selected object
emits even such a candidate. `summary.hard_duplicate_by_section` groups the
still-fatal strong duplicate symbols by their COFF section; it does not
silently coalesce repeated `.bss` ownership.

Data-definition evidence lives in
`tools/native/data_definitions/<image>.json`. Each size, alignment, and
initializer must carry its own source; initializer byte counts must match the
explicit size, alignments must be powers of two, and definitions must join the
data map by exact `(address, name)`. The loader rejects unsorted, duplicate,
unmapped, or reference-image-mismatched entries. During an audit, initializer
bytes are also compared with the memory-mapped reference PE, including its
virtual zero-fill. The loader never derives an extent from the next symbol and
never treats unknown bytes as zero.

Section membership still comes from the IDA segment export. Fields remain
`null` when no explicit definition exists. `data.json.priorities` ranks the
top 50 mapped data entries by unresolved COFF reference fan-in and preserves
each requested decorated symbol, so inconsistent declaration types remain
visible. A `fully-specified` manifest entry is eligible for the generated data
object; it claims linker closure only when that object emits every requested
exact symbol. `objects.json.data_objects` records the input manifest, emitted
aliases, section offsets, region layout, and object hash.
