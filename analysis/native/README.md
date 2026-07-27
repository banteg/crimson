# Native linker artifacts

This directory contains deterministic reports for the classic Win32/x86
linker track. Regenerate the Grim pilot with:

```bash
just native-audit grim.dll
```

Each image directory contains:

- `objects.json`: the canonical one-function-per-translation-unit selection,
  compiler profile, matching state, and source/config/object hashes;
- `objects.txt`: the same object files in ascending reference-address order;
- `exports.def`: explicit reference-export name/ordinal mappings to decorated
  object symbols;
- `closure.json`: exact decorated COFF definitions and references, duplicate
  definitions, PE exports/imports, linker directives, and unresolved-symbol
  categories;
- `data.json`: the curated data-map rows joined to reference-image sections.

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
- every recovered function remains its own translation unit;
- symbol closure uses exact decorated COFF names;
- the reference PE export must have an unambiguous `.def` mapping;
- no unresolved symbol is hidden behind a generated stub.

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

The initial data report does not infer facts absent from `data_map.json`.
Section membership comes from the IDA segment export; size, alignment, and
initializer fields remain `null` until backed by explicit evidence.
