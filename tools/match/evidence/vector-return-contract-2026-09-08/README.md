# Vector helper return-contract ambiguity

The native helpers at `0x00417640` (`vec2_sub`) and `0x0044ecf0`
(`vec2_add_out`) do not distinguish an explicit output-pointer method from
an ordinary C++ method returning a two-float object by value. Under the
canonical `msvc6.5 /O2 /GB /W3 /GR-` profile, both source contracts produce
the same complete 26-byte native bodies, with no relocations.

| Machine location | Explicit-output interpretation | Value-return interpretation |
| --- | --- | --- |
| `ECX` | Source object | Source object |
| `[ESP+4]` on entry | Explicit destination pointer | Hidden object-return buffer |
| `[ESP+8]` on entry | Explicit right operand pointer | Right operand reference |
| `EAX` on return | Destination pointer | Object-return buffer pointer |
| `ret 8` | Pop two explicit arguments | Pop hidden buffer and one explicit argument |

The original `game_bins/crimsonland/1.9.93-gog/crimsonland.exe` has no COFF
symbol table or exports, and contains neither recovered helper name nor its
candidate class name. The decorated symbols in the canonical scratch configs
therefore identify reconstructed objects, not original C++ signatures.
`comparison.json` records the original image hash, reference addresses and
body hashes, control-source hashes, compiler fingerprints, and comparisons.

`helpers.cpp` compiles four ordinary out-of-line methods: explicit subtraction
and addition, and the corresponding value-return operators. `callers.cpp`
compiles separately so the helper calls remain real boundaries. It compares:

- A value-expression temporary consumed by an inline reference angle helper
  against an explicit output pointer consumed by an inline pointer angle
  helper. Both caller bodies are 33 identical bytes; their helper relocations
  name the two independently verified equivalent subtraction bodies.
- A value-expression temporary passed through an inline reference adapter
  to `consume` against direct explicit-output consumption. Both caller bodies
  are 32 identical bytes with equivalent helper and identical consumer
  references.

The named value-local control is deliberately retained too: it reloads the
local address with `lea`, illustrating that local source ownership can matter
even when the callee's machine contract is indistinguishable.

Native Fire Cough calls subtraction at `0x00413b7f`, then executes
`fld [eax]; fld [eax+4]; fxch st(1); fpatan`. That immediate use of the returned
address is compatible with either contract. The tiny angle controls have a
different local x87 load order; they demonstrate contract ambiguity, not an
exact match of the large caller or a whole-function improvement.

The authenticated 2003 SDK independently shows value-return subtraction at
`cl_crimsonroks/src/cltypes.h:69-72`, addition at `:74-77`, and
`VEC2_Angle(const vec2_t&)` at `:155-157`. Its pinned header hash is
`f56d2713518c010ce3ed8c76508678c7e5beff79a6d8a25fd7e736114bdb860f` in
`analysis/mod_sdk_provenance.json`. This is support for a source hypothesis;
it does not establish the 1.9.93 source class, helper signature, translation
unit, or compiler provenance. No canonical helper source/configuration is
changed by this evidence.

## Reproduce

From the repository root, with the usual ignored original image, VC6 bundle,
and `wibo` available:

```sh
uv run --no-sync python tools/match/evidence/vector-return-contract-2026-09-08/verify.py --out /private/tmp/crimson-vector-return-contract-check
```

The verifier copies the three control sources into the chosen output directory
and runs these compiler arguments there, with `MSVC_VER=msvc6.5`:

```text
tools/match/cl.sh /c /O2 /GB /W3 /GR- /FAs helpers.cpp
tools/match/cl.sh /c /O2 /GB /W3 /GR- /FAs callers.cpp
```

It writes `comparison.json` beside the temporary objects and assembly listings
and exits unsuccessfully if any claimed body or caller equivalence fails.
Tracked evidence contains no binaries or large disassembly dumps.
