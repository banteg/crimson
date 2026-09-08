# VC6 math entry boundaries

The pinned VC6 SP6 `libcmt.lib` (SHA-256
`a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a`)
contains the native `_pow` and `_acos` entries in `pow.obj` and `acos.obj`.
They were absent from matching candidates because their COFF symbols continue
into bodies which the native IDA manifest splits into separate functions.

| Recovered entry | Native range | Archive symbol offset | Proven prefix |
|---|---|---|---|
| `crt_pow_entry` | `0x00461159..0x00461162` | `_pow`, `.text+0x19` | `lea edx,[esp+0xc]`; call `crt_fload_with_fb` |
| `crt_acos_entry` | `0x00463194..0x0046319d` | `_acos`, `.text+0x14` | `lea edx,[esp+4]`; call `crt_fload_with_fb` |

The existing `ARCHIVE_SIZE=9` contract selects these public-symbol prefixes.
The native manifest supplies the independent exclusive boundaries. Each
candidate has two identical instructions, a matching relocation-aware encoded body
(the call uses REL32), and one resolved call reference. No bytes, aliases for
unlike callees, or artificial return instructions are introduced. These are
entry fragments that fall through to the adjacent implementation, not complete
standalone nine-byte implementations of pow or acos.

The surrounding archive code corroborates ownership: `__CIpow` and `__CIacos`
precede these entries and call their shared continuations, at `.text+0x22` and
`.text+0x1d` respectively. The remaining anonymous continuations and private
math labels need their own bounded provenance; the two prefix matches do not
give them credit. The linker continues to use the complete original CRT archive
members. No additional physical object or duplicate provider is introduced.

This recovers two full-image manifest entries and 18 encoded bytes. They remain
outside the game/engine port scope, whose denominator stays at 810 functions.
The saved evidence includes these archive matches; the public decomp.dev code
score intentionally credits source-built code only and does not increase.
