# Compiler context controls, 2026-09-09

The verified wibo fork fixes VC6 precompiled-header creation and reuse, but
neither PCH mode changes the two full network workers. Across Wine and the
fork, plain compilation, PCH creation, and PCH reuse produce identical COFF
objects per function after zeroing only timestamp bytes 4 through 7.

The statistics worker remains 99.182561%, 367 instructions, prefix 252, and
120 clean references. The highscore worker remains 96.860133%, 526
instructions, prefix 340, and 126 clean references. Neither body is exact.

The controls compile each unchanged source with `/O2 /GB /W3 /GR- /c`.
PCH creation and reuse both add `/YX /Fp<path>`; creation starts without that
file and reuse preserves it. The compiler and source hashes, complete metrics,
and normalized object hashes are in [results.json](results.json).

The fork commit `08b7997500fc1bc3005edb6d2110c1a2a6c1909b` supplies
`MoveFileExA/W` and reserves fixed file mappings in the virtual allocator.
It is proposed in [wibo PR #146](https://github.com/decompals/wibo/pull/146).
The compiler outputs establish compatibility on these workloads; they do not
prove compatibility for every compiler or Windows program.

Separately, adding `/Zd` or `/Zi` to each of the five recorded baseline
functions leaves the matching metrics unchanged. The target PE has no debug
directory; these are bounded controls, not evidence that either flag was used
for the original game. No candidate source or compiler profile is changed.
