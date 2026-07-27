# `crimsonland_main`

Native target: `crimsonland.exe` at `0x0042c450` (3,214 bytes).

Live Binary Ninja shows that this is the WinMain-style game entry reached from
the CRT with four stdcall arguments, despite older analysis presenting it as a
zero-argument helper. It performs the DirectX 8.1 gate, verifies D3D creation,
initializes console/config state, loads the Grim2D interface, applies the
selected backend and input settings, installs startup/audio callbacks, loads
the splash resources, hands control to Grim, and then saves and tears down all
runtime state.

The source is reconstructed from the live BN control flow and the already
matched subsystem surfaces used by each call. In particular, the two-player
binding copy preserves the persisted Y/X axis ordering, the texture scale is
accepted only at 0.5, 1, 2, or 4, and the deferred update URL is converted to a
wide string only after shutdown when online synchronization is idle. The
registry path's two-stage byte construction is also preserved: the native
writes `Software\Sock` before the development DLL load and appends
`etPlugins\Default\` afterward.

The native fallback path flushes `console.log` after the conditional
development-DLL retry, including when that first load succeeds. Moving the
flush to that evidenced join recovers its reference and corrects the
development-success side effect.

Live Binary Ninja also resolves the former 50-instruction hole at
`0x0042c80e..0x0042c8d1`. The native compares the loaded interface pointer
with its one-object successor and, only for that deliberately unreachable or
anti-tamper condition, prints nine hint strings through pointer globals at
`0x00473a10..0x00473a34`. The strings cover the redistribution build marker,
secret weapons, the credits secret path, Alien Zoo Keeper, Magic Paint, and
the Muzzy/haxx0r messages. Expressing the observed pointer comparison and nine
calls directly reproduces the entire block, including the post-call interface
reload. It does not introduce a dummy branch, fake relocation, volatility, or
layout-only control flow.

With the target-local MSVC 6.5 `/O2 /GB /W3 /GR-` profile, the reconstruction
has all 832 native instructions. Before the final shutdown-join correction it
had risen from 89.34% to 97.48%, reducing the fuzzy gap from 343 to about 81
weighted bytes. Resolved references had risen from 356 to 392; two
compiler-alignment mismatches and no unresolved reference uses remained.
The shared data map now names the nine recovered hint-pointer globals after
live Binary Ninja confirmed each `char *` value and pointed-to string. This
improves the audit from `378/13/3` to `387/4/3` without a local reference
alias. The native 0x424-byte frame and `retn 0x10` WinMain ABI remain
reproduced.

Expressing the two-player binding copy directly through the source and
destination arrays, rather than short-lived row pointers, recovers the native
`move_key_backward` destination induction base. This reduces the loop's
changed operands from 21 to 13, improves the score from 96.51% to 97.48%, and
turns one former reference mismatch into a resolved reference without adding
an alias.

## Deferred update shutdown join

The update-check worker writes `update_notice_pending` asynchronously. Giving
the entry point's declaration the corresponding `volatile` qualifier recovers
the native final-store schedule and adds 3.86 weighted bytes. Applying that
qualifier to other readers was neutral or harmful, so the evidence supports
this worker/join boundary rather than a shared-header-wide change. The
qualifier sweep is recorded under spec SHA
`a29d0da2bba0a9997eb41a07c4ba3e4007010a05636651c2d0dd0a1121f7211a`.

More importantly, native false branches at `0x0042d036`, `0x0042d043`, and
`0x0042d04b` all land on the final `console_log_queue.flush_log("console.log")`
call. The flush is therefore unconditional after the optional URL navigation;
it is not part of that conditional. Moving it to the evidenced join adds
27.04 weighted bytes and advances the exact prefix from 27 to 684
instructions. That positive sweep is recorded under spec SHA
`4b589c2d2811c693e625973944d96aaab19cfc7366a9935dc08709c33df56754`.

The final result is 98.4375%, with a 50.21875-byte fuzzy gap, all 832 native
instructions, a 684-instruction exact prefix, and audit `393/0/2`. The only
remaining instruction residual is the aggregate binding copy's source
induction base: as in `config_load_presets`, VC6 still rebases the reconstructed
config row to `move_key_backward` rather than native `axis_move_x`. Three
source-cursor menus were all negative and are recorded under spec SHAs
`e0a2032628fd2c93f9478250c5cfa0dd20a64cba6a53b486b4c912803ba56a4b`,
`2d54b3cc6a08d0d215244c536d9a63601b771eb66a6c1d6d04753229c77ec597`,
and `23686c59c2e449df6f7d388aa34c4933bfb969ada76ea721919529bc42de2e23`.

## Recovery classification audit

The live Binary Ninja control flow accounts for the complete startup gate,
console/config/Grim initialization, callback and resource setup, main handoff,
save/teardown, and deferred-update path. Candidate and native each have 832
instructions. The two mismatched references are the documented config-copy
induction rebasing and remain compiler debt.

The four unresolved uses are genuine missing data-map identities rather than
SequenceMatcher alignment artifacts. Binary Ninja proves native `0x00473a64`
is the integrity-cookie store/compare pair, `0x004aaeda` is the byte copied
from `config_blob.music_disabled`, and `0x00473a30` is the 510-byte key-input
buffer size loaded for both initialization and registration. The shared data
map now assigns those exact source identities, resolving all four uses without
a local alias. The final audit is `393/0/2`, so recovery is classified
`semantic-complete` with a `compiler` residual.
