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
now has all 832 native instructions and rises from 89.34% to 96.51%, reducing
the fuzzy gap from 343 to about 112 weighted bytes. The 27-instruction exact
prefix is unchanged. Resolved references rise from 356 to 387; the original
three mismatches and four pre-existing unresolved reference uses remain.
The shared data map now names the nine recovered hint-pointer globals after
live Binary Ninja confirmed each `char *` value and pointed-to string. This
improves the audit from `378/13/3` to `387/4/3` without a local reference
alias. The native 0x424-byte frame and `retn 0x10` WinMain ABI remain
reproduced.

The largest remaining instruction residual is the aggregate two-player input
copy: as in `config_load_presets`, VC6 rebases the reconstructed loop to a
different interior field than the native `axis_move_x`/`move_key_backward`
induction pair. The other changed instructions are branch-target shifts and
small call/register scheduling differences outside the newly exact hint block.
