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

With the target-local MSVC 6.5 `/O2 /GB /W3 /GR-` profile, the reconstruction
matches 89.34%: 782 candidate instructions against 832 target instructions, a
27-instruction exact prefix, and 356 resolved matching references (three
mismatches and four unresolved data references). The native 0x424-byte frame
and `retn 0x10` WinMain ABI are reproduced.

The guarded developer hint block is intentionally omitted from the first
candidate. Binary Ninja renders its condition as an impossible interface
pointer comparison, and the repository evidence describes it as a debug or
anti-tamper path rather than normal boot behavior. No dummy branch, fake
reference, volatile state, or compiler-order constraint is introduced to
recreate it. That omitted block accounts for the dominant 50-instruction
residual. The other material residual is the honest aggregate two-player input
copy: as in `config_load_presets`, VC6 rebases the reconstructed loop to a
different interior field than the native `axis_move_x`/`move_key_backward`
induction pair.
