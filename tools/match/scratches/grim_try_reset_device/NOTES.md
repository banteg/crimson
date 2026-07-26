# grim_try_reset_device

The native log strings identify the helper at `0x10002cf0` as
`D3D_TryResetDevice`. It releases cached render-target/backbuffer surfaces and
the owned default-pool texture objects before calling `IDirect3DDevice8::Reset`.
Failed resets are retried every 500 ms; after four attempts, a Retry/Cancel
dialog either continues after releasing all owned backup/texture surfaces or
returns `D3DERR_DEVICENOTRESET`.

After a successful reset, the function reapplies render state, recreates each
owned texture as a one-level default-pool render target, restores the backed-up
contents, logs the retry count, and clears it. Texture recreation failures are
reported, nulled, and delayed for 200 ms before the scan continues.

The recovered `HRESULT` function matches all 205 native instructions and all
48 references under MSVC 6.5 `/O2 /GB`. A natural local `canceled` flag is
optimized into the native cold failure edge; no forced labels or registers are
needed.
