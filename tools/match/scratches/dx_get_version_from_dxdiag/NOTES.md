# `dx_get_version_from_dxdiag`

Native target: `crimsonland.exe` at `0x0041cdb0` (556 bytes).

Live Binary Ninja evidence identifies a conventional `IDxDiagProvider` COM
query. It initializes COM, creates the provider with the native CLSID/IID,
opens `DxDiag_SystemInfo`, reads the major/minor unsigned properties and BSTR
letter property, converts the letter through `WideCharToMultiByte`, releases
all three interfaces, and balances `CoInitialize` only when it succeeded.

The provider and container projections preserve their native `STDMETHODCALLTYPE`
vtable slots. The returned `HRESULT` is `S_OK` only when all three properties
were recovered. No dummy references, inline assembly, volatile ordering
constraints, or dead expressions are used.
