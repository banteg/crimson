# `win32_file_get_version_words`

Native target: `crimsonland.exe` at `0x0041db50` (187 bytes).

Live Binary Ninja evidence recovers a conventional Win32 version-resource
query. The helper validates both pointers, allocates the exact byte count from
`GetFileVersionInfoSizeA`, queries the root `VS_FIXEDFILEINFO`, writes the MS
and LS version words to the caller's two-word output, and returns the standard
`HRESULT` values for invalid arguments, allocation failure, and malformed or
missing version resources.

The allocation and all post-allocation failure paths preserve the native
cleanup behavior. No dummy references, inline assembly, volatile ordering
constraints, or dead expressions are used.
