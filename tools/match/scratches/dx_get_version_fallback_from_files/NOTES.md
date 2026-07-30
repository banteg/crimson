# dx_get_version_fallback_from_files

The function is the pre-StrSafe form of Microsoft's legacy
`GetDirectXVersionViaFileVersions` DirectX SDK sample. Its filenames,
thresholds, stack layout, helper order, and repeated inline `strcpy`/`strcat`
sequences agree with the executable.

The recovered names map as follows:

- `GetFileVersion` -> `win32_file_get_version_words`
- `MakeInt64` -> `dx_version_pack_4x16`
- `CompareLargeInts` -> `dx_version_compare_4x16`

The scratch keeps the original two 512-byte buffers and direct pointer checks
because both materially determine the VC6 code shape.
