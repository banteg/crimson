# PNG Structure Analysis for grim.dll

## Status

**Implemented.** We now ship a libpng 1.1.x-compatible shim (`third_party/headers/png_struct_stub.h`)
and parse it via `ImportThirdPartyHeaders.java` so Ghidra can resolve `png_struct`
field accesses. Re-run the grim.dll Ghidra export to apply the updated types.

## Problem

The decompiled code shows 314+ `png_ptr` references typed as `int *` with raw array offsets like:
```c
png_ptr[0x10]  // error callback
png_ptr[0x27]  // zbuf pointer
png_ptr[0x43]  // chunk name
```

This happens because:
1. **Game uses libpng 1.1.3** (from ~2000, confirmed by string `"1.1.3"` in code)
2. **Our headers are libpng 1.6.54** (2026) - completely different internal layout
3. **`png_struct` is opaque** - the public API doesn't expose field definitions
4. **Structure layout changed** between major versions (1.0.x → 1.2.x → 1.5.x → 1.6.x)

## Root Cause

In older libpng versions (<1.5.0), `png_struct` was defined directly in `png.h`. Since 1.5.0, it moved to private `pngstruct.h` and applications can't access fields directly.

The version mismatch means Ghidra can't resolve struct members from modern headers.

## Offset Mapping

Based on decompiled code patterns and libpng 1.2.5 structure documentation:

### Win32 Layout (jmpbuf = 64 bytes)

| Index | Byte Offset | Field Name | Evidence |
|-------|-------------|------------|----------|
| 0x00-0x0F | 0x00-0x3F | `jmpbuf[16]` | `setjmp3(png_ptr,0)` |
| 0x10 | 0x40 | `error_fn` | Called with `(png_ptr, msg)` |
| 0x11 | 0x44 | `warning_fn` | Called with `(png_ptr, msg)` |
| 0x12 | 0x48 | `error_ptr` | User error context |
| 0x13 | 0x4C | `write_data_fn` | I/O callback |
| 0x14 | 0x50 | `read_data_fn` | I/O callback |
| 0x15 | 0x54 | `io_ptr` | User I/O context |
| 0x16 | 0x58 | `mode` | Flag bit operations |
| 0x17 | 0x5C | `flags` | `\| 0x20` operations |
| 0x18 | 0x60 | `transformations` | Transform flags |
| 0x19-0x26 | 0x64-0x98 | `zstream` | z_stream (~56 bytes) |
| 0x27 | 0x9C | `zbuf` | `png_malloc(png_ptr, 0x2000)` result |
| 0x28 | 0xA0 | `zbuf_size` | Set to `0x2000` |
| 0x2E | 0xB8 | `bit_depth` | Image format |
| 0x2F | 0xBC | `color_type` | Image format |
| 0x32 | 0xC8 | `width` | Image dimensions |
| 0x33 | 0xCC | `height` | Image dimensions |
| 0x34 | 0xD0 | `rowbytes` | Bytes per row |
| 0x35 | 0xD4 | `pass` | Interlace pass |
| 0x36 | 0xD8 | `row_buf` | Current row buffer |
| 0x37 | 0xDC | `prev_row` | Previous row (filtering) |
| 0x3D | 0xF4 | `pixel_depth` | Calculated pixel size |
| 0x3F | 0xFC | `idat_size` | Remaining IDAT bytes |
| 0x43 | 0x10C | `chunk_name` | `0x54414449` = "IDAT" |
| 0x45 | 0x114 | `current_pass` | Interlace pass number |
| 0x4E | 0x138 | `palette_entries` | Palette data |
| 0x51 | 0x144 | `palette` | Palette pointer |
| 0x5B | 0x16C | `row_callback_fn` | Progressive read callback |

## Unique Offsets Found

```
png_ptr[0x10] png_ptr[0x11] png_ptr[0x14] png_ptr[0x16]
png_ptr[0x17] png_ptr[0x18] png_ptr[0x19] png_ptr[0x1a]
png_ptr[0x1c] png_ptr[0x1d] png_ptr[0x1f] png_ptr[0x21]
png_ptr[0x22] png_ptr[0x23] png_ptr[0x27] png_ptr[0x28]
png_ptr[0x2e] png_ptr[0x2f] png_ptr[0x30] png_ptr[0x32]
png_ptr[0x33] png_ptr[0x34] png_ptr[0x35] png_ptr[0x36]
png_ptr[0x37] png_ptr[0x3d] png_ptr[0x3f] png_ptr[0x40]
png_ptr[0x41] png_ptr[0x43] png_ptr[0x45] png_ptr[0x4c]
png_ptr[0x4e] png_ptr[0x51] png_ptr[0x5b]
```

Total: 35 unique field accesses

## Sample Decompiled Code

### Before (current state)
```c
void png_error(int *png_ptr, char *msg) {
    if ((code *)png_ptr[0x10] != (code *)0x0) {
        (*(code *)png_ptr[0x10])(png_ptr, msg);
    }
    longjmp(png_ptr, 1);
}
```

### After (with proper struct)
```c
void png_error(png_structp png_ptr, char *msg) {
    if (png_ptr->error_fn != NULL) {
        png_ptr->error_fn(png_ptr, msg);
    }
    longjmp(png_ptr->jmpbuf, 1);
}
```

## Solution

Created `third_party/headers/png_struct_stub.h` with:
- Reconstructed `png_struct_def` matching the observed offsets
- Callback function typedefs
- Common PNG function signatures

### To Apply

1. Add to `ImportThirdPartyHeaders.java`:
   ```java
   addHeader(headerFiles, missing, new File(root, "png_struct_stub.h"));
   ```

2. Re-run Ghidra headless analysis

### Expected Impact

- ~314 `png_ptr` references should resolve to named struct fields
- ~35 unique field offsets → named members
- Functions like `png_error`, `png_warning`, `png_read_*` get proper signatures

## Verification

After applying, check for:
```c
// Should see this pattern:
png_ptr->error_fn(png_ptr, msg);
png_ptr->zbuf = png_malloc(png_ptr, png_ptr->zbuf_size);

// Instead of:
(*(code *)png_ptr[0x10])(png_ptr, msg);
png_ptr[0x27] = png_malloc(png_ptr, png_ptr[0x28]);
```

## Sources

- [libpng 1.2.5 manual](https://www.libpng.org/pub/png/libpng-1.2.5-manual.html)
- [libpng 1.0.3 manual](https://www.libpng.org/pub/png/libpng-1.0.3-manual.html)
- [W3 Amaya libpng source](https://dev.w3.org/Amaya/libpng/)
- [pnggroup/libpng GitHub](https://github.com/pnggroup/libpng)
