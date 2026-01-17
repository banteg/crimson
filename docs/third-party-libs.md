# Third-party libraries

This page tracks third-party libraries referenced by the Crimsonland binaries and
our current analysis status.

Legend:
- Processed: header/stub imported by `ImportThirdPartyHeaders`.
- Mapped: function signatures or data types applied via `analysis/ghidra/maps/*`.

## Identified versions

- libpng 1.0.5 (grim.dll calls `png_create_read_struct("1.0.5", ...)`)
- zlib 1.1.3 (grim.dll initializes zlib with "1.1.3" and includes deflate/inflate strings)

## Inventory

| Library | Evidence | Version | Processed | Mapped |
| --- | --- | --- | --- | --- |
| libpng | grim.dll decompile calls `png_create_read_struct("1.0.5", ...)` and contains libpng error strings | 1.0.5 | Yes (`png_struct_stub.h`) | Yes (png_* signatures) |
| zlib | grim.dll uses zlib init with "1.1.3" (deflate/inflate strings present) | 1.1.3 | Yes (`zlib.h`) | No |
| libjpeg | grim.dll strings include JPEG error texts | Unknown | Yes (`jpeg_all.h` → `jpeglib.h` + `jpegint.h`) | No |
| libvorbisfile / libvorbis / libogg | crimsonland.exe strings reference `vorbisfile.dll`, Ogg bitstream errors, and `.ogg` assets | Unknown | Yes (`ogg/ogg.h`, `vorbis/codec.h`, `vorbis/vorbisfile.h`) | No |
