---
tags:
  - contributor
---

# Third-party libraries

Libraries linked into, or shipped with, the original 1.9.93 binaries. The
ports' own dependencies are pinned in their manifests and the
[port notes](https://github.com/banteg/crimson/blob/master/crimson-core/PORT.md).

[`analysis/library_provenance.json`](https://github.com/banteg/crimson/blob/master/analysis/library_provenance.json)
is the source of truth: source archive URLs and hashes, embedded address
ranges with their archive-match counts, version strings, imports, synced
headers and sources, and the derived provider archives. Check it against your
local `game_bins/` copies (not checked in):

```sh
uv run crimson match provenance --check
```

The [library provenance notes](https://github.com/banteg/crimson/blob/master/analysis/library-provenance-notes.md)
keep the dated per-function evidence: Rich-header builds, compiler profiles,
and the matcher and native-provider history for each module.

## DirectX 8.1 SDK (D3DX8)

- Version: `DX81SDK_FULL.exe` (2001-10-16), member `DXF/DXSDK/lib/d3dx8.lib`.
- Hashes: archive SHA-256
  `73f6791e0ae7f8a1d74f71d8ebe517a79c0cbf03fd344424696fd7a3816d2d02`,
  `d3dx8.lib` SHA-256
  `39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28`.
- Evidence: both images call `Direct3DCreate8(220)` and statically contain
  D3DX; Grim's error string names DirectX 8.1, and its input setup passes
  `0x0800` to `DirectInput8Create`. The archive's members match
  `crimsonland.exe` `0x00452ef0..0x00460cb8` and Grim `0x1000aaa6..0x1004b5b0`
  byte for byte after relocation. Its Rich records are VC7-generation provider
  output, compatible with the images' VC6 final link. Both images link the
  pinned archive natively.

```sh
mkdir -p /tmp/crimson-dx81
curl -L -o /tmp/crimson-dx81/DX81SDK_FULL.exe \
  'https://web.archive.org/web/20040108202259id_/http://download.microsoft.com/download/whistler/dx/8.1/W982KMeXP/EN-US/DX81SDK_FULL.exe'
shasum -a 256 /tmp/crimson-dx81/DX81SDK_FULL.exe
unzip -j /tmp/crimson-dx81/DX81SDK_FULL.exe \
  DXF/DXSDK/lib/d3dx8.lib -d /tmp/crimson-dx81

uv run crimson match archive /tmp/crimson-dx81/d3dx8.lib \
  --image game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  --start 0x00452ef0 --end 0x00460cb8 \
  --expected-sha256 39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28 \
  --check
uv run crimson match archive /tmp/crimson-dx81/d3dx8.lib \
  --image game_bins/crimsonland/1.9.93-gog/grim.dll \
  --start 0x1000aaa6 --end 0x1004b5b0 \
  --expected-sha256 39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28 \
  --check
```

Add `--missing-scratches` to skip target addresses that already have a
scratch, and `--show-matches --json` to list the uniquely attributable
functions that remain.

## Visual C++ 6.0 SP6 runtime

- Version: `VS6sp61.cab` from the VS6 SP6 media (`vs6sp6.iso.zip`).
- Hashes: `vc98/lib/libcmt.lib` SHA-256
  `a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a`,
  `vc98/lib/msvcrt.lib` SHA-256
  `3efc3ddf045a459a2b6403f0b821be2cb7c316ffca67dddddb346cea7a9e4f63`.
- Evidence: `LIBCMT.LIB` matches the executable's static CRT
  `0x00460cb8..0x0046e920`; the single-threaded `LIBC.LIB` matches far fewer
  functions. Grim imports `MSVCRT.DLL`; its startup glue `0x1000a8d0..0x1000aaa6`
  matches both archives, most specifically `MSVCRT.LIB`, whose `dllsupp.obj` defines the `__except_list` and
  `__fltused` the native link needs. The JAZ/zlib helpers at
  `0x1000a810..0x1000a8c2` are Grim's own code.

```sh
mkdir -p /tmp/crimson-vc6
curl -L -o /tmp/crimson-vc6/vs6sp6.iso.zip \
  'https://archive.org/download/vs6.iso/vs6sp6.iso.zip'
shasum -a 256 /tmp/crimson-vc6/vs6sp6.iso.zip
unzip -j /tmp/crimson-vc6/vs6sp6.iso.zip -d /tmp/crimson-vc6
7z e /tmp/crimson-vc6/vs6sp6.iso VS6sp61.cab -o/tmp/crimson-vc6
cabextract -F vc98/lib/libcmt.lib -d /tmp/crimson-vc6 \
  /tmp/crimson-vc6/VS6sp61.cab
cabextract -F vc98/lib/msvcrt.lib -d /tmp/crimson-vc6 \
  /tmp/crimson-vc6/VS6sp61.cab

uv run crimson match archive /tmp/crimson-vc6/vc98/lib/libcmt.lib \
  --image game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  --start 0x00460cb8 --end 0x0046e920 \
  --expected-sha256 a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a \
  --check
uv run crimson match archive /tmp/crimson-vc6/vc98/lib/libcmt.lib \
  --image game_bins/crimsonland/1.9.93-gog/grim.dll \
  --start 0x1000a8d0 --end 0x1000aaa6 \
  --expected-sha256 a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a \
  --check
uv run crimson match archive /tmp/crimson-vc6/vc98/lib/msvcrt.lib \
  --image game_bins/crimsonland/1.9.93-gog/grim.dll \
  --start 0x1000a8d0 --end 0x1000aaa6 \
  --expected-sha256 3efc3ddf045a459a2b6403f0b821be2cb7c316ffca67dddddb346cea7a9e4f63 \
  --show-matches --check
```

## libpng 1.0.5

- Evidence: `d3dx_image_load_dib` at `0x100103d6` passes `"1.0.5"` to
  `d3dx_png_create_read_struct`. The `png*.obj` members of the pinned `d3dx8.lib`
  match Grim directly; there is no separate copy.
- Sources: `png.h`, `pngconf.h` and `pngrutil.c` are synced from the release
  under `third_party/` and checked by `match provenance`.

## zlib 1.1.3

- Evidence: Grim carries the `deflate 1.1.3` and `inflate 1.1.3` banners. D3DX
  has its own namespaced copy inside `d3dx8.lib`; the JAZ path calls a separate
  plain-C copy.
- Provider: stock zlib 1.1.3 built with VC6 `/O2 /GB /W3 /MD`; the
  normalized archive has SHA-256
  `6b44ac2a8a67123b929cb9286c343730af5f6777609a54e12e402e5ac7e503b0` and
  reproduces `zlib_uncompress` at `0x10046400` byte for byte.

## libjpeg (IJG 6a)

- Evidence: Grim carries the release string `6a  7-Feb-96` and the IJG 1996
  copyright. D3DX's copy is inside `d3dx8.lib`; the JAZ decoder links a
  separate copy, built with IJG's Windows `typedef unsigned char boolean`.
- Provider: the normalized archive has SHA-256
  `c0bf240e27e8684357c676030e3cb8913d04e6b1e14f8000f069b43b17de6869`.
  `grim_jpeg_memory_src` is recovered custom source;
  `grim_jaz_jpeg_error_exit` and the JAZ payload/RLE logic are Grim's own.

Rebuild both open-source provider archives from the pinned releases:

```sh
curl -L -o /tmp/jpegsrc.v6a.tar.gz \
  https://www.ijg.org/files/jpegsrc.v6a.tar.gz
curl -L -o /tmp/zlib-1.1.3.tar.gz \
  https://zlib.net/fossils/zlib-1.1.3.tar.gz

uv run python scripts/build_native_codec_providers.py \
  --jpeg-tar /tmp/jpegsrc.v6a.tar.gz \
  --zlib-tar /tmp/zlib-1.1.3.tar.gz
```

The recipe checks the source hashes, the VC6/Wibo tool hashes, the normalized
output hashes and the required reference-address matches before publishing
either ignored archive.

## Ogg Vorbis Win32 SDK 1.0

- Version: `OggVorbis-win32sdk-1.0.zip`, SHA-256
  `e40f25803224ce4fee102e74d97c1bf77231986a9acc33eb613232e860fee7fe`.
- Evidence: the shipped `ogg.dll`, `vorbis.dll` and `vorbisfile.dll` are
  byte-identical to the SDK's. `crimsonland.exe` imports `vorbisfile.dll`
  dynamically. The headers under `third_party/headers/ogg/` and
  `third_party/headers/vorbis/` match the SDK's after CRLF normalization.
  No signatures are mapped.

```sh
mkdir -p /tmp/crimson-xiph
curl -L -o /tmp/crimson-xiph/OggVorbis-win32sdk-1.0.zip \
  'https://web.archive.org/web/20030403114946id_/http://www.vorbis.com/files/1.0/windows/OggVorbis-win32sdk-1.0.zip'
shasum -a 256 /tmp/crimson-xiph/OggVorbis-win32sdk-1.0.zip
unzip -j /tmp/crimson-xiph/OggVorbis-win32sdk-1.0.zip \
  'oggvorbis-win32sdk-1.0/bin/*.dll' -d /tmp/crimson-xiph
cmp game_bins/crimsonland/1.9.93-gog/ogg.dll /tmp/crimson-xiph/ogg.dll
cmp game_bins/crimsonland/1.9.93-gog/vorbis.dll /tmp/crimson-xiph/vorbis.dll
cmp game_bins/crimsonland/1.9.93-gog/vorbisfile.dll \
  /tmp/crimson-xiph/vorbisfile.dll
```

## Imports

`match provenance` checks each image's library imports. The full import
tables are in `analysis/ida/raw/<image>/imports.json`.
