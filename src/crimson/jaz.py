from __future__ import annotations

"""
JAZ texture format (Crimsonland Classic).

File layout:
  - u32 comp_info: compressed size in high 24 bits, low 8 bits = 1 (zlib)
  - u32 raw_info: uncompressed size in high 24 bits, low 8 bits = 0
  - u8  flags: always 0 in shipped assets
  - zlib stream (length = comp_size)

Decompressed payload:
  - u32 jpeg_len
  - jpeg bytes (length = jpeg_len)
  - alpha_rle: (count, value) byte pairs for alpha channel

Notes from assets:
  - alpha runs expand to width*height for most files; one file is short by 1 pixel.
    We pad any remaining pixels with 0 (transparent).
"""

import io
import struct
import zlib
from pathlib import Path

from PIL import Image


class JazImage:
    def __init__(self, width: int, height: int, jpeg: bytes, alpha: bytes) -> None:
        self.width = width
        self.height = height
        self.jpeg = jpeg
        self.alpha = alpha

    def rgb_image(self) -> Image.Image:
        img = Image.open(io.BytesIO(self.jpeg))
        return img.convert("RGB")

    def alpha_image(self) -> Image.Image:
        return Image.frombytes("L", (self.width, self.height), self.alpha)

    def composite_image(self) -> Image.Image:
        rgb = self.rgb_image()
        alpha = self.alpha_image()
        rgb.putalpha(alpha)
        return rgb


def decode_alpha_rle(data: bytes, expected: int) -> bytes:
    out = bytearray(expected)
    filled = 0
    for i in range(0, len(data) - 1, 2):
        count = data[i]
        value = data[i + 1]
        if count == 0:
            continue
        if filled >= expected:
            break
        end = min(filled + count, expected)
        out[filled:end] = bytes([value]) * (end - filled)
        filled = end
    return bytes(out)


def decode_jaz_bytes(data: bytes) -> JazImage:
    comp_info, raw_info = struct.unpack_from("<II", data, 0)
    comp_method = comp_info & 0xFF
    comp_size = comp_info >> 8
    raw_size = raw_info >> 8
    if comp_method != 1:
        raise ValueError(f"unsupported compression method: {comp_method}")
    comp = data[9 : 9 + comp_size]
    raw = zlib.decompress(comp)
    if len(raw) != raw_size:
        raise ValueError(f"raw size mismatch: {len(raw)} != {raw_size}")
    jpeg_len = struct.unpack_from("<I", raw, 0)[0]
    jpeg = raw[4 : 4 + jpeg_len]
    alpha_rle = raw[4 + jpeg_len :]
    img = Image.open(io.BytesIO(jpeg))
    width, height = img.size
    alpha = decode_alpha_rle(alpha_rle, width * height)
    return JazImage(width, height, jpeg, alpha)


def decode_jaz(path: str | Path) -> JazImage:
    return decode_jaz_bytes(Path(path).read_bytes())
