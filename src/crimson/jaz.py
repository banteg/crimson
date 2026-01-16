from __future__ import annotations

"""
JAZ texture format (Crimsonland Classic).

File layout:
  - u8  method: compression method (1 = zlib)
  - u32 comp_size: compressed payload size (bytes)
  - u32 raw_size: uncompressed payload size (bytes)
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
import zlib
from pathlib import Path

from PIL import Image
from construct import Bytes, Int8ul, Int32ul, Struct, this


JAZ_HEADER = Struct(
    "method" / Int8ul,
    "comp_size" / Int32ul,
    "raw_size" / Int32ul,
)

JAZ_FILE = Struct(
    "header" / JAZ_HEADER,
    "compressed" / Bytes(this.header.comp_size),
)


def jaz_payload(raw_size: int) -> Struct:
    return Struct(
        "jpeg_len" / Int32ul,
        "jpeg" / Bytes(this.jpeg_len),
        "alpha_rle" / Bytes(raw_size - 4 - this.jpeg_len),
    )


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
    parsed = JAZ_FILE.parse(data)
    header = parsed.header
    if header.method != 1:
        raise ValueError(f"unsupported compression method: {header.method}")
    raw = zlib.decompress(parsed.compressed)
    if len(raw) != header.raw_size:
        raise ValueError(f"raw size mismatch: {len(raw)} != {header.raw_size}")
    payload = jaz_payload(header.raw_size).parse(raw)
    img = Image.open(io.BytesIO(payload.jpeg))
    width, height = img.size
    alpha = decode_alpha_rle(payload.alpha_rle, width * height)
    return JazImage(width, height, payload.jpeg, alpha)


def decode_jaz(path: str | Path) -> JazImage:
    return decode_jaz_bytes(Path(path).read_bytes())
