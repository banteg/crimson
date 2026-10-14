"""
JAZ texture format (Crimsonland).

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

from __future__ import annotations

import io
import struct
import zlib

from PIL import Image

_JAZ_HEADER = struct.Struct("<BII")
_U32 = struct.Struct("<I")

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


def _parse_jaz_payload(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < _JAZ_HEADER.size:
        raise ValueError("truncated JAZ header")
    method, comp_size, raw_size = _JAZ_HEADER.unpack_from(data, 0)
    if method != 1:
        raise ValueError(f"unsupported compression method: {method}")
    comp_end = _JAZ_HEADER.size + comp_size
    if len(data) < comp_end:
        raise ValueError("truncated JAZ compressed stream")
    raw = zlib.decompress(data[_JAZ_HEADER.size : comp_end])
    if len(raw) != raw_size:
        raise ValueError(f"raw size mismatch: {len(raw)} != {raw_size}")
    if len(raw) < _U32.size:
        raise ValueError("truncated JAZ payload")
    (jpeg_len,) = _U32.unpack_from(raw, 0)
    jpeg_end = _U32.size + jpeg_len
    if jpeg_end > len(raw):
        raise ValueError("truncated JAZ JPEG stream")
    return raw[_U32.size : jpeg_end], raw[jpeg_end:]


def jaz_size(data: bytes) -> tuple[int, int]:
    """Return (width, height) from the embedded JPEG header without decoding pixels."""
    jpeg, _alpha_rle = _parse_jaz_payload(data)
    return Image.open(io.BytesIO(jpeg)).size


def decode_jaz_bytes(data: bytes) -> JazImage:
    jpeg, alpha_rle = _parse_jaz_payload(data)
    img = Image.open(io.BytesIO(jpeg))
    width, height = img.size
    alpha = decode_alpha_rle(alpha_rle, width * height)
    return JazImage(width, height, jpeg, alpha)
