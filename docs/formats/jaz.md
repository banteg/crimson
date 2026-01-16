# JAZ texture format

**Status:** Completed

JAZ wraps a JPEG color image with a run-length encoded alpha channel.
The file begins with a small header followed by a zlib stream.

## Layout

```
u8      method     (1 = zlib)
u32     comp_size  (compressed payload size)
u32     raw_size   (uncompressed payload size)
u8[comp_size] zlib_stream
```

Decompressed payload:

```
u32        jpeg_len
u8[jpeg_len] jpeg_bytes
u8[]        alpha_rle (pairs of count,value bytes)
```

## Alpha RLE

The alpha stream is a sequence of `(count, value)` byte pairs.
Each pair expands to `count` pixels with alpha value `value`.
The expected output size is `width * height`, where width/height come from the
decoded JPEG. Most assets match exactly; one file is short by 1 pixel, so the
decoder pads with 0 (transparent) to reach the expected size.

## Notes

- The JPEG provides RGB; alpha is applied to make a composite RGBA image.
- The extractor currently writes only the composite PNG for `.jaz` entries.
