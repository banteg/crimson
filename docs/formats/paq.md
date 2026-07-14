---
tags:
  - status-parity
---

# PAQ archive format
PAQ is the simple container format used by Crimsonland.
It is a flat stream with no central directory; entries are read sequentially
until EOF.

## Layout

```
u8[4]  magic      = "paq\\0"
repeat until EOF:
  cstring name    (NUL-terminated UTF-8 path)
  u32     size    (little-endian)
  u8[size] payload
```

## Notes

- `name` is a relative path (often with backslashes in the original files).
- There is no checksum or footer.
- The extractor normalizes path separators and rejects `.`/`..` segments to
  avoid directory traversal.
- Native `grim_lookup_blob_find` starts at `strlen("paq") + 1`, compares each
  path exactly, returns `name + strlen(name) + 5` on a match, and otherwise
  advances by the encoded payload size plus the path and header lengths.
