---
tags:
  - status-completed
---

# PAQ archive format

**Status:** Completed

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
