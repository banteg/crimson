---
name: zig
description: "Zig 0.15.x migration notes for I/O, ArrayList, JSON, and formatting changes."
---

## Zig “15” = Zig 0.15.x (baseline: 0.15.2)

Zig uses **0.x** versioning (pre-1.0). What people call “Zig 15” is almost always **Zig 0.15.x**. As of **Oct 11, 2025**, the latest stable is **0.15.2**; **0.15.1** (Aug 19, 2025) is the one with the big release notes that describe most of the breaking changes you’ll hit when moving to 0.15. ([Zig Programming Language][1])

If you’re upgrading from *much* older Zig (e.g., 0.12), one practical approach recommended by Zig’s lead is to upgrade **one release at a time** (0.13 → 0.14 → 0.15), because each step is smaller and you can use each set of release notes. ([Ziggit][2])

This guide focuses on the big 0.15.x breakage areas you named: **I/O**, **Reader/Writer**, **arrays / ArrayList**, and **JSON**—with “before/after” style migration patterns.

---

# 1) The big one: “Writergate” (new I/O model)

## What changed conceptually

Zig 0.15 deprecates the old `std.io` reader/writer interfaces and introduces **new non-generic** interfaces:

* `std.Io.Reader`
* `std.Io.Writer`

The key design shift is: **the buffer is part of the interface** (“buffer above the vtable”), not wrapped via separate `BufferedReader/BufferedWriter` layers. This is meant to reduce “anytype poisoning”, improve optimizer visibility (especially in Debug), and provide richer stream operations (discard, splat, sendFile, peek, etc.). ([Zig Programming Language][3])

### The practical consequences you feel immediately

* You now **provide buffers explicitly** in many places.
* **You must flush** buffered writers or output may never appear.
* Lots of stdlib APIs (HTTP, TLS, compression, file APIs) now accept **`*std.Io.Reader` / `*std.Io.Writer`** rather than concrete stream types. ([Zig Programming Language][3])

---

## The new “default” stdout printing pattern (buffer + flush)

### Old (pre-0.15-ish)

```zig
var stdout = std.io.getStdOut().writer();
try stdout.print("Hello\n", .{});
```

### New (0.15)

```zig
const std = @import("std");

pub fn main() !void {
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Hello\n", .{});
    try stdout.flush();
}
```

This is the recommended migration pattern: **buffering + explicit flush**. ([Zig Programming Language][3])

### “But I just want Hello World”

The language reference still shows a minimal “Hello World” via:

```zig
try std.fs.File.stdout().writeAll("Hello, World!\n");
```

That’s fine for simple output; for formatted/high-frequency output, the buffered writer pattern above is what 0.15 pushes you toward. ([Zig Programming Language][4])

---

## BufferedWriter and CountingWriter are gone (and what replaces them)

### `std.io.bufferedWriter` deleted → you supply the buffer

Old:

```zig
var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
const stdout = bw.writer();
try stdout.print("...\n", .{});
try bw.flush();
```

New:

```zig
var stdout_buffer: [4096]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout = &stdout_writer.interface;

try stdout.print("...\n", .{});
try stdout.flush();
```

([Zig Programming Language][3])

### `CountingWriter` deleted → use these instead

* discard + count: `std.Io.Writer.Discarding`
* allocate output: `std.Io.Writer.Allocating`
* fixed buffer output: `std.Io.Writer.fixed` (check `.end`) ([Zig Programming Language][3])

---

## Adapter: bridging old writers/readers to the new API

If you still have an old-style writer (common while migrating a codebase), there’s an adapter:

```zig
fn foo(old_writer: anytype) !void {
    var adapter = old_writer.adaptToNewApi(&.{});
    const w: *std.Io.Writer = &adapter.new_interface;
    try w.print("{s}", .{"example"});
}
```

This can help you migrate incrementally. ([Zig Programming Language][3])

---

# 2) Readers/Writers in 0.15: “how do I actually *use* them now?”

## The “interface pointer” shape (and the consistency trap)

A very common 0.15 stumbling block is: different concrete reader/writer wrappers expose the `*std.Io.Reader` / `*std.Io.Writer` differently:

* Some readers give you an `interface()` method.
* Some writers expose an `.interface` field you take the address of.

This is shown both in official release notes (HTTP server example) and discussed in the community (e.g., the TLS client example). ([Zig Programming Language][3])

### Example: net.Stream → TLS client

A minimal “convert Stream.Reader/Writer to Io.Reader/Writer” pattern looks like:

```zig
var writer = stream.writer(&write_buf);
var reader = stream.reader(&read_buf);

var tls_client = try std.crypto.tls.Client.init(
    reader.interface(),   // Reader → *std.Io.Reader
    &writer.interface,    // Writer → *std.Io.Writer
    .{},
);
```

Two important gotchas called out in practice:

1. **Reader/writer must have a stable address** (don’t take pointers to temporaries).
2. The buffer sizes may need to meet minimums (TLS documents a minimum like `std.crypto.tls.max_ciphertext_record_len`). ([openmymind.net][5])

---

## Reading: line-based input changed (and the error model is more explicit)

Release notes show a new pattern for delimiter-based reading that surfaces actionable errors such as:

* `error.EndOfStream`
* `error.StreamTooLong`
* `error.ReadFailed` ([Zig Programming Language][3])

Example (from the new API style):

```zig
while (reader.takeDelimiterExclusive('\n')) |line| {
    // use line
} else |err| switch (err) {
    error.EndOfStream,
    error.StreamTooLong,
    error.ReadFailed,
    => |e| return e,
}
```

([Zig Programming Language][3])

You’ll also see simpler “read line” patterns in updated community guides using methods like `takeDelimiter`. ([Zig Guide][6])

---

## Reading a file into memory using the new reader

A concrete example of the new `file.reader(&buffer)` style:

```zig
const file = try std.fs.cwd().createFile("junk_file2.txt", .{ .read = true });
defer file.close();

try file.writeAll("Hello File!");
try file.seekTo(0);

var file_buffer: [1024]u8 = undefined;
var file_reader = file.reader(&file_buffer);

const contents = try file_reader.interface.readAlloc(std.testing.allocator, 1024);
defer std.testing.allocator.free(contents);
```

This highlights a few 0.15 realities:

* you supply a **buffer** when creating the reader,
* you call through the reader interface (`file_reader.interface...`). ([Zig Guide][6])

---

# 3) Formatting + print breakage: `{f}` is now required for format methods

## The new rule

If a value has a `format` method, plain `{}` can become ambiguous. Zig 0.15 requires you to explicitly say:

* `{f}` to **call a format method**
* `{any}` to **skip** it ([Zig Programming Language][3])

Example from the release notes:

```zig
std.debug.print("{f}", .{std.zig.fmtId("example")});
```

([Zig Programming Language][3])

### Why it matters for JSON

`std.json.fmt(...)` produces a value intended to be formatted via a format method—so you typically print it with **`{f}`** (more in the JSON section). ([Zig Guide][7])

---

## Other formatting-related breakage you may notice

* **Formatted alignment is now ASCII/bytes-only**, not Unicode-aware. If you were depending on Unicode column alignment, you’ll need your own Unicode-width handling. ([Zig Programming Language][3])
* `std.fmt.format` is deprecated in favor of `std.Io.Writer.print`. ([Zig Programming Language][3])

---

# 4) Arrays in 0.15: ArrayList flipped (unmanaged is now the default)

This is the other big “every codebase feels it” change.

## What changed

* Old `std.ArrayList` (managed, stored an allocator) moved to:

  * `std.array_list.Managed`
* The default `std.ArrayList` is now the **unmanaged-style** API (allocator passed to methods). The managed variants are expected to be removed eventually. ([Zig Programming Language][3])

A community summary puts it bluntly:

> what used to be `ArrayListUnmanaged` is now `ArrayList` … old `ArrayList` is now `std.array_list.Managed`. ([Ziggit][2])

## Migration patterns

### Pattern A: building a growable byte buffer (string builder)

**0.15-style (allocator passed explicitly):**

```zig
pub fn build_query(allocator: std.mem.Allocator, params: []Param) ![]u8 {
    var response = try std.ArrayList(u8).initCapacity(allocator, 64);

    for (params) |param| {
        if (response.items.len > 0) try response.append(allocator, '&');
        try response.appendSlice(allocator, param.name);
        try response.append(allocator, '=');
        try response.appendSlice(allocator, param.value);
    }

    return response.toOwnedSlice(allocator);
}
```

This is exactly the “new normal”: allocator is *not* stored; you pass it in. ([Ziggit][2])

### Pattern B: “I just want an empty list and append”

```zig
var list: std.ArrayList(u8) = .empty;
defer list.deinit(allocator);

try list.append(allocator, 'A');
try list.appendSlice(allocator, "BC");
```

The `.empty` + `deinit(allocator)` style is used in updated 0.15 guides. ([Zig Guide][6])

### Pattern C: formatted append directly into an ArrayList

`ArrayList(u8)` can act like a string builder with `print`:

```zig
var list: std.ArrayList(u8) = .empty;
defer list.deinit(allocator);

try list.print(allocator, "Hello {s}!", .{"World"});
```

([Zig Guide][6])

---

## BoundedArray removed: what to use instead

`std.BoundedArray` is removed. The release notes recommend three broad migration choices:

1. If the “bound” is arbitrary / guessy → don’t guess; accept a buffer slice from the caller or use heap allocation.
2. If it’s “type safety around a stack buffer” → use ArrayList (unmanaged) backed by a fixed buffer.
3. If it’s a rare fixed-capacity ordered set → hand-roll it. ([Zig Programming Language][3])

The notes show replacing BoundedArray with `initBuffer(&buffer)` + bounded append operations. ([Zig Programming Language][3])

---

## “Ring buffers” and `std.fifo` deletions (related to arrays + IO)

0.15 deletes several ring-buffer implementations (`std.fifo.LinearFifo`, `std.RingBuffer`, etc.), explicitly pointing out that the new `std.Io.Reader` / `std.Io.Writer` are themselves ring buffers and cover many of the prior use cases. `std.fifo` is deleted. ([Zig Programming Language][3])

If your code used `std.fifo`/queues, expect to either:

* switch to a different std container (if available),
* adopt a third-party deque/queue,
* or implement a small specialized structure.

---

# 5) JSON in Zig 0.15: parsing is familiar; writing changed because I/O changed

## Parsing JSON: `parseFromSlice` still looks like you remember

Example:

```zig
const Place = struct { lat: f32, long: f32 };

const parsed = try std.json.parseFromSlice(
    Place,
    allocator,
    \\{ "lat": 40.684540, "long": -74.401422 }
,
    .{},
);
defer parsed.deinit();

const place = parsed.value;
```

Key points:

* you pass an allocator,
* you `deinit()` the parsed result to free allocations. ([Zig Guide][7])

---

## Writing / stringifying JSON: two good 0.15-native approaches

### Approach A: `std.json.fmt(...)` + print with `{f}`

This is very ergonomic when you already have a Writer and want formatting control:

```zig
try writer.print("{f}", .{std.json.fmt(value, .{})});
```

A full “stringify into an allocated string” example uses an allocating writer and the `{f}` format specifier:

```zig
var out: std.Io.Writer.Allocating = .init(allocator);
defer out.deinit();

try out.writer.print("{f}", .{std.json.fmt(x, .{})});
const bytes = out.written();
```

This pattern is shown in up-to-date 0.15 guides, and `{f}` is required due to the 0.15 formatting rule change. ([Zig Guide][7])

### Approach B: `std.json.Stringify.value(...)` writing directly to a `*std.Io.Writer`

This is great for fixed buffers and for streaming to files/sockets.

Fixed buffer example:

```zig
var buffer: [256]u8 = undefined;
var w = std.Io.Writer.fixed(&buffer);

try std.json.Stringify.value(.{
    .a_number = @as(u32, 10),
    .a_str = "hello",
}, .{}, &w);

const json_bytes = buffer[0..w.end];
```

That exact shape is used in modern 0.15 examples. ([Renato Athaydes][8])

---

## Writing JSON to a file in 0.15 (putting it all together)

A practical pattern:

1. Create a **buffered file writer**
2. Write JSON using either method
3. `flush()`

```zig
const std = @import("std");

pub fn writeJsonToStdout(value: anytype) !void {
    var buf: [4096]u8 = undefined;
    var fw = std.fs.File.stdout().writer(&buf);
    const out = &fw.interface;

    try out.print("{f}\n", .{std.json.fmt(value, .{})});
    try out.flush();
}
```

This combines:

* buffered stdout writer + flush ([Zig Programming Language][3])
* `{f}` rule for format-method values like `std.json.fmt` ([Zig Programming Language][3])

---

# 6) High-signal “rename/deletion” cheat sheet for these areas

From the 0.15 release notes’ “Deletions and Deprecations” section (selected items that commonly break builds): ([Zig Programming Language][3])

### I/O / Reader / Writer

* `std.io.GenericReader` → `std.Io.Reader`
* `std.io.GenericWriter` → `std.Io.Writer`
* `std.io.AnyReader` → `std.Io.Reader`
* `std.io.AnyWriter` → `std.Io.Writer`
* `std.fs.File.reader` → `std.fs.File.deprecatedReader`
* `std.fs.File.writer` → `std.fs.File.deprecatedWriter`
* deleted: `std.io.SeekableStream`
  → use `*std.fs.File.Reader`, `*std.fs.File.Writer`, or an in-memory concrete type like ArrayList (depending on what you’re actually doing). ([Zig Programming Language][3])
* deleted: `std.Io.BufferedReader`
* deleted: `std.io.bufferedWriter` (BufferedWriter)
  → supply a buffer to the writer directly. ([Zig Programming Language][3])

### Arrays / ArrayList

* `std.ArrayList` (managed) → `std.array_list.Managed` (planned for eventual removal)
* default `std.ArrayList` is now unmanaged-style (allocator passed to methods). ([Zig Programming Language][3])
* removed: `std.BoundedArray`
  → use caller-provided buffers, allocation, or ArrayList backed by a stack buffer. ([Zig Programming Language][3])

### JSON

* Parsing: `std.json.parseFromSlice` remains the go-to for “parse JSON bytes into a type.” ([Zig Guide][7])
* Writing: prefer `std.json.fmt` + `{f}`, or `std.json.Stringify.value` to a `*std.Io.Writer`. ([Zig Guide][7])

---

# 7) Common 0.15 migration errors and what they mean

## “Nothing prints”

You forgot to `flush()` your buffered writer. The release notes explicitly warn about this, and it’s the most common surprise. ([Zig Programming Language][3])

## “ambiguous format string; specify {f} … or {any} …”

You’re printing something that provides a format method (e.g. `std.zig.fmtId`, `std.json.fmt`, and many more). Update `{}` to `{f}` (or `{any}` if you explicitly want the raw debug-ish representation). ([Zig Programming Language][3])

## “expected type *std.Io.Writer, found …”

A stdlib API now wants the **interface pointer**, not your concrete writer type.

* For many writers you pass `&some_writer.interface`
* For some readers you pass `some_reader.interface()`

Also ensure the underlying objects live long enough (stable address). ([Zig Programming Language][3])

## ArrayList: “method requires allocator parameter”

That’s expected: in 0.15 the default ArrayList no longer stores the allocator. Update calls like:

* `list.append(x)` → `list.append(allocator, x)`
* `list.deinit()` → `list.deinit(allocator)`
* `list.toOwnedSlice()` → `list.toOwnedSlice(allocator)` ([Ziggit][2])

---

# 8) A practical upgrade checklist (I/O + arrays + JSON)

1. **Pick Zig 0.15.2** as your target compiler. ([Zig Programming Language][1])
2. If upgrading from older Zig, do sequential upgrades (0.13 → 0.14 → 0.15) and read each release note set. ([Ziggit][2])
3. Replace old stdout/stderr patterns:

   * `std.io.getStdOut().writer()` → `std.fs.File.stdout().writer(&buf)` + `flush()` ([Zig Programming Language][3])
4. Remove `bufferedWriter`/`CountingWriter` usage; switch to explicit buffers and the new helper writers. ([Zig Programming Language][3])
5. Fix formatting compilation errors:

   * `{}` → `{f}` where needed
   * use `std.Io.Writer.print` instead of old `std.fmt.format`-centric patterns ([Zig Programming Language][3])
6. Convert ArrayList usage:

   * assume allocator is now an argument to methods
   * use `.empty`, `initCapacity`, `deinit(allocator)` patterns ([Zig Programming Language][3])
7. JSON:

   * parsing likely unchanged
   * writing: use `std.json.fmt` + `{f}` or `std.json.Stringify.value` to a `*std.Io.Writer` ([Zig Guide][7])

---

If you want, paste one or two representative snippets from your *pre-0.15* code (one I/O example + one ArrayList/JSON example) and I’ll rewrite them into idiomatic 0.15.2 style using the new interfaces—no “mystery anytype”, explicit allocator passing, and correct flush behavior.

[1]: https://ziglang.org/download/ "https://ziglang.org/download/"
[2]: https://ziggit.dev/t/arraylist-and-allocator-updating-code-to-0-15/12167 "https://ziggit.dev/t/arraylist-and-allocator-updating-code-to-0-15/12167"
[3]: https://ziglang.org/download/0.15.1/release-notes.html "https://ziglang.org/download/0.15.1/release-notes.html"
[4]: https://ziglang.org/documentation/0.15.2/ "https://ziglang.org/documentation/0.15.2/"
[5]: https://www.openmymind.net/Im-Too-Dumb-For-Zigs-New-IO-Interface/ "https://www.openmymind.net/Im-Too-Dumb-For-Zigs-New-IO-Interface/"
[6]: https://zig.guide/standard-library/readers-and-writers/ "https://zig.guide/standard-library/readers-and-writers/"
[7]: https://zig.guide/standard-library/json/ "https://zig.guide/standard-library/json/"
[8]: https://renatoathaydes.github.io/zig-common-tasks/ "https://renatoathaydes.github.io/zig-common-tasks/"
