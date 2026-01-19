# Zig "15" = Zig 0.15.x (baseline: 0.15.2)

Zig uses **0.x** versioning (pre-1.0). What people call “Zig 15” is almost always **Zig 0.15.x**. As of **Oct 11, 2025**, the latest stable is **0.15.2**; **0.15.1** (Aug 19, 2025) is the one with the big release notes that describe most of the breaking changes you’ll hit when moving to 0.15. ([Zig Programming Language][1])

If you’re upgrading from *much* older Zig (e.g., 0.12), one practical approach recommended by Zig’s lead is to upgrade **one release at a time** (0.13 → 0.14 → 0.15), because each step is smaller and you can use each set of release notes. ([Ziggit][2])

This guide focuses on the big 0.15.x breakage areas you named: **I/O**, **Reader/Writer**, **arrays / ArrayList**, and **JSON**—with “before/after” style migration patterns.

---

## 1) The big one: "Writergate" (new I/O model)

### What changed conceptually

Zig 0.15 deprecates the old `std.io` reader/writer interfaces and introduces **new non-generic** interfaces:

* `std.Io.Reader`
* `std.Io.Writer`

The key design shift is: **the buffer is part of the interface** (“buffer above the vtable”), not wrapped via separate `BufferedReader/BufferedWriter` layers. This is meant to reduce “anytype poisoning”, improve optimizer visibility (especially in Debug), and provide richer stream operations (discard, splat, sendFile, peek, etc.). ([Zig Programming Language][3])

#### The practical consequences you feel immediately

* You now **provide buffers explicitly** in many places.
* **You must flush** buffered writers or output may never appear.
* Lots of stdlib APIs (HTTP, TLS, compression, file APIs) now accept **`*std.Io.Reader` / `*std.Io.Writer`** rather than concrete stream types. ([Zig Programming Language][3])

---

### The new "default" stdout printing pattern (buffer + flush)

#### Old (pre-0.15-ish)

```zig
var stdout = std.io.getStdOut().writer();
try stdout.print("Hello\n", .{});
```

#### New (0.15)

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

#### "But I just want Hello World"

The language reference still shows a minimal “Hello World” via:

```zig
try std.fs.File.stdout().writeAll("Hello, World!\n");
```

That’s fine for simple output; for formatted/high-frequency output, the buffered writer pattern above is what 0.15 pushes you toward. ([Zig Programming Language][4])

---

### BufferedWriter and CountingWriter are gone (and what replaces them)

#### `std.io.bufferedWriter` deleted → you supply the buffer

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

#### `CountingWriter` deleted → use these instead

* discard + count: `std.Io.Writer.Discarding`
* allocate output: `std.Io.Writer.Allocating`
* fixed buffer output: `std.Io.Writer.fixed` (check `.end`) ([Zig Programming Language][3])

---

### Adapter: bridging old writers/readers to the new API

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

## 2) Readers/Writers in 0.15: "how do I actually *use* them now?"

### The "interface pointer" shape (and the consistency trap)

A very common 0.15 stumbling block is: different concrete reader/writer wrappers expose the `*std.Io.Reader` / `*std.Io.Writer` differently:

* Some readers give you an `interface()` method.
* Some writers expose an `.interface` field you take the address of.

This is shown both in official release notes (HTTP server example) and discussed in the community (e.g., the TLS client example). ([Zig Programming Language][3])

#### Example: net.Stream → TLS client

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

### Reading: line-based input changed (and the error model is more explicit)

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

### Reading a file into memory using the new reader

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

## 3) Formatting + print breakage: `{f}` is now required for format methods

### The new rule

If a value has a `format` method, plain `{}` can become ambiguous. Zig 0.15 requires you to explicitly say:

* `{f}` to **call a format method**
* `{any}` to **skip** it ([Zig Programming Language][3])

Example from the release notes:

```zig
std.debug.print("{f}", .{std.zig.fmtId("example")});
```

([Zig Programming Language][3])

#### Why it matters for JSON

`std.json.fmt(...)` produces a value intended to be formatted via a format method—so you typically print it with **`{f}`** (more in the JSON section). ([Zig Guide][7])

---

### Other formatting-related breakage you may notice

* **Formatted alignment is now ASCII/bytes-only**, not Unicode-aware. If you were depending on Unicode column alignment, you’ll need your own Unicode-width handling. ([Zig Programming Language][3])
* `std.fmt.format` is deprecated in favor of `std.Io.Writer.print`. ([Zig Programming Language][3])

---

## 4) Arrays in 0.15: ArrayList flipped (unmanaged is now the default)

This is the other big “every codebase feels it” change.

### What changed

* Old `std.ArrayList` (managed, stored an allocator) moved to:

  * `std.array_list.Managed`
* The default `std.ArrayList` is now the **unmanaged-style** API (allocator passed to methods). The managed variants are expected to be removed eventually. ([Zig Programming Language][3])

A community summary puts it bluntly:

> what used to be `ArrayListUnmanaged` is now `ArrayList` … old `ArrayList` is now `std.array_list.Managed`. ([Ziggit][2])

### Migration patterns

#### Pattern A: building a growable byte buffer (string builder)

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

#### Pattern B: "I just want an empty list and append"

```zig
var list: std.ArrayList(u8) = .empty;
defer list.deinit(allocator);

try list.append(allocator, 'A');
try list.appendSlice(allocator, "BC");
```

The `.empty` + `deinit(allocator)` style is used in updated 0.15 guides. ([Zig Guide][6])

#### Pattern C: formatted append directly into an ArrayList

`ArrayList(u8)` can act like a string builder with `print`:

```zig
var list: std.ArrayList(u8) = .empty;
defer list.deinit(allocator);

try list.print(allocator, "Hello {s}!", .{"World"});
```

([Zig Guide][6])

---

### BoundedArray removed: what to use instead

`std.BoundedArray` is removed. The release notes recommend three broad migration choices:

1. If the “bound” is arbitrary / guessy → don’t guess; accept a buffer slice from the caller or use heap allocation.
2. If it’s “type safety around a stack buffer” → use ArrayList (unmanaged) backed by a fixed buffer.
3. If it’s a rare fixed-capacity ordered set → hand-roll it. ([Zig Programming Language][3])

The notes show replacing BoundedArray with `initBuffer(&buffer)` + bounded append operations. ([Zig Programming Language][3])

---

### "Ring buffers" and `std.fifo` deletions (related to arrays + IO)

0.15 deletes several ring-buffer implementations (`std.fifo.LinearFifo`, `std.RingBuffer`, etc.), explicitly pointing out that the new `std.Io.Reader` / `std.Io.Writer` are themselves ring buffers and cover many of the prior use cases. `std.fifo` is deleted. ([Zig Programming Language][3])

If your code used `std.fifo`/queues, expect to either:

* switch to a different std container (if available),
* adopt a third-party deque/queue,
* or implement a small specialized structure.

---

## 5) JSON in Zig 0.15: parsing is familiar; writing changed because I/O changed

### Parsing JSON: `parseFromSlice` still looks like you remember

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

### Writing / stringifying JSON: two good 0.15-native approaches

#### Approach A: `std.json.fmt(...)` + print with `{f}`

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

#### Approach B: `std.json.Stringify.value(...)` writing directly to a `*std.Io.Writer`

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

### Writing JSON to a file in 0.15 (putting it all together)

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

## 6) High-signal "rename/deletion" cheat sheet for these areas

From the 0.15 release notes’ “Deletions and Deprecations” section (selected items that commonly break builds): ([Zig Programming Language][3])

#### I/O / Reader / Writer

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

#### Arrays / ArrayList

* `std.ArrayList` (managed) → `std.array_list.Managed` (planned for eventual removal)
* default `std.ArrayList` is now unmanaged-style (allocator passed to methods). ([Zig Programming Language][3])
* removed: `std.BoundedArray`
  → use caller-provided buffers, allocation, or ArrayList backed by a stack buffer. ([Zig Programming Language][3])

#### JSON

* Parsing: `std.json.parseFromSlice` remains the go-to for “parse JSON bytes into a type.” ([Zig Guide][7])
* Writing: prefer `std.json.fmt` + `{f}`, or `std.json.Stringify.value` to a `*std.Io.Writer`. ([Zig Guide][7])

---

## 7) Common 0.15 migration errors and what they mean

### "Nothing prints"

You forgot to `flush()` your buffered writer. The release notes explicitly warn about this, and it’s the most common surprise. ([Zig Programming Language][3])

### "ambiguous format string; specify {f} … or {any} …"

You’re printing something that provides a format method (e.g. `std.zig.fmtId`, `std.json.fmt`, and many more). Update `{}` to `{f}` (or `{any}` if you explicitly want the raw debug-ish representation). ([Zig Programming Language][3])

### "expected type *std.Io.Writer, found …"

A stdlib API now wants the **interface pointer**, not your concrete writer type.

* For many writers you pass `&some_writer.interface`
* For some readers you pass `some_reader.interface()`

Also ensure the underlying objects live long enough (stable address). ([Zig Programming Language][3])

### ArrayList: "method requires allocator parameter"

That’s expected: in 0.15 the default ArrayList no longer stores the allocator. Update calls like:

* `list.append(x)` → `list.append(allocator, x)`
* `list.deinit()` → `list.deinit(allocator)`
* `list.toOwnedSlice()` → `list.toOwnedSlice(allocator)` ([Ziggit][2])

---

## 8) A practical upgrade checklist (I/O + arrays + JSON)

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

---

Below is a “how to write idiomatic Zig” guide aimed at **Zig 0.15.x** (what you called “Zig 15”). I’m going to assume **Zig 0.15.2** as the reference point (released **2025‑10‑11**). ([Zig Programming Language][1])

---

## Idiomatic Zig 0.15: style, patterns, and cheatsheets

### The mindset that produces idiomatic Zig

Zig’s own “Zen” is a good north star. It’s not “rules”, but it explains why idioms look the way they do. ([Zig Programming Language][2])

* **Communicate intent precisely.** ([Zig Programming Language][2])
* **Edge cases matter.** ([Zig Programming Language][2])
* **Favor reading code over writing code.** ([Zig Programming Language][2])
* **Only one obvious way to do things.** ([Zig Programming Language][2])
* **Runtime crashes are better than bugs.** ([Zig Programming Language][2])
* **Compile errors are better than runtime crashes.** ([Zig Programming Language][2])
* **Incremental improvements.** ([Zig Programming Language][2])
* **Avoid local maximums.** ([Zig Programming Language][2])
* **Reduce the amount one must remember.** ([Zig Programming Language][2])
* **Minimize energy spent on coding style.** ([Zig Programming Language][2])
* **Together we serve the users.** ([Zig Programming Language][2])

Two other “philosophy facts” drive idioms a lot:

* Zig tries hard to avoid **hidden control flow** and **hidden allocations**—you can usually trust what you see. ([Zig Programming Language][3])
* Zig expects you to **handle allocation failure** and to pass allocators into code that needs them. ([Zig Programming Language][3])

---

### "Style" in Zig: mostly just `zig fmt`

#### The golden rule

Run **`zig fmt`** and don’t fight it. The official style guide explicitly says `zig fmt` will apply the recommendations and that a style guide is only needed for cases where `zig fmt` doesn’t format something. ([Zig Programming Language][2])

#### Naming conventions (official)

The language reference’s style guide lays out the conventions most people treat as canonical: ([Zig Programming Language][2])

* `lower_snake_case` for:

  * functions
  * variables
  * file names (when the file is “a namespace/module”) ([Zig Programming Language][2])
* `TitleCase` for:

  * types (`struct`, `enum`, `union`, etc.) ([Zig Programming Language][2])
* Names should **not** redundantly encode the namespace/type (avoid `array_list.ArrayList`-style repetition). ([Zig Programming Language][2])

#### Doc comments (official)

* `///` documents the next declaration.
* `//!` documents the containing *thing* (often a file/module). ([Zig Programming Language][2])

The style guide also recommends a useful convention in API docs:

* Use **“Assume”** for preconditions that are *illegal behavior* if violated.
* Use **“Assert”** for preconditions that are checked and produce safety-checked failure. ([Zig Programming Language][2])

#### Bonus: generating docs

Doc comments can be emitted as HTML using `zig test -femit-docs …`. ([Zig Programming Language][2])

---

### Idiomatic defaults: `const`, explicit lifetimes, explicit ownership

#### Prefer `const` by default

Idiomatic Zig code is aggressively immutable until it must be mutable:

```zig
const std = @import("std");

pub fn main() !void {
    const greeting = "hello";
    var counter: usize = 0;

    // counter changes, greeting doesn’t.
    counter += 1;
    _ = greeting;
}
```

This aligns with “communicate intent precisely”: mutability stands out.

#### Ownership & lifetime are part of the API surface

The language reference is blunt: it’s the programmer’s responsibility to ensure pointers aren’t used after the memory is gone, and docs should explain who “owns” returned pointers. ([Zig Programming Language][2])

Idiomatic library functions that return allocated memory typically follow this contract:

* Function takes `allocator: std.mem.Allocator`
* Return value is `![]u8` / `![]T`
* Doc says: **caller owns returned memory** → caller frees it with the same allocator

Example pattern:

```zig
/// Reads an entire file into memory.
/// Caller owns the returned buffer and must free it with `allocator.free`.
fn read_file_alloc(allocator: std.mem.Allocator, path: []const u8, max: usize) ![]u8 {
    const std = @import("std");

    const file = try std.fs.cwd().openFile(path, .{ .read = true });
    defer file.close();

    var buf: [4096]u8 = undefined;
    var r = file.reader(&buf);

    // readAlloc allocates up to `max`, else error (e.g. StreamTooLong).
    const data = try r.interface.readAlloc(allocator, max);
    return data;
}
```

That `file.reader(&buf)` + `r.interface.readAlloc(...)` pattern matches current 0.15-era usage. ([Zig Guide][4])

---

### Strings, bytes, and "arrays vs slices" (the idiomatic mental model)

#### Strings are bytes

In Zig, “strings” are usually just `[]const u8` (a byte slice you *treat* as UTF‑8).

#### Arrays vs slices (practical meaning)

* `[N]T` is an **array value** with length known at compile time.
* `[]T` is a **slice**: pointer + length (a view into something else).
* `[]const u8` is the most common “string view”.

#### String literals are *not* mutable slices

The language reference shows this sharp edge clearly: string literals have an array pointer type, and you can’t assign them to `[]u8` (mutable slice).

If you want a mutable buffer, allocate or use an array:

```zig
var buf: [13]u8 = "hello, world!".*; // make a mutable copy
const slice: []u8 = buf[0..];
```

---

### Errors & optionals: idiomatic control flow tools

#### Errors are values and can't be silently ignored

Zig will complain if you discard an error union without handling it, and it tells you to use `try`, `catch`, or `if`. ([Zig Programming Language][3])

#### Idiomatic patterns

**1) Propagate with `try`**

```zig
const file = try std.fs.cwd().openFile("x.txt", .{});
defer file.close();
```

**2) Handle or map with `catch`**

```zig
const file = std.fs.cwd().openFile("x.txt", .{}) catch |err| switch (err) {
    error.FileNotFound => return, // treat as “no-op”
    else => return err,
};
defer file.close();
```

**3) Cleanup on errors with `errdefer`**
This is the “idiomatic RAII substitute”: allocate in steps, `errdefer` cleanup each step.

```zig
var list: std.ArrayList(u8) = .empty;
errdefer list.deinit(allocator);

try list.appendSlice(allocator, "hello");
// if later code errors, list gets deinit’d automatically
```

**4) Use `?T` for “maybe present”, not `error`**

* `?T` means “this is allowed to be missing”
* `error!T` means “this operation can fail”

#### Heap allocation failure is a first-class error

Zig’s docs explicitly recommend treating `error.OutOfMemory` as the representation of heap allocation failure, rather than unconditionally crashing. ([Zig Programming Language][2])

That’s why idiomatic Zig APIs:

* take allocators explicitly
* return `error.OutOfMemory` when they allocate

---

### Resource management: `defer` and "make cleanup obvious"

Idiomatic Zig tries to make resource cleanup visually checkable:

```zig
const file = try std.fs.cwd().openFile("data.bin", .{});
defer file.close(); // always runs, even on error

// ...
```

Use `errdefer` when the cleanup is only correct for the error path (e.g., before “ownership” has been transferred).

---

### Containers in Zig 0.15: ArrayList is unmanaged by default

#### The big idiom shift

In Zig 0.15, the **unmanaged** variant is the default:

* `std.ArrayList` → `std.array_list.Managed` (old “allocator-storing” flavor)
* the default `std.ArrayList` now follows the “pass allocator to methods” style
  The release notes explain the rationale and warn the managed names will eventually be removed. ([Zig Programming Language][5])

#### Idiomatic ArrayList usage (0.15)

Use `.empty`, pass an allocator to operations, and `deinit(allocator)`:

```zig
const std = @import("std");

test "arraylist basics" {
    const allocator = std.testing.allocator;

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);

    try list.appendSlice(allocator, "Hello");
    try list.appendSlice(allocator, " World!");

    try std.testing.expectEqualStrings("Hello World!", list.items);
}
```

That matches common 0.15-era examples. ([Zig Guide][6])

#### Stack-buffer backed "array list"

0.15 also pushes a pattern: if you want a fixed maximum but stack storage, use `ArrayListUnmanaged.initBuffer(&buffer)` and bounded appends. ([Zig Programming Language][5])

---

### I/O in Zig 0.15: the idiomatic Reader/Writer style

Zig 0.15’s I/O story heavily influences “idiomatic Zig”, because it nudges you to write APIs that accept readers/writers rather than concrete streams or generic types.

#### The core idiom

* Create a writer/reader with an explicit buffer
* Pass around `*std.Io.Writer` / `*std.Io.Reader` (the interface)
* Remember to `flush()` when you need output visible

The release notes are explicit: “Please use buffering! And don’t forget to flush!” and show the new stdout pattern. ([Zig Programming Language][5])

Example (stdout):

```zig
const std = @import("std");

pub fn main() !void {
    var buf: [1024]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    const stdout = &w.interface;

    try stdout.print("Hello, {s}!\n", .{"world"});
    try stdout.flush();
}
```

#### Write functions that accept a writer (idiomatic library design)

```zig
fn greet(writer: *std.Io.Writer, name: []const u8) !void {
    try writer.print("Hello, {s}!\n", .{name});
}
```

This is idiomatic because:

* it avoids hidden allocations (callers choose buffering / destination)
* it composes with files, sockets, memory writers, etc.

#### `std.debug.print` is for "debug output; ignore errors"

The language reference notes that `std.debug.print` is appropriate for stderr where errors are irrelevant, and it’s simpler than building your own writer. ([Zig Programming Language][2])

---

### Formatting in Zig 0.15: `{f}`, new `format` signature, and "print everywhere"

#### Prefer `writer.print(...)` over `std.fmt.format`

0.15 deprecates/redirects older formatting patterns toward writers:

* `std.fmt.format -> std.Io.Writer.print` ([Zig Programming Language][5])

#### `{f}` is how you call a type's format method now

Zig 0.15.1 changed custom formatting:

* Old `format` took a format string + options + `anytype writer`
* New `format` is:

  ```zig
  pub fn format(this: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void
  ```

  ([Zig Programming Language][5])

And it’s invoked with `{f}` rather than `{}`. ([Zig Programming Language][5])

#### `std.fmt.allocPrint` and friends are still idiomatic when you need a string

If you truly want a string in memory, `std.fmt.allocPrint` is a straightforward idiom. ([Zig Guide][7])

```zig
const s = try std.fmt.allocPrint(allocator, "{d} + {d}", .{ 1, 2 });
defer allocator.free(s);
```

#### Formatting specifier cheat sheet (common ones)

A few that show up constantly (examples are from Zig 0.15.2 guides): ([Zig Guide][8])

* `{s}` string / byte slice
* `{d}` decimal (ints & floats)
* `{x}` / `{X}` hex (lower/upper)
* `{b}` binary, `{o}` octal
* `{c}` ASCII character for a byte
* `{*}` pointer address formatting ([Zig Guide][8])
* `{e}` scientific notation ([Zig Guide][8])
* `{t}` shorthand for `@tagName()` / `@errorName()` ([Zig Programming Language][5])
* `{B}` / `{Bi}` size formatting variants ([Zig Guide][8])
* `{f}` call `.format(writer)` on a value ([Zig Programming Language][5])

---

### JSON in Zig 0.15: idiomatic parsing & printing

#### Parse into a typed struct (idiomatic)

The “typed parse” pattern is:

* `std.json.parseFromSlice(T, allocator, input, options)`
* `defer parsed.deinit()`
* use `parsed.value`

Example: ([Zig Guide][9])

```zig
const Place = struct { lat: f32, long: f32 };

const parsed = try std.json.parseFromSlice(
    Place,
    allocator,
    input_bytes,
    .{},
);
defer parsed.deinit();

const place = parsed.value;
```

#### Stringify / format JSON (idiomatic)

A convenient idiom in 0.15 is: create an allocating writer, then `print("{f}", .{std.json.fmt(value, .{})})`. ([Zig Guide][9])

```zig
var out: std.io.Writer.Allocating = .init(allocator);
defer out.deinit();

try out.writer.print("{f}", .{std.json.fmt(value, .{})});
const json_bytes = out.written();
```

(Notice the `{f}`: it matches the 0.15 formatting model.) ([Zig Guide][9])

Also note: JSON parsing needs an allocator for strings/arrays/maps inside JSON data. ([Zig Guide][9])

---

### Build system (0.15 idioms): `root_module` + `createModule`

A minimal, idiomatic `build.zig` in 0.15 looks like this (from Zig’s build system docs): ([Zig Programming Language][10])

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "hello",
        .root_module = b.createModule(.{
            .root_source_file = b.path("hello.zig"),
            .target = b.graph.host,
        }),
    });

    b.installArtifact(exe);
}
```

If you’re coming from older versions: 0.15 removed deprecated root module fields, so this `root_module = b.createModule(...)` style is the “new normal”. ([Zig Programming Language][5])

---

### Comptime & generics: idiomatic guidance (practical, not dogmatic)

Zig idioms around generics tend to favor:

* **Use `comptime` and `@TypeOf`** when it improves clarity, not just because you can.
* Prefer a **`*std.Io.Writer` / `*std.Io.Reader`** argument (interface) over `anytype` writer/reader in public APIs if you want to avoid code bloat and keep call sites stable—0.15’s I/O changes reinforce this. ([Zig Programming Language][5])
* When supporting multiple Zig versions, prefer **feature detection** (`@hasDecl`, `@hasField`) over version checks. ([Zig Programming Language][2])

---

## Cheatsheets

### 1) Declarations & basics

```zig
const std = @import("std");

// immutable binding
const x: i32 = 123;

// mutable binding
var y: usize = 0;

// function
fn add(a: i32, b: i32) i32 {
    return a + b;
}

// error-returning main (common)
pub fn main() !void {}

// test
test "something" {
    try std.testing.expect(true);
}
```

### 2) Types: arrays, slices, pointers

* `[N]T` → array value (stack-allocated when local)
* `[]T` → slice (ptr + len)
* `[]const u8` → most common “string”
* `*T` → single-item pointer (non-null)
* `?*T` → optional pointer
* `[*]T` → many-item pointer (unknown length)
* `[*:0]const u8` → sentinel-terminated pointer (C string)
* `[:0]u8` → sentinel-terminated slice

**String literal reminder:** not a mutable `[]u8` by default.

### 3) Optionals (`?T`)

```zig
const maybe: ?u32 = 10;

const v1: u32 = maybe orelse 0;

if (maybe) |v| {
    // v: u32
} else {
    // was null
}
```

### 4) Errors (`error!T`) and propagation

```zig
fn mightFail() !u32 {
    return 123;
}

pub fn main() !void {
    const v = try mightFail();
    _ = v;
}
```

Handle an error:

```zig
const v = mightFail() catch |err| switch (err) {
    error.OutOfMemory => 0,
    else => return err,
};
```

### 5) Resource cleanup (`defer` / `errdefer`)

```zig
const file = try std.fs.cwd().openFile("data.txt", .{});
defer file.close();

// allocate
var list: std.ArrayList(u8) = .empty;
errdefer list.deinit(allocator);

try list.appendSlice(allocator, "hi");
defer list.deinit(allocator); // once ownership is “committed”
```

### 6) ArrayList (0.15 style)

**Heap-backed:**

```zig
var list: std.ArrayList(u8) = .empty;
defer list.deinit(allocator);

try list.append(allocator, 'A');
try list.appendSlice(allocator, "BC");
```

(That `.empty` + `deinit(allocator)` style is standard 0.15-era usage.) ([Zig Guide][6])

**Stack-backed buffer:**

```zig
var buf: [64]u8 = undefined;
var list = std.ArrayListUnmanaged(u8).initBuffer(&buf);
// bounded appends exist in 0.15 era
```

([Zig Programming Language][5])

### 7) I/O (0.15 stdout writer pattern)

```zig
var buf: [1024]u8 = undefined;
var w = std.fs.File.stdout().writer(&buf);
const out = &w.interface;

try out.print("Hello {s}\n", .{"world"});
try out.flush();
```

([Zig Programming Language][5])

### 8) "Write to memory" patterns

* Use `std.ArrayList(u8)` and `list.print(allocator, ...)` ([Zig Guide][4])
* Or use an allocating writer for formatting / JSON output ([Zig Guide][9])

Example with `ArrayList`:

```zig
var list: std.ArrayList(u8) = .empty;
defer list.deinit(allocator);

try list.print(allocator, "Hello {s}!", .{"World"});
```

([Zig Guide][4])

### 9) Formatting quick ref

* Build a string: `std.fmt.allocPrint` ([Zig Guide][7])
* Print to any writer: `writer.print(...)` (and prefer this over older `std.fmt.format`) ([Zig Programming Language][5])
* Custom formatting: implement `format(this, writer: *std.Io.Writer) ...` and call with `{f}` ([Zig Programming Language][5])

### 10) JSON quick ref

**Parse:**

```zig
const parsed = try std.json.parseFromSlice(T, allocator, bytes, .{});
defer parsed.deinit();
const value = parsed.value;
```

([Zig Guide][9])

**Stringify / print:**

```zig
try writer.print("{f}", .{std.json.fmt(value, .{})});
```

([Zig Guide][9])

### 11) Build.zig "hello world"

```zig
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "hello",
        .root_module = b.createModule(.{
            .root_source_file = b.path("hello.zig"),
            .target = b.graph.host,
        }),
    });
    b.installArtifact(exe);
}
```

([Zig Programming Language][10])

---

If you want, I can also provide an **“idiomatic Zig 0.15 project skeleton”** (file layout + `main.zig` template + `build.zig` + common helper modules), but the core patterns above are the ones that make Zig code *feel* idiomatic in 0.15—especially the allocator discipline, the ownership documentation habit, and the new Reader/Writer + `{f}` formatting ecosystem.

[1]: https://ziglang.org/download/ "https://ziglang.org/download/"
[2]: https://ziglang.org/documentation/0.15.2/ "https://ziglang.org/documentation/0.15.2/"
[3]: https://ziglang.org/learn/overview/ "https://ziglang.org/learn/overview/"
[4]: https://zig.guide/standard-library/readers-and-writers/ "https://zig.guide/standard-library/readers-and-writers/"
[5]: https://ziglang.org/download/0.15.1/release-notes.html "https://ziglang.org/download/0.15.1/release-notes.html"
[6]: https://zig.guide/standard-library/arraylist/ "https://zig.guide/standard-library/arraylist/"
[7]: https://zig.guide/standard-library/formatting/ "https://zig.guide/standard-library/formatting/"
[8]: https://zig.guide/standard-library/formatting-specifiers/ "https://zig.guide/standard-library/formatting-specifiers/"
[9]: https://zig.guide/standard-library/json/ "https://zig.guide/standard-library/json/"
[10]: https://ziglang.org/learn/build-system/ "https://ziglang.org/learn/build-system/"

