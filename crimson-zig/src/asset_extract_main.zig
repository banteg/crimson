const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const window_assets = @import("window_assets.zig");

const schema_version: i32 = 1;

const OutputFormat = enum {
    human,
    json,
};

const ExtractRequest = struct {
    game_dir: ?[]const u8 = null,
    assets_dir: ?[]const u8 = null,
    output_format: OutputFormat = .human,
};

const ParseOutcome = union(enum) {
    help,
    ok: ExtractRequest,
    invalid: []const u8,
};

const ExtractStats = struct {
    paq_files: usize = 0,
    archive_entries: usize = 0,
    written_files: usize = 0,
    image_entries: usize = 0,
    raw_entries: usize = 0,
};

const ExtractPayload = struct {
    schema_version: i32,
    status: []const u8,
    game_dir: []const u8,
    assets_dir: []const u8,
    paq_files: usize,
    archive_entries: usize,
    written_files: usize,
    image_entries: usize,
    raw_entries: usize,
};

pub fn main(init: std.process.Init) !void {
    rl.setTraceLogLevel(.err);

    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const request = switch (parseArgs(args[1..])) {
        .help => {
            try printUsage();
            return;
        },
        .ok => |request| request,
        .invalid => |detail| {
            try writeStderrFmt("asset-extract: invalid args: {s}\n", .{detail});
            try printUsage();
            std.process.exit(2);
        },
    };

    const game_dir = request.game_dir.?;
    const assets_dir = request.assets_dir.?;
    const stats = runExtract(allocator, game_dir, assets_dir) catch |err| {
        try writeStderrFmt("asset-extract: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    const stdout = switch (request.output_format) {
        .human => try buildHumanOutput(allocator, stats),
        .json => try buildJsonOutput(allocator, game_dir, assets_dir, stats),
    };
    defer allocator.free(stdout);

    try writeStdout(stdout);
}

fn runExtract(allocator: std.mem.Allocator, game_dir: []const u8, assets_dir: []const u8) !ExtractStats {
    const paq_paths = try collectPaqPaths(allocator, game_dir);
    defer freeOwnedStrings(allocator, paq_paths);
    if (paq_paths.len == 0) return error.NoPaqFiles;

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().createDirPath(io, assets_dir);

    var stats: ExtractStats = .{
        .paq_files = paq_paths.len,
    };
    for (paq_paths) |paq_rel_path| {
        const paq_path = try std.fs.path.join(allocator, &.{ game_dir, paq_rel_path });
        defer allocator.free(paq_path);
        try extractOnePaq(allocator, paq_path, assets_dir, &stats);
    }
    return stats;
}

fn extractOnePaq(allocator: std.mem.Allocator, paq_path: []const u8, assets_dir: []const u8, stats: *ExtractStats) !void {
    var archive = try window_assets.AssetArchive.fromPath(allocator, paq_path);
    defer archive.deinit();

    const paq_stem = std.fs.path.stem(paq_path);
    const out_root = try std.fs.path.join(allocator, &.{ assets_dir, paq_stem });
    defer allocator.free(out_root);
    try std.Io.Dir.cwd().createDirPath(std.Io.Threaded.global_single_threaded.io(), out_root);

    stats.archive_entries += archive.entryCount();
    for (archive.normalized_names, 0..) |rel_path, idx| {
        const payload = archive.archive.entries[idx].payload;
        try extractEntry(allocator, out_root, rel_path, payload, stats);
    }
}

fn extractEntry(
    allocator: std.mem.Allocator,
    out_root: []const u8,
    rel_path: []const u8,
    payload: []const u8,
    stats: *ExtractStats,
) !void {
    const format = window_assets.detectAssetFormat(rel_path);
    const out_path = try extractedEntryPath(allocator, out_root, rel_path, format);
    defer allocator.free(out_path);

    switch (format) {
        .jaz, .tga => {
            var image = try window_assets.decodeImageFromBytes(allocator, rel_path, payload);
            defer image.unload();

            const png_bytes = try rl.exportImageToMemory(image, ".png");
            defer rl.memFree(@ptrCast(png_bytes.ptr));

            try writeFileWithParents(out_path, png_bytes);
            stats.image_entries += 1;
        },
        .jpg, .jpeg, .dat, .unsupported => {
            try writeFileWithParents(out_path, payload);
            stats.raw_entries += 1;
        },
    }
    stats.written_files += 1;
}

fn extractedEntryPath(allocator: std.mem.Allocator, out_root: []const u8, rel_path: []const u8, format: window_assets.AssetFormat) ![]u8 {
    switch (format) {
        .jaz, .tga => {
            const ext = std.fs.path.extension(rel_path);
            const stem_path = if (ext.len == 0) rel_path else rel_path[0 .. rel_path.len - ext.len];
            const png_rel = try std.fmt.allocPrint(allocator, "{s}.png", .{stem_path});
            defer allocator.free(png_rel);
            return std.fs.path.join(allocator, &.{ out_root, png_rel });
        },
        .jpg, .jpeg, .dat, .unsupported => return std.fs.path.join(allocator, &.{ out_root, rel_path }),
    }
}

fn collectPaqPaths(allocator: std.mem.Allocator, game_dir: []const u8) ![][]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = try std.Io.Dir.cwd().openDir(io, game_dir, .{ .iterate = true });
    defer dir.close(io);

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    var paths: std.ArrayList([]u8) = .empty;
    errdefer freeOwnedStrings(allocator, paths.items);

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.ascii.endsWithIgnoreCase(entry.path, ".paq")) continue;
        const path_copy = try allocator.dupe(u8, entry.path);
        paths.append(allocator, path_copy) catch |err| {
            allocator.free(path_copy);
            return err;
        };
    }

    std.sort.heap([]u8, paths.items, {}, stringLessThan);
    return paths.toOwnedSlice(allocator);
}

fn freeOwnedStrings(allocator: std.mem.Allocator, strings: []const []u8) void {
    for (strings) |string| allocator.free(string);
    allocator.free(strings);
}

fn stringLessThan(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn writeFileWithParents(path: []const u8, bytes: []const u8) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.Io.Dir.cwd().createDirPath(io, dir);
    }
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes,
    });
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    var request: ExtractRequest = .{};
    var positional_count: usize = 0;

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return .help;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            request.output_format = .json;
            continue;
        }
        if (std.mem.eql(u8, arg, "--format")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --format" };
            idx += 1;
            request.output_format = parseOutputFormat(args[idx]) orelse return .{ .invalid = "invalid --format value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--format=")) {
            request.output_format = parseOutputFormat(arg["--format=".len..]) orelse return .{ .invalid = "invalid --format value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            return .{ .invalid = "unknown option" };
        }

        switch (positional_count) {
            0 => request.game_dir = arg,
            1 => request.assets_dir = arg,
            else => return .{ .invalid = "too many positional arguments" },
        }
        positional_count += 1;
    }

    if (request.game_dir == null) return .{ .invalid = "missing game-dir argument" };
    if (request.assets_dir == null) return .{ .invalid = "missing assets-dir argument" };
    return .{ .ok = request };
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
}

fn buildHumanOutput(allocator: std.mem.Allocator, stats: ExtractStats) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "asset-extract: extracted {d} files from {d} paq(s)\narchive_entries={d} images={d} raw={d}\n",
        .{
            stats.written_files,
            stats.paq_files,
            stats.archive_entries,
            stats.image_entries,
            stats.raw_entries,
        },
    );
}

fn buildJsonOutput(allocator: std.mem.Allocator, game_dir: []const u8, assets_dir: []const u8, stats: ExtractStats) ![]u8 {
    const payload: ExtractPayload = .{
        .schema_version = schema_version,
        .status = "ok",
        .game_dir = game_dir,
        .assets_dir = assets_dir,
        .paq_files = stats.paq_files,
        .archive_entries = stats.archive_entries,
        .written_files = stats.written_files,
        .image_entries = stats.image_entries,
        .raw_entries = stats.raw_entries,
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{}, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn printUsage() !void {
    try writeStdout(
        \\Usage:
        \\  crimson-zig-asset-extract <game-dir> <assets-dir> [--json|--format <human|json>]
        \\  zig build asset-extract -- /path/to/game /path/to/assets
        \\
        \\Extracts all .paq files under game-dir into assets-dir.
        \\JAZ/TGA entries are decoded and written as PNG files.
        \\
    );
}

fn writeStdout(bytes: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    var writer = std.Io.File.stdout().writer(std.Io.Threaded.global_single_threaded.io(), &buffer);
    const out = &writer.interface;
    try out.writeAll(bytes);
    try out.flush();
}

fn writeStderrFmt(comptime fmt: []const u8, args: anytype) !void {
    var buffer: [1024]u8 = undefined;
    var writer = std.Io.File.stderr().writer(std.Io.Threaded.global_single_threaded.io(), &buffer);
    const err = &writer.interface;
    try err.print(fmt, args);
    try err.flush();
}

test "asset-extract parser accepts dirs and json output" {
    const parsed = parseArgs(&.{ "/game", "/assets", "--json" });
    try std.testing.expect(parsed == .ok);
    try std.testing.expectEqualStrings("/game", parsed.ok.game_dir.?);
    try std.testing.expectEqualStrings("/assets", parsed.ok.assets_dir.?);
    try std.testing.expectEqual(OutputFormat.json, parsed.ok.output_format);
}

test "asset-extract parser requires game and assets dirs" {
    const parsed = parseArgs(&.{"/game"});
    try std.testing.expect(parsed == .invalid);
    try std.testing.expectEqualStrings("missing assets-dir argument", parsed.invalid);
}

test "asset-extract output path converts image extensions to png" {
    const path = try extractedEntryPath(std.testing.allocator, "/assets/crimson", "ui/panel.jaz", .jaz);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/assets/crimson/ui/panel.png", path);

    const jpg_path = try extractedEntryPath(std.testing.allocator, "/assets/crimson", "load/splash.jpg", .jpg);
    defer std.testing.allocator.free(jpg_path);
    try std.testing.expectEqualStrings("/assets/crimson/load/splash.jpg", jpg_path);
}

test "asset-extract raw paq entries preserve normalized paths" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const game_dir = try std.fs.path.join(allocator, &.{ base_dir, "game" });
    defer allocator.free(game_dir);
    const nested_dir = try std.fs.path.join(allocator, &.{ game_dir, "packs" });
    defer allocator.free(nested_dir);
    const assets_dir = try std.fs.path.join(allocator, &.{ base_dir, "assets" });
    defer allocator.free(assets_dir);
    const paq_path = try std.fs.path.join(allocator, &.{ nested_dir, "crimson.paq" });
    defer allocator.free(paq_path);

    const encoded = try formats.paq.encode(allocator, &[_]formats.paq.EntryInput{
        .{ .name = "load\\smallFnt.dat", .payload = "widths" },
        .{ .name = "docs/readme.txt", .payload = "notes" },
    });
    defer allocator.free(encoded);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().createDirPath(io, nested_dir);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = paq_path, .data = encoded });

    const stats = try runExtract(allocator, game_dir, assets_dir);
    try std.testing.expectEqual(@as(usize, 1), stats.paq_files);
    try std.testing.expectEqual(@as(usize, 2), stats.archive_entries);
    try std.testing.expectEqual(@as(usize, 2), stats.written_files);
    try std.testing.expectEqual(@as(usize, 0), stats.image_entries);
    try std.testing.expectEqual(@as(usize, 2), stats.raw_entries);

    const widths_path = try std.fs.path.join(allocator, &.{ assets_dir, "crimson", "load", "smallFnt.dat" });
    defer allocator.free(widths_path);
    const widths = try std.Io.Dir.cwd().readFileAlloc(io, widths_path, allocator, .limited(1024));
    defer allocator.free(widths);
    try std.testing.expectEqualStrings("widths", widths);
}

test "asset-extract json output reports counters" {
    const out = try buildJsonOutput(std.testing.allocator, "/game", "/assets", .{
        .paq_files = 1,
        .archive_entries = 3,
        .written_files = 3,
        .image_entries = 2,
        .raw_entries = 1,
    });
    defer std.testing.allocator.free(out);

    try std.testing.expect(std.mem.indexOf(u8, out, "\"schema_version\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"status\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"game_dir\":\"/game\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"written_files\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"image_entries\":2") != null);
}
