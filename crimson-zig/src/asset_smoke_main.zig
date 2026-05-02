const std = @import("std");
const rl = @import("raylib");

const runtime_paths = @import("crimson_zig").runtime_paths;
const window_assets = @import("window_assets.zig");

const schema_version: i32 = 1;

const OutputFormat = enum {
    human,
    json,
};

const SmokeStats = struct {
    archive_entries: usize = 0,
    jaz_entries: usize = 0,
    tga_entries: usize = 0,
    jpg_entries: usize = 0,
    jpeg_entries: usize = 0,
    dat_entries: usize = 0,
    skipped_entries: usize = 0,
    decoded_entries: usize = 0,
    runtime_texture_specs: usize = 0,
    failures: usize = 0,
};

const SmokeRequest = struct {
    assets_dir: ?[]const u8 = null,
    output_format: OutputFormat = .human,
};

const ParseOutcome = union(enum) {
    help,
    ok: SmokeRequest,
    invalid: []const u8,
};

const SmokeStatsPayload = struct {
    schema_version: i32,
    status: []const u8,
    assets_dir: []const u8,
    archive_entries: usize,
    decoded_entries: usize,
    jaz_entries: usize,
    tga_entries: usize,
    jpg_entries: usize,
    jpeg_entries: usize,
    dat_entries: usize,
    skipped_entries: usize,
    runtime_texture_specs: usize,
    failures: usize,
};

pub fn main(init: std.process.Init) !void {
    runtime_paths.useEnviron(init.environ_map);
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
            try writeStderrFmt("asset-smoke: invalid args: {s}\n", .{detail});
            try printUsage();
            std.process.exit(2);
        },
    };

    const assets_dir = if (request.assets_dir) |path|
        try allocator.dupe(u8, path)
    else
        (try window_assets.resolveRuntimeAssetsDir(allocator)) orelse {
            try writeStderr("asset-smoke: no runtime assets dir resolved\n");
            try writeStderr("set CRIMSON_ASSETS_DIR or place crimson.paq under the runtime dir\n");
            std.process.exit(1);
        };
    defer allocator.free(assets_dir);

    const stats = try runSmoke(allocator, assets_dir);
    const stdout = switch (request.output_format) {
        .human => try buildHumanOutput(allocator, assets_dir, stats),
        .json => try buildJsonOutput(allocator, assets_dir, stats),
    };
    defer allocator.free(stdout);

    try writeStdout(stdout);

    if (stats.failures != 0) {
        std.process.exit(1);
    }
}

fn runSmoke(allocator: std.mem.Allocator, assets_dir: []const u8) !SmokeStats {
    const paq_path = try std.fs.path.join(allocator, &.{ assets_dir, window_assets.paq_name });
    defer allocator.free(paq_path);

    var archive = try window_assets.AssetArchive.fromPath(allocator, paq_path);
    defer archive.deinit();

    var stats: SmokeStats = .{
        .archive_entries = archive.entryCount(),
    };

    for (archive.normalized_names, 0..) |rel_path, idx| {
        const payload = archive.archive.entries[idx].payload;
        const decoded = try decodeArchiveEntry(allocator, rel_path, payload, &stats);
        if (decoded) {
            stats.decoded_entries += 1;
        }
    }

    inline for (std.meta.fields(window_assets.TextureId)) |field| {
        const texture_id: window_assets.TextureId = @enumFromInt(field.value);
        const spec = window_assets.runtimeTextureSpec(texture_id);
        stats.runtime_texture_specs += 1;

        if (archive.get(spec.rel_path)) |payload| {
            if (!try decodeImage(allocator, spec.rel_path, payload)) {
                stats.failures += 1;
            }
        } else {
            try printFailure(spec.rel_path, error.MissingTextureAsset);
            stats.failures += 1;
        }
    }

    if (archive.get(window_assets.small_font_widths_path) == null) {
        try printFailure(window_assets.small_font_widths_path, error.MissingFontWidths);
        stats.failures += 1;
    }

    return stats;
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    var request: SmokeRequest = .{};

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
        if (request.assets_dir != null) {
            return .{ .invalid = "too many assets dir arguments" };
        }
        request.assets_dir = arg;
    }

    return .{ .ok = request };
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
}

fn buildHumanOutput(allocator: std.mem.Allocator, assets_dir: []const u8, stats: SmokeStats) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "asset-smoke: {s}\narchive_entries={d} decoded={d} jaz={d} tga={d} jpg={d} jpeg={d} dat={d} skipped={d} runtime_specs={d} failures={d}\n",
        .{
            assets_dir,
            stats.archive_entries,
            stats.decoded_entries,
            stats.jaz_entries,
            stats.tga_entries,
            stats.jpg_entries,
            stats.jpeg_entries,
            stats.dat_entries,
            stats.skipped_entries,
            stats.runtime_texture_specs,
            stats.failures,
        },
    );
}

fn buildJsonOutput(allocator: std.mem.Allocator, assets_dir: []const u8, stats: SmokeStats) ![]u8 {
    const payload: SmokeStatsPayload = .{
        .schema_version = schema_version,
        .status = if (stats.failures == 0) "ok" else "failed",
        .assets_dir = assets_dir,
        .archive_entries = stats.archive_entries,
        .decoded_entries = stats.decoded_entries,
        .jaz_entries = stats.jaz_entries,
        .tga_entries = stats.tga_entries,
        .jpg_entries = stats.jpg_entries,
        .jpeg_entries = stats.jpeg_entries,
        .dat_entries = stats.dat_entries,
        .skipped_entries = stats.skipped_entries,
        .runtime_texture_specs = stats.runtime_texture_specs,
        .failures = stats.failures,
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{}, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn decodeArchiveEntry(allocator: std.mem.Allocator, rel_path: []const u8, payload: []const u8, stats: *SmokeStats) !bool {
    return switch (window_assets.detectAssetFormat(rel_path)) {
        .jaz => blk: {
            stats.jaz_entries += 1;
            break :blk try decodeImage(allocator, rel_path, payload);
        },
        .tga => blk: {
            stats.tga_entries += 1;
            break :blk try decodeImage(allocator, rel_path, payload);
        },
        .jpg => blk: {
            stats.jpg_entries += 1;
            break :blk try decodeImage(allocator, rel_path, payload);
        },
        .jpeg => blk: {
            stats.jpeg_entries += 1;
            break :blk try decodeImage(allocator, rel_path, payload);
        },
        .dat => blk: {
            stats.dat_entries += 1;
            break :blk false;
        },
        .unsupported => blk: {
            stats.skipped_entries += 1;
            break :blk false;
        },
    };
}

fn decodeImage(allocator: std.mem.Allocator, rel_path: []const u8, payload: []const u8) !bool {
    var image = window_assets.decodeImageFromBytes(allocator, rel_path, payload) catch |err| {
        try printFailure(rel_path, err);
        return false;
    };
    defer image.unload();
    return true;
}

fn printFailure(rel_path: []const u8, err: anyerror) !void {
    var err_buf: [1024]u8 = undefined;
    var err_writer = std.Io.File.stderr().writer(std.Io.Threaded.global_single_threaded.io(), &err_buf);
    const stderr = &err_writer.interface;
    try stderr.print("asset-smoke failure: {s}: {s}\n", .{ rel_path, @errorName(err) });
    try stderr.flush();
}

fn printUsage() !void {
    try writeStdout(
        \\Usage:
        \\  crimson-zig-asset-smoke [assets-dir] [--json|--format <human|json>]
        \\  zig build asset-smoke
        \\  zig build asset-smoke -- /path/to/assets --json
        \\
        \\Runs a local decode smoke pass over crimson.paq and runtime-mapped assets.
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

fn writeStderr(bytes: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    var writer = std.Io.File.stderr().writer(std.Io.Threaded.global_single_threaded.io(), &buffer);
    const err = &writer.interface;
    try err.writeAll(bytes);
    try err.flush();
}

fn writeStderrFmt(comptime fmt: []const u8, args: anytype) !void {
    var buffer: [1024]u8 = undefined;
    var writer = std.Io.File.stderr().writer(std.Io.Threaded.global_single_threaded.io(), &buffer);
    const err = &writer.interface;
    try err.print(fmt, args);
    try err.flush();
}

test "asset-smoke parser accepts json output and assets dir" {
    const parsed = parseArgs(&.{ "/tmp/assets", "--json" });
    try std.testing.expect(parsed == .ok);
    try std.testing.expectEqualStrings("/tmp/assets", parsed.ok.assets_dir.?);
    try std.testing.expectEqual(OutputFormat.json, parsed.ok.output_format);
}

test "asset-smoke parser accepts format option before assets dir" {
    const parsed = parseArgs(&.{ "--format=json", "/tmp/assets" });
    try std.testing.expect(parsed == .ok);
    try std.testing.expectEqualStrings("/tmp/assets", parsed.ok.assets_dir.?);
    try std.testing.expectEqual(OutputFormat.json, parsed.ok.output_format);
}

test "asset-smoke parser rejects duplicate assets dir" {
    const parsed = parseArgs(&.{ "/tmp/assets-a", "/tmp/assets-b" });
    try std.testing.expect(parsed == .invalid);
    try std.testing.expectEqualStrings("too many assets dir arguments", parsed.invalid);
}

test "asset-smoke json output reports status and counters" {
    const stats: SmokeStats = .{
        .archive_entries = 9,
        .jaz_entries = 2,
        .tga_entries = 1,
        .jpg_entries = 3,
        .jpeg_entries = 1,
        .dat_entries = 1,
        .skipped_entries = 1,
        .decoded_entries = 7,
        .runtime_texture_specs = 68,
        .failures = 0,
    };
    const out = try buildJsonOutput(std.testing.allocator, "/tmp/assets", stats);
    defer std.testing.allocator.free(out);

    try std.testing.expect(std.mem.indexOf(u8, out, "\"schema_version\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"status\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"assets_dir\":\"/tmp/assets\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"archive_entries\":9") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"runtime_texture_specs\":68") != null);
}
