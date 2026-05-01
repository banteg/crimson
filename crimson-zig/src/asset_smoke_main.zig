const std = @import("std");
const rl = @import("raylib");

const runtime_paths = @import("crimson_zig").runtime_paths;
const window_assets = @import("window_assets.zig");

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

pub fn main(init: std.process.Init) !void {
    runtime_paths.useEnviron(init.environ_map);
    rl.setTraceLogLevel(.err);

    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len >= 2 and (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h"))) {
        try printUsage();
        return;
    }
    if (args.len > 2) {
        try printUsage();
        std.process.exit(2);
    }

    const assets_dir = if (args.len == 2)
        try allocator.dupe(u8, args[1])
    else
        (try window_assets.resolveRuntimeAssetsDir(allocator)) orelse {
            try writeStderr("asset-smoke: no runtime assets dir resolved\n");
            try writeStderr("set CRIMSON_ASSETS_DIR or place crimson.paq under the runtime dir\n");
            std.process.exit(1);
        };
    defer allocator.free(assets_dir);

    const stats = try runSmoke(allocator, assets_dir);

    var out_buf: [4096]u8 = undefined;
    var out_writer = std.Io.File.stdout().writer(std.Io.Threaded.global_single_threaded.io(), &out_buf);
    const out = &out_writer.interface;
    try out.print(
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
    try out.flush();

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
        \\  crimson-zig-asset-smoke [assets-dir]
        \\  zig build asset-smoke
        \\  zig build asset-smoke -- /path/to/assets
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
