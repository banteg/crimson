const builtin = @import("builtin");
const std = @import("std");

pub const ResolveRuntimePathError = std.process.Environ.GetAllocError || std.mem.Allocator.Error || std.Io.Dir.AccessError;

var configured_environ: ?*std.process.Environ.Map = null;
var configured_runtime_dir: ?[]const u8 = null;
var configured_assets_dir: ?[]const u8 = null;

pub fn useEnviron(environ: *std.process.Environ.Map) void {
    configured_environ = environ;
}

pub fn useRuntimeDir(path: ?[]const u8) void {
    configured_runtime_dir = path;
}

pub fn useAssetsDir(path: ?[]const u8) void {
    configured_assets_dir = path;
}

pub fn resolveArchiveDir(
    allocator: std.mem.Allocator,
    archive_name: []const u8,
) ResolveRuntimePathError!?[]u8 {
    if (builtin.target.os.tag == .emscripten) return null;

    if (configured_assets_dir) |dir| {
        if (try archiveExistsAtDir(allocator, dir, archive_name)) {
            const owned = try allocator.dupe(u8, dir);
            return owned;
        }
    }

    const env_assets_dir = getEnvVarOwned(allocator, "CRIMSON_ASSETS_DIR") catch |err| switch (err) {
        error.EnvironmentVariableMissing => null,
        else => return err,
    };

    if (env_assets_dir) |dir| {
        if (try archiveExistsAtDir(allocator, dir, archive_name)) {
            return dir;
        }
        allocator.free(dir);
    }

    const runtime_dir = try defaultRuntimeDir(allocator);
    if (runtime_dir) |dir| {
        if (try archiveExistsAtDir(allocator, dir, archive_name)) {
            return dir;
        }
        allocator.free(dir);
    }

    const default_candidates = [_][]const u8{
        "artifacts/assets",
        ".",
    };
    for (default_candidates) |candidate| {
        if (try archiveExistsAtDir(allocator, candidate, archive_name)) {
            const owned = try allocator.dupe(u8, candidate);
            return owned;
        }
    }

    return null;
}

pub fn defaultRuntimeDir(
    allocator: std.mem.Allocator,
) (std.process.Environ.GetAllocError || std.mem.Allocator.Error)!?[]u8 {
    if (builtin.target.os.tag == .emscripten or builtin.target.os.tag == .freestanding) {
        return null;
    }

    if (configured_runtime_dir) |path| {
        const owned = try allocator.dupe(u8, path);
        return owned;
    }

    if (getEnvVarOwned(allocator, "CRIMSON_RUNTIME_DIR")) |path| {
        return path;
    } else |err| switch (err) {
        error.EnvironmentVariableMissing => {},
        else => return err,
    }

    if (getEnvVarOwned(allocator, "CRIMSON_BASE_DIR")) |path| {
        return path;
    } else |err| switch (err) {
        error.EnvironmentVariableMissing => {},
        else => return err,
    }

    return switch (builtin.target.os.tag) {
        .macos => blk: {
            const home = getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
                error.EnvironmentVariableMissing => return null,
                else => return err,
            };
            defer allocator.free(home);
            break :blk try std.fs.path.join(allocator, &.{ home, "Library", "Application Support", "banteg", "crimsonland" });
        },
        .windows => blk: {
            const appdata = getEnvVarOwned(allocator, "APPDATA") catch |err| switch (err) {
                error.EnvironmentVariableMissing => return null,
                else => return err,
            };
            defer allocator.free(appdata);
            break :blk try std.fs.path.join(allocator, &.{ appdata, "banteg", "crimsonland" });
        },
        else => blk: {
            if (getEnvVarOwned(allocator, "XDG_DATA_HOME")) |xdg_data_home| {
                defer allocator.free(xdg_data_home);
                break :blk try std.fs.path.join(allocator, &.{ xdg_data_home, "banteg", "crimsonland" });
            } else |err| switch (err) {
                error.EnvironmentVariableMissing => {},
                else => return err,
            }

            const home = getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
                error.EnvironmentVariableMissing => return null,
                else => return err,
            };
            defer allocator.free(home);
            break :blk try std.fs.path.join(allocator, &.{ home, ".local", "share", "banteg", "crimsonland" });
        },
    };
}

pub fn envVarOwned(allocator: std.mem.Allocator, key: []const u8) std.process.Environ.GetAllocError![]u8 {
    if (builtin.is_test) {
        return std.testing.environ.getAlloc(allocator, key);
    }
    const environ = configured_environ orelse return error.EnvironmentVariableMissing;
    const value = environ.get(key) orelse return error.EnvironmentVariableMissing;
    return allocator.dupe(u8, value);
}

const getEnvVarOwned = envVarOwned;

pub fn archiveExistsAtDir(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    archive_name: []const u8,
) (std.mem.Allocator.Error || std.Io.Dir.AccessError)!bool {
    const archive_path = try std.fs.path.join(allocator, &.{ dir_path, archive_name });
    defer allocator.free(archive_path);

    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.Dir.cwd().access(io, archive_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

test "default runtime dir matches python platformdirs layout on supported targets" {
    const allocator = std.testing.allocator;
    useRuntimeDir(null);
    useAssetsDir(null);
    const runtime_dir = (try defaultRuntimeDir(allocator)) orelse return;
    defer allocator.free(runtime_dir);

    switch (builtin.target.os.tag) {
        .macos => try std.testing.expect(std.mem.endsWith(u8, runtime_dir, "/Library/Application Support/banteg/crimsonland")),
        .windows => try std.testing.expect(std.mem.endsWith(u8, runtime_dir, "\\banteg\\crimsonland") or std.mem.endsWith(u8, runtime_dir, "/banteg/crimsonland")),
        else => try std.testing.expect(std.mem.endsWith(u8, runtime_dir, "/banteg/crimsonland")),
    }
}

test "configured runtime dir overrides environment defaults" {
    const allocator = std.testing.allocator;
    useRuntimeDir("custom-runtime");
    defer useRuntimeDir(null);

    const runtime_dir = (try defaultRuntimeDir(allocator)) orelse return error.TestExpectedRuntimeDir;
    defer allocator.free(runtime_dir);

    try std.testing.expectEqualStrings("custom-runtime", runtime_dir);
}

test "configured assets dir has archive lookup precedence" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    try std.Io.Dir.cwd().createDirPath(std.Io.Threaded.global_single_threaded.io(), base_dir);

    const archive_path = try std.fs.path.join(allocator, &.{ base_dir, "crimson.paq" });
    defer allocator.free(archive_path);
    try std.Io.Dir.cwd().writeFile(std.Io.Threaded.global_single_threaded.io(), .{
        .sub_path = archive_path,
        .data = "",
    });

    useAssetsDir(base_dir);
    defer useAssetsDir(null);

    const archive_dir = (try resolveArchiveDir(allocator, "crimson.paq")) orelse return error.TestExpectedArchiveDir;
    defer allocator.free(archive_dir);

    try std.testing.expectEqualStrings(base_dir, archive_dir);
}
