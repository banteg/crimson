const builtin = @import("builtin");
const std = @import("std");

pub const ResolveRuntimePathError = std.process.GetEnvVarOwnedError || std.mem.Allocator.Error || std.fs.Dir.AccessError;

pub fn resolveArchiveDir(
    allocator: std.mem.Allocator,
    archive_name: []const u8,
) ResolveRuntimePathError!?[]u8 {
    if (builtin.target.os.tag == .emscripten) return null;

    const env_assets_dir = std.process.getEnvVarOwned(allocator, "CRIMSON_ASSETS_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
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
) (std.process.GetEnvVarOwnedError || std.mem.Allocator.Error)!?[]u8 {
    if (builtin.target.os.tag == .emscripten or builtin.target.os.tag == .freestanding) {
        return null;
    }

    if (std.process.getEnvVarOwned(allocator, "CRIMSON_RUNTIME_DIR")) |path| {
        return path;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    if (std.process.getEnvVarOwned(allocator, "CRIMSON_BASE_DIR")) |path| {
        return path;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return switch (builtin.target.os.tag) {
        .macos => blk: {
            const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
                error.EnvironmentVariableNotFound => return null,
                else => return err,
            };
            defer allocator.free(home);
            break :blk try std.fs.path.join(allocator, &.{ home, "Library", "Application Support", "banteg", "crimsonland" });
        },
        .windows => blk: {
            const appdata = std.process.getEnvVarOwned(allocator, "APPDATA") catch |err| switch (err) {
                error.EnvironmentVariableNotFound => return null,
                else => return err,
            };
            defer allocator.free(appdata);
            break :blk try std.fs.path.join(allocator, &.{ appdata, "banteg", "crimsonland" });
        },
        else => blk: {
            if (std.process.getEnvVarOwned(allocator, "XDG_DATA_HOME")) |xdg_data_home| {
                defer allocator.free(xdg_data_home);
                break :blk try std.fs.path.join(allocator, &.{ xdg_data_home, "banteg", "crimsonland" });
            } else |err| switch (err) {
                error.EnvironmentVariableNotFound => {},
                else => return err,
            }

            const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
                error.EnvironmentVariableNotFound => return null,
                else => return err,
            };
            defer allocator.free(home);
            break :blk try std.fs.path.join(allocator, &.{ home, ".local", "share", "banteg", "crimsonland" });
        },
    };
}

pub fn archiveExistsAtDir(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    archive_name: []const u8,
) (std.mem.Allocator.Error || std.fs.Dir.AccessError)!bool {
    const archive_path = try std.fs.path.join(allocator, &.{ dir_path, archive_name });
    defer allocator.free(archive_path);

    std.fs.cwd().access(archive_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

test "default runtime dir matches python platformdirs layout on supported targets" {
    const allocator = std.testing.allocator;
    const runtime_dir = (try defaultRuntimeDir(allocator)) orelse return;
    defer allocator.free(runtime_dir);

    switch (builtin.target.os.tag) {
        .macos => try std.testing.expect(std.mem.endsWith(u8, runtime_dir, "/Library/Application Support/banteg/crimsonland")),
        .windows => try std.testing.expect(std.mem.endsWith(u8, runtime_dir, "\\banteg\\crimsonland") or std.mem.endsWith(u8, runtime_dir, "/banteg/crimsonland")),
        else => try std.testing.expect(std.mem.endsWith(u8, runtime_dir, "/banteg/crimsonland")),
    }
}
