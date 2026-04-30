const std = @import("std");
const formats = @import("crimson_zig").formats;

pub const RuntimeArchiveError = formats.paq.PaqError || std.mem.Allocator.Error || error{
    InvalidAssetPath,
};

pub const OpenArchiveError = RuntimeArchiveError ||
    std.Io.Dir.ReadFileAllocError;

pub const Archive = struct {
    allocator: std.mem.Allocator,
    archive: formats.paq.Archive,
    normalized_names: [][]u8,
    index_by_name: std.StringHashMap(usize),

    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) RuntimeArchiveError!Archive {
        var archive = try formats.paq.decode(allocator, bytes);
        errdefer archive.deinit(allocator);

        var normalized_names = try allocator.alloc([]u8, archive.entries.len);
        errdefer allocator.free(normalized_names);
        @memset(normalized_names, &.{});
        errdefer {
            for (normalized_names) |name| {
                if (name.len == 0) continue;
                allocator.free(name);
            }
        }

        var index_by_name = std.StringHashMap(usize).init(allocator);
        errdefer index_by_name.deinit();

        for (archive.entries, 0..) |entry, idx| {
            const normalized = try normalizeArchiveEntryNameOwned(allocator, entry.name);
            normalized_names[idx] = normalized;
            try index_by_name.put(normalized, idx);
        }

        return .{
            .allocator = allocator,
            .archive = archive,
            .normalized_names = normalized_names,
            .index_by_name = index_by_name,
        };
    }

    pub fn fromPath(allocator: std.mem.Allocator, paq_path: []const u8) OpenArchiveError!Archive {
        const bytes = try readFileAlloc(allocator, paq_path);
        defer allocator.free(bytes);
        return fromBytes(allocator, bytes);
    }

    pub fn deinit(self: *Archive) void {
        for (self.normalized_names) |name| {
            if (name.len == 0) continue;
            self.allocator.free(name);
        }
        self.allocator.free(self.normalized_names);
        self.index_by_name.deinit();
        self.archive.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn get(self: *const Archive, rel_path: []const u8) ?[]const u8 {
        const idx = self.index_by_name.get(rel_path) orelse return null;
        return self.archive.entries[idx].payload;
    }

    pub fn entryCount(self: *const Archive) usize {
        return self.archive.entries.len;
    }
};

pub fn readFileAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
) std.Io.Dir.ReadFileAllocError![]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited);
}

fn normalizeArchiveEntryNameOwned(
    allocator: std.mem.Allocator,
    raw_name: []const u8,
) RuntimeArchiveError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var segment_start: usize = 0;
    var segment_count: usize = 0;
    var idx: usize = 0;
    while (idx <= raw_name.len) : (idx += 1) {
        const is_separator = idx == raw_name.len or raw_name[idx] == '/' or raw_name[idx] == '\\';
        if (!is_separator) continue;

        const segment = raw_name[segment_start..idx];
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.InvalidAssetPath;
        }
        if (segment_count > 0) try out.append(allocator, '/');
        try out.appendSlice(allocator, segment);
        segment_count += 1;
        segment_start = idx + 1;
    }

    if (segment_count == 0) return error.InvalidAssetPath;
    return out.toOwnedSlice(allocator);
}

test "archive normalizes separators and rejects traversal" {
    const allocator = std.testing.allocator;

    const encoded = try formats.paq.encode(allocator, &[_]formats.paq.EntryInput{
        .{ .name = "ui\\button\\icon.tga", .payload = "abc" },
    });
    defer allocator.free(encoded);

    var archive = try Archive.fromBytes(allocator, encoded);
    defer archive.deinit();

    try std.testing.expectEqual(@as(usize, 1), archive.entryCount());
    try std.testing.expectEqualStrings("abc", archive.get("ui/button/icon.tga").?);

    const traversal = try formats.paq.encode(allocator, &[_]formats.paq.EntryInput{
        .{ .name = "../escape.tga", .payload = "abc" },
    });
    defer allocator.free(traversal);
    try std.testing.expectError(error.InvalidAssetPath, Archive.fromBytes(allocator, traversal));
}
