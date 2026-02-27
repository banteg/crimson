const std = @import("std");
const binary = @import("binary.zig");

pub const magic = "paq\x00";

pub const PaqError = binary.BinaryError || error{
    InvalidMagic,
    MissingNameTerminator,
    InvalidUtf8Name,
    TruncatedEntry,
    PayloadTooLarge,
    OutOfMemory,
};

pub const Entry = struct {
    name: []u8,
    payload: []u8,
};

pub const EntryInput = struct {
    name: []const u8,
    payload: []const u8,
};

pub const Archive = struct {
    entries: []Entry,

    pub fn deinit(self: Archive, allocator: std.mem.Allocator) void {
        for (self.entries) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.payload);
        }
        allocator.free(self.entries);
    }
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) PaqError!Archive {
    if (bytes.len < magic.len) return error.InvalidMagic;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return error.InvalidMagic;

    var entries: std.ArrayList(Entry) = .empty;
    errdefer {
        for (entries.items) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.payload);
        }
        entries.deinit(allocator);
    }

    var cursor = binary.Reader.init(bytes[magic.len..]);

    while (cursor.remaining() > 0) {
        const entry = try decodeEntry(allocator, bytes[magic.len..], &cursor);
        try entries.append(allocator, entry);
    }

    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

fn decodeEntry(
    allocator: std.mem.Allocator,
    paq_tail: []const u8,
    cursor: *binary.Reader,
) PaqError!Entry {
    const name_start = cursor.pos;
    const name_end_rel = std.mem.indexOfScalarPos(u8, paq_tail, name_start, 0) orelse return error.MissingNameTerminator;

    const raw_name = paq_tail[name_start..name_end_rel];
    if (!std.unicode.utf8ValidateSlice(raw_name)) return error.InvalidUtf8Name;

    cursor.pos = name_end_rel + 1;
    const payload_len_u32 = cursor.readU32Le() catch return error.TruncatedEntry;
    const payload_len: usize = payload_len_u32;
    const raw_payload = cursor.readBytes(payload_len) catch return error.TruncatedEntry;

    const name_copy = allocator.dupe(u8, raw_name) catch return error.OutOfMemory;
    errdefer allocator.free(name_copy);

    const payload_copy = allocator.dupe(u8, raw_payload) catch return error.OutOfMemory;
    return .{ .name = name_copy, .payload = payload_copy };
}

pub fn encode(allocator: std.mem.Allocator, entries: []const EntryInput) PaqError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, magic);

    for (entries) |entry| {
        if (!std.unicode.utf8ValidateSlice(entry.name)) return error.InvalidUtf8Name;
        if (entry.payload.len > std.math.maxInt(u32)) return error.PayloadTooLarge;

        try out.appendSlice(allocator, entry.name);
        try out.append(allocator, 0);

        var len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_bytes, @intCast(entry.payload.len), .little);
        try out.appendSlice(allocator, &len_bytes);
        try out.appendSlice(allocator, entry.payload);
    }

    return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

test "PAQ golden vector decode and re-encode" {
    const allocator = std.testing.allocator;
    const blob = [_]u8{
        0x70, 0x61, 0x71, 0x00, 0x66, 0x6f, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x62, 0x61, 0x72, 0x2e, 0x62,
        0x69, 0x6e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
    };

    var archive = try decode(allocator, &blob);
    defer archive.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), archive.entries.len);
    try std.testing.expectEqualStrings("foo.txt", archive.entries[0].name);
    try std.testing.expectEqualSlices(u8, "abc", archive.entries[0].payload);
    try std.testing.expectEqualStrings("bar.bin", archive.entries[1].name);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0x02 }, archive.entries[1].payload);

    const encoded = try encode(allocator, &[_]EntryInput{
        .{ .name = archive.entries[0].name, .payload = archive.entries[0].payload },
        .{ .name = archive.entries[1].name, .payload = archive.entries[1].payload },
    });
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &blob, encoded);
}

test "PAQ rejects invalid magic" {
    const allocator = std.testing.allocator;
    const bad = [_]u8{ 'p', 'a', 'q', '1' };
    try std.testing.expectError(error.InvalidMagic, decode(allocator, &bad));
}

test "PAQ rejects missing entry name terminator" {
    const allocator = std.testing.allocator;
    const bad = [_]u8{ 'p', 'a', 'q', 0x00, 'f', 'o', 'o' };
    try std.testing.expectError(error.MissingNameTerminator, decode(allocator, &bad));
}

test "PAQ rejects truncated payload size and bytes" {
    const allocator = std.testing.allocator;

    const missing_size = [_]u8{ 'p', 'a', 'q', 0x00, 'x', 0x00, 0x01, 0x02 };
    try std.testing.expectError(error.TruncatedEntry, decode(allocator, &missing_size));

    const missing_payload = [_]u8{ 'p', 'a', 'q', 0x00, 'x', 0x00, 0x05, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expectError(error.TruncatedEntry, decode(allocator, &missing_payload));
}
