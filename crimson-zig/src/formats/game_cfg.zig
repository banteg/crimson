const std = @import("std");
const msgpack = @import("msgpack");
const binary = @import("binary.zig");

pub const blob_size: usize = 0x268;
pub const file_size: usize = blob_size + 4;
pub const weapon_usage_count: usize = 53;
pub const quest_play_count: usize = 91;
pub const reserved_seed_words_byte_size: usize = 0x10;

pub const GameCfgError = binary.BinaryError || error{
    InvalidSize,
};

pub const Status = struct {
    quest_unlock_index: u16,
    quest_unlock_index_full: u16,
    weapon_usage_counts: [weapon_usage_count]u32,
    quest_play_counts: [quest_play_count]u32,
    mode_play_survival: u32,
    mode_play_rush: u32,
    mode_play_typo: u32,
    mode_play_other: u32,
    play_time_ms: u32,
    reserved_seed_words: [reserved_seed_words_byte_size]u8,

    pub fn msgpackWrite(self: Status, packer: anytype) !void {
        try packer.writeMapHeader(10);
        try packer.writeString("quest_unlock_index");
        try packer.writeInt(self.quest_unlock_index);
        try packer.writeString("quest_unlock_index_full");
        try packer.writeInt(self.quest_unlock_index_full);
        try packer.writeString("weapon_usage_counts");
        try packer.writeArray(u32, self.weapon_usage_counts[0..]);
        try packer.writeString("quest_play_counts");
        try packer.writeArray(u32, self.quest_play_counts[0..]);
        try packer.writeString("mode_play_survival");
        try packer.writeInt(self.mode_play_survival);
        try packer.writeString("mode_play_rush");
        try packer.writeInt(self.mode_play_rush);
        try packer.writeString("mode_play_typo");
        try packer.writeInt(self.mode_play_typo);
        try packer.writeString("mode_play_other");
        try packer.writeInt(self.mode_play_other);
        try packer.writeString("play_time_ms");
        try packer.writeInt(self.play_time_ms);
        try packer.writeString("reserved_seed_words");
        try packer.writeBinary(self.reserved_seed_words[0..]);
    }

    pub fn msgpackRead(unpacker: anytype) !Status {
        var status = std.mem.zeroes(Status);
        const field_count = try unpacker.readMapHeader(u32);
        for (0..field_count) |_| {
            const key = try unpacker.readString();
            if (std.mem.eql(u8, key, "quest_unlock_index")) {
                status.quest_unlock_index = try unpacker.readInt(u16);
            } else if (std.mem.eql(u8, key, "quest_unlock_index_full")) {
                status.quest_unlock_index_full = try unpacker.readInt(u16);
            } else if (std.mem.eql(u8, key, "weapon_usage_counts")) {
                const values = try unpacker.readArrayInto(u32, status.weapon_usage_counts[0..]);
                if (values.len != weapon_usage_count) return error.InvalidSize;
            } else if (std.mem.eql(u8, key, "quest_play_counts")) {
                const values = try unpacker.readArrayInto(u32, status.quest_play_counts[0..]);
                if (values.len != quest_play_count) return error.InvalidSize;
            } else if (std.mem.eql(u8, key, "mode_play_survival")) {
                status.mode_play_survival = try unpacker.readInt(u32);
            } else if (std.mem.eql(u8, key, "mode_play_rush")) {
                status.mode_play_rush = try unpacker.readInt(u32);
            } else if (std.mem.eql(u8, key, "mode_play_typo")) {
                status.mode_play_typo = try unpacker.readInt(u32);
            } else if (std.mem.eql(u8, key, "mode_play_other")) {
                status.mode_play_other = try unpacker.readInt(u32);
            } else if (std.mem.eql(u8, key, "play_time_ms")) {
                status.play_time_ms = try unpacker.readInt(u32);
            } else if (std.mem.eql(u8, key, "reserved_seed_words")) {
                const bytes = try unpacker.readBinaryInto(status.reserved_seed_words[0..]);
                if (bytes.len != reserved_seed_words_byte_size) return error.InvalidSize;
            } else {
                return error.UnknownStatusField;
            }
        }
        return status;
    }
};

pub const ParsedFile = struct {
    decoded: [blob_size]u8,
    checksum: u32,
    checksum_expected: u32,

    pub fn checksumValid(self: ParsedFile) bool {
        return self.checksum == self.checksum_expected;
    }
};

pub fn indexPoly(idx: usize) i32 {
    const i_u8: u8 = @truncate(idx);
    const i_s8: i8 = @bitCast(i_u8);
    const i: i32 = i_s8;
    return ((i * 7 + 0x0f) * i + 0x03) * i;
}

fn toS8(byte: u8) i32 {
    const signed: i8 = @bitCast(byte);
    return signed;
}

pub fn decodeBlob(encoded: []const u8) GameCfgError![blob_size]u8 {
    if (encoded.len != blob_size) return error.InvalidSize;

    var decoded: [blob_size]u8 = undefined;
    for (encoded, 0..) |byte, idx| {
        const value: i32 = @as(i32, byte) - 0x6f - indexPoly(idx);
        decoded[idx] = @intCast(value & 0xff);
    }
    return decoded;
}

pub fn encodeBlob(decoded: []const u8) GameCfgError![blob_size]u8 {
    if (decoded.len != blob_size) return error.InvalidSize;

    var encoded: [blob_size]u8 = undefined;
    for (decoded, 0..) |byte, idx| {
        const value: i32 = @as(i32, byte) + 0x6f + indexPoly(idx);
        encoded[idx] = @intCast(value & 0xff);
    }
    return encoded;
}

pub fn computeChecksum(decoded: []const u8) GameCfgError!u32 {
    if (decoded.len != blob_size) return error.InvalidSize;

    var acc: u32 = 0;
    var u: i64 = 0;

    for (decoded, 0..) |byte, idx| {
        const c: i64 = toS8(byte);
        const i_var5: i64 = (c * 7 + @as(i64, @intCast(idx))) * c + u;
        const addend: i64 = 0x0d + i_var5;
        acc +%= @intCast(addend & 0xffffffff);
        u += 0x6f;
    }

    return acc;
}

pub fn parseFile(raw: []const u8) GameCfgError!ParsedFile {
    if (raw.len != file_size) return error.InvalidSize;

    const decoded = try decodeBlob(raw[0..blob_size]);
    const checksum = std.mem.readInt(u32, raw[blob_size..file_size], .little);
    const checksum_expected = try computeChecksum(decoded[0..]);

    return .{
        .decoded = decoded,
        .checksum = checksum,
        .checksum_expected = checksum_expected,
    };
}

pub fn buildFile(decoded: []const u8) GameCfgError![file_size]u8 {
    if (decoded.len != blob_size) return error.InvalidSize;

    const encoded = try encodeBlob(decoded);
    const checksum = try computeChecksum(decoded);

    var out: [file_size]u8 = undefined;
    @memcpy(out[0..blob_size], encoded[0..]);
    std.mem.writeInt(u32, out[blob_size..file_size], checksum, .little);
    return out;
}

pub fn parseStatusBlob(decoded: []const u8) GameCfgError!Status {
    if (decoded.len != blob_size) return error.InvalidSize;

    var reader = binary.Reader.init(decoded);

    const quest_unlock_index = try reader.readU16Le();
    const quest_unlock_index_full = try reader.readU16Le();

    var weapon_counts: [weapon_usage_count]u32 = undefined;
    for (&weapon_counts) |*slot| slot.* = try reader.readU32Le();

    var quest_counts: [quest_play_count]u32 = undefined;
    for (&quest_counts) |*slot| slot.* = try reader.readU32Le();

    return .{
        .quest_unlock_index = quest_unlock_index,
        .quest_unlock_index_full = quest_unlock_index_full,
        .weapon_usage_counts = weapon_counts,
        .quest_play_counts = quest_counts,
        .mode_play_survival = try reader.readU32Le(),
        .mode_play_rush = try reader.readU32Le(),
        .mode_play_typo = try reader.readU32Le(),
        .mode_play_other = try reader.readU32Le(),
        .play_time_ms = try reader.readU32Le(),
        .reserved_seed_words = try reader.readArray(reserved_seed_words_byte_size),
    };
}

pub fn buildStatusBlob(status: Status) [blob_size]u8 {
    var out: [blob_size]u8 = undefined;
    var writer = binary.Writer.init(out[0..]);

    writer.writeU16Le(status.quest_unlock_index) catch unreachable;
    writer.writeU16Le(status.quest_unlock_index_full) catch unreachable;
    for (status.weapon_usage_counts) |value| writer.writeU32Le(value) catch unreachable;
    for (status.quest_play_counts) |value| writer.writeU32Le(value) catch unreachable;
    writer.writeU32Le(status.mode_play_survival) catch unreachable;
    writer.writeU32Le(status.mode_play_rush) catch unreachable;
    writer.writeU32Le(status.mode_play_typo) catch unreachable;
    writer.writeU32Le(status.mode_play_other) catch unreachable;
    writer.writeU32Le(status.play_time_ms) catch unreachable;
    writer.writeBytes(&status.reserved_seed_words) catch unreachable;

    std.debug.assert(writer.pos == blob_size);
    return out;
}

test "game.cfg checksum and encode vectors for zero blob" {
    const decoded: [blob_size]u8 = [_]u8{0} ** blob_size;

    const checksum = try computeChecksum(decoded[0..]);
    try std.testing.expectEqual(@as(u32, 0x0140f29c), checksum);

    const encoded = try encodeBlob(decoded[0..]);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x6f, 0x88, 0xe9, 0xbc, 0x2b, 0x60, 0x85, 0xc4,
        0x47, 0x38, 0xc1, 0x0c, 0x43, 0x90, 0x1d, 0x14,
    }, encoded[0..16]);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x37, 0x18, 0xb1, 0x2c, 0xb3, 0x70, 0x8d, 0x34,
        0x8f, 0xc8, 0x09, 0x7c, 0x4b, 0xa0, 0xa5, 0x84,
    }, encoded[blob_size - 16 .. blob_size]);
}

test "game.cfg blob encode/decode roundtrip" {
    var decoded: [blob_size]u8 = undefined;
    for (&decoded, 0..) |*byte, idx| byte.* = @truncate(idx * 13 + 7);

    const encoded = try encodeBlob(decoded[0..]);
    const rebuilt = try decodeBlob(encoded[0..]);

    try std.testing.expectEqualSlices(u8, decoded[0..], rebuilt[0..]);
}

test "game.cfg file build/parse preserves checksum and payload" {
    var decoded: [blob_size]u8 = undefined;
    for (&decoded, 0..) |*byte, idx| byte.* = @intCast((255 +% idx) & 0xFF);

    const raw = try buildFile(decoded[0..]);
    const parsed = try parseFile(raw[0..]);

    try std.testing.expectEqualSlices(u8, decoded[0..], parsed.decoded[0..]);
    try std.testing.expect(parsed.checksumValid());
}

test "game.cfg status blob parse/build roundtrip" {
    var status = std.mem.zeroes(Status);
    status.quest_unlock_index = 12;
    status.quest_unlock_index_full = 34;
    status.weapon_usage_counts[5] = 99;
    status.quest_play_counts[7] = 1234;
    status.mode_play_survival = 1;
    status.mode_play_rush = 2;
    status.mode_play_typo = 3;
    status.mode_play_other = 4;
    status.play_time_ms = 0x12345678;
    status.reserved_seed_words = [_]u8{0xA5} ** reserved_seed_words_byte_size;

    const blob = buildStatusBlob(status);
    const parsed = try parseStatusBlob(blob[0..]);

    try std.testing.expectEqual(status.quest_unlock_index, parsed.quest_unlock_index);
    try std.testing.expectEqual(status.quest_unlock_index_full, parsed.quest_unlock_index_full);
    try std.testing.expectEqual(status.weapon_usage_counts[5], parsed.weapon_usage_counts[5]);
    try std.testing.expectEqual(status.quest_play_counts[7], parsed.quest_play_counts[7]);
    try std.testing.expectEqual(status.mode_play_survival, parsed.mode_play_survival);
    try std.testing.expectEqual(status.mode_play_rush, parsed.mode_play_rush);
    try std.testing.expectEqual(status.mode_play_typo, parsed.mode_play_typo);
    try std.testing.expectEqual(status.mode_play_other, parsed.mode_play_other);
    try std.testing.expectEqual(status.play_time_ms, parsed.play_time_ms);
    try std.testing.expectEqualSlices(u8, &status.reserved_seed_words, &parsed.reserved_seed_words);
}

test "game.cfg status msgpack roundtrip mirrors python data shape" {
    var status = std.mem.zeroes(Status);
    status.quest_unlock_index = 12;
    status.quest_unlock_index_full = 34;
    status.weapon_usage_counts[5] = 99;
    status.quest_play_counts[7] = 1234;
    status.mode_play_survival = 1;
    status.mode_play_rush = 2;
    status.mode_play_typo = 3;
    status.mode_play_other = 4;
    status.play_time_ms = 0x12345678;
    status.reserved_seed_words = [_]u8{0xA5} ** reserved_seed_words_byte_size;

    var writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer writer.deinit();
    try msgpack.encode(status, &writer.writer);

    const decoded = try msgpack.decodeFromSlice(Status, std.testing.allocator, writer.written());
    defer decoded.deinit();
    try std.testing.expectEqual(status.quest_unlock_index, decoded.value.quest_unlock_index);
    try std.testing.expectEqual(status.quest_unlock_index_full, decoded.value.quest_unlock_index_full);
    try std.testing.expectEqual(status.weapon_usage_counts[5], decoded.value.weapon_usage_counts[5]);
    try std.testing.expectEqual(status.quest_play_counts[7], decoded.value.quest_play_counts[7]);
    try std.testing.expectEqual(status.mode_play_survival, decoded.value.mode_play_survival);
    try std.testing.expectEqual(status.mode_play_rush, decoded.value.mode_play_rush);
    try std.testing.expectEqual(status.mode_play_typo, decoded.value.mode_play_typo);
    try std.testing.expectEqual(status.mode_play_other, decoded.value.mode_play_other);
    try std.testing.expectEqual(status.play_time_ms, decoded.value.play_time_ms);
    try std.testing.expectEqualSlices(u8, &status.reserved_seed_words, &decoded.value.reserved_seed_words);
}
