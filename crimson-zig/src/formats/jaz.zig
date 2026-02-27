const std = @import("std");
const binary = @import("binary.zig");

pub const JazError = binary.BinaryError || error{
    InvalidHeader,
    UnsupportedMethod,
    TruncatedCompressedPayload,
    InvalidCompressedPayload,
    RawSizeMismatch,
    InvalidPayload,
    OutOfMemory,
};

pub const Header = struct {
    method: u8,
    comp_size: u32,
    raw_size: u32,
};

pub const Decoded = struct {
    header: Header,
    jpeg_bytes: []u8,
    alpha_rle_bytes: []u8,

    pub fn deinit(self: Decoded, allocator: std.mem.Allocator) void {
        allocator.free(self.jpeg_bytes);
        allocator.free(self.alpha_rle_bytes);
    }
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) JazError!Decoded {
    if (bytes.len < 9) return error.InvalidHeader;

    var header_reader = binary.Reader.init(bytes);
    const header = Header{
        .method = try header_reader.readU8(),
        .comp_size = try header_reader.readU32Le(),
        .raw_size = try header_reader.readU32Le(),
    };

    if (header.method != 1) return error.UnsupportedMethod;

    const needed = 9 + @as(usize, header.comp_size);
    if (bytes.len < needed) return error.TruncatedCompressedPayload;

    const compressed = bytes[9..needed];
    const raw = try inflateRawPayload(allocator, compressed, header.raw_size);
    defer allocator.free(raw);

    if (raw.len < 4) return error.InvalidPayload;

    var payload_reader = binary.Reader.init(raw);
    const jpeg_len = try payload_reader.readU32Le();
    if (jpeg_len > raw.len - 4) return error.InvalidPayload;

    const jpeg = try allocator.dupe(u8, raw[4 .. 4 + jpeg_len]);
    errdefer allocator.free(jpeg);

    const alpha = try allocator.dupe(u8, raw[4 + jpeg_len ..]);
    return .{
        .header = header,
        .jpeg_bytes = jpeg,
        .alpha_rle_bytes = alpha,
    };
}

fn inflateRawPayload(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    expected_size_u32: u32,
) JazError![]u8 {
    const expected_size: usize = expected_size_u32;

    var input: std.Io.Reader = .fixed(compressed);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&input, .zlib, &window);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    var chunk: [8192]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = decompress.reader.readSliceShort(&chunk) catch return error.InvalidCompressedPayload;
        if (n == 0) break;
        total += n;
        if (total > expected_size) return error.RawSizeMismatch;
        try out.appendSlice(allocator, chunk[0..n]);
        if (n < chunk.len) break;
    }

    if (total != expected_size) return error.RawSizeMismatch;
    return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

test "JAZ golden vector decode" {
    const allocator = std.testing.allocator;

    const jaz_blob = [_]u8{
        0x01, 0x14, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x78, 0x9c, 0x63, 0x61, 0x60, 0x60, 0xf8, 0x7f, 0xe3,
        0xff, 0x4d, 0xe6, 0x7a, 0x26, 0x07, 0x00, 0x1a, 0x20,
        0x04, 0x78,
    };

    var decoded = try decode(allocator, &jaz_blob);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 1), decoded.header.method);
    try std.testing.expectEqual(@as(u32, 20), decoded.header.comp_size);
    try std.testing.expectEqual(@as(u32, 12), decoded.header.raw_size);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xff, 0xd8, 0xff, 0xd9 }, decoded.jpeg_bytes);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x7f, 0x02, 0x40 }, decoded.alpha_rle_bytes);
}

test "JAZ rejects unsupported compression method" {
    const allocator = std.testing.allocator;
    const bad = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectError(error.UnsupportedMethod, decode(allocator, &bad));
}

test "JAZ rejects raw-size mismatch" {
    const allocator = std.testing.allocator;

    var jaz_blob = [_]u8{
        0x01, 0x14, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
        0x78, 0x9c, 0x63, 0x61, 0x60, 0x60, 0xf8, 0x7f, 0xe3,
        0xff, 0x4d, 0xe6, 0x7a, 0x26, 0x07, 0x00, 0x1a, 0x20,
        0x04, 0x78,
    };

    try std.testing.expectError(error.RawSizeMismatch, decode(allocator, &jaz_blob));
}

test "JAZ rejects invalid payload split" {
    const allocator = std.testing.allocator;

    const bad = [_]u8{
        0x01, 0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x78, 0x9c, 0xfb, 0xff, 0xff, 0x7f, 0x3d, 0x00, 0x09,
        0x7a, 0x03, 0x7d,
    };

    try std.testing.expectError(error.InvalidPayload, decode(allocator, &bad));
}

test "JAZ rejects truncated compressed payload" {
    const allocator = std.testing.allocator;
    const bad = [_]u8{ 0x01, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x78, 0x9c };
    try std.testing.expectError(error.TruncatedCompressedPayload, decode(allocator, &bad));
}
