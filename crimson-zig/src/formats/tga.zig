const std = @import("std");
const binary = @import("binary.zig");

pub const TgaError = binary.BinaryError || std.mem.Allocator.Error || error{
    UnsupportedColorMap,
    UnsupportedImageType,
    UnsupportedPixelDepth,
    InvalidDimensions,
    InvalidImageData,
};

pub const Header = struct {
    id_length: u8,
    color_map_type: u8,
    image_type: u8,
    color_map_origin: u16,
    color_map_length: u16,
    color_map_depth: u8,
    x_origin: u16,
    y_origin: u16,
    width: u16,
    height: u16,
    pixel_depth: u8,
    image_descriptor: u8,
};

pub const Image = struct {
    width: u16,
    height: u16,
    pixels_rgba: []u8,

    pub fn deinit(self: Image, allocator: std.mem.Allocator) void {
        allocator.free(self.pixels_rgba);
    }
};

const image_type_truecolor_rle: u8 = 10;
const descriptor_origin_right: u8 = 0x10;
const descriptor_origin_top: u8 = 0x20;

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) TgaError!Image {
    if (bytes.len < 18) return error.UnexpectedEof;

    var reader = binary.Reader.init(bytes);
    const header: Header = .{
        .id_length = try reader.readU8(),
        .color_map_type = try reader.readU8(),
        .image_type = try reader.readU8(),
        .color_map_origin = try reader.readU16Le(),
        .color_map_length = try reader.readU16Le(),
        .color_map_depth = try reader.readU8(),
        .x_origin = try reader.readU16Le(),
        .y_origin = try reader.readU16Le(),
        .width = try reader.readU16Le(),
        .height = try reader.readU16Le(),
        .pixel_depth = try reader.readU8(),
        .image_descriptor = try reader.readU8(),
    };

    _ = header.color_map_origin;
    _ = header.color_map_length;
    _ = header.color_map_depth;
    _ = header.x_origin;
    _ = header.y_origin;

    if (header.color_map_type != 0) return error.UnsupportedColorMap;
    if (header.image_type != image_type_truecolor_rle) return error.UnsupportedImageType;
    if (header.pixel_depth != 32) return error.UnsupportedPixelDepth;
    if (header.width == 0 or header.height == 0) return error.InvalidDimensions;

    _ = try reader.readBytes(header.id_length);

    const pixel_count = @as(usize, header.width) * @as(usize, header.height);
    const pixels_rgba = try allocator.alloc(u8, pixel_count * 4);
    errdefer allocator.free(pixels_rgba);

    var emitted_pixels: usize = 0;
    var encoded_y: usize = 0;
    var encoded_x: usize = 0;
    while (emitted_pixels < pixel_count) {
        const packet_header = try reader.readU8();
        const packet_count = @as(usize, (packet_header & 0x7f) + 1);
        if (packet_count > pixel_count - emitted_pixels) return error.InvalidImageData;

        if ((packet_header & 0x80) != 0) {
            const pixel = try readPixel(reader.readBytes(4) catch return error.UnexpectedEof);
            for (0..packet_count) |_| {
                writePixel(
                    pixels_rgba,
                    header,
                    encoded_x,
                    encoded_y,
                    pixel,
                );
                advanceCursor(header, &encoded_x, &encoded_y);
                emitted_pixels += 1;
            }
        } else {
            for (0..packet_count) |_| {
                const pixel = try readPixel(reader.readBytes(4) catch return error.UnexpectedEof);
                writePixel(
                    pixels_rgba,
                    header,
                    encoded_x,
                    encoded_y,
                    pixel,
                );
                advanceCursor(header, &encoded_x, &encoded_y);
                emitted_pixels += 1;
            }
        }
    }

    return .{
        .width = header.width,
        .height = header.height,
        .pixels_rgba = pixels_rgba,
    };
}

fn readPixel(raw: []const u8) TgaError![4]u8 {
    if (raw.len != 4) return error.InvalidImageData;
    return .{ raw[2], raw[1], raw[0], raw[3] };
}

fn advanceCursor(header: Header, encoded_x: *usize, encoded_y: *usize) void {
    encoded_x.* += 1;
    if (encoded_x.* >= header.width) {
        encoded_x.* = 0;
        encoded_y.* += 1;
    }
}

fn writePixel(
    pixels_rgba: []u8,
    header: Header,
    encoded_x: usize,
    encoded_y: usize,
    pixel: [4]u8,
) void {
    const width_usize: usize = header.width;
    const height_usize: usize = header.height;
    const out_x = if ((header.image_descriptor & descriptor_origin_right) != 0)
        width_usize - 1 - encoded_x
    else
        encoded_x;
    const out_y = if ((header.image_descriptor & descriptor_origin_top) != 0)
        encoded_y
    else
        height_usize - 1 - encoded_y;

    const offset = (out_y * width_usize + out_x) * 4;
    pixels_rgba[offset..][0..4].* = pixel;
}

test "decode RLE 32-bit TGA with bottom-left origin" {
    const allocator = std.testing.allocator;
    const bytes = [_]u8{
        0,    0,    10,   0,    0,    0,    0,    0,    0,    0,    0,    0,
        2,    0,    2,    0,    32,   8,    0x81, 0x01, 0x02, 0x03, 0x04, 0x01,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    };

    const image = try decode(allocator, &bytes);
    defer image.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 2), image.width);
    try std.testing.expectEqual(@as(u16, 2), image.height);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x07, 0x06, 0x05, 0x08,
        0x0b, 0x0a, 0x09, 0x0c,
        0x03, 0x02, 0x01, 0x04,
        0x03, 0x02, 0x01, 0x04,
    }, image.pixels_rgba);
}

test "decode rejects unsupported pixel depth" {
    const allocator = std.testing.allocator;
    const bytes = [_]u8{
        0, 0, 10, 0, 0,  0, 0, 0, 0, 0, 0, 0,
        1, 0, 1,  0, 24, 0,
    };
    try std.testing.expectError(error.UnsupportedPixelDepth, decode(allocator, &bytes));
}
