//! Validate the current CDT wire shape before typed decoding can apply defaults
//! or narrow a noncanonical float64 value to f32.
const std = @import("std");
const BinaryBytes = @import("replay_codec.zig").BinaryBytes;

pub const Error = error{InvalidTraceWire};

pub fn validate(comptime T: type, bytes: []const u8) Error!void {
    var reader: Reader = .{ .bytes = bytes };
    try reader.value(T);
    if (reader.pos != bytes.len) return error.InvalidTraceWire;
}

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    skip_depth: usize = 0,

    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (n > self.bytes.len - self.pos) return error.InvalidTraceWire;
        const result = self.bytes[self.pos..][0..n];
        self.pos += n;
        return result;
    }
    fn byte(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }
    fn uint(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    fn length(self: *Reader, kind: enum { map, array }) Error!usize {
        const tag = try self.byte();
        return switch (kind) {
            .map => switch (tag) {
                0x80...0x8f => tag & 15,
                0xde => try self.uint(u16),
                0xdf => try self.uint(u32),
                else => error.InvalidTraceWire,
            },
            .array => switch (tag) {
                0x90...0x9f => tag & 15,
                0xdc => try self.uint(u16),
                0xdd => try self.uint(u32),
                else => error.InvalidTraceWire,
            },
        };
    }
    fn string(self: *Reader, binary: bool) Error![]const u8 {
        const tag = try self.byte();
        const size: usize = if (binary) switch (tag) {
            0xc4 => try self.uint(u8),
            0xc5 => try self.uint(u16),
            0xc6 => try self.uint(u32),
            else => return error.InvalidTraceWire,
        } else switch (tag) {
            0xa0...0xbf => tag & 31,
            0xd9 => try self.uint(u8),
            0xda => try self.uint(u16),
            0xdb => try self.uint(u32),
            else => return error.InvalidTraceWire,
        };
        const bytes = try self.take(size);
        if (!binary and !std.unicode.utf8ValidateSlice(bytes)) return error.InvalidTraceWire;
        return bytes;
    }
    fn map(self: *Reader, comptime T: type, tag_value: ?[]const u8) Error!void {
        const fields = @typeInfo(T).@"struct".fields;
        const count = try self.length(.map);
        if (count != fields.len + @as(usize, @intFromBool(tag_value != null))) return error.InvalidTraceWire;
        var seen = [_]bool{false} ** fields.len;
        var tag_seen = false;
        for (0..count) |_| {
            const key = try self.string(false);
            if (tag_value != null and std.mem.eql(u8, key, "type")) {
                if (tag_seen or !std.mem.eql(u8, try self.string(false), tag_value.?)) return error.InvalidTraceWire;
                tag_seen = true;
                continue;
            }
            inline for (fields, 0..) |field, index| {
                if (std.mem.eql(u8, key, field.name)) {
                    if (seen[index]) return error.InvalidTraceWire;
                    seen[index] = true;
                    try self.value(field.type);
                    break;
                }
            } else return error.InvalidTraceWire;
        }
        for (seen) |present| {
            if (!present) return error.InvalidTraceWire;
        }
        if (tag_value != null and !tag_seen) return error.InvalidTraceWire;
    }
    fn value(self: *Reader, comptime T: type) Error!void {
        if (T == BinaryBytes) {
            _ = try self.string(true);
            return;
        }
        switch (@typeInfo(T)) {
            .optional => |info| {
                if (self.pos == self.bytes.len) return error.InvalidTraceWire;
                if (self.bytes[self.pos] == 0xc0) {
                    self.pos += 1;
                    return;
                }
                try self.value(info.child);
            },
            .@"struct" => try self.map(T, null),
            .@"union" => |info| {
                const start = self.pos;
                const count = try self.length(.map);
                var tag: ?[]const u8 = null;
                for (0..count) |_| {
                    const key = try self.string(false);
                    if (std.mem.eql(u8, key, "type")) {
                        tag = try self.string(false);
                    } else try self.skip();
                }
                self.pos = start;
                if (tag) |name| {
                    inline for (info.fields) |field| {
                        if (std.mem.eql(u8, name, field.name)) {
                            try self.map(field.type, name);
                            return;
                        }
                    }
                }
                return error.InvalidTraceWire;
            },
            .pointer => |info| {
                if (info.size != .slice) @compileError("expected wire slice");
                if (info.child == u8) {
                    _ = try self.string(false);
                } else {
                    const count = try self.length(.array);
                    for (0..count) |_| try self.value(info.child);
                }
            },
            .array => |info| {
                if (try self.length(.array) != info.len) return error.InvalidTraceWire;
                for (0..info.len) |_| try self.value(info.child);
            },
            .float => {
                const number: f64 = switch (try self.byte()) {
                    0xca => @as(f32, @bitCast(try self.uint(u32))),
                    0xcb => @bitCast(try self.uint(u64)),
                    else => return error.InvalidTraceWire,
                };
                if (!std.math.isFinite(number) or @as(f64, @as(f32, @floatCast(number))) != number) return error.InvalidTraceWire;
            },
            .int, .@"enum" => {
                // Typed decoding checks signedness and range after this token check.
                switch (try self.byte()) {
                    0x00...0x7f, 0xe0...0xff => {},
                    0xcc, 0xd0 => {
                        _ = try self.take(1);
                    },
                    0xcd, 0xd1 => {
                        _ = try self.take(2);
                    },
                    0xce, 0xd2 => {
                        _ = try self.take(4);
                    },
                    0xcf, 0xd3 => {
                        _ = try self.take(8);
                    },
                    else => return error.InvalidTraceWire,
                }
            },
            .bool => {
                const tag = try self.byte();
                if (tag != 0xc2 and tag != 0xc3) return error.InvalidTraceWire;
            },
            else => @compileError("unsupported CDT wire type " ++ @typeName(T)),
        }
    }
    fn skip(self: *Reader) Error!void {
        if (self.skip_depth >= 32) return error.InvalidTraceWire;
        self.skip_depth += 1;
        defer self.skip_depth -= 1;
        if (self.pos == self.bytes.len) return error.InvalidTraceWire;
        switch (self.bytes[self.pos]) {
            0x80...0x8f, 0xde, 0xdf => {
                const n = try self.length(.map);
                for (0..n) |_| {
                    try self.skip();
                    try self.skip();
                }
            },
            0x90...0x9f, 0xdc, 0xdd => {
                const n = try self.length(.array);
                for (0..n) |_| try self.skip();
            },
            0xa0...0xbf, 0xd9...0xdb => {
                _ = try self.string(false);
            },
            0xc4...0xc6 => {
                _ = try self.string(true);
            },
            0xc0, 0xc2, 0xc3 => {
                self.pos += 1;
            },
            0xca, 0xcb => try self.value(f64),
            else => try self.value(i64),
        }
    }
};

test "strict CDT wire validation requires explicit defaults and exact f32 values" {
    const Row = struct { health: f32 = 100 };
    try validate(Row, &.{ 0x81, 0xa6, 'h', 'e', 'a', 'l', 't', 'h', 0xca, 0x42, 0xc8, 0, 0 });
    try std.testing.expectError(error.InvalidTraceWire, validate(Row, &.{0x80}));
    try std.testing.expectError(error.InvalidTraceWire, validate(Row, &.{ 0x81, 0xa6, 'h', 'e', 'a', 'l', 't', 'h', 0xcb, 0x3f, 0xb9, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a }));
    try std.testing.expectError(error.InvalidTraceWire, validate(Row, &.{ 0x81, 0xa6, 'h', 'e', 'a', 'l', 't', 'h', 100 }));
}
