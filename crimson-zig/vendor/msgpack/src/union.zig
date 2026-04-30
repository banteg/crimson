const std = @import("std");
const hdrs = @import("headers.zig");

const NonOptional = @import("utils.zig").NonOptional;
const Optional = @import("utils.zig").Optional;
const isOptional = @import("utils.zig").isOptional;
const NoAllocator = @import("utils.zig").NoAllocator;

const maybePackNull = @import("null.zig").maybePackNull;
const maybeUnpackNull = @import("null.zig").maybeUnpackNull;

const packMapHeader = @import("map.zig").packMapHeader;
const unpackMapHeader = @import("map.zig").unpackMapHeader;

const packInt = @import("int.zig").packInt;
const unpackInt = @import("int.zig").unpackInt;

const packString = @import("string.zig").packString;
const unpackStringInto = @import("string.zig").unpackStringInto;

const packArrayHeader = @import("array.zig").packArrayHeader;
const unpackArrayHeader = @import("array.zig").unpackArrayHeader;

const packAny = @import("any.zig").packAny;
const unpackAny = @import("any.zig").unpackAny;

const unpackStructAsMap = @import("struct.zig").unpackStructAsMap;
const unpackStructFromMapBody = @import("struct.zig").unpackStructFromMapBody;
const StructAsMapOptions = @import("struct.zig").StructAsMapOptions;

pub const UnionAsMapOptions = struct {
    key: union(enum) {
        field_name,
        field_name_prefix: u8,
        field_index,
    },
    omit_nulls: bool = true,
    omit_defaults: bool = false,
};

pub const UnionAsTaggedOptions = struct {
    tag_field: []const u8 = "type",
    tag_value: union(enum) {
        field_name,
        field_name_prefix: u8,
        field_index,
    } = .field_name,
};

pub const UnionFormat = union(enum) {
    as_map: UnionAsMapOptions,
    as_tagged: UnionAsTaggedOptions,
};

pub const default_union_format = UnionFormat{
    .as_map = .{
        .key = .field_name,
    },
};

fn strPrefix(src: []const u8, len: usize) []const u8 {
    return src[0..@min(src.len, len)];
}

pub fn packUnionAsMap(writer: *std.Io.Writer, comptime T: type, value: T, opts: UnionAsMapOptions) !void {
    const type_info = @typeInfo(T);
    const fields = type_info.@"union".fields;

    const TagType = @typeInfo(T).@"union".tag_type.?;

    try packMapHeader(writer, 1);

    inline for (fields, 0..) |field, i| {
        if (value == @field(TagType, field.name)) {
            switch (opts.key) {
                .field_index => {
                    try packInt(writer, u16, i);
                },
                .field_name => {
                    try packString(writer, field.name);
                },
                .field_name_prefix => |prefix| {
                    try packString(writer, strPrefix(field.name, prefix));
                },
            }
            try packAny(writer, @field(value, field.name));
        }
    }
}

pub fn packUnionAsTagged(writer: *std.Io.Writer, comptime T: type, value: T, opts: UnionAsTaggedOptions) !void {
    const type_info = @typeInfo(T);
    const fields = type_info.@"union".fields;

    const TagType = @typeInfo(T).@"union".tag_type.?;

    inline for (fields, 0..) |field, i| {
        if (value == @field(TagType, field.name)) {
            const field_value = @field(value, field.name);
            const field_type_info = @typeInfo(field.type);

            const field_count = if (field_type_info == .@"struct") field_type_info.@"struct".fields.len else 0;

            try packMapHeader(writer, field_count + 1);

            try packString(writer, opts.tag_field);
            switch (opts.tag_value) {
                .field_index => {
                    try packInt(writer, u16, i);
                },
                .field_name => {
                    try packString(writer, field.name);
                },
                .field_name_prefix => |prefix| {
                    try packString(writer, strPrefix(field.name, prefix));
                },
            }

            if (field_type_info == .@"struct") {
                inline for (field_type_info.@"struct".fields) |struct_field| {
                    try packString(writer, struct_field.name);
                    try packAny(writer, @field(field_value, struct_field.name));
                }
            } else if (field.type != void) {
                return error.TaggedUnionUnsupportedFieldType;
            }

            return;
        }
    }
}

pub fn packUnion(writer: *std.Io.Writer, comptime T: type, value_or_maybe_null: T) !void {
    const value = try maybePackNull(writer, T, value_or_maybe_null) orelse return;
    const Type = @TypeOf(value);
    const type_info = @typeInfo(Type);

    if (type_info != .@"union") {
        @compileError("Expected union type");
    }

    const format = if (std.meta.hasFn(Type, "msgpackFormat")) T.msgpackFormat() else default_union_format;
    switch (format) {
        .as_map => |opts| {
            return packUnionAsMap(writer, Type, value, opts);
        },
        .as_tagged => |opts| {
            return packUnionAsTagged(writer, Type, value, opts);
        },
    }
}

pub fn unpackUnionAsMap(reader: *std.Io.Reader, allocator: std.mem.Allocator, comptime T: type, opts: UnionAsMapOptions) !T {
    const len = if (@typeInfo(T) == .optional)
        try unpackMapHeader(reader, ?u16) orelse return null
    else
        try unpackMapHeader(reader, u16);

    if (len != 1) {
        return error.InvalidUnionFieldCount;
    }

    const Type = NonOptional(T);
    const type_info = @typeInfo(Type);
    const fields = type_info.@"union".fields;

    var field_name_buffer: [256]u8 = undefined;

    var result: Type = undefined;

    switch (opts.key) {
        .field_index => {
            const field_index = try unpackInt(reader, u16);
            inline for (fields, 0..) |field, i| {
                if (field_index == i) {
                    const value = try unpackAny(reader, allocator, field.type);
                    result = @unionInit(Type, field.name, value);
                    break;
                }
            } else {
                return error.UnknownUnionField;
            }
        },
        .field_name => {
            const field_name = try unpackStringInto(reader, &field_name_buffer);
            inline for (fields) |field| {
                if (std.mem.eql(u8, field.name, field_name)) {
                    const value = try unpackAny(reader, allocator, field.type);
                    result = @unionInit(Type, field.name, value);
                    break;
                }
            } else {
                return error.UnknownUnionField;
            }
        },
        .field_name_prefix => |prefix| {
            const field_name = try unpackStringInto(reader, &field_name_buffer);
            inline for (fields) |field| {
                if (std.mem.startsWith(u8, field.name, strPrefix(field_name, prefix))) {
                    const value = try unpackAny(reader, allocator, field.type);
                    result = @unionInit(Type, field.name, value);
                    break;
                }
            } else {
                return error.UnknownUnionField;
            }
        },
    }

    return result;
}

pub fn unpackUnionAsTagged(reader: *std.Io.Reader, allocator: std.mem.Allocator, comptime T: type, opts: UnionAsTaggedOptions) !T {
    const len = if (@typeInfo(T) == .optional)
        try unpackMapHeader(reader, ?u16) orelse return null
    else
        try unpackMapHeader(reader, u16);

    if (len == 0) {
        return error.InvalidTaggedUnionFieldCount;
    }

    const Type = NonOptional(T);
    const type_info = @typeInfo(Type);
    const fields = type_info.@"union".fields;

    var tag_field_buffer: [256]u8 = undefined;
    var tag_value_buffer: [256]u8 = undefined;

    const tag_field_name = try unpackStringInto(reader, &tag_field_buffer);
    if (!std.mem.eql(u8, tag_field_name, opts.tag_field)) {
        return error.InvalidTagField;
    }

    var union_field_index: ?usize = null;
    var union_field_name: ?[]const u8 = null;

    switch (opts.tag_value) {
        .field_index => {
            const field_index = try unpackInt(reader, u16);
            union_field_index = field_index;
        },
        .field_name => {
            const field_name = try unpackStringInto(reader, &tag_value_buffer);
            union_field_name = field_name;
        },
        .field_name_prefix => {
            const field_name = try unpackStringInto(reader, &tag_value_buffer);
            union_field_name = field_name;
        },
    }

    inline for (fields, 0..) |field, i| {
        const is_match = switch (opts.tag_value) {
            .field_index => union_field_index == i,
            .field_name => if (union_field_name) |name| std.mem.eql(u8, field.name, name) else false,
            .field_name_prefix => |prefix| if (union_field_name) |name| std.mem.startsWith(u8, field.name, strPrefix(name, prefix)) else false,
        };

        if (is_match) {
            const field_type_info = @typeInfo(field.type);

            if (field.type == void) {
                if (len != 1) {
                    return error.InvalidTaggedUnionFieldCount;
                }
                return @unionInit(Type, field.name, {});
            } else if (field_type_info == .@"struct") {
                const struct_opts = StructAsMapOptions{ .key = .field_name };
                const struct_value = try unpackStructFromMapBody(reader, allocator, field.type, len - 1, struct_opts);
                return @unionInit(Type, field.name, struct_value);
            } else {
                return error.TaggedUnionUnsupportedFieldType;
            }
        }
    }

    return error.UnknownUnionField;
}

pub fn unpackUnion(reader: *std.Io.Reader, allocator: std.mem.Allocator, comptime T: type) !T {
    const Type = NonOptional(T);

    const format = if (std.meta.hasFn(Type, "msgpackFormat")) T.msgpackFormat() else default_union_format;
    switch (format) {
        .as_map => |opts| {
            return try unpackUnionAsMap(reader, allocator, T, opts);
        },
        .as_tagged => |opts| {
            return try unpackUnionAsTagged(reader, allocator, T, opts);
        },
    }
}
const Msg1 = union(enum) {
    a: u32,
    b: u64,

    pub fn msgpackFormat() UnionFormat {
        return .{ .as_map = .{ .key = .field_index } };
    }
};
const msg1 = Msg1{ .a = 1 };
const msg1_packed = [_]u8{
    0x81, // map with 1 elements
    0x00, // key: fixint 0
    0x01, // value: u32(1)
};

const Msg2 = union(enum) {
    a,
    b: u64,

    pub fn msgpackFormat() UnionFormat {
        return .{ .as_map = .{ .key = .field_index } };
    }
};
const msg2 = Msg2{ .a = {} };
const msg2_packed = [_]u8{
    0x81, // map with 1 elements
    0x00, // key: fixint 0
    0xc0, // value: nil
};

test "writeUnion: int field" {
    var buffer: [100]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packUnion(&writer, Msg1, msg1);

    try std.testing.expectEqualSlices(u8, &msg1_packed, writer.buffered());
}

test "writeUnion: void field" {
    var buffer: [100]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packUnion(&writer, Msg2, msg2);

    try std.testing.expectEqualSlices(u8, &msg2_packed, writer.buffered());
}

test "readUnion: int field" {
    var reader = std.Io.Reader.fixed(&msg1_packed);
    const value = try unpackUnion(&reader, NoAllocator.allocator(), Msg1);
    try std.testing.expectEqual(msg1, value);
}

test "readUnion: void field" {
    var reader = std.Io.Reader.fixed(&msg2_packed);
    const value = try unpackUnion(&reader, NoAllocator.allocator(), Msg2);
    try std.testing.expectEqual(msg2, value);
}

const Msg3 = union(enum) {
    get: struct { key: u32 },
    put: struct { key: u32, val: u64 },

    pub fn msgpackFormat() UnionFormat {
        return .{ .as_tagged = .{} };
    }
};

const Msg4 = union(enum) {
    get: struct { key: u32 },
    put: struct { key: u32, val: u64 },

    pub fn msgpackFormat() UnionFormat {
        return .{ .as_tagged = .{
            .tag_field = "op",
            .tag_value = .field_index,
        } };
    }
};

const msg3_get = Msg3{ .get = .{ .key = 42 } };
const msg3_get_packed = [_]u8{
    0x82, // map with 2 elements
    0xa4, 't', 'y', 'p', 'e', // key: "type"
    0xa3, 'g', 'e', 't', // value: "get"
    0xa3, 'k', 'e', 'y', // key: "key"
    42, // value: 42
};

const msg3_put = Msg3{ .put = .{ .key = 10, .val = 20 } };
const msg3_put_packed = [_]u8{
    0x83, // map with 3 elements
    0xa4, 't', 'y', 'p', 'e', // key: "type"
    0xa3, 'p', 'u', 't', // value: "put"
    0xa3, 'k', 'e', 'y', // key: "key"
    10, // value: 10
    0xa3, 'v', 'a', 'l', // key: "val"
    20, // value: 20
};

const msg4_get = Msg4{ .get = .{ .key = 99 } };
const msg4_get_packed = [_]u8{
    0x82, // map with 2 elements
    0xa2, 'o', 'p', // key: "op"
    0x00, // value: 0 (field index)
    0xa3, 'k', 'e', 'y', // key: "key"
    99, // value: 99
};

test "writeUnion: tagged format with field name" {
    var buffer: [100]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packUnion(&writer, Msg3, msg3_get);
    try std.testing.expectEqualSlices(u8, &msg3_get_packed, writer.buffered());
}

test "writeUnion: tagged format with multiple fields" {
    var buffer: [100]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packUnion(&writer, Msg3, msg3_put);
    try std.testing.expectEqualSlices(u8, &msg3_put_packed, writer.buffered());
}

test "writeUnion: tagged format with field index" {
    var buffer: [100]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packUnion(&writer, Msg4, msg4_get);
    try std.testing.expectEqualSlices(u8, &msg4_get_packed, writer.buffered());
}

test "readUnion: tagged format with field name" {
    var reader = std.Io.Reader.fixed(&msg3_get_packed);
    const value = try unpackUnion(&reader, NoAllocator.allocator(), Msg3);
    try std.testing.expectEqual(42, value.get.key);
}

test "readUnion: tagged format with multiple fields" {
    var reader = std.Io.Reader.fixed(&msg3_put_packed);
    const value = try unpackUnion(&reader, NoAllocator.allocator(), Msg3);
    try std.testing.expectEqual(10, value.put.key);
    try std.testing.expectEqual(20, value.put.val);
}

test "readUnion: tagged format with field index" {
    var reader = std.Io.Reader.fixed(&msg4_get_packed);
    const value = try unpackUnion(&reader, NoAllocator.allocator(), Msg4);
    try std.testing.expectEqual(99, value.get.key);
}
