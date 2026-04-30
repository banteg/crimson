const std = @import("std");
const mem = std.mem;

pub fn NonOptional(comptime T: type) type {
    const type_info = @typeInfo(T);
    if (type_info == .optional) {
        return type_info.optional.child;
    }
    return T;
}

pub fn Optional(comptime T: type, comptime is_optional: bool) type {
    return if (is_optional) ?T else T;
}

pub inline fn isOptional(comptime T: type) bool {
    return @typeInfo(T) == .optional;
}

test isOptional {
    try std.testing.expect(isOptional(?u32));
    try std.testing.expect(!isOptional(u32));
}

var no_allocator_dummy: u8 = 0;

pub const NoAllocator = struct {
    pub fn noAlloc(ctx: *anyopaque, len: usize, ptr_align: mem.Alignment, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = len;
        _ = ptr_align;
        _ = ret_addr;
        return null;
    }

    pub fn allocator() std.mem.Allocator {
        return .{
            .ptr = &no_allocator_dummy,
            .vtable = &.{
                .alloc = noAlloc,
                .resize = std.mem.Allocator.noResize,
                .free = std.mem.Allocator.noFree,
                .remap = std.mem.Allocator.noRemap,
            },
        };
    }
};
