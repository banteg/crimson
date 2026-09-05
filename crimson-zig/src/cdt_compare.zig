const std = @import("std");

pub const Mismatch = struct {
    kind: []const u8 = "field_mismatch",
    tick_index: i32,
    field: ?[]const u8 = null,
    expected: ?i64 = null,
    actual: ?i64 = null,
    expected_float: ?f64 = null,
    actual_float: ?f64 = null,
    expected_text: ?[]const u8 = null,
    actual_text: ?[]const u8 = null,
    numeric_delta: ?f64 = null,
    expected_f32_hex: ?[]const u8 = null,
    actual_f32_hex: ?[]const u8 = null,
    f32_ulp_distance: ?u64 = null,
};

/// Returned strings belong to allocator. Callers use a report-owned arena.
pub fn firstMismatch(allocator: std.mem.Allocator, tick: i32, expected: anytype, actual: @TypeOf(expected), path: []const u8) !?Mismatch {
    var context: Context = .{ .allocator = allocator, .tick = tick };
    return context.compare(expected, actual, path);
}

const Context = struct {
    allocator: std.mem.Allocator,
    tick: i32,

    fn mismatch(self: Context, path: []const u8) !Mismatch {
        return .{ .tick_index = self.tick, .field = try self.allocator.dupe(u8, path) };
    }

    fn compare(self: Context, expected: anytype, actual: @TypeOf(expected), path: []const u8) std.mem.Allocator.Error!?Mismatch {
        const T = @TypeOf(expected);
        var buffer: [1024]u8 = undefined;
        switch (@typeInfo(T)) {
            .@"struct" => |info| {
                inline for (info.fields) |field| {
                    const next = std.fmt.bufPrint(&buffer, "{s}.{s}", .{ path, field.name }) catch unreachable;
                    if (try self.compare(@field(expected, field.name), @field(actual, field.name), next)) |found| return found;
                }
            },
            .@"union" => |info| {
                const tag = std.meta.activeTag(expected);
                if (tag != std.meta.activeTag(actual)) return try self.compare(@tagName(tag), @tagName(std.meta.activeTag(actual)), path);
                inline for (info.fields) |field| {
                    if (tag == @field(info.tag_type.?, field.name)) return self.compare(@field(expected, field.name), @field(actual, field.name), path);
                }
            },
            .optional => {
                if (expected) |value| {
                    if (actual) |other| return self.compare(value, other, path);
                } else if (actual == null) return null;
                return try self.mismatch(path);
            },
            .pointer => |info| {
                if (info.size != .slice) @compileError("CDT comparisons require slices");
                if (info.child == u8) {
                    if (!std.mem.eql(u8, expected, actual)) {
                        var found = try self.mismatch(path);
                        found.expected_text = try self.allocator.dupe(u8, expected);
                        found.actual_text = try self.allocator.dupe(u8, actual);
                        return found;
                    }
                    return null;
                }
                if (expected.len != actual.len) {
                    const next = std.fmt.bufPrint(&buffer, "{s}._len", .{path}) catch unreachable;
                    return self.compare(expected.len, actual.len, next);
                }
                // Entity order is incidental: the shared contract compares by UID.
                if (comptime @typeInfo(info.child) == .@"struct" and @hasField(info.child, "uid")) {
                    for (expected, 0..) |entry, index| {
                        const next = std.fmt.bufPrint(&buffer, "{s}[uid={d}]", .{ path, entry.uid }) catch unreachable;
                        if (actual[index].uid == entry.uid) {
                            if (try self.compare(entry, actual[index], next)) |found| return found;
                            continue;
                        }
                        var other: ?info.child = null;
                        for (actual) |candidate| {
                            if (candidate.uid == entry.uid) {
                                other = candidate;
                                break;
                            }
                        }
                        if (other) |value| {
                            if (try self.compare(entry, value, next)) |found| return found;
                        } else return try self.mismatch(next);
                    }
                } else {
                    for (expected, actual, 0..) |entry, other, i| {
                        const next = std.fmt.bufPrint(&buffer, "{s}[{d}]", .{ path, i }) catch unreachable;
                        if (try self.compare(entry, other, next)) |found| return found;
                    }
                }
            },
            .array => {
                for (expected, actual, 0..) |entry, other, i| {
                    const next = std.fmt.bufPrint(&buffer, "{s}[{d}]", .{ path, i }) catch unreachable;
                    if (try self.compare(entry, other, next)) |found| return found;
                }
            },
            .float => {
                if (expected != actual) {
                    var found = try self.mismatch(path);
                    found.expected_float = expected;
                    found.actual_float = actual;
                    found.numeric_delta = @as(f64, actual) - @as(f64, expected);
                    const left: u32 = @bitCast(@as(f32, @floatCast(expected)));
                    const right: u32 = @bitCast(@as(f32, @floatCast(actual)));
                    found.expected_f32_hex = try std.fmt.allocPrint(self.allocator, "0x{x:0>8}", .{left});
                    found.actual_f32_hex = try std.fmt.allocPrint(self.allocator, "0x{x:0>8}", .{right});
                    const a = orderedFloatBits(left);
                    const b = orderedFloatBits(right);
                    found.f32_ulp_distance = @max(a, b) - @min(a, b);
                    return found;
                }
            },
            .int, .comptime_int => {
                if (expected != actual) {
                    var found = try self.mismatch(path);
                    found.expected = @intCast(expected);
                    found.actual = @intCast(actual);
                    return found;
                }
            },
            .bool => return self.compare(@as(u8, @intFromBool(expected)), @as(u8, @intFromBool(actual)), path),
            .@"enum" => return self.compare(@intFromEnum(expected), @intFromEnum(actual), path),
            else => @compileError("unsupported CDT comparison type: " ++ @typeName(T)),
        }
        return null;
    }
};

fn orderedFloatBits(bits: u32) u32 {
    return if (bits & 0x80000000 != 0) 0x80000000 - (bits & 0x7fffffff) else 0x80000000 + bits;
}

test "comparison walks arrays and nested float fields with exact diagnostics" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const Item = struct { pos: struct { x: f32 }, flags: u32 };
    const expected = [_]Item{.{ .pos = .{ .x = 1.0 }, .flags = 0 }};
    const actual = [_]Item{.{ .pos = .{ .x = @bitCast(@as(u32, 0x3f800001)) }, .flags = 0 }};
    const result = (try firstMismatch(arena.allocator(), 3, expected, actual, "samples")).?;
    try std.testing.expectEqualStrings("samples[0].pos.x", result.field.?);
    try std.testing.expectEqual(@as(?u64, 1), result.f32_ulp_distance);
}
