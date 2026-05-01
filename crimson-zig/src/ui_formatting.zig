const std = @import("std");

pub fn formatOrdinal(buf: []u8, value_1_based: i32) []const u8 {
    const value = value_1_based;
    const abs_value = @abs(value);
    const suffix = if (@mod(abs_value, 100) >= 11 and @mod(abs_value, 100) <= 13)
        "th"
    else switch (@mod(abs_value, 10)) {
        1 => "st",
        2 => "nd",
        3 => "rd",
        else => "th",
    };
    return std.fmt.bufPrint(buf, "{d}{s}", .{ value, suffix }) catch "";
}

pub fn formatTimeMmSs(buf: []u8, ms: i32) []const u8 {
    const total_s = @divFloor(@max(0, ms), 1000);
    const minutes = @divFloor(total_s, 60);
    const seconds = @mod(total_s, 60);
    return std.fmt.bufPrint(buf, "{d}:{d:0>2}", .{ minutes, seconds }) catch "";
}

test "format ordinal matches python result helpers" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("1st", formatOrdinal(&buf, 1));
    try std.testing.expectEqualStrings("2nd", formatOrdinal(&buf, 2));
    try std.testing.expectEqualStrings("3rd", formatOrdinal(&buf, 3));
    try std.testing.expectEqualStrings("4th", formatOrdinal(&buf, 4));
    try std.testing.expectEqualStrings("11th", formatOrdinal(&buf, 11));
    try std.testing.expectEqualStrings("12th", formatOrdinal(&buf, 12));
    try std.testing.expectEqualStrings("13th", formatOrdinal(&buf, 13));
    try std.testing.expectEqualStrings("21st", formatOrdinal(&buf, 21));
    try std.testing.expectEqualStrings("112th", formatOrdinal(&buf, 112));
}

test "format time clamps to zero and uses m:ss" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("0:00", formatTimeMmSs(&buf, -1));
    try std.testing.expectEqualStrings("0:00", formatTimeMmSs(&buf, 999));
    try std.testing.expectEqualStrings("0:01", formatTimeMmSs(&buf, 1000));
    try std.testing.expectEqualStrings("1:01", formatTimeMmSs(&buf, 61_999));
    try std.testing.expectEqualStrings("12:20", formatTimeMmSs(&buf, 740_000));
}
