const std = @import("std");

/// `format_ordinal`: 8..20 take "th"; otherwise the last digit picks st/nd/rd.
pub fn formatOrdinal(buf: []u8, value: i32) []const u8 {
    const suffix = if (value >= 8 and value <= 20) "th" else switch (@mod(value, 10)) {
        1 => "st",
        2 => "nd",
        3 => "rd",
        else => "th",
    };
    return std.fmt.bufPrint(buf, "{d}{s}", .{ value, suffix }) catch "";
}

const month_labels = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

pub fn formatHighscoreDateLabel(buf: []u8, day: u8, month_index: u8, year: i32) []const u8 {
    const month = if (month_index >= 1 and month_index <= 12) month_labels[month_index - 1] else "???";
    return std.fmt.bufPrint(buf, "{d}. {s} {d}", .{ day, month, year }) catch "";
}

pub fn formatTimeMmSs(buf: []u8, ms: i32) []const u8 {
    const total_s = @divFloor(@max(0, ms), 1000);
    const minutes = @divFloor(total_s, 60);
    const seconds = @mod(total_s, 60);
    return std.fmt.bufPrint(buf, "{d}:{d:0>2}", .{ minutes, seconds }) catch "";
}

test "format ordinal follows native: 8..20 take th, the last digit picks the rest" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("1st", formatOrdinal(&buf, 1));
    try std.testing.expectEqualStrings("3rd", formatOrdinal(&buf, 3));
    try std.testing.expectEqualStrings("4th", formatOrdinal(&buf, 4));
    try std.testing.expectEqualStrings("11th", formatOrdinal(&buf, 11));
    try std.testing.expectEqualStrings("21st", formatOrdinal(&buf, 21));
    try std.testing.expectEqualStrings("111st", formatOrdinal(&buf, 111));
    try std.testing.expectEqualStrings("112nd", formatOrdinal(&buf, 112));
}

test "high-score date label marks an unknown month" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("3. Feb 2026", formatHighscoreDateLabel(&buf, 3, 2, 2026));
    try std.testing.expectEqualStrings("0. ??? 2000", formatHighscoreDateLabel(&buf, 0, 0, 2000));
}

test "format time clamps to zero and uses m:ss" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("0:00", formatTimeMmSs(&buf, -1));
    try std.testing.expectEqualStrings("0:00", formatTimeMmSs(&buf, 999));
    try std.testing.expectEqualStrings("0:01", formatTimeMmSs(&buf, 1000));
    try std.testing.expectEqualStrings("1:01", formatTimeMmSs(&buf, 61_999));
    try std.testing.expectEqualStrings("12:20", formatTimeMmSs(&buf, 740_000));
}
