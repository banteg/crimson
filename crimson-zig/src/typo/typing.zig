const std = @import("std");

pub const typing_max_chars: usize = 17;

pub const TypingBuffer = struct {
    text_len: usize = 0,
    text: [typing_max_chars]u8 = [_]u8{0} ** typing_max_chars,
    submit_count: i32 = 0,
    match_count: i32 = 0,

    pub fn clear(self: *TypingBuffer) void {
        self.text_len = 0;
        @memset(self.text[0..], 0);
    }

    pub fn slice(self: *const TypingBuffer) []const u8 {
        return self.text[0..self.text_len];
    }

    pub fn backspace(self: *TypingBuffer) void {
        if (self.text_len == 0) return;
        self.text_len -= 1;
        self.text[self.text_len] = 0;
    }

    pub fn pushChar(self: *TypingBuffer, ch: u8) void {
        if (ch == 0) return;
        if (self.text_len >= typing_max_chars) return;
        self.text[self.text_len] = ch;
        self.text_len += 1;
    }

    pub fn submit(self: *TypingBuffer, matched: bool) ?[]const u8 {
        if (self.text_len == 0) return null;
        self.submit_count += 1;
        if (matched) self.match_count += 1;
        const entered_len = self.text_len;
        self.text_len = 0;
        return self.text[0..entered_len];
    }
};

test "typing buffer enforces max chars and submit counts" {
    var buffer: TypingBuffer = .{};
    for (0..typing_max_chars + 3) |_| {
        buffer.pushChar('a');
    }
    try std.testing.expectEqual(typing_max_chars, buffer.text_len);

    const submitted = buffer.submit(true).?;
    try std.testing.expectEqual(typing_max_chars, submitted.len);
    try std.testing.expectEqual(@as(i32, 1), buffer.submit_count);
    try std.testing.expectEqual(@as(i32, 1), buffer.match_count);
    try std.testing.expectEqual(@as(usize, 0), buffer.text_len);
}
