const std = @import("std");
const rl = @import("raylib");

pub const input_code_unbound: i32 = 0x17E;

pub fn raylibKeyFromInputCode(code: i32) ?rl.KeyboardKey {
    return switch (code) {
        0x01 => @enumFromInt(256),
        0x02 => @enumFromInt(49),
        0x03 => @enumFromInt(50),
        0x04 => @enumFromInt(51),
        0x05 => @enumFromInt(52),
        0x06 => @enumFromInt(53),
        0x07 => @enumFromInt(54),
        0x08 => @enumFromInt(55),
        0x09 => @enumFromInt(56),
        0x0A => @enumFromInt(57),
        0x0B => @enumFromInt(48),
        0x0C => @enumFromInt(45),
        0x0D => @enumFromInt(61),
        0x0E => @enumFromInt(259),
        0x0F => @enumFromInt(258),
        0x10 => @enumFromInt(81),
        0x11 => @enumFromInt(87),
        0x12 => @enumFromInt(69),
        0x13 => @enumFromInt(82),
        0x14 => @enumFromInt(84),
        0x15 => @enumFromInt(89),
        0x16 => @enumFromInt(85),
        0x17 => @enumFromInt(73),
        0x18 => @enumFromInt(79),
        0x19 => @enumFromInt(80),
        0x1A => @enumFromInt(91),
        0x1B => @enumFromInt(93),
        0x1C => @enumFromInt(257),
        0x1D => @enumFromInt(341),
        0x1E => @enumFromInt(65),
        0x1F => @enumFromInt(83),
        0x20 => @enumFromInt(68),
        0x21 => @enumFromInt(70),
        0x22 => @enumFromInt(71),
        0x23 => @enumFromInt(72),
        0x24 => @enumFromInt(74),
        0x25 => @enumFromInt(75),
        0x26 => @enumFromInt(76),
        0x27 => @enumFromInt(59),
        0x28 => @enumFromInt(39),
        0x29 => @enumFromInt(96),
        0x2A => @enumFromInt(340),
        0x2B => @enumFromInt(92),
        0x2C => @enumFromInt(90),
        0x2D => @enumFromInt(88),
        0x2E => @enumFromInt(67),
        0x2F => @enumFromInt(86),
        0x30 => @enumFromInt(66),
        0x31 => @enumFromInt(78),
        0x32 => @enumFromInt(77),
        0x33 => @enumFromInt(44),
        0x34 => @enumFromInt(46),
        0x35 => @enumFromInt(47),
        0x36 => @enumFromInt(344),
        0x38 => @enumFromInt(342),
        0x39 => @enumFromInt(32),
        0x3B => @enumFromInt(290),
        0x3C => @enumFromInt(291),
        0x3D => @enumFromInt(292),
        0x3E => @enumFromInt(293),
        0x3F => @enumFromInt(294),
        0x40 => @enumFromInt(295),
        0x41 => @enumFromInt(296),
        0x42 => @enumFromInt(297),
        0x43 => @enumFromInt(298),
        0x44 => @enumFromInt(299),
        0x57 => @enumFromInt(300),
        0x58 => @enumFromInt(301),
        0x9D => @enumFromInt(345),
        0xC7 => @enumFromInt(268),
        0xC8 => @enumFromInt(265),
        0xC9 => @enumFromInt(266),
        0xCB => @enumFromInt(263),
        0xCD => @enumFromInt(262),
        0xCF => @enumFromInt(269),
        0xD0 => @enumFromInt(264),
        0xD1 => @enumFromInt(267),
        0xD2 => @enumFromInt(260),
        0xD3 => @enumFromInt(261),
        else => null,
    };
}

pub fn raylibMouseButtonFromInputCode(code: i32) ?rl.MouseButton {
    return switch (code) {
        0x100 => .left,
        0x101 => .right,
        0x102 => .middle,
        0x103 => .side,
        0x104 => .extra,
        else => null,
    };
}

pub fn inputCodeIsDown(code: i32) bool {
    if (raylibKeyFromInputCode(code)) |key| return rl.isKeyDown(key);
    if (raylibMouseButtonFromInputCode(code)) |button| return rl.isMouseButtonDown(button);
    return false;
}

pub fn inputCodeIsPressed(code: i32) bool {
    if (raylibKeyFromInputCode(code)) |key| return rl.isKeyPressed(key);
    if (raylibMouseButtonFromInputCode(code)) |button| return rl.isMouseButtonPressed(button);
    return false;
}

test "input code mapping covers default gameplay bindings" {
    try std.testing.expectEqual(@as(?rl.KeyboardKey, @enumFromInt(87)), raylibKeyFromInputCode(0x11));
    try std.testing.expectEqual(@as(?rl.KeyboardKey, @enumFromInt(83)), raylibKeyFromInputCode(0x1F));
    try std.testing.expectEqual(@as(?rl.KeyboardKey, @enumFromInt(65)), raylibKeyFromInputCode(0x1E));
    try std.testing.expectEqual(@as(?rl.KeyboardKey, @enumFromInt(68)), raylibKeyFromInputCode(0x20));
    try std.testing.expectEqual(@as(?rl.MouseButton, .left), raylibMouseButtonFromInputCode(0x100));
    try std.testing.expectEqual(@as(?rl.MouseButton, .right), raylibMouseButtonFromInputCode(0x101));
}
