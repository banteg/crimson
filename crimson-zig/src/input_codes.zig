const std = @import("std");
const rl = @import("raylib");

pub const input_code_unbound: i32 = 0x17E;

const axis_deadzone: f32 = 0.2;
const axis_down_threshold: f32 = 0.5;
const primary_edge_sentinel_player: i32 = -1;
const primary_edge_sentinel_key: i32 = -1;
const max_pressed_entries: usize = 96;

const PressedEntry = struct {
    player_index: i32,
    key_code: i32,
    value: bool,
};

const PressedState = struct {
    prev_down: [max_pressed_entries]PressedEntry = undefined,
    prev_down_len: usize = 0,
    down: [max_pressed_entries]PressedEntry = undefined,
    down_len: usize = 0,
    pressed_cache: [max_pressed_entries]PressedEntry = undefined,
    pressed_cache_len: usize = 0,
    wheel_up: bool = false,
    wheel_down: bool = false,

    fn beginFrame(self: *PressedState, wheel_move: f32) void {
        @memcpy(self.prev_down[0..self.down_len], self.down[0..self.down_len]);
        self.prev_down_len = self.down_len;
        self.pressed_cache_len = 0;
        self.wheel_up = wheel_move > 0.0;
        self.wheel_down = wheel_move < 0.0;
    }

    fn markDown(self: *PressedState, player_index: i32, key_code: i32, is_down: bool) bool {
        self.setValue(&self.down, &self.down_len, player_index, key_code, is_down);
        return is_down;
    }

    fn isPressed(self: *PressedState, player_index: i32, key_code: i32, is_down: bool) bool {
        if (self.getValue(self.pressed_cache[0..self.pressed_cache_len], player_index, key_code)) |cached| {
            return cached;
        }
        const prev = self.getValue(self.prev_down[0..self.prev_down_len], player_index, key_code) orelse false;
        const pressed = is_down and !prev;
        self.setValue(&self.down, &self.down_len, player_index, key_code, is_down);
        self.setValue(&self.pressed_cache, &self.pressed_cache_len, player_index, key_code, pressed);
        return pressed;
    }

    fn getValue(self: *const PressedState, entries: []const PressedEntry, player_index: i32, key_code: i32) ?bool {
        _ = self;
        for (entries) |entry| {
            if (entry.player_index == player_index and entry.key_code == key_code) {
                return entry.value;
            }
        }
        return null;
    }

    fn setValue(
        self: *PressedState,
        entries: *[max_pressed_entries]PressedEntry,
        len: *usize,
        player_index: i32,
        key_code: i32,
        value: bool,
    ) void {
        _ = self;
        var idx: usize = 0;
        while (idx < len.*) : (idx += 1) {
            if (entries[idx].player_index == player_index and entries[idx].key_code == key_code) {
                entries[idx].value = value;
                return;
            }
        }
        if (len.* >= entries.len) return;
        entries[len.*] = .{
            .player_index = player_index,
            .key_code = key_code,
            .value = value,
        };
        len.* += 1;
    }
};

var pressed_state: PressedState = .{};

pub fn inputBeginFrame() void {
    pressed_state.beginFrame(rl.getMouseWheelMove());
}

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

fn gamepadButtonFromInputCode(code: i32) ?rl.GamepadButton {
    return switch (code) {
        0x11F => .right_face_down,
        0x120 => .right_face_right,
        0x121 => .right_face_left,
        0x122 => .right_face_up,
        0x123 => .left_face_up,
        0x124 => .left_face_right,
        0x125 => .left_face_down,
        0x126 => .left_face_left,
        0x127 => .left_trigger_1,
        0x128 => .right_trigger_1,
        0x129 => .left_trigger_2,
        0x12A => .right_trigger_2,
        0x131 => .left_face_up,
        0x132 => .left_face_down,
        0x133 => .left_face_left,
        0x134 => .left_face_right,
        else => null,
    };
}

fn gamepadAxisFromInputCode(code: i32) ?rl.GamepadAxis {
    return switch (code) {
        0x13F => .left_x,
        0x140 => .left_y,
        0x141 => .right_y,
        0x153 => .right_x,
        0x154 => .right_y,
        0x155 => .right_trigger,
        else => null,
    };
}

fn rimAxisFromInputCode(code: i32) ?struct { player_index: i32, axis: rl.GamepadAxis } {
    return switch (code) {
        0x163 => .{ .player_index = 0, .axis = .left_x },
        0x164 => .{ .player_index = 1, .axis = .left_x },
        0x165 => .{ .player_index = 2, .axis = .left_x },
        0x168 => .{ .player_index = 0, .axis = .left_y },
        0x169 => .{ .player_index = 1, .axis = .left_y },
        0x16A => .{ .player_index = 2, .axis = .left_y },
        else => null,
    };
}

fn rimButtonFromInputCode(code: i32) ?struct { player_index: i32, button: rl.GamepadButton } {
    return switch (code) {
        0x16D => .{ .player_index = 0, .button = .right_face_down },
        0x16E => .{ .player_index = 0, .button = .right_face_right },
        0x16F => .{ .player_index = 0, .button = .right_face_left },
        0x170 => .{ .player_index = 0, .button = .right_face_up },
        0x171 => .{ .player_index = 0, .button = .left_trigger_1 },
        0x172 => .{ .player_index = 1, .button = .right_face_down },
        0x173 => .{ .player_index = 1, .button = .right_face_right },
        0x174 => .{ .player_index = 1, .button = .right_face_left },
        0x175 => .{ .player_index = 1, .button = .right_face_up },
        0x176 => .{ .player_index = 1, .button = .left_trigger_1 },
        0x177 => .{ .player_index = 2, .button = .right_face_down },
        0x178 => .{ .player_index = 2, .button = .right_face_right },
        0x179 => .{ .player_index = 2, .button = .right_face_left },
        0x17A => .{ .player_index = 2, .button = .right_face_up },
        0x17B => .{ .player_index = 2, .button = .left_trigger_1 },
        else => null,
    };
}

fn playerGamepadIndex(player_index: i32) i32 {
    return std.math.clamp(player_index, 0, 3);
}

fn axisValueForGamepad(gamepad_index: i32, axis: rl.GamepadAxis) f32 {
    if (!rl.isGamepadAvailable(gamepad_index)) return 0.0;
    const value = rl.getGamepadAxisMovement(gamepad_index, axis);
    if (@abs(value) < axis_deadzone) return 0.0;
    return std.math.clamp(value, @as(f32, -1.0), @as(f32, 1.0));
}

fn axisValueFromCode(key_code: i32, player_index: i32) f32 {
    if (gamepadAxisFromInputCode(key_code)) |axis| {
        return axisValueForGamepad(playerGamepadIndex(player_index), axis);
    }
    if (rimAxisFromInputCode(key_code)) |rim_axis| {
        return axisValueForGamepad(rim_axis.player_index, rim_axis.axis);
    }
    return 0.0;
}

pub fn inputAxisValue(key_code: i32, player_index: i32) f32 {
    return axisValueFromCode(key_code, player_index);
}

fn digitalDownForPlayer(key_code: i32, player_index: i32) bool {
    if (key_code == input_code_unbound) return false;

    if (raylibMouseButtonFromInputCode(key_code)) |button| {
        return rl.isMouseButtonDown(button);
    }
    if (key_code < 0x100) {
        if (raylibKeyFromInputCode(key_code)) |key| {
            return rl.isKeyDown(key);
        }
        return false;
    }
    if (gamepadButtonFromInputCode(key_code)) |button| {
        const gamepad = playerGamepadIndex(player_index);
        return rl.isGamepadAvailable(gamepad) and rl.isGamepadButtonDown(gamepad, button);
    }
    if (rimButtonFromInputCode(key_code)) |rim_button| {
        return rl.isGamepadAvailable(rim_button.player_index) and rl.isGamepadButtonDown(rim_button.player_index, rim_button.button);
    }
    if (gamepadAxisFromInputCode(key_code) != null or rimAxisFromInputCode(key_code) != null) {
        return @abs(axisValueFromCode(key_code, player_index)) >= axis_down_threshold;
    }
    return false;
}

pub fn inputCodeIsDown(key_code: i32, player_index: i32) bool {
    const down = digitalDownForPlayer(key_code, player_index);
    return pressed_state.markDown(player_index, key_code, down);
}

pub fn inputCodeIsPressed(key_code: i32, player_index: i32) bool {
    if (key_code == 0x109) return pressed_state.wheel_up;
    if (key_code == 0x10A) return pressed_state.wheel_down;
    const down = digitalDownForPlayer(key_code, player_index);
    return pressed_state.isPressed(player_index, key_code, down);
}

pub fn captureFirstPressedInputCode(
    player_index: i32,
    include_keyboard: bool,
    include_mouse: bool,
    include_gamepad: bool,
    include_axes: bool,
    axis_threshold: f32,
) ?i32 {
    if (include_keyboard) {
        while (true) {
            const key = rl.getKeyPressed();
            if (key <= 0) break;
            inline for ([_]i32{
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
                0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x38, 0x39, 0x3B, 0x3C, 0x3D, 0x3E,
                0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x57, 0x58, 0x9D, 0xC7, 0xC8, 0xC9, 0xCB, 0xCD, 0xCF,
                0xD0, 0xD1, 0xD2, 0xD3,
            }) |code| {
                if (raylibKeyFromInputCode(code)) |mapped_key| {
                    if (@intFromEnum(mapped_key) == key) return code;
                }
            }
        }
    }

    if (include_mouse) {
        inline for ([_]i32{ 0x100, 0x101, 0x102, 0x103, 0x104 }) |code| {
            if (raylibMouseButtonFromInputCode(code)) |button| {
                if (rl.isMouseButtonPressed(button)) return code;
            }
        }
        const wheel = rl.getMouseWheelMove();
        if (wheel > 0.0) return 0x109;
        if (wheel < 0.0) return 0x10A;
    }

    if (include_gamepad) {
        const gamepad = playerGamepadIndex(player_index);
        if (rl.isGamepadAvailable(gamepad)) {
            inline for ([_]i32{
                0x11F, 0x120, 0x121, 0x122, 0x123, 0x124, 0x125, 0x126, 0x127, 0x128, 0x129, 0x12A, 0x131, 0x132,
                0x133, 0x134,
            }) |code| {
                if (gamepadButtonFromInputCode(code)) |button| {
                    if (rl.isGamepadButtonPressed(gamepad, button)) return code;
                }
            }
        }
    }

    if (include_axes) {
        const gamepad = playerGamepadIndex(player_index);
        if (rl.isGamepadAvailable(gamepad)) {
            inline for ([_]i32{ 0x13F, 0x140, 0x141, 0x153, 0x154, 0x155 }) |code| {
                if (gamepadAxisFromInputCode(code)) |axis| {
                    if (@abs(rl.getGamepadAxisMovement(gamepad, axis)) >= axis_threshold) return code;
                }
            }
        }
    }
    return null;
}

pub fn inputCodeName(key_code: i32) []const u8 {
    return switch (key_code) {
        input_code_unbound => "unbound",
        0x100 => "Mouse1",
        0x101 => "Mouse2",
        0x102 => "Mouse3",
        0x103 => "Mouse4",
        0x104 => "Mouse5",
        0x109 => "MWheelUp",
        0x10A => "MWheelDown",
        0x11F => "Joys1",
        0x120 => "Joys2",
        0x121 => "Joys3",
        0x122 => "Joys4",
        0x123 => "Joys5",
        0x124 => "Joys6",
        0x125 => "Joys7",
        0x126 => "Joys8",
        0x127 => "Joys9",
        0x128 => "Joys10",
        0x129 => "Joys11",
        0x12A => "Joys12",
        0x131 => "JoysUp",
        0x132 => "JoysDown",
        0x133 => "JoysLeft",
        0x134 => "JoysRight",
        0x13F => "JoyAxisX",
        0x140 => "JoyAxisY",
        0x141 => "JoyAxisZ",
        0x153 => "JoyRotX",
        0x154 => "JoyRotY",
        0x155 => "JoyRotZ",
        0x163 => "RIM0XAxis",
        0x164 => "RIM1XAxis",
        0x165 => "RIM2XAxis",
        0x168 => "RIM0YAxis",
        0x169 => "RIM1YAxis",
        0x16A => "RIM2YAxis",
        0x16D => "RIM0Btn1",
        0x16E => "RIM0Btn2",
        0x16F => "RIM0Btn3",
        0x170 => "RIM0Btn4",
        0x171 => "RIM0Btn5",
        0x172 => "RIM1Btn1",
        0x173 => "RIM1Btn2",
        0x174 => "RIM1Btn3",
        0x175 => "RIM1Btn4",
        0x176 => "RIM1Btn5",
        0x177 => "RIM2Btn1",
        0x178 => "RIM2Btn2",
        0x179 => "RIM2Btn3",
        0x17A => "RIM2Btn4",
        0x17B => "RIM2Btn5",
        else => blk: {
            if (key_code > 0x163) break :blk "RawInput ?";
            break :blk switch (key_code) {
                0x01 => "Escape",
                0x0F => "Tab",
                0x10 => "Q",
                0x11 => "W",
                0x12 => "E",
                0x13 => "R",
                0x1C => "Enter",
                0x1D => "LControl",
                0x1E => "A",
                0x1F => "S",
                0x20 => "D",
                0x2A => "LShift",
                0x36 => "RShift",
                0x38 => "LAlt",
                0x39 => "Space",
                0x9D => "RControl",
                0xC8 => "Up",
                0xC9 => "PageUp",
                0xCB => "Left",
                0xCD => "Right",
                0xD0 => "Down",
                0xD1 => "PageDown",
                0xD3 => "Delete",
                else => "DIK",
            };
        },
    };
}

fn inputPrimaryAnyDown(fire_codes: []const i32, player_count: i32) bool {
    if (inputCodeIsDown(0x100, 0)) return true;

    const clamped_count = std.math.clamp(player_count, 1, 4);
    if (fire_codes.len < @as(usize, @intCast(clamped_count))) return false;
    var player_index: i32 = 0;
    while (player_index < clamped_count) : (player_index += 1) {
        if (inputCodeIsDown(fire_codes[@intCast(player_index)], player_index)) return true;
    }
    return false;
}

pub fn inputPrimaryIsDown(fire_codes: []const i32, player_count: i32) bool {
    const down = inputPrimaryAnyDown(fire_codes, player_count);
    _ = pressed_state.markDown(primary_edge_sentinel_player, primary_edge_sentinel_key, down);
    return down;
}

pub fn inputPrimaryJustPressed(fire_codes: []const i32, player_count: i32) bool {
    const down = inputPrimaryAnyDown(fire_codes, player_count);
    return pressed_state.isPressed(primary_edge_sentinel_player, primary_edge_sentinel_key, down);
}

pub const RaylibInputSampler = struct {
    pub fn codeIsDown(_: RaylibInputSampler, code: i32, player_index: i32) bool {
        return inputCodeIsDown(code, player_index);
    }

    pub fn codeIsPressed(_: RaylibInputSampler, code: i32, player_index: i32) bool {
        return inputCodeIsPressed(code, player_index);
    }

    pub fn axisValue(_: RaylibInputSampler, code: i32, player_index: i32) f32 {
        return inputAxisValue(code, player_index);
    }
};

test "input code mapping covers default gameplay bindings" {
    try std.testing.expectEqual(@as(?rl.KeyboardKey, @enumFromInt(87)), raylibKeyFromInputCode(0x11));
    try std.testing.expectEqual(@as(?rl.KeyboardKey, @enumFromInt(83)), raylibKeyFromInputCode(0x1F));
    try std.testing.expectEqual(@as(?rl.KeyboardKey, @enumFromInt(65)), raylibKeyFromInputCode(0x1E));
    try std.testing.expectEqual(@as(?rl.KeyboardKey, @enumFromInt(68)), raylibKeyFromInputCode(0x20));
    try std.testing.expectEqual(@as(?rl.MouseButton, .left), raylibMouseButtonFromInputCode(0x100));
    try std.testing.expectEqual(@as(?rl.MouseButton, .right), raylibMouseButtonFromInputCode(0x101));
}

test "input code name extended axes match original labels" {
    try std.testing.expectEqualStrings("JoyAxisX", inputCodeName(0x13F));
    try std.testing.expectEqualStrings("JoyAxisY", inputCodeName(0x140));
    try std.testing.expectEqualStrings("JoyAxisZ", inputCodeName(0x141));
    try std.testing.expectEqualStrings("JoyRotX", inputCodeName(0x153));
    try std.testing.expectEqualStrings("JoyRotY", inputCodeName(0x154));
    try std.testing.expectEqualStrings("JoyRotZ", inputCodeName(0x155));
}

test "input code name extended rim codes match original labels" {
    try std.testing.expectEqualStrings("RIM0XAxis", inputCodeName(0x163));
    try std.testing.expectEqualStrings("RIM2XAxis", inputCodeName(0x165));
    try std.testing.expectEqualStrings("RIM0YAxis", inputCodeName(0x168));
    try std.testing.expectEqualStrings("RIM2YAxis", inputCodeName(0x16A));
    try std.testing.expectEqualStrings("RIM0Btn1", inputCodeName(0x16D));
    try std.testing.expectEqualStrings("RIM1Btn5", inputCodeName(0x176));
    try std.testing.expectEqualStrings("RIM2Btn5", inputCodeName(0x17B));
}

test "input code name unbound and rawinput fallback" {
    try std.testing.expectEqualStrings("unbound", inputCodeName(input_code_unbound));
    try std.testing.expectEqualStrings("RawInput ?", inputCodeName(0x17F));
}

test "axis z and rot x bindings use distinct raylib axes" {
    try std.testing.expect(gamepadAxisFromInputCode(0x141).? != gamepadAxisFromInputCode(0x153).?);
}

test "pressed edge does not retrigger after unpolled held frame" {
    var state: PressedState = .{};

    state.beginFrame(0.0);
    try std.testing.expect(state.isPressed(0, 0x11, true));

    state.beginFrame(0.0);
    state.beginFrame(0.0);

    try std.testing.expect(!state.isPressed(0, 0x11, true));
}

test "primary edge latch is shared across all fire sources" {
    var state: PressedState = .{};

    state.beginFrame(0.0);
    try std.testing.expect(state.isPressed(primary_edge_sentinel_player, primary_edge_sentinel_key, true));

    state.beginFrame(0.0);
    try std.testing.expect(!state.isPressed(primary_edge_sentinel_player, primary_edge_sentinel_key, true));

    state.beginFrame(0.0);
    try std.testing.expect(!state.isPressed(primary_edge_sentinel_player, primary_edge_sentinel_key, true));

    state.beginFrame(0.0);
    try std.testing.expect(!state.isPressed(primary_edge_sentinel_player, primary_edge_sentinel_key, false));

    state.beginFrame(0.0);
    try std.testing.expect(state.isPressed(primary_edge_sentinel_player, primary_edge_sentinel_key, true));
}
