//! Modern controller profile, applied the first time a player on stock bindings
//! uses a pad. Mirrors `src/crimson/gamepad_profile.py`.
//!
//! The stock `crimson.cfg` bindings are the original's DirectInput-era defaults
//! (swapped `JoyAxis*` aim axes, `JoyAxisZ`/`JoyRotX` movement). When a player
//! whose bindings are still exactly those defaults touches their pad, the player
//! switches to twin-stick controls in standard controller codes. The switch is an
//! ordinary config edit, so any later change in Controls leaves the player
//! customized and it never re-triggers.
const std = @import("std");

const crimson_cfg = @import("formats/crimson_cfg.zig");

pub const gamepad_slot_count: usize = 4;

/// Port-only codes for the standard controller layout (SDL/GLFW mappings, buttons
/// named by position). Native Grim returns zero for ids it does not know, so the
/// original game treats them as unbound.
pub const PadCode = enum(i32) {
    left_stick_x = 0x200,
    left_stick_y = 0x201,
    right_stick_x = 0x202,
    right_stick_y = 0x203,
    face_down = 0x210,
    face_right = 0x211,
    face_left = 0x212,
    face_up = 0x213,
    l1 = 0x214,
    r1 = 0x215,
    l2 = 0x216,
    r2 = 0x217,
    l3 = 0x218,
    r3 = 0x219,
    select = 0x21A,
    start = 0x21B,
    dpad_up = 0x21C,
    dpad_down = 0x21D,
    dpad_left = 0x21E,
    dpad_right = 0x21F,

    pub fn code(self: PadCode) i32 {
        return @intFromEnum(self);
    }
};

pub const default_pick_perk_code: u32 = 0x101;
pub const default_reload_code: u32 = 0x102;

const movement_static: u32 = 2;
const movement_dual_action_pad: u32 = 3;
const aim_mouse: u32 = 0;
const aim_dual_action_pad: u32 = 4;

pub fn playerGamepadIndex(player_index: usize) usize {
    return @min(player_index, gamepad_slot_count - 1);
}

pub fn playerBindingsAreStock(cfg: *const crimson_cfg.CrimsonCfg, player_index: usize) bool {
    // Raw movement 0 decodes as Static, like the Python codec.
    const movement = crimson_cfg.playerMovement(cfg, player_index);
    if (movement != 0 and movement != movement_static) return false;
    if (crimson_cfg.playerAimScheme(cfg, player_index) != aim_mouse) return false;
    const binds = crimson_cfg.playerBindBlock(cfg, player_index);
    const stock = crimson_cfg.defaultPlayerBindBlock(player_index);
    return binds.move_forward == stock.move_forward and
        binds.move_backward == stock.move_backward and
        binds.turn_left == stock.turn_left and
        binds.turn_right == stock.turn_right and
        binds.fire == stock.fire and
        binds.aim_left == stock.aim_left and
        binds.aim_right == stock.aim_right and
        binds.axis_aim_y == stock.axis_aim_y and
        binds.axis_aim_x == stock.axis_aim_x and
        binds.axis_move_y == stock.axis_move_y and
        binds.axis_move_x == stock.axis_move_x;
}

/// Keyboard codes stay, so picking a keyboard movement method later brings the
/// stock keys back. Reload and Level Up are global codes owned by player 1; they
/// move to the pad only while still at their stock mouse buttons.
pub fn applyPadProfile(cfg: *crimson_cfg.CrimsonCfg, player_index: usize) void {
    crimson_cfg.setPlayerMovement(cfg, player_index, movement_dual_action_pad);
    crimson_cfg.setPlayerAimScheme(cfg, player_index, aim_dual_action_pad);
    var binds = crimson_cfg.playerBindBlock(cfg, player_index);
    binds.axis_move_y = PadCode.left_stick_y.code();
    binds.axis_move_x = PadCode.left_stick_x.code();
    binds.axis_aim_y = PadCode.right_stick_y.code();
    binds.axis_aim_x = PadCode.right_stick_x.code();
    binds.fire = PadCode.r2.code();
    crimson_cfg.setPlayerBindBlock(cfg, player_index, binds);
    if (player_index != 0) return;
    if (cfg.keybind_reload == default_reload_code) cfg.keybind_reload = @bitCast(PadCode.face_left.code());
    if (cfg.keybind_pick_perk == default_pick_perk_code) cfg.keybind_pick_perk = @bitCast(PadCode.face_up.code());
}

pub const SwitchedPlayers = std.bit_set.IntegerBitSet(crimson_cfg.port_player_slot_count);

/// Apply the pad profile to each active stock-bound player whose pad is in use.
/// `pad_active` provides `isActive(gamepad_index: usize) bool`. The caller
/// persists the config.
pub fn autoApplyPadProfiles(cfg: *crimson_cfg.CrimsonCfg, pad_active: anytype) SwitchedPlayers {
    var switched = SwitchedPlayers.initEmpty();
    const player_count = std.math.clamp(cfg.player_count, 1, crimson_cfg.port_player_slot_count);
    for (0..player_count) |player_index| {
        if (!playerBindingsAreStock(cfg, player_index)) continue;
        if (!pad_active.isActive(playerGamepadIndex(player_index))) continue;
        applyPadProfile(cfg, player_index);
        switched.set(player_index);
    }
    return switched;
}

const FakePads = struct {
    active: []const usize,

    fn isActive(self: FakePads, gamepad_index: usize) bool {
        return std.mem.indexOfScalar(usize, self.active, gamepad_index) != null;
    }
};

test "stock player switches to the pad profile once their pad is used" {
    var cfg = crimson_cfg.defaultConfig();
    const idle: FakePads = .{ .active = &.{} };
    const pad0: FakePads = .{ .active = &.{0} };
    try std.testing.expect(autoApplyPadProfiles(&cfg, idle).count() == 0);

    const switched = autoApplyPadProfiles(&cfg, pad0);
    try std.testing.expect(switched.isSet(0));
    try std.testing.expectEqual(movement_dual_action_pad, crimson_cfg.playerMovement(&cfg, 0));
    try std.testing.expectEqual(aim_dual_action_pad, crimson_cfg.playerAimScheme(&cfg, 0));
    const binds = crimson_cfg.playerBindBlock(&cfg, 0);
    try std.testing.expectEqual(PadCode.left_stick_y.code(), binds.axis_move_y);
    try std.testing.expectEqual(PadCode.left_stick_x.code(), binds.axis_move_x);
    try std.testing.expectEqual(PadCode.right_stick_y.code(), binds.axis_aim_y);
    try std.testing.expectEqual(PadCode.right_stick_x.code(), binds.axis_aim_x);
    try std.testing.expectEqual(PadCode.r2.code(), binds.fire);
    try std.testing.expectEqual(@as(i32, 0x11), binds.move_forward);
    try std.testing.expectEqual(@as(u32, 0x212), cfg.keybind_reload);
    try std.testing.expectEqual(@as(u32, 0x213), cfg.keybind_pick_perk);

    try std.testing.expect(!playerBindingsAreStock(&cfg, 0));
    try std.testing.expect(autoApplyPadProfiles(&cfg, pad0).count() == 0);
}

test "customized players and inactive player slots are left alone" {
    var cfg = crimson_cfg.defaultConfig();
    var binds = crimson_cfg.playerBindBlock(&cfg, 0);
    binds.fire = 0x39;
    crimson_cfg.setPlayerBindBlock(&cfg, 0, binds);
    cfg.player_count = 2;
    cfg.keybind_reload = 0x13;

    const pads: FakePads = .{ .active = &.{ 0, 1, 2 } };
    const switched = autoApplyPadProfiles(&cfg, pads);
    try std.testing.expect(!switched.isSet(0));
    try std.testing.expect(switched.isSet(1));
    try std.testing.expect(!switched.isSet(2));
    try std.testing.expectEqual(aim_mouse, crimson_cfg.playerAimScheme(&cfg, 0));
    try std.testing.expectEqual(@as(u32, 0x13), cfg.keybind_reload);
    try std.testing.expectEqual(default_pick_perk_code, cfg.keybind_pick_perk);
}

test "pad profile survives a crimson.cfg round trip" {
    var cfg = crimson_cfg.defaultConfig();
    applyPadProfile(&cfg, 0);
    const decoded = try crimson_cfg.decode(crimson_cfg.encode(cfg)[0..]);
    try std.testing.expectEqual(PadCode.r2.code(), crimson_cfg.playerBindBlock(&decoded, 0).fire);
    try std.testing.expectEqual(PadCode.right_stick_x.code(), crimson_cfg.playerBindBlock(&decoded, 0).axis_aim_x);
    try std.testing.expectEqual(@as(u32, 0x213), decoded.keybind_pick_perk);
}
