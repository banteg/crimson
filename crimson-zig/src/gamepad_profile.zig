//! Modern controller profile, applied when a player first uses a pad. Mirrors
//! `src/crimson/gamepad_profile.py`.
//!
//! The stock `crimson.cfg` bindings are the original's DirectInput-era defaults
//! (swapped `JoyAxis*` aim axes, `JoyAxisZ`/`JoyRotX` movement). When a player
//! connects their pad, every binding that still holds its stock value and matters
//! for pad play moves to the standard controller codes:
//! - a fully stock player also switches aim and movement to Dual Action Pad, once
//!   the pad is actually used;
//! - stock axis pairs become the sticks (only pad methods read them);
//! - with pad aim, a stock Fire becomes R2;
//! - for player 1 on any pad method, stock Reload and Level Up become pad buttons.
//! Methods and bindings the player changed are never touched, and each upgrade
//! replaces a stock value, so nothing is pending after one pass.
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

pub const PadUpgrades = packed struct(u8) {
    methods: bool = false,
    move_axes: bool = false,
    aim_axes: bool = false,
    fire: bool = false,
    reload: bool = false,
    level_up: bool = false,
    _padding: u2 = 0,

    pub fn any(self: PadUpgrades) bool {
        return @as(u8, @bitCast(self)) != 0;
    }

    /// Comma-separated labels, matching the Python log line.
    pub fn describe(self: PadUpgrades, buf: []u8) []const u8 {
        var len: usize = 0;
        inline for (.{
            .{ self.methods, "aim/move methods" },
            .{ self.move_axes, "move axes" },
            .{ self.aim_axes, "aim axes" },
            .{ self.fire, "fire" },
            .{ self.reload, "reload" },
            .{ self.level_up, "level up" },
        }) |entry| {
            if (entry[0]) {
                const text = if (len == 0) entry[1] else ", " ++ entry[1];
                if (len + text.len > buf.len) return buf[0..len];
                @memcpy(buf[len .. len + text.len], text);
                len += text.len;
            }
        }
        return buf[0..len];
    }
};

pub fn pendingPadUpgrades(cfg: *const crimson_cfg.CrimsonCfg, player_index: usize) PadUpgrades {
    const binds = crimson_cfg.playerBindBlock(cfg, player_index);
    const stock = crimson_cfg.defaultPlayerBindBlock(player_index);
    const switching = playerBindingsAreStock(cfg, player_index);
    const aim_pad = switching or crimson_cfg.playerAimScheme(cfg, player_index) == aim_dual_action_pad;
    const any_pad = aim_pad or crimson_cfg.playerMovement(cfg, player_index) == movement_dual_action_pad;
    // Reload and Level Up are global codes owned by player 1 (Controls edits them there).
    const owns_globals = player_index == 0 and any_pad;
    return .{
        .methods = switching,
        .move_axes = binds.axis_move_y == stock.axis_move_y and binds.axis_move_x == stock.axis_move_x,
        .aim_axes = binds.axis_aim_y == stock.axis_aim_y and binds.axis_aim_x == stock.axis_aim_x,
        .fire = aim_pad and binds.fire == stock.fire,
        .reload = owns_globals and cfg.keybind_reload == default_reload_code,
        .level_up = owns_globals and cfg.keybind_pick_perk == default_pick_perk_code,
    };
}

/// Keyboard codes stay, so keyboard methods keep their stock keys.
pub fn applyPadUpgrades(cfg: *crimson_cfg.CrimsonCfg, player_index: usize, upgrades: PadUpgrades) void {
    if (upgrades.methods) {
        crimson_cfg.setPlayerMovement(cfg, player_index, movement_dual_action_pad);
        crimson_cfg.setPlayerAimScheme(cfg, player_index, aim_dual_action_pad);
    }
    var binds = crimson_cfg.playerBindBlock(cfg, player_index);
    if (upgrades.move_axes) {
        binds.axis_move_y = PadCode.left_stick_y.code();
        binds.axis_move_x = PadCode.left_stick_x.code();
    }
    if (upgrades.aim_axes) {
        binds.axis_aim_y = PadCode.right_stick_y.code();
        binds.axis_aim_x = PadCode.right_stick_x.code();
    }
    if (upgrades.fire) binds.fire = PadCode.r2.code();
    crimson_cfg.setPlayerBindBlock(cfg, player_index, binds);
    if (upgrades.reload) cfg.keybind_reload = @bitCast(PadCode.l1.code());
    if (upgrades.level_up) cfg.keybind_pick_perk = @bitCast(PadCode.face_up.code());
}

/// Switch a stock player to the full twin-stick profile.
pub fn applyPadProfile(cfg: *crimson_cfg.CrimsonCfg, player_index: usize) void {
    applyPadUpgrades(cfg, player_index, pendingPadUpgrades(cfg, player_index));
}

pub const AppliedUpgrades = [crimson_cfg.port_player_slot_count]PadUpgrades;

/// Apply pending upgrades for each active player whose pad is connected.
/// Stale stock bindings only matter to pad play, so they upgrade as soon as the
/// pad is connected; switching a fully stock player's methods waits until the pad
/// is used. `pads` provides `isConnected(gamepad_index: usize) bool` and
/// `isActive(gamepad_index: usize) bool`. Returns what changed per player; the
/// caller logs it and persists the config.
pub fn autoApplyPadProfiles(cfg: *crimson_cfg.CrimsonCfg, pads: anytype) AppliedUpgrades {
    var applied = [_]PadUpgrades{.{}} ** crimson_cfg.port_player_slot_count;
    const player_count = std.math.clamp(cfg.player_count, 1, crimson_cfg.port_player_slot_count);
    for (0..player_count) |player_index| {
        const upgrades = pendingPadUpgrades(cfg, player_index);
        if (!upgrades.any()) continue;
        const gamepad = playerGamepadIndex(player_index);
        if (!pads.isConnected(gamepad)) continue;
        if (upgrades.methods and !pads.isActive(gamepad)) continue;
        applyPadUpgrades(cfg, player_index, upgrades);
        applied[player_index] = upgrades;
    }
    return applied;
}

/// Controls "Reset" button: stock bindings, or the full pad profile when a pad is
/// connected. Reload and Level Up are global codes owned by player 1, so only
/// player 1's reset touches them. The direction-arrow toggle is a HUD preference
/// and stays.
pub fn resetPlayerControls(cfg: *crimson_cfg.CrimsonCfg, player_index: usize, pad_connected: bool) void {
    crimson_cfg.setPlayerMovement(cfg, player_index, movement_static);
    crimson_cfg.setPlayerAimScheme(cfg, player_index, aim_mouse);
    crimson_cfg.setPlayerBindBlock(cfg, player_index, crimson_cfg.defaultPlayerBindBlock(player_index));
    if (player_index == 0) {
        cfg.keybind_reload = default_reload_code;
        cfg.keybind_pick_perk = default_pick_perk_code;
    }
    if (pad_connected) applyPadProfile(cfg, player_index);
}

pub fn anyApplied(applied: AppliedUpgrades) bool {
    for (applied) |upgrades| {
        if (upgrades.any()) return true;
    }
    return false;
}

const FakePads = struct {
    active: []const usize,
    /// Defaults to the active pads.
    connected: ?[]const usize = null,

    fn isActive(self: FakePads, gamepad_index: usize) bool {
        return std.mem.indexOfScalar(usize, self.active, gamepad_index) != null;
    }

    fn isConnected(self: FakePads, gamepad_index: usize) bool {
        return std.mem.indexOfScalar(usize, self.connected orelse self.active, gamepad_index) != null;
    }
};

const all_upgrades: PadUpgrades = .{
    .methods = true,
    .move_axes = true,
    .aim_axes = true,
    .fire = true,
    .reload = true,
    .level_up = true,
};

test "stock player switches to the pad profile once their pad is used" {
    var cfg = crimson_cfg.defaultConfig();
    const idle: FakePads = .{ .active = &.{} };
    const pad0: FakePads = .{ .active = &.{0} };
    try std.testing.expect(!anyApplied(autoApplyPadProfiles(&cfg, idle)));

    const applied = autoApplyPadProfiles(&cfg, pad0);
    try std.testing.expectEqual(all_upgrades, applied[0]);
    try std.testing.expectEqual(movement_dual_action_pad, crimson_cfg.playerMovement(&cfg, 0));
    try std.testing.expectEqual(aim_dual_action_pad, crimson_cfg.playerAimScheme(&cfg, 0));
    const binds = crimson_cfg.playerBindBlock(&cfg, 0);
    try std.testing.expectEqual(PadCode.left_stick_y.code(), binds.axis_move_y);
    try std.testing.expectEqual(PadCode.left_stick_x.code(), binds.axis_move_x);
    try std.testing.expectEqual(PadCode.right_stick_y.code(), binds.axis_aim_y);
    try std.testing.expectEqual(PadCode.right_stick_x.code(), binds.axis_aim_x);
    try std.testing.expectEqual(PadCode.r2.code(), binds.fire);
    try std.testing.expectEqual(@as(i32, 0x11), binds.move_forward);
    try std.testing.expectEqual(@as(u32, 0x214), cfg.keybind_reload);
    try std.testing.expectEqual(@as(u32, 0x213), cfg.keybind_pick_perk);

    try std.testing.expect(!playerBindingsAreStock(&cfg, 0));
    try std.testing.expect(!pendingPadUpgrades(&cfg, 0).any());
    try std.testing.expect(!anyApplied(autoApplyPadProfiles(&cfg, pad0)));
}

test "hand-picked pad methods with stock legacy bindings upgrade" {
    var cfg = crimson_cfg.defaultConfig();
    crimson_cfg.setPlayerAimScheme(&cfg, 0, aim_dual_action_pad);
    crimson_cfg.setPlayerMovement(&cfg, 0, movement_dual_action_pad);
    cfg.keybind_reload = 0x13;
    const pad0: FakePads = .{ .active = &.{0} };

    const applied = autoApplyPadProfiles(&cfg, pad0);
    const expected: PadUpgrades = .{ .move_axes = true, .aim_axes = true, .fire = true, .level_up = true };
    try std.testing.expectEqual(expected, applied[0]);
    var buf: [96]u8 = undefined;
    try std.testing.expectEqualStrings("move axes, aim axes, fire, level up", applied[0].describe(&buf));
    const binds = crimson_cfg.playerBindBlock(&cfg, 0);
    try std.testing.expectEqual(PadCode.left_stick_y.code(), binds.axis_move_y);
    try std.testing.expectEqual(PadCode.right_stick_x.code(), binds.axis_aim_x);
    try std.testing.expectEqual(PadCode.r2.code(), binds.fire);
    try std.testing.expectEqual(@as(u32, 0x13), cfg.keybind_reload);
    try std.testing.expectEqual(@as(u32, 0x213), cfg.keybind_pick_perk);
    try std.testing.expect(!anyApplied(autoApplyPadProfiles(&cfg, pad0)));
}

test "connected idle pad upgrades stale bindings but not methods" {
    var cfg = crimson_cfg.defaultConfig();
    crimson_cfg.setPlayerAimScheme(&cfg, 0, aim_dual_action_pad);
    crimson_cfg.setPlayerMovement(&cfg, 0, movement_dual_action_pad);
    const idle: FakePads = .{ .active = &.{}, .connected = &.{0} };
    const expected: PadUpgrades = .{ .move_axes = true, .aim_axes = true, .fire = true, .reload = true, .level_up = true };
    try std.testing.expectEqual(expected, autoApplyPadProfiles(&cfg, idle)[0]);

    var stock = crimson_cfg.defaultConfig();
    try std.testing.expect(!anyApplied(autoApplyPadProfiles(&stock, idle)));
    try std.testing.expectEqual(aim_mouse, crimson_cfg.playerAimScheme(&stock, 0));
    const pad0: FakePads = .{ .active = &.{0} };
    try std.testing.expectEqual(all_upgrades, autoApplyPadProfiles(&stock, pad0)[0]);

    var unplugged = crimson_cfg.defaultConfig();
    crimson_cfg.setPlayerAimScheme(&unplugged, 0, aim_dual_action_pad);
    const none: FakePads = .{ .active = &.{} };
    try std.testing.expect(!anyApplied(autoApplyPadProfiles(&unplugged, none)));
}

test "mouse and keyboard player only gets the axis upgrade" {
    var cfg = crimson_cfg.defaultConfig();
    var binds = crimson_cfg.playerBindBlock(&cfg, 0);
    binds.move_forward = 0xC8;
    crimson_cfg.setPlayerBindBlock(&cfg, 0, binds);
    const pad0: FakePads = .{ .active = &.{0} };

    const applied = autoApplyPadProfiles(&cfg, pad0);
    const expected: PadUpgrades = .{ .move_axes = true, .aim_axes = true };
    try std.testing.expectEqual(expected, applied[0]);
    try std.testing.expectEqual(aim_mouse, crimson_cfg.playerAimScheme(&cfg, 0));
    try std.testing.expectEqual(movement_static, crimson_cfg.playerMovement(&cfg, 0));
    try std.testing.expectEqual(@as(i32, 0x100), crimson_cfg.playerBindBlock(&cfg, 0).fire);
    try std.testing.expectEqual(default_reload_code, cfg.keybind_reload);
    try std.testing.expectEqual(default_pick_perk_code, cfg.keybind_pick_perk);
    try std.testing.expect(!anyApplied(autoApplyPadProfiles(&cfg, pad0)));
}

test "customized axes and fire are left alone" {
    var cfg = crimson_cfg.defaultConfig();
    crimson_cfg.setPlayerAimScheme(&cfg, 0, aim_dual_action_pad);
    crimson_cfg.setPlayerMovement(&cfg, 0, movement_dual_action_pad);
    var binds = crimson_cfg.playerBindBlock(&cfg, 0);
    binds.axis_move_y = 0x140;
    binds.axis_move_x = 0x13F;
    binds.axis_aim_y = PadCode.right_stick_x.code();
    binds.axis_aim_x = PadCode.right_stick_y.code();
    binds.fire = 0x39;
    crimson_cfg.setPlayerBindBlock(&cfg, 0, binds);
    cfg.keybind_reload = 0x13;
    cfg.keybind_pick_perk = 0x39;

    try std.testing.expect(!pendingPadUpgrades(&cfg, 0).any());
    const pad0: FakePads = .{ .active = &.{0} };
    try std.testing.expect(!anyApplied(autoApplyPadProfiles(&cfg, pad0)));
    try std.testing.expectEqual(@as(i32, 0x140), crimson_cfg.playerBindBlock(&cfg, 0).axis_move_y);
}

test "other players' pads leave player 1 and its global codes alone" {
    var cfg = crimson_cfg.defaultConfig();
    cfg.player_count = 2;
    const pads: FakePads = .{ .active = &.{ 1, 2 } };

    const applied = autoApplyPadProfiles(&cfg, pads);
    try std.testing.expect(!applied[0].any());
    const expected: PadUpgrades = .{ .methods = true, .move_axes = true, .aim_axes = true, .fire = true };
    try std.testing.expectEqual(expected, applied[1]);
    try std.testing.expect(!applied[2].any());
    try std.testing.expectEqual(aim_mouse, crimson_cfg.playerAimScheme(&cfg, 0));
    try std.testing.expectEqual(default_reload_code, cfg.keybind_reload);
    try std.testing.expectEqual(default_pick_perk_code, cfg.keybind_pick_perk);
}

fn customizeAll(cfg: *crimson_cfg.CrimsonCfg) void {
    for (0..crimson_cfg.port_player_slot_count) |idx| {
        crimson_cfg.setPlayerMovement(cfg, idx, 1);
        crimson_cfg.setPlayerAimScheme(cfg, idx, 1);
        crimson_cfg.setPlayerShowDirectionArrow(cfg, idx, false);
        var binds = crimson_cfg.playerBindBlock(cfg, idx);
        binds.fire = 0x39;
        binds.axis_move_y = 0x140;
        crimson_cfg.setPlayerBindBlock(cfg, idx, binds);
    }
    cfg.keybind_reload = 0x13;
    cfg.keybind_pick_perk = 0x2A;
}

test "reset without a pad restores stock bindings" {
    var cfg = crimson_cfg.defaultConfig();
    customizeAll(&cfg);
    resetPlayerControls(&cfg, 0, false);
    try std.testing.expect(playerBindingsAreStock(&cfg, 0));
    try std.testing.expect(!crimson_cfg.playerShowDirectionArrow(&cfg, 0));
    try std.testing.expectEqual(default_reload_code, cfg.keybind_reload);
    try std.testing.expectEqual(default_pick_perk_code, cfg.keybind_pick_perk);
}

test "reset with a pad applies the full pad profile" {
    var cfg = crimson_cfg.defaultConfig();
    customizeAll(&cfg);
    resetPlayerControls(&cfg, 0, true);
    try std.testing.expectEqual(movement_dual_action_pad, crimson_cfg.playerMovement(&cfg, 0));
    try std.testing.expectEqual(aim_dual_action_pad, crimson_cfg.playerAimScheme(&cfg, 0));
    const binds = crimson_cfg.playerBindBlock(&cfg, 0);
    try std.testing.expectEqual(PadCode.r2.code(), binds.fire);
    try std.testing.expectEqual(PadCode.left_stick_y.code(), binds.axis_move_y);
    try std.testing.expectEqual(@as(u32, 0x214), cfg.keybind_reload);
    try std.testing.expectEqual(@as(u32, 0x213), cfg.keybind_pick_perk);
}

test "resetting another player keeps player 1's global codes" {
    var cfg = crimson_cfg.defaultConfig();
    customizeAll(&cfg);
    resetPlayerControls(&cfg, 1, true);
    try std.testing.expectEqual(@as(u32, 0x13), cfg.keybind_reload);
    try std.testing.expectEqual(@as(u32, 0x2A), cfg.keybind_pick_perk);
    try std.testing.expectEqual(@as(i32, 0x39), crimson_cfg.playerBindBlock(&cfg, 0).fire);
    try std.testing.expectEqual(PadCode.r2.code(), crimson_cfg.playerBindBlock(&cfg, 1).fire);
}

test "pad profile survives a crimson.cfg round trip" {
    var cfg = crimson_cfg.defaultConfig();
    applyPadProfile(&cfg, 0);
    const decoded = try crimson_cfg.decode(crimson_cfg.encode(cfg)[0..]);
    try std.testing.expectEqual(PadCode.r2.code(), crimson_cfg.playerBindBlock(&decoded, 0).fire);
    try std.testing.expectEqual(PadCode.right_stick_x.code(), crimson_cfg.playerBindBlock(&decoded, 0).axis_aim_x);
    try std.testing.expectEqual(@as(u32, 0x213), decoded.keybind_pick_perk);
}
