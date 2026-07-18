const std = @import("std");

const formats = @import("formats/mod.zig");
const player_runtime = @import("runtime/player.zig");
const state_mod = @import("runtime/state.zig");

pub const aim_keyboard_turn_rate: f32 = 3.0;
pub const aim_joystick_turn_rate: f32 = 4.0;

pub const aim_radius_keyboard: f32 = 60.0;
pub const aim_radius_pad_base: f32 = 42.0;
pub const aim_radius_pad_scale: f32 = 96.0;
pub const point_click_stop_radius: f32 = 20.0;
pub const computer_target_switch_hysteresis: f32 = 64.0;
pub const computer_arena_center: state_mod.Vec2 = .{ .x = 512.0, .y = 512.0 };
pub const computer_move_target_radius: f32 = 300.0;
pub const computer_aim_snap_distance: f32 = 4.0;
pub const computer_aim_track_gain: f32 = 6.0;
pub const computer_auto_fire_distance: f32 = 128.0;

pub const movement_control_unknown: i32 = 0;
pub const movement_control_relative: i32 = 1;
pub const movement_control_static: i32 = 2;
pub const movement_control_dual_action_pad: i32 = 3;
pub const movement_control_mouse_point_click: i32 = 4;
pub const movement_control_computer: i32 = 5;

pub const aim_scheme_unknown: i32 = -1;
pub const aim_scheme_mouse: i32 = 0;
pub const aim_scheme_keyboard: i32 = 1;
pub const aim_scheme_joystick: i32 = 2;
pub const aim_scheme_mouse_relative: i32 = 3;
pub const aim_scheme_dual_action_pad: i32 = 4;
pub const aim_scheme_computer: i32 = 5;

const alt_move_key_up: i32 = 0xC8;
const alt_move_key_down: i32 = 0xD0;
const alt_move_key_left: i32 = 0xCB;
const alt_move_key_right: i32 = 0xCD;
const aim_pov_left_code: i32 = 0x133;
const aim_pov_right_code: i32 = 0x134;

pub const PerPlayerInputState = struct {
    aim_heading: f32 = 0.0,
    move_target: state_mod.Vec2 = .{ .x = -1.0, .y = -1.0 },
    computer_target_creature_index: i32 = -1,
};

pub const LocalInputInterpreter = struct {
    states: [state_mod.max_players]PerPlayerInputState = [_]PerPlayerInputState{.{}} ** state_mod.max_players,
    preserve_bugs: bool = false,

    pub fn setPreserveBugs(self: *LocalInputInterpreter, enabled: bool) void {
        self.preserve_bugs = enabled;
    }

    pub fn reset(self: *LocalInputInterpreter, players: ?[]const state_mod.PlayerState) void {
        for (&self.states) |*state| {
            state.* = .{};
        }
        if (players) |player_slice| {
            for (player_slice, 0..) |player, idx| {
                const slot = stateSlotForPlayer(idx, &player);
                if (std.math.isFinite(player.aim_heading)) {
                    self.states[slot].aim_heading = player.aim_heading;
                }
            }
        }
    }

    pub fn buildPlayerInput(
        self: *LocalInputInterpreter,
        sampler: anytype,
        player_index: usize,
        player_count: usize,
        player: *const state_mod.PlayerState,
        config: *const formats.crimson_cfg.CrimsonCfg,
        mouse_screen: state_mod.Vec2,
        mouse_world: state_mod.Vec2,
        screen_center: state_mod.Vec2,
        dt: f32,
        creatures: anytype,
    ) player_runtime.GameInput {
        const idx = @min(player_index, state_mod.max_players - 1);
        const state = self.stateForPlayer(idx, player);
        const binds = formats.crimson_cfg.playerBindBlock(config, idx);
        const aim_scheme = resolveAimScheme(config, idx);
        const move_mode_type = resolveMovementMode(config, idx);
        const reload_key: i32 = @bitCast(config.keybind_reload);

        const move_forward_key = binds.move_forward;
        const move_backward_key = binds.move_backward;
        const turn_left_key = binds.turn_left;
        const turn_right_key = binds.turn_right;
        const fire_key = binds.fire;
        const aim_left_key = binds.aim_left;
        const aim_right_key = binds.aim_right;
        const aim_axis_y = binds.axis_aim_y;
        const aim_axis_x = binds.axis_aim_x;
        const move_axis_y = binds.axis_move_y;
        const move_axis_x = binds.axis_move_x;

        var move_vec: state_mod.Vec2 = .{};
        var move_forward_pressed: ?bool = null;
        var move_backward_pressed: ?bool = null;
        var turn_left_pressed: ?bool = null;
        var turn_right_pressed: ?bool = null;
        var move_to_cursor_pressed = false;
        var computer_target_index: ?i32 = null;

        const computer_move_active = move_mode_type == movement_control_computer;

        if (computer_move_active) {
            computer_target_index = self.selectComputerTarget(idx, player, creatures);
            const center_delta = sub(computer_arena_center, player.pos);
            const center_dist = length(center_delta);
            const move_delta: state_mod.Vec2 = blk: {
                if (computer_target_index) |target_idx| {
                    if (creatureAt(creatures, target_idx)) |target| {
                        if (center_dist <= computer_move_target_radius) {
                            break :blk sub(target.pos, player.pos);
                        }
                        break :blk center_delta;
                    }
                }

                const away = sub(player.pos, computer_arena_center);
                const orbit: state_mod.Vec2 = .{ .x = -away.y, .y = away.x };
                if (lengthSq(orbit) > 1e-12) break :blk orbit;
                break :blk state_mod.Vec2{ .x = 0.0, .y = 1.0 };
            };

            const move_dir = normalized(move_delta);
            if (lengthSq(move_delta) > 1e-12) {
                move_vec = move_dir;
            }
        } else if (move_mode_type == movement_control_relative) {
            move_forward_pressed = keyDownWithSinglePlayerAlt(sampler, move_forward_key, alt_move_key_up, player_count, idx);
            move_backward_pressed = keyDownWithSinglePlayerAlt(sampler, move_backward_key, alt_move_key_down, player_count, idx);
            turn_left_pressed = keyDownWithSinglePlayerAlt(sampler, turn_left_key, alt_move_key_left, player_count, idx);
            turn_right_pressed = keyDownWithSinglePlayerAlt(sampler, turn_right_key, alt_move_key_right, player_count, idx);
            move_vec = .{
                .x = boolToFloat(turnRightPressed(turn_right_pressed)) - boolToFloat(turnLeftPressed(turn_left_pressed)),
                .y = boolToFloat(moveBackwardPressed(move_backward_pressed)) - boolToFloat(moveForwardPressed(move_forward_pressed)),
            };
        } else if (move_mode_type == movement_control_dual_action_pad) {
            const axis_y = -sampler.axisValue(move_axis_y, @intCast(idx));
            const axis_x = -sampler.axisValue(move_axis_x, @intCast(idx));
            move_vec = .{
                .x = clampUnit(axis_x),
                .y = clampUnit(axis_y),
            };
        } else if (move_mode_type == movement_control_mouse_point_click) {
            move_to_cursor_pressed = sampler.codeIsDown(reload_key, @intCast(idx));
            if (move_to_cursor_pressed) {
                state.move_target = mouse_world;
            }
            if (state.move_target.x >= 0.0 and state.move_target.y >= 0.0) {
                const delta = sub(state.move_target, player.pos);
                const dir = normalized(delta);
                const dist = length(delta);
                if (dist > point_click_stop_radius) {
                    move_vec = dir;
                }
            }
        } else if (move_mode_type == movement_control_static) {
            const move_up_pressed = keyDownWithSinglePlayerAlt(sampler, move_forward_key, alt_move_key_up, player_count, idx);
            const move_down_pressed = keyDownWithSinglePlayerAlt(sampler, move_backward_key, alt_move_key_down, player_count, idx);
            const move_left_pressed = keyDownWithSinglePlayerAlt(sampler, turn_left_key, alt_move_key_left, player_count, idx);
            const move_right_pressed = keyDownWithSinglePlayerAlt(sampler, turn_right_key, alt_move_key_right, player_count, idx);
            move_forward_pressed = move_up_pressed;
            move_backward_pressed = move_down_pressed;
            turn_left_pressed = move_left_pressed;
            turn_right_pressed = move_right_pressed;
            move_vec = resolveStaticMoveVector(move_up_pressed, move_down_pressed, move_left_pressed, move_right_pressed);
        } else {
            move_vec = .{
                .x = boolToFloat(sampler.codeIsDown(turn_right_key, @intCast(idx))) - boolToFloat(sampler.codeIsDown(turn_left_key, @intCast(idx))),
                .y = boolToFloat(sampler.codeIsDown(move_backward_key, @intCast(idx))) - boolToFloat(sampler.codeIsDown(move_forward_key, @intCast(idx))),
            };
        }

        var heading = if (std.math.isFinite(state.aim_heading)) state.aim_heading else player.aim_heading;
        var aim = player.aim;
        var computer_auto_fire = false;

        switch (aim_scheme) {
            aim_scheme_mouse => {
                aim = mouse_world;
                const delta = sub(aim, player.pos);
                if (lengthSq(delta) > 1e-9) {
                    heading = toHeading(delta);
                }
            },
            aim_scheme_keyboard => {
                if (move_mode_type == movement_control_relative or move_mode_type == movement_control_static) {
                    if (sampler.codeIsDown(aim_right_key, @intCast(idx))) {
                        heading += dt * aim_keyboard_turn_rate;
                    }
                    if (sampler.codeIsDown(aim_left_key, @intCast(idx))) {
                        heading -= dt * aim_keyboard_turn_rate;
                    }
                    aim = aimPointFromHeading(player.pos, heading, aim_radius_keyboard);
                }
            },
            aim_scheme_mouse_relative => {
                const rel = sub(mouse_screen, screen_center);
                if (lengthSq(rel) > 1.0) {
                    heading = toHeading(rel);
                    aim = aimPointFromHeading(player.pos, heading, aim_radius_keyboard);
                }
            },
            aim_scheme_dual_action_pad => {
                const axis_y = sampler.axisValue(aim_axis_y, @intCast(idx));
                const axis_x = sampler.axisValue(aim_axis_x, @intCast(idx));
                const axis_vec: state_mod.Vec2 = .{ .x = axis_x, .y = axis_y };
                const mag_sq = lengthSq(axis_vec);
                if (mag_sq > 1e-9) {
                    const mag = length(axis_vec);
                    const axis_dir = if (mag > 1e-9) axis_vec.mul(1.0 / mag) else state_mod.Vec2{};
                    heading = toHeading(axis_dir);
                    const radius = aim_radius_pad_base + mag * aim_radius_pad_scale;
                    aim = add(player.pos, axis_dir.mul(radius));
                } else {
                    aim = aimPointFromHeading(player.pos, heading, aim_radius_keyboard);
                }
            },
            aim_scheme_joystick => {
                if (aimPovRightActive(sampler, idx, self.preserve_bugs)) {
                    heading += dt * aim_joystick_turn_rate;
                }
                if (aimPovLeftActive(sampler, idx, self.preserve_bugs)) {
                    heading -= dt * aim_joystick_turn_rate;
                }
                aim = aimPointFromHeading(player.pos, heading, aim_radius_keyboard);
            },
            aim_scheme_computer => {
                var target_index = computer_target_index;
                if (target_index == null) {
                    target_index = self.selectComputerTarget(idx, player, creatures);
                }
                if (target_index) |resolved_idx| {
                    if (creatureAt(creatures, resolved_idx)) |target| {
                        aim = player.aim;
                        const to_target = sub(target.pos, aim);
                        const target_dist = length(to_target);
                        if (target_dist >= computer_aim_snap_distance) {
                            const target_dir = if (target_dist > 1e-9) to_target.mul(1.0 / target_dist) else state_mod.Vec2{};
                            aim = add(aim, target_dir.mul(target_dist * computer_aim_track_gain * dt));
                        } else {
                            aim = target.pos;
                        }
                        const delta = sub(aim, player.pos);
                        if (lengthSq(delta) > 1e-9) {
                            heading = toHeading(delta);
                        }
                        computer_auto_fire = target_dist < computer_auto_fire_distance;
                    } else {
                        target_index = null;
                    }
                }
                if (target_index == null) {
                    var away = normalized(sub(player.pos, computer_arena_center));
                    if (lengthSq(away) <= 1e-12) {
                        away = .{ .x = 0.0, .y = -1.0 };
                    }
                    aim = add(player.pos, away.mul(aim_radius_keyboard));
                    heading = toHeading(away);
                }
            },
            else => {},
        }

        const aim_delta = sub(aim, player.pos);
        if (lengthSq(aim_delta) > 1e-9) {
            heading = toHeading(aim_delta);
        }
        state.aim_heading = heading;

        var fire_down = sampler.codeIsDown(fire_key, @intCast(idx));
        const fire_pressed = sampler.codeIsPressed(fire_key, @intCast(idx));
        if (aim_scheme == aim_scheme_computer and computer_auto_fire) {
            fire_down = true;
        }
        const reload_pressed = sampler.codeIsPressed(reload_key, @intCast(idx));
        const reload_down = sampler.codeIsDown(reload_key, @intCast(idx));

        return .{
            .move_x = move_vec.x,
            .move_y = move_vec.y,
            .aim_x = aim.x,
            .aim_y = aim.y,
            .flags = .{
                .fire_down = fire_down,
                .fire_pressed = fire_pressed,
                .reload_pressed = reload_pressed,
                .reload_down = reload_down,
                .move_to_cursor_pressed = move_to_cursor_pressed,
                .move_mode = move_mode_type,
                .aim_scheme = aim_scheme,
                .move_forward_pressed = move_forward_pressed,
                .move_backward_pressed = move_backward_pressed,
                .turn_left_pressed = turn_left_pressed,
                .turn_right_pressed = turn_right_pressed,
            },
        };
    }

    fn stateForPlayer(
        self: *LocalInputInterpreter,
        player_index: usize,
        player: *const state_mod.PlayerState,
    ) *PerPlayerInputState {
        const slot = stateSlotForPlayer(player_index, player);
        const state = &self.states[slot];
        if (!std.math.isFinite(state.aim_heading)) {
            state.aim_heading = player.aim_heading;
        }
        return state;
    }

    fn selectComputerTarget(
        self: *LocalInputInterpreter,
        player_index: usize,
        player: *const state_mod.PlayerState,
        creatures: anytype,
    ) ?i32 {
        const slot = stateSlotForPlayer(player_index, player);
        const state = &self.states[slot];
        const candidate = nearestLivingCreatureIndex(player.pos, creatures);
        const current = state.computer_target_creature_index;

        if (candidate == null) {
            state.computer_target_creature_index = -1;
            return null;
        }
        if (current < 0) {
            state.computer_target_creature_index = candidate.?;
            return candidate;
        }

        const current_creature = creatureAt(creatures, current) orelse {
            state.computer_target_creature_index = candidate.?;
            return candidate;
        };
        if (!current_creature.active or current_creature.hp <= 0.0) {
            state.computer_target_creature_index = candidate.?;
            return candidate;
        }
        if (candidate.? == current) return candidate;

        const candidate_creature = creatureAt(creatures, candidate.?) orelse return current;
        if (!candidate_creature.active or candidate_creature.hp <= 0.0) return current;

        const current_dist = length(sub(current_creature.pos, player.pos));
        const candidate_dist = length(sub(candidate_creature.pos, player.pos));
        if (candidate_dist + computer_target_switch_hysteresis < current_dist) {
            state.computer_target_creature_index = candidate.?;
            return candidate;
        }
        return current;
    }
};

fn resolveMovementMode(config: *const formats.crimson_cfg.CrimsonCfg, player_index: usize) i32 {
    return @intCast(formats.crimson_cfg.playerMovement(config, player_index));
}

fn resolveAimScheme(config: *const formats.crimson_cfg.CrimsonCfg, player_index: usize) i32 {
    return @bitCast(formats.crimson_cfg.playerAimScheme(config, player_index));
}

fn stateSlotForPlayer(player_index: usize, player: *const state_mod.PlayerState) usize {
    const raw_slot = if (player.index >= 0) @as(usize, @intCast(player.index)) else player_index;
    return @min(raw_slot, state_mod.max_players - 1);
}

fn singlePlayerAltKeysEnabled(player_count: usize, player_index: usize) bool {
    return player_index == 0 and player_count == 1;
}

fn keyDownWithSinglePlayerAlt(
    sampler: anytype,
    primary_key: i32,
    alt_key: i32,
    player_count: usize,
    player_index: usize,
) bool {
    if (sampler.codeIsDown(primary_key, @intCast(player_index))) return true;
    if (singlePlayerAltKeysEnabled(player_count, player_index)) {
        return sampler.codeIsDown(alt_key, @intCast(player_index));
    }
    return false;
}

fn aimPovLeftActive(sampler: anytype, player_index: usize, preserve_bugs: bool) bool {
    const pov_index: i32 = if (preserve_bugs) 0 else @intCast(player_index);
    return sampler.codeIsDown(aim_pov_left_code, pov_index);
}

fn aimPovRightActive(sampler: anytype, player_index: usize, preserve_bugs: bool) bool {
    const pov_index: i32 = if (preserve_bugs) 0 else @intCast(player_index);
    return sampler.codeIsDown(aim_pov_right_code, pov_index);
}

fn resolveStaticMoveVector(move_up: bool, move_down: bool, move_left: bool, move_right: bool) state_mod.Vec2 {
    var move: state_mod.Vec2 = .{};
    if (move_left) move = .{ .x = -1.0, .y = 0.0 };
    if (move_right) move = .{ .x = 1.0, .y = 0.0 };

    if (move_up) {
        if (move_left) {
            move = .{ .x = -1.0, .y = -1.0 };
        } else if (move_right) {
            move = .{ .x = 1.0, .y = -1.0 };
        } else {
            move = .{ .x = 0.0, .y = -1.0 };
        }
    }

    if (move_down) {
        if (move_left) {
            move = .{ .x = -1.0, .y = 1.0 };
        } else if (move_right) {
            move = .{ .x = 1.0, .y = 1.0 };
        } else {
            move = .{ .x = 0.0, .y = 1.0 };
        }
    }

    return move;
}

fn nearestLivingCreatureIndex(pos: state_mod.Vec2, creatures: anytype) ?i32 {
    var best_idx: ?i32 = null;
    var best_dist_sq: f32 = 0.0;
    for (creatures, 0..) |creature, idx| {
        if (!@field(creature, "active")) continue;
        if (@field(creature, "hp") <= 0.0) continue;
        const dist_sq = lengthSq(sub(@field(creature, "pos"), pos));
        if (best_idx == null or dist_sq < best_dist_sq) {
            best_idx = @intCast(idx);
            best_dist_sq = dist_sq;
        }
    }
    return best_idx;
}

fn creatureAt(creatures: anytype, index: i32) ?@TypeOf(&creatures[0]) {
    if (index < 0) return null;
    const idx: usize = @intCast(index);
    if (idx >= creatures.len) return null;
    return &creatures[idx];
}

fn boolToFloat(value: bool) f32 {
    return if (value) 1.0 else 0.0;
}

fn moveForwardPressed(value: ?bool) bool {
    return value orelse false;
}

fn moveBackwardPressed(value: ?bool) bool {
    return value orelse false;
}

fn turnLeftPressed(value: ?bool) bool {
    return value orelse false;
}

fn turnRightPressed(value: ?bool) bool {
    return value orelse false;
}

fn clampUnit(v: f32) f32 {
    return std.math.clamp(v, @as(f32, -1.0), @as(f32, 1.0));
}

fn aimPointFromHeading(pos: state_mod.Vec2, heading: f32, radius: f32) state_mod.Vec2 {
    return add(pos, state_mod.Vec2.fromAngle(heading).mul(radius));
}

fn add(a: state_mod.Vec2, b: state_mod.Vec2) state_mod.Vec2 {
    return state_mod.Vec2.add(a, b);
}

fn sub(a: state_mod.Vec2, b: state_mod.Vec2) state_mod.Vec2 {
    return state_mod.Vec2.sub(a, b);
}

fn length(vec: state_mod.Vec2) f32 {
    return vec.length();
}

fn lengthSq(vec: state_mod.Vec2) f32 {
    return vec.lengthSq();
}

fn normalized(vec: state_mod.Vec2) state_mod.Vec2 {
    const len = length(vec);
    if (!(len > 1e-9)) return .{};
    return vec.mul(1.0 / len);
}

fn toHeading(vec: state_mod.Vec2) f32 {
    return vec.toHeading();
}

const FakeSampler = struct {
    down: []const KeyState = &.{},
    pressed: []const KeyState = &.{},
    axes: []const AxisState = &.{},

    const KeyState = struct {
        player_index: i32,
        code: i32,
        value: bool,
    };

    const AxisState = struct {
        player_index: i32,
        code: i32,
        value: f32,
    };

    fn codeIsDown(self: FakeSampler, code: i32, player_index: i32) bool {
        for (self.down) |entry| {
            if (entry.player_index == player_index and entry.code == code) return entry.value;
        }
        return false;
    }

    fn codeIsPressed(self: FakeSampler, code: i32, player_index: i32) bool {
        for (self.pressed) |entry| {
            if (entry.player_index == player_index and entry.code == code) return entry.value;
        }
        return false;
    }

    fn axisValue(self: FakeSampler, code: i32, player_index: i32) f32 {
        for (self.axes) |entry| {
            if (entry.player_index == player_index and entry.code == code) return entry.value;
        }
        return 0.0;
    }
};

fn makePlayer(index: i32, pos: state_mod.Vec2, aim: state_mod.Vec2, aim_heading: f32) state_mod.PlayerState {
    return .{
        .index = index,
        .pos = pos,
        .aim = aim,
        .aim_heading = aim_heading,
    };
}

fn expectFloatClose(expected: f32, actual: f32) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-4);
}

test "computer aim auto fires without fire pressed" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 512.0, .y = 512.0 }, .{ .x = 560.0, .y = 512.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.aim_scheme_p1 = @bitCast(@as(i32, aim_scheme_computer));

    const creatures = [_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{
        .{ .active = true, .hp = 20.0, .pos = .{ .x = 612.0, .y = 512.0 } },
    };

    const out = interpreter.buildPlayerInput(.{}, 0, 1, &player, &cfg, .{}, .{}, .{}, 0.1, creatures[0..]);

    try std.testing.expect(out.flags.fire_down);
    try std.testing.expect(!out.flags.fire_pressed);
    try expectFloatClose(591.2, out.aim_x);
    try expectFloatClose(512.0, out.aim_y);
}

test "static mode conflict precedence matches native" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 160.0, .y = 100.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();

    const sampler: FakeSampler = .{
        .down = &.{
            .{ .player_index = 0, .code = formats.crimson_cfg.playerBindBlock(&cfg, 0).move_forward, .value = true },
            .{ .player_index = 0, .code = formats.crimson_cfg.playerBindBlock(&cfg, 0).turn_left, .value = true },
            .{ .player_index = 0, .code = formats.crimson_cfg.playerBindBlock(&cfg, 0).turn_right, .value = true },
        },
    };
    const out = interpreter.buildPlayerInput(sampler, 0, 1, &player, &cfg, .{}, .{}, .{}, 0.1, &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{});

    try expectFloatClose(-1.0, out.move_x);
    try expectFloatClose(-1.0, out.move_y);
}

test "relative mode single player uses alt arrow fallback" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 160.0, .y = 100.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.player_mode_flag_p1 = @intCast(movement_control_relative);
    formats.crimson_cfg.setPlayerBindBlock(&cfg, 0, .{
        .move_forward = formats.crimson_cfg.keybind_unbound_code,
        .move_backward = formats.crimson_cfg.keybind_unbound_code,
        .turn_left = formats.crimson_cfg.keybind_unbound_code,
        .turn_right = formats.crimson_cfg.keybind_unbound_code,
        .fire = 0x100,
        .reserved_keys = .{ formats.crimson_cfg.keybind_unbound_code, formats.crimson_cfg.keybind_unbound_code },
        .aim_left = formats.crimson_cfg.keybind_unbound_code,
        .aim_right = formats.crimson_cfg.keybind_unbound_code,
        .axis_aim_y = formats.crimson_cfg.keybind_unbound_code,
        .axis_aim_x = formats.crimson_cfg.keybind_unbound_code,
        .axis_move_y = formats.crimson_cfg.keybind_unbound_code,
        .axis_move_x = formats.crimson_cfg.keybind_unbound_code,
        .padding = .{
            formats.crimson_cfg.keybind_unbound_code,
            formats.crimson_cfg.keybind_unbound_code,
            formats.crimson_cfg.keybind_unbound_code,
        },
    });

    const out = interpreter.buildPlayerInput(
        .{ .down = &.{
            .{ .player_index = 0, .code = alt_move_key_up, .value = true },
            .{ .player_index = 0, .code = alt_move_key_left, .value = true },
        } },
        0,
        1,
        &player,
        &cfg,
        .{},
        .{},
        .{},
        0.1,
        &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{},
    );

    try std.testing.expect(out.flags.move_forward_pressed.?);
    try std.testing.expect(out.flags.turn_left_pressed.?);
    try expectFloatClose(-1.0, out.move_x);
    try expectFloatClose(-1.0, out.move_y);
}

test "relative mode multiplayer does not use alt arrow fallback" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 160.0, .y = 100.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.player_mode_flag_p1 = @intCast(movement_control_relative);
    formats.crimson_cfg.setPlayerBindBlock(&cfg, 0, .{
        .move_forward = formats.crimson_cfg.keybind_unbound_code,
        .move_backward = formats.crimson_cfg.keybind_unbound_code,
        .turn_left = formats.crimson_cfg.keybind_unbound_code,
        .turn_right = formats.crimson_cfg.keybind_unbound_code,
        .fire = 0x100,
        .reserved_keys = .{ formats.crimson_cfg.keybind_unbound_code, formats.crimson_cfg.keybind_unbound_code },
        .aim_left = formats.crimson_cfg.keybind_unbound_code,
        .aim_right = formats.crimson_cfg.keybind_unbound_code,
        .axis_aim_y = formats.crimson_cfg.keybind_unbound_code,
        .axis_aim_x = formats.crimson_cfg.keybind_unbound_code,
        .axis_move_y = formats.crimson_cfg.keybind_unbound_code,
        .axis_move_x = formats.crimson_cfg.keybind_unbound_code,
        .padding = .{
            formats.crimson_cfg.keybind_unbound_code,
            formats.crimson_cfg.keybind_unbound_code,
            formats.crimson_cfg.keybind_unbound_code,
        },
    });

    const out = interpreter.buildPlayerInput(
        .{ .down = &.{
            .{ .player_index = 0, .code = alt_move_key_up, .value = true },
            .{ .player_index = 0, .code = alt_move_key_left, .value = true },
        } },
        0,
        2,
        &player,
        &cfg,
        .{},
        .{},
        .{},
        0.1,
        &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{},
    );

    try std.testing.expectEqual(@as(bool, false), out.flags.move_forward_pressed.?);
    try std.testing.expectEqual(@as(bool, false), out.flags.turn_left_pressed.?);
    try expectFloatClose(0.0, out.move_x);
    try expectFloatClose(0.0, out.move_y);
}

test "mouse point click marks move to cursor press" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 160.0, .y = 100.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.player_mode_flag_p1 = @intCast(movement_control_mouse_point_click);

    const mouse_world: state_mod.Vec2 = .{ .x = 160.0, .y = 140.0 };
    const out = interpreter.buildPlayerInput(
        .{
            .down = &.{.{ .player_index = 0, .code = @bitCast(cfg.keybind_reload), .value = true }},
            .pressed = &.{.{ .player_index = 0, .code = @bitCast(cfg.keybind_reload), .value = true }},
        },
        0,
        1,
        &player,
        &cfg,
        .{},
        mouse_world,
        .{},
        0.1,
        &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{},
    );

    try std.testing.expect(out.flags.reload_pressed);
    try std.testing.expect(out.flags.move_to_cursor_pressed);
    const expected = normalized(sub(mouse_world, player.pos));
    try expectFloatClose(expected.x, out.move_x);
    try expectFloatClose(expected.y, out.move_y);
}

test "computer move mode near center heads toward target" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 500.0, .y = 500.0 }, .{ .x = 560.0, .y = 500.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.player_mode_flag_p1 = @intCast(movement_control_computer);
    const creatures = [_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{
        .{ .active = true, .hp = 20.0, .pos = .{ .x = 560.0, .y = 500.0 } },
    };

    const out = interpreter.buildPlayerInput(.{}, 0, 1, &player, &cfg, .{}, .{}, .{}, 0.1, creatures[0..]);

    try expectFloatClose(1.0, out.move_x);
    try expectFloatClose(0.0, out.move_y);
}

test "computer move mode far from center heads toward center" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 900.0, .y = 900.0 }, .{ .x = 960.0, .y = 900.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.player_mode_flag_p1 = @intCast(movement_control_computer);
    const creatures = [_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{
        .{ .active = true, .hp = 20.0, .pos = .{ .x = 960.0, .y = 900.0 } },
    };

    const out = interpreter.buildPlayerInput(.{}, 0, 1, &player, &cfg, .{}, .{}, .{}, 0.1, creatures[0..]);
    const expected = normalized(sub(computer_arena_center, player.pos));
    try expectFloatClose(expected.x, out.move_x);
    try expectFloatClose(expected.y, out.move_y);
}

test "joystick aim uses pov not aim keybinds" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 160.0, .y = 100.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.aim_scheme_p1 = @bitCast(@as(i32, aim_scheme_joystick));

    const out = interpreter.buildPlayerInput(
        .{ .down = &.{.{ .player_index = 0, .code = formats.crimson_cfg.playerBindBlock(&cfg, 0).aim_right, .value = true }} },
        0,
        1,
        &player,
        &cfg,
        .{},
        .{},
        .{},
        0.1,
        &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{},
    );

    try expectFloatClose(100.0, out.aim_x);
    try expectFloatClose(40.0, out.aim_y);
}

test "joystick aim turns with pov input" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 160.0, .y = 100.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.aim_scheme_p1 = @bitCast(@as(i32, aim_scheme_joystick));

    const out = interpreter.buildPlayerInput(
        .{ .down = &.{.{ .player_index = 0, .code = aim_pov_right_code, .value = true }} },
        0,
        1,
        &player,
        &cfg,
        .{},
        .{},
        .{},
        0.1,
        &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{},
    );
    const expected = aimPointFromHeading(player.pos, 0.4, aim_radius_keyboard);
    try expectFloatClose(expected.x, out.aim_x);
    try expectFloatClose(expected.y, out.aim_y);
}

test "dual action pad aim uses native radius scale" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 160.0, .y = 100.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.aim_scheme_p1 = @bitCast(@as(i32, aim_scheme_dual_action_pad));

    const binds = formats.crimson_cfg.playerBindBlock(&cfg, 0);
    const out = interpreter.buildPlayerInput(
        .{ .axes = &.{.{ .player_index = 0, .code = binds.axis_aim_x, .value = 1.0 }} },
        0,
        1,
        &player,
        &cfg,
        .{},
        .{},
        .{},
        0.1,
        &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{},
    );

    try expectFloatClose(238.0, out.aim_x);
    try expectFloatClose(100.0, out.aim_y);
}

test "keyboard aim in static mode reanchors to heading" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 180.0, .y = 130.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.aim_scheme_p1 = @bitCast(@as(i32, aim_scheme_keyboard));

    const out = interpreter.buildPlayerInput(.{}, 0, 1, &player, &cfg, .{}, .{}, .{}, 0.1, &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{});

    try expectFloatClose(100.0, out.aim_x);
    try expectFloatClose(40.0, out.aim_y);
}

test "keyboard aim with non relative move mode keeps world aim" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 180.0, .y = 130.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.aim_scheme_p1 = @bitCast(@as(i32, aim_scheme_keyboard));
    cfg.player_mode_flag_p1 = @intCast(movement_control_dual_action_pad);

    const out = interpreter.buildPlayerInput(.{}, 0, 1, &player, &cfg, .{}, .{}, .{}, 0.1, &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{});

    try expectFloatClose(180.0, out.aim_x);
    try expectFloatClose(130.0, out.aim_y);
}

test "relative mouse aim centered keeps world aim" {
    var interpreter: LocalInputInterpreter = .{};
    const player = makePlayer(0, .{ .x = 100.0, .y = 100.0 }, .{ .x = 180.0, .y = 130.0 }, 0.0);
    var cfg = formats.crimson_cfg.defaultConfig();
    cfg.aim_scheme_p1 = @bitCast(@as(i32, aim_scheme_mouse_relative));
    const center: state_mod.Vec2 = .{ .x = 320.0, .y = 200.0 };

    const out = interpreter.buildPlayerInput(.{}, 0, 1, &player, &cfg, center, .{}, center, 0.1, &[_]struct { active: bool, hp: f32, pos: state_mod.Vec2 }{});

    try expectFloatClose(180.0, out.aim_x);
    try expectFloatClose(130.0, out.aim_y);
}
