const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");
const creatures_mod = @import("creatures.zig");
const perks = @import("perks.zig");
const player_runtime = @import("player.zig");
const state_mod = @import("state.zig");
const survival_progression = @import("survival_progression.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;
const GameInput = player_runtime.GameInput;
const GameInputFlags = player_runtime.GameInputFlags;
const native_half_pi: f32 = native_math.native_half_pi;
const native_pi: f32 = native_math.native_pi;
const native_tau: f32 = native_math.native_tau;
const relative_move_heading_none: f32 = -1.0;
const relative_move_heading_forward: f32 = 0.0;
const relative_move_heading_forward_right: f32 = 0.7853981852531433;
const relative_move_heading_right: f32 = native_half_pi;
const relative_move_heading_backward_right: f32 = 2.356194496154785;
const relative_move_heading_backward: f32 = native_pi;
const relative_move_heading_backward_left: f32 = 3.9269909858703613;
const relative_move_heading_left: f32 = narrowF32(native_tau - native_half_pi);
const relative_move_heading_forward_left: f32 = 5.4977874755859375;
const relative_move_turn_align_scale: f32 = 7.957746982574463;
const movement_control_relative: i32 = 1;
const movement_control_static: i32 = 2;
const movement_control_dual_action_pad: i32 = 3;
const movement_control_computer: i32 = 5;
const aim_scheme_mouse: i32 = 0;
const aim_scheme_computer: i32 = 5;

pub fn updatePlayerFromGameInput(
    player: *state_mod.PlayerState,
    input: GameInput,
    state: *const state_mod.GameplayState,
    creatures: ?*const creatures_mod.CreaturePool,
    dt: f32,
) void {
    const prev_pos = player.pos;
    var movement_dt = dt;
    if (state.time_scale_active and movement_dt > 0.0) {
        const time_scale_factor = survival_progression.reflexBoostTimeScaleFactor(
            state.bonuses.reflex_boost,
            true,
        );
        if (time_scale_factor > 0.0) {
            movement_dt = native_math.pc24Mul(
                native_math.pc24Div(@as(f32, 0.6), time_scale_factor),
                movement_dt,
            );
        }
    }

    const flags = input.flags;
    const move_mode = resolveMoveModeForUpdate(flags);
    const aim_scheme = resolveAimSchemeForUpdate(flags);

    var raw_move: state_mod.Vec2 = .{
        .x = narrowF32(input.move_x),
        .y = narrowF32(input.move_y),
    };
    const raw_mag = raw_move.length();
    var move_ext = directionFromHeadingNativeExt(player.heading);

    var speed_multiplier = player.speed_multiplier;
    if (player.speed_bonus_timer > 0.0) {
        speed_multiplier += 1.0;
    }

    var speed: f32 = 0.0;
    var phase_sign: f32 = 1.0;
    var move_delta_override: ?state_mod.Vec2 = null;
    const player_controlled_movement =
        move_mode != movement_control_computer and
        aim_scheme != aim_scheme_computer;

    if (player_controlled_movement) {
        if (move_mode == movement_control_relative) {
            const turning_left = flags.turn_left_pressed orelse false;
            const turning_right = flags.turn_right_pressed orelse false;
            const moving_forward = flags.move_forward_pressed orelse false;
            const moving_backward = flags.move_backward_pressed orelse false;
            var turned = false;

            if (player.turn_speed < 1.0) player.turn_speed = 1.0;
            if (player.turn_speed > 7.0) player.turn_speed = 7.0;

            if (turning_left) {
                player.turn_speed = narrowF32(player.turn_speed + movement_dt * 10.0);
                const turn_step = narrowF32(player.turn_speed * movement_dt * 0.5);
                player.heading = narrowF32(player.heading - turn_step);
                player.aim_heading = narrowF32(player.aim_heading - turn_step);
                turned = true;
            } else if (turning_right) {
                player.turn_speed = narrowF32(player.turn_speed + movement_dt * 10.0);
                const turn_step = narrowF32(player.turn_speed * movement_dt * 0.5);
                player.heading = narrowF32(player.heading + turn_step);
                player.aim_heading = narrowF32(player.aim_heading + turn_step);
                turned = true;
            }

            if (moving_forward) {
                playerAccelerateMoveSpeed(player, movement_dt);
                playerApplyMoveSpeedCaps(player);
                move_delta_override = playerMoveDeltaFromHeading(player, movement_dt, 25.0);
            } else if (moving_backward) {
                playerAccelerateMoveSpeed(player, movement_dt);
                phase_sign = -1.0;
                move_delta_override = playerMoveDeltaFromHeading(player, movement_dt, -25.0);
            } else {
                if (!turned) {
                    player.turn_speed = 1.0;
                }
                playerDecelerateMoveSpeed(player, movement_dt);
                move_delta_override = playerMoveDeltaFromHeading(player, movement_dt, 25.0);
            }
        } else if (move_mode == movement_control_static) {
            const moving_forward = flags.move_forward_pressed orelse (raw_move.y < -0.5);
            const moving_backward = flags.move_backward_pressed orelse (raw_move.y > 0.5);
            const turning_left = flags.turn_left_pressed orelse (raw_move.x < -0.5);
            const turning_right = flags.turn_right_pressed orelse (raw_move.x > 0.5);

            var target_heading = relative_move_heading_none;
            if (turning_left) target_heading = relative_move_heading_left;
            if (turning_right) target_heading = relative_move_heading_right;

            if (moving_forward) {
                if (turning_left) {
                    target_heading = relative_move_heading_forward_left;
                } else if (turning_right) {
                    target_heading = relative_move_heading_forward_right;
                } else {
                    target_heading = relative_move_heading_forward;
                }
            }
            if (moving_backward) {
                if (turning_left) {
                    target_heading = relative_move_heading_backward_left;
                } else if (turning_right) {
                    target_heading = relative_move_heading_backward_right;
                } else {
                    target_heading = relative_move_heading_backward;
                }
            }

            if (!moving_backward and target_heading == relative_move_heading_none) {
                playerDecelerateMoveSpeed(player, movement_dt);
                move_ext = directionFromHeadingNativeExt(player.heading);
                const speed_scale_wide =
                    @as(f64, @floatCast(player.move_speed)) *
                    @as(f64, @floatCast(speed_multiplier)) *
                    @as(f64, @floatCast(@as(f32, 25.0)));
                const move_dx = headingMulWideNarrow(move_ext.x, speed_scale_wide);
                const move_dy = headingMulWideNarrow(move_ext.y, speed_scale_wide);
                move_delta_override = movementDeltaFromVelocityNative(movement_dt, move_dx, move_dy);
            } else {
                const heading_result = playerHeadingApproachTargetWithDelta(
                    player,
                    target_heading,
                    movement_dt,
                );
                player.aim_heading = narrowF32(player.aim_heading + heading_result.turn_delta);
                playerAccelerateMoveSpeed(player, movement_dt);
                playerApplyMoveSpeedCaps(player);
                move_ext = directionFromHeadingNativeExt(player.heading);
                const velocity = playerTurnAlignedVelocityNative(
                    move_ext,
                    player.move_speed,
                    heading_result.diff,
                    speed_multiplier,
                );
                move_delta_override = movementDeltaFromVelocityNative(movement_dt, velocity.x, velocity.y);
            }
        } else {
            const moving_input = raw_mag > 0.2;
            var turn_alignment_scale: f32 = 1.0;
            if (moving_input) {
                raw_move = normalizeVec2SafeNative(raw_move);
                const target_heading = normalizeHeading(raw_move.toHeading());
                const angle_diff = playerHeadingApproachTarget(player, target_heading, movement_dt);
                move_ext = directionFromHeadingNativeExt(player.heading);
                turn_alignment_scale = @max(0.0, (native_pi - angle_diff) / native_pi);
                playerAccelerateMoveSpeed(player, movement_dt);
            } else {
                playerDecelerateMoveSpeed(player, movement_dt);
                move_ext = directionFromHeadingNativeExt(player.heading);
            }

            playerApplyMoveSpeedCaps(player);
            speed = player.move_speed * speed_multiplier * 25.0;
            if (moving_input) {
                speed *= @min(1.0, raw_mag);
                speed *= turn_alignment_scale;
            }
        }
    } else {
        const move_input_threshold: f32 = 0.2;
        const moving_input = raw_mag > move_input_threshold;
        var turn_alignment_scale: f32 = 1.0;
        if (moving_input) {
            raw_move = normalizeVec2SafeNative(raw_move);
            const target_heading = normalizeHeading(raw_move.toHeading());
            const angle_diff = playerHeadingApproachTarget(player, target_heading, movement_dt);
            move_ext = directionFromHeadingNativeExt(player.heading);
            turn_alignment_scale = @max(0.0, (native_pi - angle_diff) / native_pi);
            playerAccelerateMoveSpeed(player, movement_dt);
        } else {
            playerDecelerateMoveSpeed(player, movement_dt);
            move_ext = directionFromHeadingNativeExt(player.heading);
        }

        playerApplyMoveSpeedCaps(player);
        speed = player.move_speed * speed_multiplier * 25.0;
        if (moving_input) {
            speed *= @min(1.0, raw_mag);
            speed *= turn_alignment_scale;
        }
    }

    const delta = if (move_delta_override) |override|
        override
    else
        state_mod.Vec2{
            .x = headingMulNarrow(move_ext.x, narrowF32(speed * movement_dt)),
            .y = headingMulNarrow(move_ext.y, narrowF32(speed * movement_dt)),
        };
    playerApplyMoveWithSpawnAvoidance(player, delta, creatures);

    const move_delta = state_mod.Vec2.sub(player.pos, prev_pos);
    const reload_stationary = move_delta.x == 0.0 and move_delta.y == 0.0;
    player.reload_stationary_latch = reload_stationary;
    if (!reload_stationary) {
        // Native clears these post-perk-tick timers after movement when position changed.
        player.man_bomb_timer = 0.0;
        player.living_fortress_timer = 0.0;
    }
    player.move_phase = narrowF32(player.move_phase + narrowF32(phase_sign * movement_dt * player.move_speed * 19.0));

    player.aim = .{
        .x = narrowF32(input.aim_x),
        .y = narrowF32(input.aim_y),
    };
    const aim_dir = normalizeVec2SafeNative(state_mod.Vec2.sub(player.aim, player.pos));
    if (aim_dir.lengthSq() > 0.0) {
        player.aim_dir = aim_dir;
        player.aim_heading = aimHeadingFromAimPointNative(player.pos, player.aim);
    }
}

pub fn finalizePlayerPostUpdate(
    player: *state_mod.PlayerState,
    world_size: f32,
) void {
    while (player.move_phase > 14.0) {
        player.move_phase = narrowF32(player.move_phase - 14.0);
    }
    while (player.move_phase < 0.0) {
        player.move_phase = narrowF32(player.move_phase + 14.0);
    }

    const half_size = @max(0.0, player.size * 0.5);
    const clamped_pos = player.pos.clampRect(
        half_size,
        half_size,
        narrowF32(world_size - half_size),
        narrowF32(world_size - half_size),
    );
    player.pos = .{
        .x = narrowF32(clamped_pos.x),
        .y = narrowF32(clamped_pos.y),
    };
    if (player.muzzle_flash_alpha > 0.8) {
        player.muzzle_flash_alpha = 0.8;
    }
}

pub fn resolveMoveModeForUpdate(
    flags: GameInputFlags,
) i32 {
    if (flags.move_mode) |mode| return mode;
    if (flags.move_forward_pressed != null and
        flags.move_backward_pressed != null and
        flags.turn_left_pressed != null and
        flags.turn_right_pressed != null)
    {
        return movement_control_static;
    }
    return movement_control_dual_action_pad;
}

pub fn resolveAimSchemeForUpdate(
    flags: GameInputFlags,
) i32 {
    if (flags.aim_scheme) |scheme| return scheme;
    return aim_scheme_mouse;
}

fn playerMoveDeltaFromHeading(
    player: *const state_mod.PlayerState,
    movement_dt: f32,
    speed_scale: f32,
) state_mod.Vec2 {
    const move_ext = directionFromHeadingNativeExt(player.heading);
    const speed_scale_wide =
        @as(f64, @floatCast(player.move_speed)) *
        @as(f64, @floatCast(speed_scale));
    const move_dx = headingMulWideNarrow(move_ext.x, speed_scale_wide);
    const move_dy = headingMulWideNarrow(move_ext.y, speed_scale_wide);
    return movementDeltaFromVelocityNative(movement_dt, move_dx, move_dy);
}

const HeadingDirectionExt = struct {
    x: f64,
    y: f64,
};

fn headingMulNarrow(component: f64, scalar: f32) f32 {
    return headingMulWideNarrow(component, @as(f64, @floatCast(scalar)));
}

fn headingMulWideNarrow(component: f64, scale_wide: f64) f32 {
    // `player_update` (0x004136b0) computes fcos/fsin movement products in x87
    // and spills once to float move_dx/move_dy.
    return narrowF32(component * scale_wide);
}

fn playerTurnAlignedVelocityNative(
    direction: HeadingDirectionExt,
    move_speed: f32,
    angle_diff: f32,
    speed_multiplier: f32,
) state_mod.Vec2 {
    const alignment = native_math.pc24Sub(native_pi, angle_diff);
    return .{
        .x = native_math.pc24Mul(
            native_math.pc24Mul(
                native_math.pc24Mul(
                    native_math.pc24Mul(direction.x, move_speed),
                    alignment,
                ),
                speed_multiplier,
            ),
            relative_move_turn_align_scale,
        ),
        .y = native_math.pc24Mul(
            native_math.pc24Mul(
                native_math.pc24Mul(
                    native_math.pc24Mul(direction.y, move_speed),
                    alignment,
                ),
                speed_multiplier,
            ),
            relative_move_turn_align_scale,
        ),
    };
}

fn movementDeltaFromVelocityNative(movement_dt: f32, move_dx: f32, move_dy: f32) state_mod.Vec2 {
    // Decompile stores `local_10/local_c = frame_dt * move_d{xy}` after x87 math.
    const dt_wide = @as(f64, @floatCast(movement_dt));
    return .{
        .x = narrowF32(dt_wide * @as(f64, @floatCast(move_dx))),
        .y = narrowF32(dt_wide * @as(f64, @floatCast(move_dy))),
    };
}

fn normalizeVec2SafeNative(value: state_mod.Vec2) state_mod.Vec2 {
    const normalized = native_math.normalizeVec2Safe(value.x, value.y);
    return .{
        .x = normalized[0],
        .y = normalized[1],
    };
}

fn distanceF32Xy(
    ax: f32,
    ay: f32,
    bx: f32,
    by: f32,
) f32 {
    const dx = narrowF32(ax - bx);
    const dy = narrowF32(ay - by);
    const dist_sq = narrowF32(narrowF32(dx * dx) + narrowF32(dy * dy));
    return narrowF32(std.math.sqrt(dist_sq));
}

fn playerApplyMoveWithSpawnAvoidance(
    player: *state_mod.PlayerState,
    delta: state_mod.Vec2,
    creatures: ?*const creatures_mod.CreaturePool,
) void {
    var dx = delta.x;
    var dy = delta.y;
    if (perks.perkActive(player, PerkId.alternate_weapon)) {
        dx = narrowF32(dx * 0.8);
        dy = narrowF32(dy * 0.8);
    }

    var pos_x = narrowF32(player.pos.x + dx);
    var pos_y = narrowF32(player.pos.y + dy);

    if (creatures) |creature_pool| {
        const slot_count = @min(creature_pool.spawn_slot_count, creature_pool.spawn_slots.len);
        for (creature_pool.spawn_slots[0..slot_count]) |slot| {
            if (slot.owner_creature < 0) continue;
            const owner_idx: usize = @intCast(slot.owner_creature);
            if (owner_idx >= creature_pool.entries.len) continue;
            const owner = creature_pool.entries[owner_idx];
            const owner_pos = owner.pos;
            const radius = narrowF32((owner.size + player.size) * 0.33333334);
            if (distanceF32Xy(owner_pos.x, owner_pos.y, pos_x, pos_y) > radius) continue;

            const old_x = narrowF32(pos_x - dx);
            const old_y = narrowF32(pos_y - dy);
            const old_dist = distanceF32Xy(owner_pos.x, owner_pos.y, old_x, old_y);
            const x_candidate = narrowF32(old_x + dx);
            const y_candidate = narrowF32(old_y + dy);

            if (radius < old_dist) {
                pos_x = x_candidate;
                pos_y = old_y;
                if (distanceF32Xy(owner_pos.x, owner_pos.y, pos_x, pos_y) <= radius) {
                    pos_x = narrowF32(x_candidate - dx);
                    pos_y = y_candidate;
                    if (distanceF32Xy(owner_pos.x, owner_pos.y, pos_x, pos_y) <= radius) {
                        pos_y = narrowF32(y_candidate - dy);
                    }
                }
            } else {
                pos_x = x_candidate;
                pos_y = y_candidate;
            }
        }
    }

    player.pos = .{
        .x = narrowF32(pos_x),
        .y = narrowF32(pos_y),
    };
}

fn directionFromHeadingNativeExt(heading: f32) HeadingDirectionExt {
    // Gameplay runs x87 arithmetic in 24-bit precision, so the subtraction
    // rounds before fsin/fcos consume it.
    const radians = @as(f64, @floatCast(native_math.pc24Sub(heading, native_half_pi)));
    return .{
        .x = std.math.cos(radians),
        .y = std.math.sin(radians),
    };
}

fn aimHeadingFromAimPointNative(player_pos: state_mod.Vec2, aim_pos: state_mod.Vec2) f32 {
    // player_update (0x004136b0) computes:
    // aim_heading = (float)(fpatan(pos_y - aim_y, pos_x - aim_x) - 1.5707964).
    const dy = narrowF32(player_pos.y - aim_pos.y);
    const dx = narrowF32(player_pos.x - aim_pos.x);
    return narrowF32(native_math.fpatan(dy, dx) - @as(f64, native_half_pi));
}

fn playerAccelerateMoveSpeed(
    player: *state_mod.PlayerState,
    dt: f32,
) void {
    if (perks.perkActive(player, PerkId.long_distance_runner)) {
        if (player.move_speed < 2.0) {
            player.move_speed = narrowF32(player.move_speed + dt * 4.0);
        }
        player.move_speed = narrowF32(player.move_speed + dt);
        if (player.move_speed > 2.8) player.move_speed = 2.8;
    } else {
        player.move_speed = narrowF32(player.move_speed + dt * 5.0);
        if (player.move_speed > 2.0) player.move_speed = 2.0;
    }
}

fn playerDecelerateMoveSpeed(
    player: *state_mod.PlayerState,
    dt: f32,
) void {
    player.move_speed = narrowF32(player.move_speed - dt * 15.0);
    if (player.move_speed < 0.0) player.move_speed = 0.0;
}

fn playerApplyMoveSpeedCaps(
    player: *state_mod.PlayerState,
) void {
    if (player.weapon.weapon_id == game_ids.WeaponId.mean_minigun and player.move_speed > 0.8) {
        player.move_speed = 0.8;
    }
}

const HeadingApproachResult = struct {
    diff: f32,
    turn_delta: f32,
};

fn playerHeadingApproachTargetWithDelta(
    player: *state_mod.PlayerState,
    target_heading: f32,
    dt: f32,
) HeadingApproachResult {
    var heading = normalizeHeading(player.heading);
    player.heading = heading;
    const target = target_heading;

    const direct = narrowF32(@abs(narrowF32(target - heading)));
    var high = heading;
    if (target > high) high = target;
    var low = heading;
    if (target < low) low = target;
    const wrapped = narrowF32(@abs(narrowF32(native_tau - high + low)));
    const diff = if (direct >= wrapped) wrapped else direct;

    const scaled = narrowF32(dt * diff);
    var turn_delta: f32 = 0.0;
    if (direct <= wrapped) {
        if (target > heading) {
            turn_delta = narrowF32(scaled * 5.0);
        } else {
            turn_delta = narrowF32(scaled * -5.0);
        }
    } else {
        if (target >= heading) {
            turn_delta = narrowF32(scaled * -5.0);
        } else {
            turn_delta = narrowF32(scaled * 5.0);
        }
    }

    heading = narrowF32(heading + turn_delta);
    player.heading = heading;
    return .{
        .diff = diff,
        .turn_delta = turn_delta,
    };
}

fn playerHeadingApproachTarget(
    player: *state_mod.PlayerState,
    target_heading: f32,
    dt: f32,
) f32 {
    return playerHeadingApproachTargetWithDelta(player, target_heading, dt).diff;
}

fn normalizeHeading(value: f32) f32 {
    return native_math.wrapAngle0Tau(value);
}

pub fn applyPerkWorldDtSteps(
    players: []const state_mod.PlayerState,
    dt: f32,
) f32 {
    if (!(dt > 0.0)) return dt;
    if (players.len == 0) return dt;
    if (!perks.perkActive(&players[0], PerkId.reflex_boosted)) return dt;
    return narrowF32(dt * 0.9);
}

pub fn playerFrameDtAfterRoundtrip(
    dt: f32,
    time_scale_active: bool,
    reflex_boost_timer: f32,
) f32 {
    if (!time_scale_active or dt <= 0.0) {
        return dt;
    }

    const time_scale_factor = survival_progression.reflexBoostTimeScaleFactor(
        reflex_boost_timer,
        true,
    );
    if (time_scale_factor <= 0.0) {
        return dt;
    }

    const movement_dt = native_math.pc24Mul(
        native_math.pc24Div(@as(f32, 0.6), time_scale_factor),
        dt,
    );
    return native_math.pc24Mul(
        native_math.pc24Mul(time_scale_factor, movement_dt),
        @as(f32, 1.6666666),
    );
}

test "long distance runner ramps speed above base cap and coasts on release" {
    const dt = 0.1;
    const steps: usize = 12;
    var state = state_mod.GameplayState.init(1);
    var base_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = (state_mod.Vec2{ .x = 1.0, .y = 0.0 }).toHeading(),
    };
    var perk_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = (state_mod.Vec2{ .x = 1.0, .y = 0.0 }).toHeading(),
    };
    perk_player.perk_counts.set(PerkId.long_distance_runner, 1);

    const move_input: GameInput = .{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 101.0,
        .aim_y = 100.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
        },
    };

    for (0..steps) |_| {
        updatePlayerFromGameInput(&base_player, move_input, &state, null, dt);
        finalizePlayerPostUpdate(&base_player, 1024.0);
        updatePlayerFromGameInput(&perk_player, move_input, &state, null, dt);
        finalizePlayerPostUpdate(&perk_player, 1024.0);
    }

    var expected_perk_speed: f32 = 0.0;
    const dt_f32 = narrowF32(dt);
    for (0..steps) |_| {
        if (expected_perk_speed < 2.0) {
            expected_perk_speed = narrowF32(expected_perk_speed + dt_f32 * 4.0);
        }
        expected_perk_speed = narrowF32(expected_perk_speed + dt_f32);
        if (expected_perk_speed > 2.8) {
            expected_perk_speed = 2.8;
        }
    }

    try std.testing.expectApproxEqAbs(@as(f32, 2.0), base_player.move_speed, 1e-6);
    try std.testing.expectApproxEqAbs(expected_perk_speed, perk_player.move_speed, 1e-6);
    try std.testing.expect(perk_player.pos.x > base_player.pos.x);

    const prev_x = perk_player.pos.x;
    const coast_input: GameInput = .{
        .move_x = 0.0,
        .move_y = 0.0,
        .aim_x = perk_player.pos.x + 1.0,
        .aim_y = perk_player.pos.y,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
        },
    };
    updatePlayerFromGameInput(&perk_player, coast_input, &state, null, dt);
    finalizePlayerPostUpdate(&perk_player, 1024.0);

    const expected_coast_speed = narrowF32(expected_perk_speed - dt_f32 * 15.0);
    try std.testing.expectApproxEqAbs(expected_coast_speed, perk_player.move_speed, 1e-6);
    try std.testing.expect(perk_player.pos.x > prev_x);
}

test "alternate weapon slows movement by 20 percent" {
    var state = state_mod.GameplayState.init(1);
    const move_heading = (state_mod.Vec2{ .x = 1.0, .y = 0.0 }).toHeading();
    var base_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .move_speed = 2.0,
        .heading = move_heading,
    };
    var perk_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .move_speed = 2.0,
        .heading = move_heading,
    };
    perk_player.perk_counts.set(PerkId.alternate_weapon, 1);

    const input: GameInput = .{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 0.0,
        .aim_y = 0.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
        },
    };

    updatePlayerFromGameInput(&base_player, input, &state, null, 1.0);
    finalizePlayerPostUpdate(&base_player, 1024.0);
    updatePlayerFromGameInput(&perk_player, input, &state, null, 1.0);
    finalizePlayerPostUpdate(&perk_player, 1024.0);

    try std.testing.expectApproxEqAbs(@as(f32, 100.0), base_player.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 80.0), perk_player.pos.x, 1e-6);
}

test "reflex boosted perk scales world dt by 0.9" {
    const base_players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    var perk_players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    perk_players[0].perk_counts.set(PerkId.reflex_boosted, 1);

    try std.testing.expectApproxEqAbs(@as(f32, 1.0), applyPerkWorldDtSteps(base_players[0..], 1.0), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.9), applyPerkWorldDtSteps(perk_players[0..], 1.0), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), applyPerkWorldDtSteps(perk_players[0..], 0.0), 1e-6);
}

test "aim heading from aim point matches native fpatan rounding path" {
    const player_pos: state_mod.Vec2 = .{ .x = 512.0, .y = 512.0 };
    const aim_pos: state_mod.Vec2 = .{ .x = 333.0390625, .y = 391.1640625 };
    const heading = aimHeadingFromAimPointNative(player_pos, aim_pos);
    try std.testing.expectEqual(@as(u32, 0xbf7a1659), @as(u32, @bitCast(heading)));
}

test "safe normalization preserves native near-unit vector" {
    const normalized = normalizeVec2SafeNative(.{ .x = 1.0, .y = 0.0001 });

    try std.testing.expectEqual(@as(f32, 1.0), normalized.x);
    try std.testing.expectEqual(@as(u32, 0x38d1b717), @as(u32, @bitCast(normalized.y)));
}

test "safe normalization zeros native subnormal length" {
    try std.testing.expectEqual(@as(state_mod.Vec2, .{}), normalizeVec2SafeNative(.{ .x = 1e-20, .y = 0.0 }));
}

test "static movement narrows x87 direction and alignment operations" {
    const direction = directionFromHeadingNativeExt(3.9270143508911133);
    const velocity = playerTurnAlignedVelocityNative(
        direction,
        2.0,
        3.0040740966796875e-05,
        2.0,
    );

    try std.testing.expectEqual(@as(f32, -70.7116470336914), velocity.x);
    try std.testing.expectEqual(@as(f32, 70.7083511352539), velocity.y);
    try std.testing.expectEqual(
        @as(f32, 299.4222106933594),
        narrowF32(@as(f64, 302.53350830078125) + @as(f64, @floatCast(native_math.pc24Mul(0.04400000348687172, velocity.x)))),
    );
}
