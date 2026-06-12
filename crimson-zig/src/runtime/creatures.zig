const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const runtime_anim = @import("anim.zig");
const bonus_runtime = @import("bonuses.zig");
const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const effects_mod = @import("effects.zig");
const owner_ref = @import("owner_ref.zig");
const perks = @import("perks.zig");
const rng_callers = @import("../rng_caller_static.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");
const terrain_fx_mod = @import("terrain_fx.zig");
const math = @import("math.zig");
const timing = @import("timing.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;

pub const max_creatures: usize = 0x180;

const creature_speed_scale: f32 = 30.0;
const creature_turn_rate_scale: f32 = native_math.native_turn_rate_scale;
const contact_damage_cooldown: f32 = 1.0;
const plague_collision_period: f32 = 0.5;
const owner_local_player: owner_ref.OwnerRef = owner_ref.OwnerRef.fromLocalPlayer(0);
const native_half_pi: f32 = native_math.native_half_pi;
const native_pi: f32 = native_math.native_pi;
const native_tau: f32 = native_math.native_tau;

pub const CreatureRuntimeError = error{
    InvalidSpawnTemplate,
};

pub fn packBonusOnDeathArgs(bonus_id: game_ids.BonusId, amount_override: i32) i32 {
    const low: u32 = @intCast(@intFromEnum(bonus_id) & 0xFFFF);
    const high: u32 = @as(u16, @bitCast(@as(i16, @intCast(amount_override))));
    return @bitCast((high << 16) | low);
}

fn unpackBonusOnDeathArgs(link_index: i32) ?struct { bonus_id: game_ids.BonusId, amount_override: i32 } {
    const raw: u32 = @bitCast(link_index);
    const raw_bonus: i32 = @intCast(raw & 0xFFFF);
    const bonus_id = std.enums.fromInt(game_ids.BonusId, raw_bonus) orelse return null;
    const raw_amount_u16: u16 = @intCast((raw >> 16) & 0xFFFF);
    const amount_override: i32 = @as(i16, @bitCast(raw_amount_u16));
    return .{
        .bonus_id = bonus_id,
        .amount_override = amount_override,
    };
}

pub const CreatureState = struct {
    active: bool = false,
    type_id: i32 = 0,
    pos: state_mod.Vec2 = .{},
    target: state_mod.Vec2 = .{},
    target_offset: state_mod.Vec2 = .{},
    heading: f32 = 0.0,
    target_heading: f32 = 0.0,
    phase_seed: f32 = 0.0,
    anim_phase: f32 = 0.0,
    vel: state_mod.Vec2 = .{},
    move_scale: f32 = 1.0,
    force_target: i32 = 0,
    ai_mode: spawn_mod.CreatureAiMode = .orbit_player,
    // Native keeps this stale across slot reuse for some spawn paths.
    link_index: i32 = -1,
    orbit_angle: f32 = 0.0,
    orbit_radius: f32 = 0.0,
    ranged_projectile_type: i32 = 0,
    hp: f32 = 0.0,
    max_hp: f32 = 0.0,
    move_speed: f32 = 0.0,
    reward_value: f32 = 0.0,
    size: f32 = 0.0,
    contact_damage: f32 = 0.0,
    plague_infected: bool = false,
    collision_timer: f32 = plague_collision_period,
    lifecycle_stage: creature_lifecycle.Stage = creature_lifecycle.alive,
    attack_cooldown: f32 = 0.0,
    last_hit_owner: owner_ref.OwnerRef = owner_local_player,
    flags: u32 = 0,
};

pub const ShotResolutionResult = struct {
    hits: i32 = 0,
    deaths: i32 = 0,
    xp_awarded: i32 = 0,
};

const CreatureAiUpdate = struct {
    move_scale: f32,
    self_damage: ?f32 = null,
};

pub const CreaturePool = struct {
    entries: [max_creatures]CreatureState = [_]CreatureState{CreatureState{}} ** max_creatures,
    kill_count: i32 = 0,
    capture_spawn_events_authoritative: bool = false,
    hardcore: bool = false,
    demo_mode_active: bool = false,
    quest_fail_retry_count: i32 = 0,
    effects: ?*effects_mod.EffectPool = null,
    spawn_slots: [max_creatures]spawn_mod.SpawnSlotInit = [_]spawn_mod.SpawnSlotInit{
        .{
            .owner_creature = 0,
            .timer = 0.0,
            .count = 0,
            .limit = 0,
            .interval = 0.0,
            .child_template_id = 0,
        },
    } ** max_creatures,
    spawn_slot_count: usize = 0,

    pub fn reset(self: *CreaturePool) void {
        self.entries = [_]CreatureState{CreatureState{}} ** max_creatures;
        self.kill_count = 0;
        self.capture_spawn_events_authoritative = false;
        self.hardcore = false;
        self.demo_mode_active = false;
        self.quest_fail_retry_count = 0;
        self.effects = null;
        self.spawn_slot_count = 0;
    }

    pub fn activeCount(self: *const CreaturePool) usize {
        var count: usize = 0;
        for (self.entries) |creature| {
            if (creature.active) count += 1;
        }
        return count;
    }

    pub fn spawnInits(
        self: *CreaturePool,
        inits: []const spawn_mod.CreatureInit,
    ) void {
        for (inits) |init| {
            _ = self.spawnInit(init);
        }
    }

    pub fn spawnInit(self: *CreaturePool, init: spawn_mod.CreatureInit) usize {
        var slot: usize = self.entries.len - 1;
        for (self.entries, 0..) |creature, idx| {
            if (!creature.active) {
                slot = idx;
                break;
            }
        }
        const stale_link_index = self.entries[slot].link_index;
        const stale_target_heading = self.entries[slot].target_heading;
        const stale_heading = self.entries[slot].heading;

        self.entries[slot] = .{
            .active = true,
            .type_id = @intFromEnum(init.type_id),
            .pos = .{
                .x = narrowF32(init.pos.x),
                .y = narrowF32(init.pos.y),
            },
            .target = .{
                .x = narrowF32(init.pos.x),
                .y = narrowF32(init.pos.y),
            },
            .heading = if (init.set_heading) narrowF32(init.heading) else stale_heading,
            .target_heading = stale_target_heading,
            .phase_seed = narrowF32(init.phase_seed),
            .anim_phase = 0.0,
            .vel = .{},
            .move_scale = 1.0,
            .force_target = 0,
            .ai_mode = init.ai_mode,
            .link_index = stale_link_index,
            .hp = narrowF32(init.health),
            .max_hp = narrowF32(init.max_health),
            .move_speed = narrowF32(init.move_speed),
            .reward_value = narrowF32(init.reward_value),
            .size = narrowF32(init.size),
            .contact_damage = narrowF32(init.contact_damage),
            .plague_infected = false,
            .collision_timer = 0.0,
            .lifecycle_stage = creature_lifecycle.alive,
            .attack_cooldown = 0.0,
            .last_hit_owner = owner_local_player,
            .flags = init.flags,
        };
        return slot;
    }

    pub fn spawnTemplateCall(
        self: *CreaturePool,
        call: spawn_mod.SpawnTemplateCall,
        rng: *spawn_mod.Crand,
    ) CreatureRuntimeError!void {
        try self.spawnTemplateCallWithRuntimeContext(
            call,
            rng,
            null,
            0.0,
        );
    }

    pub fn spawnTemplateCallWithRuntimeContext(
        self: *CreaturePool,
        call: spawn_mod.SpawnTemplateCall,
        rng: *spawn_mod.Crand,
        state: ?*const state_mod.GameplayState,
        terrain_size: f32,
    ) CreatureRuntimeError!void {
        var was_active: [max_creatures]bool = undefined;
        for (self.entries, 0..) |creature, idx| {
            was_active[idx] = creature.active;
        }
        const spawn_slot_count_before = self.spawn_slot_count;

        switch (call.template_id) {
            @intFromEnum(spawn_mod.SpawnId.formation_ring_alien_8_12) => {
                // Parent.
                const parent_idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 200.0,
                        .move_speed = 2.2,
                        .reward_value = 600.0,
                        .size = 55.0,
                        .contact_damage = 14.0,
                    },
                );
                // Native template planning consumes a transient base-heading draw
                // after base allocation but before child allocations.
                const transient_heading = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314)) * 0.01;
                self.entries[parent_idx].heading = transient_heading;

                const angle_step = std.math.pi / 4.0;
                var primary_child_idx: usize = parent_idx;
                for (0..8) |idx| {
                    const angle = @as(f32, @floatFromInt(idx)) * angle_step;
                    const offset = state_mod.Vec2.fromAngle(narrowF32(angle)).mul(100.0);
                    const child_idx = self.spawnFromStatsWithFlags(
                        rng,
                        .{
                            .x = narrowF32(call.pos.x),
                            .y = narrowF32(call.pos.y),
                        },
                        call.heading,
                        .{
                            .type_id = .alien,
                            .health = 40.0,
                            .move_speed = 2.4,
                            .reward_value = 60.0,
                            .size = 50.0,
                            .contact_damage = 4.0,
                        },
                        0,
                        false,
                    );
                    self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.follow_link;
                    self.entries[child_idx].link_index = @intCast(parent_idx);
                    self.entries[child_idx].target_offset = .{
                        .x = narrowF32(offset.x),
                        .y = narrowF32(offset.y),
                    };
                    primary_child_idx = child_idx;
                }
                self.entries[primary_child_idx].heading = narrowF32(call.heading);
            },
            0x03 => {
                self.spawnBasicRandomTemplate(
                    rng,
                    call,
                    0x03,
                    spawn_mod.CreatureTypeId.spider_sp1,
                );
            },
            0x04 => {
                self.spawnBasicRandomTemplate(
                    rng,
                    call,
                    0x04,
                    spawn_mod.CreatureTypeId.lizard,
                );
            },
            0x05 => {
                self.spawnBasicRandomTemplate(
                    rng,
                    call,
                    0x05,
                    spawn_mod.CreatureTypeId.spider_sp2,
                );
            },
            0x06 => {
                self.spawnBasicRandomTemplate(
                    rng,
                    call,
                    0x06,
                    spawn_mod.CreatureTypeId.alien,
                );
            },
            0x00 => {
                _ = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .zombie,
                        .health = 8500.0,
                        .move_speed = 1.3,
                        .reward_value = 6600.0,
                        .size = 64.0,
                        .contact_damage = 50.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong | spawn_mod.CreatureFlags.anim_long_strip,
                    1.0,
                    812,
                    0.7,
                    0x41,
                );
            },
            0x07 => {
                _ = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .alien,
                        .health = 1000.0,
                        .move_speed = 2.0,
                        .reward_value = 3000.0,
                        .size = 50.0,
                        .contact_damage = 0.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong,
                    1.0,
                    100,
                    2.2,
                    0x1D,
                );
            },
            0x08 => {
                _ = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .alien,
                        .health = 1000.0,
                        .move_speed = 2.0,
                        .reward_value = 3000.0,
                        .size = 50.0,
                        .contact_damage = 0.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong,
                    1.0,
                    100,
                    2.8,
                    0x1D,
                );
            },
            0x09 => {
                _ = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .alien,
                        .health = 450.0,
                        .move_speed = 2.0,
                        .reward_value = 1000.0,
                        .size = 40.0,
                        .contact_damage = 0.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong,
                    1.0,
                    16,
                    2.0,
                    0x1D,
                );
            },
            0x0A => {
                _ = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .alien,
                        .health = 1000.0,
                        .move_speed = 1.5,
                        .reward_value = 3000.0,
                        .size = 55.0,
                        .contact_damage = 0.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong,
                    2.0,
                    100,
                    5.0,
                    0x32,
                );
            },
            0x0B => {
                _ = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .alien,
                        .health = 3500.0,
                        .move_speed = 1.5,
                        .reward_value = 5000.0,
                        .size = 65.0,
                        .contact_damage = 0.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong,
                    2.0,
                    100,
                    6.0,
                    0x3C,
                );
            },
            0x0C => {
                _ = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .alien,
                        .health = 50.0,
                        .move_speed = 2.8,
                        .reward_value = 1000.0,
                        .size = 32.0,
                        .contact_damage = 0.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong,
                    1.5,
                    100,
                    2.0,
                    0x31,
                );
            },
            0x0D => {
                _ = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .alien,
                        .health = 50.0,
                        .move_speed = 1.3,
                        .reward_value = 1000.0,
                        .size = 32.0,
                        .contact_damage = 0.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong,
                    2.0,
                    100,
                    6.0,
                    0x31,
                );
            },
            0x0E => {
                const parent_idx = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .alien,
                        .health = 50.0,
                        .move_speed = 2.8,
                        .reward_value = 5000.0,
                        .size = 32.0,
                        .contact_damage = 0.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong,
                    1.5,
                    64,
                    1.05,
                    0x1C,
                );

                const angle_step = std.math.pi / 12.0;
                var primary_child_idx: usize = parent_idx;
                for (0..24) |idx| {
                    const angle = @as(f32, @floatFromInt(idx)) * angle_step;
                    const offset = state_mod.Vec2.fromAngle(narrowF32(angle)).mul(100.0);
                    const child_idx = self.spawnFromStatsWithFlags(
                        rng,
                        .{
                            .x = narrowF32(call.pos.x),
                            .y = narrowF32(call.pos.y),
                        },
                        call.heading,
                        .{
                            .type_id = .alien,
                            .health = 40.0,
                            .move_speed = 4.0,
                            .reward_value = 350.0,
                            .size = 35.0,
                            .contact_damage = 30.0,
                        },
                        0,
                        false,
                    );
                    self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.follow_link;
                    self.entries[child_idx].link_index = @intCast(parent_idx);
                    self.entries[child_idx].target_offset = .{
                        .x = narrowF32(offset.x),
                        .y = narrowF32(offset.y),
                    };
                    primary_child_idx = child_idx;
                }
                self.entries[primary_child_idx].heading = narrowF32(call.heading);
            },
            0x10 => {
                _ = self.spawnParentWithSpawnSlot(
                    rng,
                    call,
                    .{
                        .type_id = .alien,
                        .health = 50.0,
                        .move_speed = 2.8,
                        .reward_value = 800.0,
                        .size = 32.0,
                        .contact_damage = 0.0,
                    },
                    spawn_mod.CreatureFlags.anim_ping_pong,
                    1.5,
                    100,
                    2.3,
                    0x32,
                );
            },
            0x0F => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 20.0,
                        .move_speed = 2.9,
                        .reward_value = 60.0,
                        .size = 50.0,
                        .contact_damage = 35.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x11 => {
                const parent_idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .lizard,
                        .health = 1500.0,
                        .move_speed = 2.1,
                        .reward_value = 1000.0,
                        .size = 69.0,
                        .contact_damage = 150.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                self.entries[parent_idx].ai_mode = spawn_mod.CreatureAiMode.orbit_player_tight;

                var chain_prev = parent_idx;
                for (0..4) |idx| {
                    const angle = @as(f32, @floatFromInt(2 + idx * 2)) * (std.math.pi / 8.0);
                    const offset = state_mod.Vec2.fromAngle(narrowF32(angle)).mul(256.0);
                    const child_idx = self.spawnFromStats(
                        rng,
                        .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                        call.heading,
                        .{
                            .type_id = .lizard,
                            .health = 60.0,
                            .move_speed = 2.4,
                            .reward_value = 60.0,
                            .size = 50.0,
                            .contact_damage = 14.0,
                        },
                    );
                    self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.follow_link;
                    self.entries[child_idx].link_index = @intCast(chain_prev);
                    self.entries[child_idx].target_offset = .{
                        .x = narrowF32(-256.0 + @as(f32, @floatFromInt(idx)) * 64.0),
                        .y = -256.0,
                    };
                    self.entries[child_idx].pos = .{
                        .x = narrowF32(call.pos.x + offset.x),
                        .y = narrowF32(call.pos.y + offset.y),
                    };
                    self.entries[child_idx].target = self.entries[child_idx].pos;
                    chain_prev = child_idx;
                }
                self.entries[parent_idx].link_index = @intCast(chain_prev);
                applyUnhandledCreatureTypeFallback(&self.entries[chain_prev]);
            },
            0x1A => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                _ = rng.randTagged(rng_callers.creature_spawn_template_ai1_blue_tint_1a) % 40;

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.alien,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player_tight,
                    .flags = 0,
                    .size = 50.0,
                    .move_speed = 2.4,
                    .health = 50.0,
                    .max_health = 50.0,
                    .reward_value = 125.0,
                    .contact_damage = 5.0,
                });
            },
            0x1B => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                _ = rng.randTagged(rng_callers.creature_spawn_template_ai1_blue_tint_1b) % 40;

                const idx = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.spider_sp1,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player_tight,
                    .flags = 0,
                    .size = 50.0,
                    .move_speed = 2.4,
                    .health = 40.0,
                    .max_health = 40.0,
                    .reward_value = 125.0,
                    .contact_damage = 5.0,
                });
                applySpiderSp1Ai7Tail(&self.entries[idx]);
            },
            0x1C => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                _ = rng.randTagged(rng_callers.creature_spawn_template_ai1_blue_tint_1c) % 40;

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.lizard,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player_tight,
                    .flags = 0,
                    .size = 50.0,
                    .move_speed = 2.4,
                    .health = 50.0,
                    .max_health = 50.0,
                    .reward_value = 125.0,
                    .contact_damage = 5.0,
                });
            },
            0x13 => {
                const parent_idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 200.0,
                        .move_speed = 2.0,
                        .reward_value = 600.0,
                        .size = 40.0,
                        .contact_damage = 20.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                self.entries[parent_idx].ai_mode = spawn_mod.CreatureAiMode.orbit_link;
                self.entries[parent_idx].pos.x = narrowF32(call.pos.x + 256.0);
                self.entries[parent_idx].target.x = self.entries[parent_idx].pos.x;

                var chain_prev = parent_idx;
                for (0..10) |idx| {
                    const angle = @as(f32, @floatFromInt(2 + idx * 2)) * (20.0 * std.math.pi / 180.0);
                    const offset = state_mod.Vec2.fromAngle(narrowF32(angle)).mul(256.0);
                    const child_idx = self.spawnFromStats(
                        rng,
                        .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                        call.heading,
                        .{
                            .type_id = .alien,
                            .health = 60.0,
                            .move_speed = 2.0,
                            .reward_value = 60.0,
                            .size = 50.0,
                            .contact_damage = 4.0,
                        },
                    );
                    self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.orbit_link;
                    self.entries[child_idx].link_index = @intCast(chain_prev);
                    self.entries[child_idx].orbit_angle = std.math.pi;
                    self.entries[child_idx].orbit_radius = 10.0;
                    self.entries[child_idx].pos = .{
                        .x = narrowF32(call.pos.x + offset.x),
                        .y = narrowF32(call.pos.y + offset.y),
                    };
                    self.entries[child_idx].target = self.entries[child_idx].pos;
                    chain_prev = child_idx;
                }
                self.entries[parent_idx].link_index = @intCast(chain_prev);
                applyUnhandledCreatureTypeFallback(&self.entries[chain_prev]);
            },
            0x1D => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                const size = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1d_size, 20, 1.0, 35.0);
                const health = narrowF32(size * (8.0 / 7.0) + 10.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1d_move_speed, 15, 0.1, 1.1);
                const reward_value = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1d_reward, 100, 1.0, 50.0);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1d_tint_r, 50, 0.001, 0.6);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1d_tint_g, 50, 0.01, 0.5);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1d_tint_b, 50, 0.001, 0.6);
                const contact_damage = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1d_contact_damage, 10, 1.0, 4.0);

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.alien,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
            },
            0x1E => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                const size = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1e_size, 30, 1.0, 35.0);
                const health = narrowF32(size * (16.0 / 7.0) + 10.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1e_move_speed, 17, 0.1, 1.5);
                const reward_value = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1e_reward, 200, 1.0, 50.0);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1e_tint_r, 50, 0.001, 0.6);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1e_tint_g, 50, 0.001, 0.6);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1e_tint_b, 50, 0.01, 0.5);
                const contact_damage = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1e_contact_damage, 30, 1.0, 4.0);

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.alien,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
            },
            0x1F => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                const size = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1f_size, 30, 1.0, 45.0);
                const health = narrowF32(size * (26.0 / 7.0) + 30.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1f_move_speed, 21, 0.1, 1.6);
                const reward_value = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1f_reward, 200, 1.0, 80.0);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1f_tint_r, 50, 0.01, 0.5);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1f_tint_g, 50, 0.001, 0.6);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1f_tint_b, 50, 0.001, 0.6);
                const contact_damage = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_1f_contact_damage, 35, 1.0, 8.0);

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.alien,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
            },
            0x20 => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                const size = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_green_20_size, 30, 1.0, 40.0);
                const health = narrowF32(size * (8.0 / 7.0) + 20.0);
                const reward_value = narrowF32(size + size + 50.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_green_20_move_speed, 18, 0.1, 1.1);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_green_20_tint_g, 40, 0.01, 0.6);
                const contact_damage = randfTagged(rng, rng_callers.creature_spawn_template_alien_random_green_20_contact_damage, 10, 1.0, 4.0);

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.alien,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
            },
            0x21 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 53.0,
                        .move_speed = 1.7,
                        .reward_value = 120.0,
                        .size = 55.0,
                        .contact_damage = 8.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x22 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 25.0,
                        .move_speed = 1.7,
                        .reward_value = 150.0,
                        .size = 50.0,
                        .contact_damage = 8.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x23 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 5.0,
                        .move_speed = 1.7,
                        .reward_value = 180.0,
                        .size = 45.0,
                        .contact_damage = 8.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x24 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 20.0,
                        .move_speed = 2.0,
                        .reward_value = 110.0,
                        .size = 50.0,
                        .contact_damage = 4.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x25 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 25.0,
                        .move_speed = 2.5,
                        .reward_value = 125.0,
                        .size = 30.0,
                        .contact_damage = 3.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x26 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 50.0,
                        .move_speed = 2.2,
                        .reward_value = 125.0,
                        .size = 45.0,
                        .contact_damage = 10.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x27 => {
                const idx = self.spawnFromStatsWithFlags(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 50.0,
                        .move_speed = 2.1,
                        .reward_value = 125.0,
                        .size = 45.0,
                        .contact_damage = 10.0,
                    },
                    spawn_mod.CreatureFlags.bonus_on_death,
                    true,
                );
                self.entries[idx].link_index = packBonusOnDeathArgs(.weapon, 5);
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x28 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 50.0,
                        .move_speed = 1.7,
                        .reward_value = 150.0,
                        .size = 55.0,
                        .contact_damage = 8.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x29 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 800.0,
                        .move_speed = 2.5,
                        .reward_value = 450.0,
                        .size = 70.0,
                        .contact_damage = 20.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x2A => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 50.0,
                        .move_speed = 3.1,
                        .reward_value = 300.0,
                        .size = 60.0,
                        .contact_damage = 8.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x14 => {
                const parent_idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 1500.0,
                        .move_speed = 2.0,
                        .reward_value = 600.0,
                        .size = 50.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                self.entries[parent_idx].ai_mode = spawn_mod.CreatureAiMode.chase_player;

                var last_idx = parent_idx;
                for (0..9) |x_idx| {
                    const x_offset = -64.0 * @as(f32, @floatFromInt(x_idx));
                    for (0..9) |y_idx| {
                        const y_offset = 128.0 + 16.0 * @as(f32, @floatFromInt(y_idx));
                        const child_idx = self.spawnFromStats(
                            rng,
                            .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                            call.heading,
                            .{
                                .type_id = .alien,
                                .health = 40.0,
                                .move_speed = 2.0,
                                .reward_value = 60.0,
                                .size = 50.0,
                                .contact_damage = 4.0,
                            },
                        );
                        self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.follow_link_tethered;
                        self.entries[child_idx].link_index = @intCast(parent_idx);
                        self.entries[child_idx].target_offset = .{
                            .x = x_offset,
                            .y = y_offset,
                        };
                        self.entries[child_idx].pos = .{
                            .x = narrowF32(call.pos.x) + x_offset,
                            .y = narrowF32(call.pos.y) + y_offset,
                        };
                        self.entries[child_idx].target = self.entries[child_idx].pos;
                        last_idx = child_idx;
                    }
                }
                applyUnhandledCreatureTypeFallback(&self.entries[last_idx]);
            },
            0x15 => {
                const parent_idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 1500.0,
                        .move_speed = 2.0,
                        .reward_value = 600.0,
                        .size = 60.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                self.entries[parent_idx].ai_mode = spawn_mod.CreatureAiMode.chase_player;

                var last_idx = parent_idx;
                for (0..9) |x_idx| {
                    const x_offset = -64.0 * @as(f32, @floatFromInt(x_idx));
                    for (0..9) |y_idx| {
                        const y_offset = 128.0 + 16.0 * @as(f32, @floatFromInt(y_idx));
                        const child_idx = self.spawnFromStats(
                            rng,
                            .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                            call.heading,
                            .{
                                .type_id = .alien,
                                .health = 40.0,
                                .move_speed = 2.0,
                                .reward_value = 60.0,
                                .size = 50.0,
                                .contact_damage = 4.0,
                            },
                        );
                        self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.link_guard;
                        self.entries[child_idx].link_index = @intCast(parent_idx);
                        self.entries[child_idx].target_offset = .{
                            .x = x_offset,
                            .y = y_offset,
                        };
                        self.entries[child_idx].pos = .{
                            .x = narrowF32(call.pos.x) + x_offset,
                            .y = narrowF32(call.pos.y) + y_offset,
                        };
                        self.entries[child_idx].target = self.entries[child_idx].pos;
                        last_idx = child_idx;
                    }
                }
                applyUnhandledCreatureTypeFallback(&self.entries[last_idx]);
            },
            0x16 => {
                const parent_idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .lizard,
                        .health = 1500.0,
                        .move_speed = 2.0,
                        .reward_value = 600.0,
                        .size = 64.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                self.entries[parent_idx].ai_mode = spawn_mod.CreatureAiMode.chase_player;

                var last_idx = parent_idx;
                for (0..9) |x_idx| {
                    const x_offset = -64.0 * @as(f32, @floatFromInt(x_idx));
                    for (0..9) |y_idx| {
                        const y_offset = 128.0 + 16.0 * @as(f32, @floatFromInt(y_idx));
                        const child_idx = self.spawnFromStats(
                            rng,
                            .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                            call.heading,
                            .{
                                .type_id = .lizard,
                                .health = 40.0,
                                .move_speed = 2.0,
                                .reward_value = 60.0,
                                .size = 60.0,
                                .contact_damage = 4.0,
                            },
                        );
                        self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.link_guard;
                        self.entries[child_idx].link_index = @intCast(parent_idx);
                        self.entries[child_idx].target_offset = .{
                            .x = x_offset,
                            .y = y_offset,
                        };
                        self.entries[child_idx].pos = .{
                            .x = narrowF32(call.pos.x) + x_offset,
                            .y = narrowF32(call.pos.y) + y_offset,
                        };
                        self.entries[child_idx].target = self.entries[child_idx].pos;
                        last_idx = child_idx;
                    }
                }
                applyUnhandledCreatureTypeFallback(&self.entries[last_idx]);
            },
            0x17 => {
                const parent_idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .spider_sp1,
                        .health = 1500.0,
                        .move_speed = 2.0,
                        .reward_value = 600.0,
                        .size = 60.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                self.entries[parent_idx].ai_mode = spawn_mod.CreatureAiMode.chase_player;

                var last_idx = parent_idx;
                for (0..9) |x_idx| {
                    const x_offset = -64.0 * @as(f32, @floatFromInt(x_idx));
                    for (0..9) |y_idx| {
                        const y_offset = 128.0 + 16.0 * @as(f32, @floatFromInt(y_idx));
                        const child_idx = self.spawnFromStats(
                            rng,
                            .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                            call.heading,
                            .{
                                .type_id = .spider_sp1,
                                .health = 40.0,
                                .move_speed = 2.0,
                                .reward_value = 60.0,
                                .size = 50.0,
                                .contact_damage = 4.0,
                            },
                        );
                        self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.link_guard;
                        self.entries[child_idx].link_index = @intCast(parent_idx);
                        self.entries[child_idx].target_offset = .{
                            .x = x_offset,
                            .y = y_offset,
                        };
                        self.entries[child_idx].pos = .{
                            .x = narrowF32(call.pos.x) + x_offset,
                            .y = narrowF32(call.pos.y) + y_offset,
                        };
                        self.entries[child_idx].target = self.entries[child_idx].pos;
                        last_idx = child_idx;
                    }
                }
                applyUnhandledCreatureTypeFallback(&self.entries[last_idx]);
            },
            0x18 => {
                const parent_idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 500.0,
                        .move_speed = 2.0,
                        .reward_value = 600.0,
                        .size = 40.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                self.entries[parent_idx].ai_mode = spawn_mod.CreatureAiMode.chase_player;

                for (0..9) |x_idx| {
                    const x_offset = -64.0 * @as(f32, @floatFromInt(x_idx));
                    for (0..9) |y_idx| {
                        const y_offset = 128.0 + 16.0 * @as(f32, @floatFromInt(y_idx));
                        const child_idx = self.spawnFromStats(
                            rng,
                            .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                            call.heading,
                            .{
                                .type_id = .alien,
                                .health = 260.0,
                                .move_speed = 3.8,
                                .reward_value = 60.0,
                                .size = 50.0,
                                .contact_damage = 35.0,
                            },
                        );
                        self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.follow_link;
                        self.entries[child_idx].link_index = @intCast(parent_idx);
                        self.entries[child_idx].target_offset = .{
                            .x = x_offset,
                            .y = y_offset,
                        };
                        self.entries[child_idx].pos = .{
                            .x = narrowF32(call.pos.x) + x_offset,
                            .y = narrowF32(call.pos.y) + y_offset,
                        };
                        self.entries[child_idx].target = self.entries[child_idx].pos;
                    }
                }
            },
            0x19 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 50.0,
                        .move_speed = 3.8,
                        .reward_value = 300.0,
                        .size = 55.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;

                const angle_step = (2.0 * std.math.pi) / 5.0;
                for (0..5) |idx| {
                    const angle = @as(f32, @floatFromInt(idx)) * angle_step;
                    const offset = state_mod.Vec2.fromAngle(narrowF32(angle)).mul(110.0);
                    const child_idx = self.spawnFromStats(
                        rng,
                        .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                        call.heading,
                        .{
                            .type_id = .alien,
                            .health = 220.0,
                            .move_speed = 3.8,
                            .reward_value = 60.0,
                            .size = 50.0,
                            .contact_damage = 35.0,
                        },
                    );
                    self.entries[child_idx].ai_mode = spawn_mod.CreatureAiMode.follow_link_tethered;
                    self.entries[child_idx].link_index = 0;
                    self.entries[child_idx].target_offset = .{
                        .x = narrowF32(offset.x),
                        .y = narrowF32(offset.y),
                    };
                    self.entries[child_idx].pos = .{
                        .x = narrowF32(call.pos.x + offset.x),
                        .y = narrowF32(call.pos.y + offset.y),
                    };
                    self.entries[child_idx].target = self.entries[child_idx].pos;
                }
            },
            @intFromEnum(spawn_mod.SpawnId.alien_const_red_fast_2b) => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 30.0,
                        .move_speed = 3.6,
                        .reward_value = 450.0,
                        .size = 35.0,
                        .contact_damage = 20.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            @intFromEnum(spawn_mod.SpawnId.alien_const_red_boss_2c) => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 3800.0,
                        .move_speed = 2.0,
                        .reward_value = 1500.0,
                        .size = 80.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x2D => {
                const idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 45.0,
                        .move_speed = 3.1,
                        .reward_value = 200.0,
                        .size = 38.0,
                        .contact_damage = 3.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                self.entries[idx].ai_mode = spawn_mod.CreatureAiMode.chase_player;
            },
            @intFromEnum(spawn_mod.SpawnId.spider_sp2_random_35) => {
                // Match Python/native plan builder ordering:
                // allocCreature phase seed, transient heading draw, then template randoms.
                const phase_seed = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f));
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;

                const size = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp2_random_35_size, 10, 1.0, 30.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp2_random_35_move_speed, 18, 0.1, 1.1);
                const tint_g = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp2_random_35_tint_g, 20, 0.01, 0.8);
                const contact_damage = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp2_random_35_contact_damage, 10, 1.0, 4.0);
                const health = narrowF32(size * (8.0 / 7.0) + 20.0);
                const reward_value = narrowF32(size + size + 50.0);

                _ = tint_g;
                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.spider_sp2,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
            },
            0x36 => {
                const idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .alien,
                        .health = 10.0,
                        .move_speed = 1.8,
                        .reward_value = 150.0,
                        .size = 50.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                _ = rng.randTagged(rng_callers.creature_spawn_template_ai7_orbiter_tint_g) % 5;
                self.entries[idx].ai_mode = spawn_mod.CreatureAiMode.hold_timer;
                self.entries[idx].orbit_radius = 1.5;
            },
            0x37 => {
                const phase_seed = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f));
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                const size = @as(f32, @floatFromInt((rng.randTagged(rng_callers.creature_spawn_template_spider_sp2_ranged_variant_37_size) & 3) + 41));

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.spider_sp2,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = spawn_mod.CreatureFlags.ranged_attack_variant,
                    .size = size,
                    .move_speed = 3.2,
                    .health = 50.0,
                    .max_health = 50.0,
                    .reward_value = 433.0,
                    .contact_damage = 10.0,
                });
            },
            @intFromEnum(spawn_mod.SpawnId.spider_sp1_ai7_timer_38) => {
                const phase_seed = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f));
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                const size = @as(f32, @floatFromInt((rng.randTagged(rng_callers.creature_spawn_template_spider_sp1_ai7_timer_38_size) & 3) + 41));

                const idx = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.spider_sp1,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = spawn_mod.CreatureFlags.ai7_link_timer,
                    .size = size,
                    .move_speed = 4.8,
                    .health = 50.0,
                    .max_health = 50.0,
                    .reward_value = 433.0,
                    .contact_damage = 10.0,
                });
                self.entries[idx].link_index = 0;
            },
            0x39 => {
                const phase_seed = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f));
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                const size = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_spawn_template_spider_sp1_ai7_timer_weak_39_size) % 4 + 26));

                const idx = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.spider_sp1,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = spawn_mod.CreatureFlags.ai7_link_timer,
                    .size = size,
                    .move_speed = 4.8,
                    .health = 4.0,
                    .max_health = 4.0,
                    .reward_value = 50.0,
                    .contact_damage = 10.0,
                });
                self.entries[idx].link_index = 0;
            },
            @intFromEnum(spawn_mod.SpawnId.spider_sp2_splitter_01) => {
                _ = self.spawnFromStatsWithFlags(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .spider_sp2,
                        .health = 400.0,
                        .move_speed = 2.0,
                        .reward_value = 1000.0,
                        .size = 80.0,
                        .contact_damage = 17.0,
                    },
                    spawn_mod.CreatureFlags.split_on_death,
                    true,
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            @intFromEnum(spawn_mod.SpawnId.spider_sp1_const_shock_boss_3a) => {
                const idx = self.spawnFromStatsWithFlags(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .spider_sp1,
                        .health = 4500.0,
                        .move_speed = 2.0,
                        .reward_value = 4500.0,
                        .size = 64.0,
                        .contact_damage = 50.0,
                    },
                    spawn_mod.CreatureFlags.ranged_attack_shock,
                    true,
                );
                self.entries[idx].orbit_angle = 0.9;
                self.entries[idx].ranged_projectile_type = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle);
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x3B => {
                const idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .spider_sp1,
                        .health = 1200.0,
                        .move_speed = 2.0,
                        .reward_value = 4000.0,
                        .size = 70.0,
                        .contact_damage = 20.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                applySpiderSp1Ai7Tail(&self.entries[idx]);
            },
            @intFromEnum(spawn_mod.SpawnId.spider_sp1_const_ranged_variant_3c) => {
                const idx = self.spawnFromStatsWithFlags(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .spider_sp1,
                        .health = 200.0,
                        .move_speed = 2.4,
                        .reward_value = 200.0,
                        .size = 40.0,
                        .contact_damage = 20.0,
                    },
                    spawn_mod.CreatureFlags.ranged_attack_variant | spawn_mod.CreatureFlags.ai7_link_timer,
                    true,
                );
                self.entries[idx].ai_mode = spawn_mod.CreatureAiMode.chase_player;
                self.entries[idx].link_index = 0;
                self.entries[idx].orbit_angle = 0.4;
                self.entries[idx].ranged_projectile_type = @intFromEnum(game_ids.ProjectileTypeId.spider_plasma);
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x2E => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                const size = randfTagged(rng, rng_callers.creature_spawn_template_lizard_random_2e_size, 30, 1.0, 40.0);
                const health = narrowF32(size * (8.0 / 7.0) + 20.0);
                const reward_value = narrowF32(size + size + 50.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_lizard_random_2e_move_speed, 18, 0.1, 1.1);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_lizard_random_2e_tint_r, 40, 0.01, 0.6);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_lizard_random_2e_tint_g, 40, 0.01, 0.6);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_lizard_random_2e_tint_b, 40, 0.01, 0.6);
                const contact_damage = randfTagged(rng, rng_callers.creature_spawn_template_lizard_random_2e_contact_damage, 10, 1.0, 4.0);

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.lizard,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
            },
            0x2F => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .lizard,
                        .health = 20.0,
                        .move_speed = 2.5,
                        .reward_value = 150.0,
                        .size = 45.0,
                        .contact_damage = 4.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x30 => {
                _ = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .lizard,
                        .health = 1000.0,
                        .move_speed = 2.0,
                        .reward_value = 400.0,
                        .size = 65.0,
                        .contact_damage = 10.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x31 => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                const size = randfTagged(rng, rng_callers.creature_spawn_template_lizard_random_31_size, 30, 1.0, 40.0);
                const health = narrowF32(size * (8.0 / 7.0) + 10.0);
                const reward_value = narrowF32(size + size + 50.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_lizard_random_31_move_speed, 18, 0.1, 1.1);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_lizard_random_31_tint, 30, 0.01, 0.6);
                const contact_damage = narrowF32(size * 0.14 + 4.0);

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.lizard,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
            },
            0x32 => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                const size = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_32_size, 25, 1.0, 40.0);
                const health = narrowF32(size + 10.0);
                const reward_value = narrowF32(size + size + 50.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_32_move_speed, 17, 0.1, 1.1);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_32_tint, 40, 0.01, 0.6);
                const contact_damage = narrowF32(size * 0.14 + 4.0);

                const idx = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.spider_sp1,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
                applySpiderSp1Ai7Tail(&self.entries[idx]);
            },
            0x33 => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                const size = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_red_33_size, 15, 1.0, 45.0);
                const health = narrowF32(size * (8.0 / 7.0) + 20.0);
                const reward_value = narrowF32(size + size + 50.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_red_33_move_speed, 18, 0.1, 1.1);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_red_33_tint_r, 40, 0.01, 0.6);
                const contact_damage = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_red_33_contact_damage, 10, 1.0, 4.0);

                const idx = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.spider_sp1,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
                applySpiderSp1Ai7Tail(&self.entries[idx]);
            },
            0x34 => {
                const phase_seed = drawPhaseSeedWithTransientHeading(rng);
                const size = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_green_34_size, 20, 1.0, 40.0);
                const health = narrowF32(size * (8.0 / 7.0) + 20.0);
                const reward_value = narrowF32(size + size + 50.0);
                const move_speed = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_green_34_move_speed, 18, 0.1, 1.1);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_green_34_tint_g, 40, 0.01, 0.6);
                const contact_damage = randfTagged(rng, rng_callers.creature_spawn_template_spider_sp1_random_green_34_contact_damage, 10, 1.0, 4.0);

                const idx = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.spider_sp1,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
                applySpiderSp1Ai7Tail(&self.entries[idx]);
            },
            0x3D => {
                const phase_seed = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f));
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                _ = rng.randTagged(rng_callers.creature_spawn_template_spider_sp1_random_3d_tint) % 20;
                const size = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_spawn_template_spider_sp1_random_3d_size) % 7 + 45));
                const contact_damage = narrowF32(size * 0.22);

                const idx = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.spider_sp1,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = 2.6,
                    .health = 70.0,
                    .max_health = 70.0,
                    .reward_value = 120.0,
                    .contact_damage = contact_damage,
                });
                applySpiderSp1Ai7Tail(&self.entries[idx]);
            },
            0x3E => {
                const idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .spider_sp1,
                        .health = 1000.0,
                        .move_speed = 2.8,
                        .reward_value = 500.0,
                        .size = 64.0,
                        .contact_damage = 40.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                applySpiderSp1Ai7Tail(&self.entries[idx]);
            },
            0x3F => {
                const idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .spider_sp1,
                        .health = 200.0,
                        .move_speed = 2.3,
                        .reward_value = 210.0,
                        .size = 35.0,
                        .contact_damage = 20.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                applySpiderSp1Ai7Tail(&self.entries[idx]);
            },
            0x40 => {
                const idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .spider_sp1,
                        .health = 70.0,
                        .move_speed = 2.2,
                        .reward_value = 160.0,
                        .size = 45.0,
                        .contact_damage = 5.0,
                    },
                );
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                applySpiderSp1Ai7Tail(&self.entries[idx]);
            },
            0x41 => {
                const phase_seed = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f));
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
                const size = randfTagged(rng, rng_callers.creature_spawn_template_zombie_random_41_size, 30, 1.0, 40.0);
                const health = narrowF32(size * (8.0 / 7.0) + 10.0);
                const reward_value = narrowF32(size + size + 50.0);
                const move_speed = narrowF32(size * 0.0025 + 0.9);
                _ = randfTagged(rng, rng_callers.creature_spawn_template_zombie_random_41_tint, 40, 0.01, 0.6);
                const contact_damage = randfTagged(rng, rng_callers.creature_spawn_template_zombie_random_41_contact_damage, 10, 1.0, 4.0);

                _ = self.spawnInit(.{
                    .origin_template_id = -1,
                    .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    .heading = narrowF32(call.heading),
                    .set_heading = true,
                    .phase_seed = phase_seed,
                    .type_id = spawn_mod.CreatureTypeId.zombie,
                    .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
                    .flags = 0,
                    .size = size,
                    .move_speed = move_speed,
                    .health = health,
                    .max_health = health,
                    .reward_value = reward_value,
                    .contact_damage = contact_damage,
                });
            },
            0x42 => {
                const idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .zombie,
                        .health = 200.0,
                        .move_speed = 1.7,
                        .reward_value = 160.0,
                        .size = 45.0,
                        .contact_damage = 15.0,
                    },
                );
                _ = idx;
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            0x43 => {
                const idx = self.spawnFromStats(
                    rng,
                    .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
                    call.heading,
                    .{
                        .type_id = .zombie,
                        .health = 2000.0,
                        .move_speed = 2.1,
                        .reward_value = 460.0,
                        .size = 70.0,
                        .contact_damage = 15.0,
                    },
                );
                _ = idx;
                _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
            },
            else => return error.InvalidSpawnTemplate,
        }

        if (findSpawnTemplatePrimaryIndex(self, &was_active)) |primary_idx| {
            const maybe_slot_idx = blk: {
                const link_index = self.entries[primary_idx].link_index;
                if (link_index < 0) break :blk null;
                const slot_idx: usize = @intCast(link_index);
                if (slot_idx < spawn_slot_count_before or slot_idx >= self.spawn_slot_count) break :blk null;
                break :blk slot_idx;
            };
            applySpawnDifficultyAdjustments(
                self,
                &self.entries[primary_idx],
                if (maybe_slot_idx) |slot_idx| &self.spawn_slots[slot_idx] else null,
            );
        }

        if (state) |game_state| {
            const call_pos_x = narrowF32(call.pos.x);
            const call_pos_y = narrowF32(call.pos.y);
            if (!game_state.demo_mode_active and
                terrain_size > 0.0 and
                call_pos_x > 0.0 and call_pos_x < terrain_size and
                call_pos_y > 0.0 and call_pos_y < terrain_size)
            {
                const effects = self.effects orelse unreachable;
                effects.spawnBurst(
                    @constCast(game_state),
                    .{ .x = call_pos_x, .y = call_pos_y },
                    8,
                    5,
                    0.4,
                    null,
                    .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
                );
            }
        }
    }

    fn findSpawnTemplatePrimaryIndex(self: *const CreaturePool, was_active: *const [max_creatures]bool) ?usize {
        for (self.entries, 0..) |creature, idx| {
            if (!was_active[idx] and creature.active) return idx;
        }
        return null;
    }

    pub fn update(
        self: *CreaturePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        dt: f32,
        world_size: f32,
        bonus_pool: *bonus_runtime.BonusPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    ) CreatureRuntimeError!void {
        if (players.len == 0) return;
        if (!(dt > 0.0)) return;
        const effect_pool = self.effects orelse unreachable;
        const dt_f32 = dt;

        if (!self.capture_spawn_events_authoritative) {
            const slot_count_snapshot = self.spawn_slot_count;
            for (self.spawn_slots[0..slot_count_snapshot]) |*slot| {
                if (slot.owner_creature < 0) continue;
                const owner_idx: usize = @intCast(slot.owner_creature);
                if (owner_idx >= self.entries.len) continue;

                const owner = self.entries[owner_idx];
                if (!owner.active) continue;

                if (spawn_mod.tickSpawnSlot(slot, dt)) |child_template_id| {
                    try self.spawnTemplateCallWithRuntimeContext(
                        .{
                            .template_id = child_template_id,
                            .pos = .{ .x = owner.pos.x, .y = owner.pos.y },
                            .heading = owner.heading,
                        },
                        &state.rng,
                        state,
                        world_size,
                    );
                }
            }
        }

        const dt_ms = @max(@as(i32, 0), timing.ftolMsI32(dt));
        const player = &players[0];
        const single_player_dead_target_pos: ?state_mod.Vec2 =
            if (players.len == 1 and players[0].health <= 0.0)
                .{
                    .x = world_size * (27.0 / 64.0),
                    .y = world_size * (27.0 / 64.0),
                }
            else
                null;

        for (&self.entries, 0..) |*creature, idx| {
            if (!creature.active) continue;
            if (state.bonuses.freeze > 0.0) continue;
            if (!(creature.hp > 0.0)) {
                applySelfDamageTickToDead(creature, dt_f32);
                tickAi7LinkTimer(creature, dt_ms, &state.rng);
                if (creature_lifecycle.isAlive(creature.lifecycle_stage)) {
                    creature.lifecycle_stage -= dt_f32;
                }
                tickDead(creature, dt_f32, &self.kill_count, state, effect_pool, terrain_fx);
                continue;
            }

            const self_tick_damage = selfDamageTickAmount(creature.flags, dt_f32);
            if (self_tick_damage > 0.0) {
                _ = self.applyDamage(
                    state,
                    players,
                    bonus_pool,
                    terrain_fx,
                    idx,
                    self_tick_damage,
                    .{},
                    creature.last_hit_owner,
                    dt_f32,
                    world_size,
                );
                if (!(creature.hp > 0.0)) {
                    if (creature.active) {
                        tickDead(creature, dt_f32, &self.kill_count, state, effect_pool, terrain_fx);
                    }
                    continue;
                }
            }

            tickAi7LinkTimer(creature, dt_ms, &state.rng);
            if (creatureFrozenByEvilEyes(state, players, idx)) {
                creature.force_target = 0;
                continue;
            }
            const ai_update = creatureAiUpdateTarget(
                creature,
                if (single_player_dead_target_pos) |dead_target| dead_target else player.pos,
                self.entries[0..],
                dt_f32,
            );
            creature.move_scale = ai_update.move_scale;
            if (ai_update.self_damage) |self_damage| {
                _ = self.applyDamage(
                    state,
                    players,
                    bonus_pool,
                    terrain_fx,
                    idx,
                    self_damage,
                    .{},
                    creature.last_hit_owner,
                    dt_f32,
                    world_size,
                );
                if (!(creature.hp > 0.0)) {
                    if (creature.active) {
                        tickDead(creature, dt_f32, &self.kill_count, state, effect_pool, terrain_fx);
                    }
                    continue;
                }
            }
            if (creature.plague_infected) {
                creature.collision_timer = narrowF32(creature.collision_timer - dt_f32);
                if (creature.collision_timer < 0.0) {
                    creature.collision_timer = narrowF32(creature.collision_timer + plague_collision_period);
                    creature.hp = narrowF32(creature.hp - 15.0);
                    if (creature.hp < 0.0) {
                        state.plaguebearer_infection_count += 1;
                        _ = self.handleSecondaryDetonationDeathFollowup(
                            state,
                            players,
                            bonus_pool,
                            terrain_fx,
                            idx,
                            creature.last_hit_owner,
                            dt_f32,
                            world_size,
                        );
                        // Plague timer kills consume one contact-SFX bank select draw.
                        consumeContactSfxRng(state, creature.type_id);
                    }
                    _ = terrain_fx.decals.addRandom(state, creature.pos);
                }
            }
            if ((state.bonuses.energizer > 0.0 and creature.max_hp < 500.0) or creature.plague_infected) {
                creature.target_heading = narrowF32(creature.target_heading + native_pi);
            }
            const turn_rate = narrowF32(creature.move_speed * creature_turn_rate_scale);
            if ((creature.flags & spawn_mod.CreatureFlags.anim_ping_pong) == 0) {
                if (creature.ai_mode != spawn_mod.CreatureAiMode.hold_timer) {
                    creature.heading = angleApproach(
                        creature.heading,
                        creature.target_heading,
                        turn_rate,
                        dt_f32,
                    );
                    const move_delta = movementDeltaFromHeadingF32(
                        creature.heading,
                        dt_f32,
                        creature.move_scale,
                        creature.move_speed,
                    );
                    creature.vel = move_delta;
                    creature.pos = advancePosByDeltaF32(creature.pos, move_delta);
                }
            } else {
                const radius = @max(@as(f32, 0.0), creature.size);
                const max_bound_raw = narrowF32(world_size - radius);
                const max_bound = if (max_bound_raw > radius) max_bound_raw else radius;

                var clamped_x = creature.pos.x;
                var clamped_y = creature.pos.y;
                if (clamped_x < radius) clamped_x = radius;
                if (clamped_y < radius) clamped_y = radius;
                if (max_bound < clamped_x) clamped_x = max_bound;
                if (max_bound < clamped_y) clamped_y = max_bound;
                creature.pos = .{
                    .x = clamped_x,
                    .y = clamped_y,
                };

                if ((creature.flags & spawn_mod.CreatureFlags.anim_long_strip) == 0) {
                    creature.vel = .{};
                } else {
                    creature.heading = angleApproach(
                        creature.heading,
                        creature.target_heading,
                        turn_rate,
                        dt_f32,
                    );
                    const move_delta = movementDeltaFromHeadingF32(
                        creature.heading,
                        dt_f32,
                        creature.move_scale,
                        creature.move_speed,
                    );
                    creature.vel = move_delta;

                    const moved_pos = advancePosByDeltaF32(creature.pos, move_delta);
                    var moved_x = moved_pos.x;
                    var moved_y = moved_pos.y;
                    if (moved_x < radius) moved_x = radius;
                    if (moved_y < radius) moved_y = radius;
                    if (max_bound < moved_x) moved_x = max_bound;
                    if (max_bound < moved_y) moved_y = max_bound;
                    creature.pos = .{
                        .x = moved_x,
                        .y = moved_y,
                    };
                }
            }
            if (runtime_anim.creatureAnimInfoForRawTypeId(creature.type_id)) |anim_info| {
                const advanced = runtime_anim.creatureAnimAdvancePhase(
                    creature.anim_phase,
                    anim_info.anim_rate,
                    creature.move_speed,
                    dt_f32,
                    creature.size,
                    creature.move_scale,
                    creature.flags,
                    creature.ai_mode,
                );
                creature.anim_phase = advanced.phase;
            }
            if (perkActive(player, PerkId.plaguebearer) and state.plaguebearer_infection_count < 0x3c) {
                spreadPlagueInfection(self.entries[0..], creature);
            }

            if (creature.attack_cooldown <= 0.0) {
                creature.attack_cooldown = 0.0;
            } else {
                creature.attack_cooldown = narrowF32(creature.attack_cooldown - dt_f32);
            }

            // Native gates on the global perk count and only fires the pulse
            // while the creature is still alive (hp > 0).
            if (anyPlayerHasPerk(players, PerkId.radioactive)) {
                const dist = state_mod.Vec2.sub(creature.pos, player.pos).length();
                if (dist < 100.0) {
                    creature.collision_timer -= dt_f32 * 1.5;
                    if (creature.collision_timer < 0.0 and creature.hp > 0.0) {
                        creature.collision_timer = plague_collision_period;
                        const pulse_damage = (100.0 - dist) * 0.3;
                        creature.hp = narrowF32(creature.hp - pulse_damage);
                        _ = terrain_fx.decals.addRandom(state, creature.pos);
                        if (creature.hp < 0.0) {
                            if (creature.type_id == @intFromEnum(spawn_mod.CreatureTypeId.lizard)) {
                                creature.hp = 1.0;
                            } else {
                                awardBaseExperienceFromReward(player, creature.reward_value);
                                creature.lifecycle_stage = narrowF32(creature.lifecycle_stage - dt_f32);
                            }
                        }
                    }
                }
            }

            // Decompile parity (`creature_update_all`, 0x00426220): compute
            // creature->target-player distance once and reuse it for ranged,
            // eat, and contact checks inside this creature tick.
            const to_player = state_mod.Vec2.sub(creature.pos, player.pos);
            const target_dist_sq = to_player.lengthSq();
            const target_dist = std.math.sqrt(target_dist_sq);

            if ((creature.flags & (spawn_mod.CreatureFlags.ranged_attack_shock | spawn_mod.CreatureFlags.ranged_attack_variant)) != 0) {
                if (target_dist > 64.0 and creature.attack_cooldown <= 0.0) {
                    if ((creature.flags & spawn_mod.CreatureFlags.ranged_attack_shock) != 0) {
                        queueCreatureProjectile(
                            state,
                            creature.pos,
                            creature.heading,
                            @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle),
                            owner_ref.OwnerRef.fromCreature(idx),
                        );
                        creature.attack_cooldown = narrowF32(creature.attack_cooldown + 1.0);
                    }

                    if ((creature.flags & spawn_mod.CreatureFlags.ranged_attack_variant) != 0 and
                        creature.attack_cooldown <= 0.0)
                    {
                        const projectile_type = creature.ranged_projectile_type;
                        queueCreatureProjectile(
                            state,
                            creature.pos,
                            creature.heading,
                            projectile_type,
                            owner_ref.OwnerRef.fromCreature(idx),
                        );
                        creature.attack_cooldown = narrowF32(
                            @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.creature_update_all_plasmaminigun_cooldown) & 3)) * 0.1 +
                                creature.orbit_angle +
                                creature.attack_cooldown,
                        );
                    }
                }
            }

            if (target_dist_sq < 20.0 * 20.0) {
                var reverted_x = creature.pos.x - creature.vel.x;
                var reverted_y = creature.pos.y - creature.vel.y;
                if (reverted_x < 0.0) {
                    reverted_x = 0.0;
                } else if (reverted_x > world_size) {
                    reverted_x = world_size;
                }
                if (reverted_y < 0.0) {
                    reverted_y = 0.0;
                } else if (reverted_y > world_size) {
                    reverted_y = world_size;
                }
                creature.pos = .{
                    .x = reverted_x,
                    .y = reverted_y,
                };

                if (state.bonuses.energizer > 0.0 and creature.max_hp < 380.0) {
                    // Native double-pays the eat kill: a direct exp += reward
                    // store here, plus creature_handle_death's own award below.
                    _ = awardExperienceOnceFromReward(&players[0], creature.reward_value);
                    effect_pool.spawnBurst(
                        state,
                        creature.pos,
                        6,
                        5,
                        0.4,
                        null,
                        .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
                    );
                    creature.last_hit_owner = owner_ref.OwnerRef.fromPlayer(@intCast(player.index));
                    const prev_spawn_guard = state.bonus_spawn_guard;
                    state.bonus_spawn_guard = true;
                    emitDeathSideEffects(
                        state,
                        players,
                        bonus_pool,
                        effect_pool,
                        terrain_fx,
                        creature.flags,
                        creature.link_index,
                        creature.pos,
                        @floatCast(world_size),
                        true,
                    );
                    state.bonus_spawn_guard = prev_spawn_guard;
                    _ = awardExperienceFromReward(state, player, creature.reward_value);
                    creature.active = false;
                    continue;
                }
            }

            const contact_sq = target_dist_sq;
            if (creature_lifecycle.isAlive(creature.lifecycle_stage) and
                creature.size > 16.0 and
                contact_sq < 30.0 * 30.0 and
                creature.attack_cooldown <= 0.0 and
                player.health > 0.0 and
                state.bonuses.energizer <= 0.0)
            {
                consumeContactSfxRng(state, creature.type_id);
                if (perkActive(player, PerkId.mr_melee)) {
                    _ = self.applyDamage(
                        state,
                        players,
                        bonus_pool,
                        terrain_fx,
                        idx,
                        25.0,
                        .{},
                        owner_ref.OwnerRef.fromPlayer(@intCast(player.index)),
                        dt_f32,
                        world_size,
                    );
                    if (!(creature.hp > 0.0) and creature.active) {
                        tickDead(creature, dt_f32, &self.kill_count, state, effect_pool, terrain_fx);
                    }
                }
                if (player.shield_timer <= 0.0) {
                    if (perkActive(player, PerkId.toxic_avenger)) {
                        creature.flags |= spawn_mod.CreatureFlags.self_damage_tick | spawn_mod.CreatureFlags.self_damage_tick_strong;
                    } else if (perkActive(player, PerkId.veins_of_poison)) {
                        creature.flags |= spawn_mod.CreatureFlags.self_damage_tick;
                    }
                }
                applyPlayerContactDamage(state, player, creature.contact_damage, dt_f32);
                const push_delta = state_mod.Vec2.sub(player.pos, creature.pos);
                const push_len = push_delta.length();
                if (push_len > 1e-6) {
                    const push_dir = push_delta.mul(1.0 / push_len);
                    _ = terrain_fx.decals.addRandom(state, state_mod.Vec2.add(player.pos, push_dir.mul(3.0)));
                } else {
                    _ = terrain_fx.decals.addRandom(state, player.pos);
                }
                creature.attack_cooldown = narrowF32(creature.attack_cooldown + contact_damage_cooldown);
            }

            if (state.bonuses.energizer <= 0.0 and
                player.plaguebearer_active and
                creature.hp < 150.0 and
                state.plaguebearer_infection_count < 0x32 and
                contact_sq < 30.0 * 30.0)
            {
                creature.plague_infected = true;
            }
            if (creature_lifecycle.isAlive(creature.lifecycle_stage) and
                contact_sq < 30.0 * 30.0 and
                creature.size <= 30.0)
            {
                creature.hp = 0.0;
                creature.lifecycle_stage -= dt_f32;
                continue;
            }
        }
    }

    pub fn finalizePostRenderLifecycle(self: *CreaturePool) void {
        for (&self.entries) |*creature| {
            if (!creature.active) continue;
            if (creature_lifecycle.isDespawned(creature.lifecycle_stage)) {
                creature.active = false;
            }
        }
    }

    pub fn applyProjectileDamage(
        self: *CreaturePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        bonus_pool: *bonus_runtime.BonusPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        creature_index: usize,
        damage: f32,
        impulse: state_mod.Vec2,
        owner: owner_ref.OwnerRef,
        dt: f32,
        world_size: f32,
    ) i32 {
        const jitter_rand = state.rng.randTagged(rng_callers.creature_apply_damage_heading_jitter);
        if (creature_index < self.entries.len) {
            var creature = &self.entries[creature_index];
            if ((creature.flags & spawn_mod.CreatureFlags.anim_ping_pong) == 0) {
                const jitter_i32: i32 = @as(i32, @intCast(jitter_rand & 0x7f)) - 0x40;
                const jitter = @as(f32, @floatFromInt(jitter_i32)) * 0.002;
                const size = @max(@as(f32, 1e-6), creature.size);
                var turn = jitter / (size * 0.025);
                // Native clamps against the f32 literal 1.5707964.
                const half_pi: f32 = native_math.roundF32(native_math.native_half_pi);
                if (turn > half_pi) turn = half_pi;
                creature.heading = narrowF32(creature.heading + turn);
            }
        }
        var damage_amount = damage;
        if (anyPlayerHasPerk(players, PerkId.uranium_filled_bullets)) {
            damage_amount *= 2.0;
        }
        if (anyPlayerHasPerk(players, PerkId.barrel_greaser)) {
            damage_amount *= 1.4;
        }
        if (anyPlayerHasPerk(players, PerkId.doctor)) {
            damage_amount *= 1.2;
        }
        if (anyPlayerHasPerk(players, PerkId.living_fortress)) {
            for (players) |player| {
                if (!(player.health > 0.0)) continue;
                if (!(player.living_fortress_timer > 0.0)) continue;
                const scale = narrowF32(player.living_fortress_timer * 0.05 + 1.0);
                damage_amount = narrowF32(damage_amount * scale);
            }
        }
        return self.applyDamage(
            state,
            players,
            bonus_pool,
            terrain_fx,
            creature_index,
            damage_amount,
            impulse,
            owner,
            dt,
            world_size,
        );
    }

    pub fn applyIonDamage(
        self: *CreaturePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        bonus_pool: *bonus_runtime.BonusPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        creature_index: usize,
        damage: f32,
        impulse: state_mod.Vec2,
        owner: owner_ref.OwnerRef,
        dt: f32,
        world_size: f32,
    ) i32 {
        var damage_amount = damage;
        if (anyPlayerHasPerk(players, PerkId.ion_gun_master)) {
            damage_amount *= 1.2;
        }
        return self.applyDamage(
            state,
            players,
            bonus_pool,
            terrain_fx,
            creature_index,
            damage_amount,
            impulse,
            owner,
            dt,
            world_size,
        );
    }

    pub fn applyFireDamage(
        self: *CreaturePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        bonus_pool: *bonus_runtime.BonusPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        creature_index: usize,
        damage: f32,
        impulse: state_mod.Vec2,
        owner: owner_ref.OwnerRef,
        dt: f32,
        world_size: f32,
    ) i32 {
        var damage_amount = damage;
        if (anyPlayerHasPerk(players, PerkId.pyromaniac)) {
            damage_amount *= 1.5;
            _ = state.rng.randTagged(rng_callers.creature_apply_damage_pyromaniac);
        }
        return self.applyDamage(
            state,
            players,
            bonus_pool,
            terrain_fx,
            creature_index,
            damage_amount,
            impulse,
            owner,
            dt,
            world_size,
        );
    }

    pub fn applyExplosionDamage(
        self: *CreaturePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        bonus_pool: *bonus_runtime.BonusPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        creature_index: usize,
        damage: f32,
        impulse: state_mod.Vec2,
        owner: owner_ref.OwnerRef,
        dt: f32,
        world_size: f32,
        killed_out: ?*bool,
    ) i32 {
        if (killed_out) |k| {
            k.* = false;
        }
        if (creature_index >= self.entries.len) return 0;
        if (players.len == 0) return 0;

        var creature = &self.entries[creature_index];
        if (!creature.active) return 0;
        creature.last_hit_owner = owner;
        const death_start_needed = creature_lifecycle.isAlive(creature.lifecycle_stage);

        // Native nuke path applies damage to active corpse entries as well.
        if (!(creature.hp > 0.0)) {
            if (dt > 0.0) {
                creature.lifecycle_stage = narrowF32(creature.lifecycle_stage - dt * 15.0);
            }
            return 0;
        }

        creature.hp = narrowF32(creature.hp - damage);
        creature.vel = .{
            .x = creature.vel.x - impulse.x,
            .y = creature.vel.y - impulse.y,
        };
        if (creature.hp > 0.0) return 0;
        if (killed_out) |k| {
            k.* = true;
        }

        if (dt > 0.0) {
            creature.lifecycle_stage = narrowF32(creature.lifecycle_stage - dt);
        } else {
            creature.lifecycle_stage = narrowF32(creature.lifecycle_stage - 0.001);
        }
        if (!death_start_needed) return 0;
        const split_can_reuse_slot =
            (creature.flags & spawn_mod.CreatureFlags.split_on_death) != 0 and
            creature.size > 35.0;
        const death_size = creature.size;
        const death_reward_value = creature.reward_value;
        creature.vel = .{
            .x = creature.vel.x - impulse.x * 2.0,
            .y = creature.vel.y - impulse.y * 2.0,
        };

        spawnSplitChildrenOnDeath(self, state, creature);
        const slot_reused_by_child = split_can_reuse_slot and creature.size != death_size;
        emitDeathSideEffects(
            state,
            players,
            bonus_pool,
            self.effects orelse unreachable,
            terrain_fx,
            creature.flags,
            creature.link_index,
            creature.pos,
            world_size,
            true,
        );
        if (dt > 0.0 and !slot_reused_by_child) {
            creature.lifecycle_stage = narrowF32(creature.lifecycle_stage - dt);
        }

        const xp_gained = awardExperienceForOwner(state, players, owner, death_reward_value);
        if (state.bonuses.freeze > 0.0) {
            self.kill_count += 1;
            if (!slot_reused_by_child) {
                creature.active = false;
            }
        }
        return xp_gained;
    }

    pub fn handleSecondaryDetonationDeathFollowup(
        self: *CreaturePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        bonus_pool: *bonus_runtime.BonusPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        creature_index: usize,
        owner: owner_ref.OwnerRef,
        dt: f32,
        world_size: f32,
    ) i32 {
        if (creature_index >= self.entries.len) return 0;
        if (players.len == 0) return 0;

        var creature = &self.entries[creature_index];
        if (!creature.active) return 0;
        if (creature.hp > 0.0) return 0;
        const split_can_reuse_slot =
            (creature.flags & spawn_mod.CreatureFlags.split_on_death) != 0 and
            creature.size > 35.0;
        const death_size = creature.size;
        const death_reward_value = creature.reward_value;

        creature.last_hit_owner = owner;
        spawnSplitChildrenOnDeath(self, state, creature);
        const slot_reused_by_child = split_can_reuse_slot and creature.size != death_size;
        emitDeathSideEffects(
            state,
            players,
            bonus_pool,
            self.effects orelse unreachable,
            terrain_fx,
            creature.flags,
            creature.link_index,
            creature.pos,
            world_size,
            false,
        );
        if (dt > 0.0 and !slot_reused_by_child) {
            creature.lifecycle_stage = narrowF32(creature.lifecycle_stage - narrowF32(dt));
        }

        const xp_gained = awardExperienceForOwner(state, players, owner, death_reward_value);
        if (state.bonuses.freeze > 0.0) {
            self.kill_count += 1;
            if (!slot_reused_by_child) {
                creature.active = false;
            }
        }
        return xp_gained;
    }

    pub fn killNoCorpse(
        self: *CreaturePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        bonus_pool: *bonus_runtime.BonusPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        creature_index: usize,
        owner: owner_ref.OwnerRef,
        dt: f32,
        world_size: f32,
    ) i32 {
        if (creature_index >= self.entries.len) return 0;
        if (players.len == 0) return 0;

        var creature = &self.entries[creature_index];
        if (!creature.active) return 0;
        if (!(creature.hp > 0.0)) return 0;
        const split_can_reuse_slot =
            (creature.flags & spawn_mod.CreatureFlags.split_on_death) != 0 and
            creature.size > 35.0;
        const death_size = creature.size;
        const death_reward_value = creature.reward_value;

        creature.last_hit_owner = owner;

        spawnSplitChildrenOnDeath(self, state, creature);
        const slot_reused_by_child = split_can_reuse_slot and creature.size != death_size;
        emitDeathSideEffects(
            state,
            players,
            bonus_pool,
            self.effects orelse unreachable,
            terrain_fx,
            creature.flags,
            creature.link_index,
            creature.pos,
            world_size,
            true,
        );

        const xp_gained = awardExperienceForOwner(state, players, owner, death_reward_value);

        if (dt > 0.0 and state.bonuses.freeze > 0.0) {
            self.kill_count += 1;
        }

        if (!slot_reused_by_child) {
            creature.active = false;
        }
        return xp_gained;
    }

    fn spawnFromStats(
        self: *CreaturePool,
        rng: *spawn_mod.Crand,
        pos: state_mod.Vec2,
        heading: f32,
        stats: SpawnStats,
    ) usize {
        return self.spawnFromStatsWithFlags(rng, pos, heading, stats, 0, true);
    }

    fn spawnParentWithSpawnSlot(
        self: *CreaturePool,
        rng: *spawn_mod.Crand,
        call: spawn_mod.SpawnTemplateCall,
        stats: SpawnStats,
        flags: u32,
        timer: f32,
        limit: i32,
        interval: f32,
        child_template_id: i32,
    ) usize {
        const parent_idx = self.spawnFromStatsWithFlags(
            rng,
            .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
            call.heading,
            stats,
            flags,
            true,
        );
        _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
        const slot_idx = self.registerSpawnSlot(parent_idx, timer, limit, interval, child_template_id);
        self.entries[parent_idx].link_index = slot_idx;
        return parent_idx;
    }

    fn spawnFromStatsWithFlags(
        self: *CreaturePool,
        rng: *spawn_mod.Crand,
        pos: state_mod.Vec2,
        heading: f32,
        stats: SpawnStats,
        flags: u32,
        set_heading: bool,
    ) usize {
        const phase_seed = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f));
        return self.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{
                .x = pos.x,
                .y = pos.y,
            },
            .heading = heading,
            .set_heading = set_heading,
            .phase_seed = phase_seed,
            .type_id = stats.type_id,
            .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
            .flags = flags,
            .size = stats.size,
            .move_speed = stats.move_speed,
            .health = stats.health,
            .max_health = stats.health,
            .reward_value = stats.reward_value,
            .contact_damage = stats.contact_damage,
        });
    }

    fn registerSpawnSlot(
        self: *CreaturePool,
        owner_idx: usize,
        timer: f32,
        limit: i32,
        interval: f32,
        child_template_id: i32,
    ) i32 {
        if (self.spawn_slot_count >= self.spawn_slots.len) return -1;
        const slot_idx = self.spawn_slot_count;
        self.spawn_slots[slot_idx] = .{
            .owner_creature = @intCast(owner_idx),
            .timer = timer,
            .count = 0,
            .limit = limit,
            .interval = interval,
            .child_template_id = child_template_id,
        };
        self.spawn_slot_count += 1;
        return @intCast(slot_idx);
    }

    fn applySpawnDifficultyAdjustments(
        self: *const CreaturePool,
        creature: *CreatureState,
        spawn_slot: ?*spawn_mod.SpawnSlotInit,
    ) void {
        if (!self.hardcore) {
            if (spawn_slot) |slot| {
                if ((creature.flags & 0x04) != 0) {
                    slot.interval = narrowF32(slot.interval + 0.2);
                }
            }

            if (self.quest_fail_retry_count > 0) {
                const d = self.quest_fail_retry_count;
                switch (d) {
                    1 => {
                        creature.reward_value = narrowF32(creature.reward_value * 0.9);
                        creature.move_speed = narrowF32(creature.move_speed * 0.95);
                        creature.contact_damage = narrowF32(creature.contact_damage * 0.95);
                        creature.hp = narrowF32(creature.hp * 0.95);
                        creature.max_hp = narrowF32(creature.max_hp * 0.95);
                    },
                    2 => {
                        creature.reward_value = narrowF32(creature.reward_value * 0.85);
                        creature.move_speed = narrowF32(creature.move_speed * 0.9);
                        creature.contact_damage = narrowF32(creature.contact_damage * 0.9);
                        creature.hp = narrowF32(creature.hp * 0.9);
                        creature.max_hp = narrowF32(creature.max_hp * 0.9);
                    },
                    3 => {
                        creature.reward_value = narrowF32(creature.reward_value * 0.85);
                        creature.move_speed = narrowF32(creature.move_speed * 0.8);
                        creature.contact_damage = narrowF32(creature.contact_damage * 0.8);
                        creature.hp = narrowF32(creature.hp * 0.8);
                        creature.max_hp = narrowF32(creature.max_hp * 0.8);
                    },
                    4 => {
                        creature.reward_value = narrowF32(creature.reward_value * 0.8);
                        creature.move_speed = narrowF32(creature.move_speed * 0.7);
                        creature.contact_damage = narrowF32(creature.contact_damage * 0.7);
                        creature.hp = narrowF32(creature.hp * 0.7);
                        creature.max_hp = narrowF32(creature.max_hp * 0.7);
                    },
                    else => {
                        creature.reward_value = narrowF32(creature.reward_value * 0.8);
                        creature.move_speed = narrowF32(creature.move_speed * 0.6);
                        creature.contact_damage = narrowF32(creature.contact_damage * 0.5);
                        creature.hp = narrowF32(creature.hp * 0.5);
                        creature.max_hp = narrowF32(creature.max_hp * 0.5);
                    },
                }
                if (spawn_slot) |slot| {
                    if ((creature.flags & 0x04) != 0) {
                        slot.interval = narrowF32(slot.interval + @min(3.0, @as(f32, @floatFromInt(d)) * 0.35));
                    }
                }
            }
            return;
        }

        creature.move_speed = narrowF32(creature.move_speed * 1.05);
        creature.contact_damage = narrowF32(creature.contact_damage * 1.4);
        creature.hp = narrowF32(creature.hp * 1.2);
        creature.max_hp = narrowF32(creature.max_hp * 1.2);

        if (spawn_slot) |slot| {
            if ((creature.flags & 0x04) != 0) {
                slot.interval = @max(0.1, narrowF32(slot.interval - 0.2));
            }
        }
    }

    fn spawnBasicRandomTemplate(
        self: *CreaturePool,
        rng: *spawn_mod.Crand,
        call: spawn_mod.SpawnTemplateCall,
        template_id: i32,
        creature_type: spawn_mod.CreatureTypeId,
    ) void {
        const phase_seed = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f));
        _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;

        const callers: BasicRandomCallers = switch (template_id) {
            0x03 => BasicRandomCallers{
                .size = rng_callers.creature_spawn_template_spider_sp1_random_03_size,
                .move_speed = rng_callers.creature_spawn_template_spider_sp1_random_03_move_speed,
                .tint = rng_callers.creature_spawn_template_spider_sp1_random_03_tint_b,
                .contact_damage = rng_callers.creature_spawn_template_spider_sp1_random_03_contact_damage,
            },
            0x04 => BasicRandomCallers{
                .size = rng_callers.creature_spawn_template_lizard_random_04_size,
                .move_speed = rng_callers.creature_spawn_template_lizard_random_04_move_speed,
                .tint = null,
                .contact_damage = rng_callers.creature_spawn_template_lizard_random_04_contact_damage,
            },
            0x05 => BasicRandomCallers{
                .size = rng_callers.creature_spawn_template_spider_sp2_random_05_size,
                .move_speed = rng_callers.creature_spawn_template_spider_sp2_random_05_move_speed,
                .tint = rng_callers.creature_spawn_template_spider_sp2_random_05_tint_b,
                .contact_damage = rng_callers.creature_spawn_template_spider_sp2_random_05_contact_damage,
            },
            0x06 => BasicRandomCallers{
                .size = rng_callers.creature_spawn_template_alien_random_06_size,
                .move_speed = rng_callers.creature_spawn_template_alien_random_06_move_speed,
                .tint = rng_callers.creature_spawn_template_alien_random_06_tint_b,
                .contact_damage = rng_callers.creature_spawn_template_alien_random_06_contact_damage,
            },
            else => unreachable,
        };

        const size = randfTagged(rng, callers.size, 15, 1.0, 38.0);
        const base_move_speed = randfTagged(rng, callers.move_speed, 18, 0.1, 1.1);
        if (callers.tint) |caller| {
            _ = randfTagged(rng, caller, 25, 0.01, 0.8);
        }
        const contact_damage = randfTagged(rng, callers.contact_damage, 10, 1.0, 4.0);
        const health = narrowF32(size * (8.0 / 7.0) + 20.0);
        const reward_value = narrowF32(size + size + 50.0);

        var flags: u32 = 0;
        var move_speed = base_move_speed;
        if (creature_type == .spider_sp1) {
            flags |= spawn_mod.CreatureFlags.ai7_link_timer;
            move_speed = narrowF32(move_speed * 1.2);
        }

        const idx = self.spawnInit(.{
            .origin_template_id = -1,
            .pos = .{ .x = narrowF32(call.pos.x), .y = narrowF32(call.pos.y) },
            .heading = narrowF32(call.heading),
            .set_heading = true,
            .phase_seed = phase_seed,
            .type_id = creature_type,
            .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
            .flags = flags,
            .size = size,
            .move_speed = move_speed,
            .health = health,
            .max_health = health,
            .reward_value = reward_value,
            .contact_damage = contact_damage,
        });
        if (creature_type == .spider_sp1) {
            self.entries[idx].link_index = 0;
        }
    }

    fn findRayHitCreature(
        self: *CreaturePool,
        origin: state_mod.Vec2,
        dir: state_mod.Vec2,
    ) ?usize {
        var best_idx: ?usize = null;
        var best_along = std.math.inf(f32);

        for (self.entries, 0..) |creature, idx| {
            if (!creature.active) continue;
            if (!(creature.hp > 0.0)) continue;
            if (!creature_lifecycle.isCollidable(creature.lifecycle_stage)) continue;

            const to_creature = state_mod.Vec2.sub(creature.pos, origin);
            const along = dot(to_creature, dir);
            if (!(along > 0.0)) continue;
            if (along >= best_along) continue;

            const proj = dir.mul(along);
            const perp = state_mod.Vec2.sub(to_creature, proj);
            const radius = hitRadiusFor(creature);
            if (perp.lengthSq() <= radius * radius) {
                best_idx = idx;
                best_along = along;
            }
        }

        return best_idx;
    }

    fn applyDamage(
        self: *CreaturePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        bonus_pool: *bonus_runtime.BonusPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        creature_index: usize,
        damage: f32,
        impulse: state_mod.Vec2,
        owner: owner_ref.OwnerRef,
        dt: f32,
        world_size: f32,
    ) i32 {
        if (creature_index >= self.entries.len) return 0;
        if (players.len == 0) return 0;

        var creature = &self.entries[creature_index];
        if (!creature.active) return 0;
        // Native damage path records the incoming owner even on corpse hits.
        creature.last_hit_owner = owner;
        if (!(creature.hp > 0.0)) {
            if (dt > 0.0) {
                creature.lifecycle_stage -= dt * 15.0;
            }
            return 0;
        }
        const death_start_needed = creature_lifecycle.isAlive(creature.lifecycle_stage);

        creature.hp -= damage;
        creature.vel = .{
            .x = creature.vel.x - impulse.x,
            .y = creature.vel.y - impulse.y,
        };
        if (creature.hp > 0.0) return 0;

        if (dt > 0.0) {
            creature.lifecycle_stage -= dt;
        } else {
            creature.lifecycle_stage -= 0.001;
        }
        if (!death_start_needed) return 0;
        const split_can_reuse_slot =
            (creature.flags & spawn_mod.CreatureFlags.split_on_death) != 0 and
            creature.size > 35.0;
        const death_size = creature.size;
        const death_reward_value = creature.reward_value;
        creature.vel = .{
            .x = creature.vel.x - impulse.x * 2.0,
            .y = creature.vel.y - impulse.y * 2.0,
        };
        spawnSplitChildrenOnDeath(self, state, creature);
        const slot_reused_by_child = split_can_reuse_slot and creature.size != death_size;
        emitDeathSideEffects(
            state,
            players,
            bonus_pool,
            self.effects orelse unreachable,
            terrain_fx,
            creature.flags,
            creature.link_index,
            creature.pos,
            world_size,
            true,
        );
        if (dt > 0.0 and !slot_reused_by_child) {
            creature.lifecycle_stage -= dt;
        }

        const xp_gained = awardExperienceForOwner(state, players, owner, death_reward_value);
        if (state.bonuses.freeze > 0.0) {
            self.kill_count += 1;
            if (!slot_reused_by_child) {
                creature.active = false;
            }
        }
        return xp_gained;
    }
};

fn creatureAiUpdateTarget(
    creature: *CreatureState,
    player_pos: state_mod.Vec2,
    creatures: []const CreatureState,
    dt: f32,
) CreatureAiUpdate {
    const dist_to_player = distanceF32(creature.pos, player_pos);
    const phase_int: i32 = @intFromFloat(creature.phase_seed);
    const phase_scale: f32 = 3.7;
    const orbit_phase = (@as(f32, @floatFromInt(phase_int)) * phase_scale) * native_pi;

    creature.force_target = 0;
    var move_scale: f32 = 1.0;
    var self_damage: ?f32 = null;
    const ai_mode = creature.ai_mode;

    if (ai_mode == spawn_mod.CreatureAiMode.orbit_player) {
        if (dist_to_player > 800.0) {
            creature.target = .{
                .x = narrowF32(player_pos.x),
                .y = narrowF32(player_pos.y),
            };
        } else {
            creature.target = orbitTargetF32(player_pos, orbit_phase, dist_to_player, 0.85);
        }
    } else if (ai_mode == spawn_mod.CreatureAiMode.orbit_player_wide) {
        creature.target = orbitTargetF32(player_pos, orbit_phase, dist_to_player, 0.9);
    } else if (ai_mode == spawn_mod.CreatureAiMode.orbit_player_tight) {
        if (dist_to_player > 800.0) {
            creature.target = .{
                .x = narrowF32(player_pos.x),
                .y = narrowF32(player_pos.y),
            };
        } else {
            creature.target = orbitTargetF32(player_pos, orbit_phase, dist_to_player, 0.55);
        }
    } else if (ai_mode == spawn_mod.CreatureAiMode.follow_link) {
        if (resolveLiveLink(creatures, creature.link_index)) |link| {
            creature.target = linkTargetF32(link.pos, creature.target_offset);
        } else {
            creature.ai_mode = spawn_mod.CreatureAiMode.orbit_player;
        }
    } else if (ai_mode == spawn_mod.CreatureAiMode.follow_link_tethered) {
        if (resolveLiveLink(creatures, creature.link_index)) |link| {
            creature.target = linkTargetF32(link.pos, creature.target_offset);
            const dist_to_target = distanceF32(creature.pos, creature.target);
            if (dist_to_target <= 64.0) {
                move_scale = narrowF32(dist_to_target * 0.015625);
            }
        } else {
            creature.ai_mode = spawn_mod.CreatureAiMode.orbit_player;
            self_damage = 1000.0;
        }
    }

    const ai_mode_after_primary = creature.ai_mode;
    if (ai_mode_after_primary == spawn_mod.CreatureAiMode.link_guard) {
        if (resolveLiveLink(creatures, creature.link_index) == null) {
            creature.ai_mode = spawn_mod.CreatureAiMode.orbit_player;
            self_damage = 1000.0;
        } else if (dist_to_player > 800.0) {
            creature.target = .{
                .x = narrowF32(player_pos.x),
                .y = narrowF32(player_pos.y),
            };
        } else {
            creature.target = orbitTargetF32(player_pos, orbit_phase, dist_to_player, 0.85);
        }
    } else if (ai_mode_after_primary == spawn_mod.CreatureAiMode.hold_timer) {
        if ((creature.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0 and creature.link_index > 0) {
            creature.target = .{
                .x = narrowF32(creature.pos.x),
                .y = narrowF32(creature.pos.y),
            };
        } else if ((creature.flags & spawn_mod.CreatureFlags.ai7_link_timer) == 0 and creature.orbit_radius > 0.0) {
            creature.target = .{
                .x = narrowF32(creature.pos.x),
                .y = narrowF32(creature.pos.y),
            };
            creature.orbit_radius = narrowF32(creature.orbit_radius - dt);
        } else {
            creature.ai_mode = spawn_mod.CreatureAiMode.orbit_player;
        }
    } else if (ai_mode_after_primary == spawn_mod.CreatureAiMode.orbit_link) {
        if (resolveLiveLink(creatures, creature.link_index)) |link| {
            const angle = narrowF32(creature.orbit_angle + creature.heading);
            const orbit_radius = narrowF32(creature.orbit_radius);
            creature.target = .{
                .x = narrowF32(math.cos(angle) * orbit_radius + link.pos.x),
                .y = narrowF32(math.sin(angle) * orbit_radius + link.pos.y),
            };
        } else {
            creature.ai_mode = spawn_mod.CreatureAiMode.orbit_player;
        }
    }

    const dist_to_target = distanceF32(creature.pos, creature.target);
    if (dist_to_target < 40.0 or dist_to_target > 400.0) {
        creature.force_target = 1;
    }
    if (creature.force_target != 0 or creature.ai_mode == spawn_mod.CreatureAiMode.chase_player) {
        creature.target = .{
            .x = narrowF32(player_pos.x),
            .y = narrowF32(player_pos.y),
        };
    }

    const dx = narrowF32(creature.target.x - creature.pos.x);
    const dy = narrowF32(creature.target.y - creature.pos.y);
    creature.target_heading = headingFromDeltaF32(dx, dy);
    return .{
        .move_scale = narrowF32(move_scale),
        .self_damage = self_damage,
    };
}

fn resolveLiveLink(
    creatures: []const CreatureState,
    link_index: i32,
) ?*const CreatureState {
    if (link_index < 0 or link_index >= creatures.len) return null;
    const idx: usize = @intCast(link_index);
    if (!(creatures[idx].hp > 0.0)) return null;
    return &creatures[idx];
}

fn linkTargetF32(
    link_pos: state_mod.Vec2,
    offset: state_mod.Vec2,
) state_mod.Vec2 {
    return .{
        .x = narrowF32(link_pos.x + offset.x),
        .y = narrowF32(link_pos.y + offset.y),
    };
}

fn distanceF32(a: state_mod.Vec2, b: state_mod.Vec2) f32 {
    const dx = narrowF32(b.x - a.x);
    const dy = narrowF32(b.y - a.y);
    // Native stores dx/dy into float locals, then computes dx*dx + dy*dy in x87
    // precision and narrows only after sqrt.
    const dx_f64 = @as(f64, @floatCast(dx));
    const dy_f64 = @as(f64, @floatCast(dy));
    const dist_sq = dx_f64 * dx_f64 + dy_f64 * dy_f64;
    return narrowF32(std.math.sqrt(dist_sq));
}

fn orbitTargetF32(
    player_pos: state_mod.Vec2,
    orbit_phase: f32,
    dist: f32,
    scale: f32,
) state_mod.Vec2 {
    const orbit_dist = narrowF32(narrowF32(dist) * narrowF32(scale));
    const phase = narrowF32(orbit_phase);
    const px = narrowF32(player_pos.x);
    const py = narrowF32(player_pos.y);
    const orbit_x = narrowF32(math.cos(phase));
    const orbit_y = narrowF32(math.sin(phase));
    const orbit_x_dist = narrowF32(@as(f64, @floatCast(orbit_x)) * @as(f64, @floatCast(orbit_dist)));
    const orbit_y_dist = narrowF32(@as(f64, @floatCast(orbit_y)) * @as(f64, @floatCast(orbit_dist)));
    return .{
        .x = narrowF32(@as(f64, @floatCast(orbit_x_dist)) + @as(f64, @floatCast(px))),
        .y = narrowF32(@as(f64, @floatCast(orbit_y_dist)) + @as(f64, @floatCast(py))),
    };
}

fn headingFromDeltaF32(dx: f32, dy: f32) f32 {
    return native_math.headingFromDeltaNative(dx, dy);
}

fn angleApproach(
    current: f32,
    target: f32,
    rate: f32,
    dt: f32,
) f32 {
    const angle = native_math.wrapAngle0Tau(current);
    const target_f = target;
    const rate_f = rate;
    const dt_f = dt;
    const tau = native_tau;

    const direct = narrowF32(@abs(narrowF32(target_f - angle)));
    const hi = if (angle < target_f) target_f else angle;
    const lo = if (target_f < angle) target_f else angle;
    const wrapped = narrowF32(@abs(narrowF32(narrowF32(tau - hi) + lo)));

    var step_scale = wrapped;
    if (direct < wrapped) {
        step_scale = direct;
    }
    if (step_scale > 1.0) {
        step_scale = 1.0;
    }
    step_scale = narrowF32(step_scale);

    const step_delta = narrowF32(narrowF32(dt_f * step_scale) * rate_f);
    if (direct <= wrapped) {
        if (angle < target_f) return narrowF32(angle + step_delta);
    } else {
        if (target_f < angle) return narrowF32(angle + step_delta);
    }
    return narrowF32(angle - step_delta);
}

fn movementDeltaFromHeadingF32(
    heading: f32,
    dt: f32,
    move_scale: f32,
    move_speed: f32,
) state_mod.Vec2 {
    // The game leaves the x87 in single-precision mode (the Direct3D 8 device
    // init does not pass D3DCREATE_FPU_PRESERVE): every multiply in the
    // velocity chain rounds to f32, while fsin/fcos evaluate in extended
    // precision internally so their rounding lands in the first multiply
    // (creature_update_all 0x426dab).
    const radians = @as(f64, @floatCast(narrowF32(heading))) - @as(f64, @floatCast(native_half_pi));

    var vx = narrowF32(std.math.cos(radians) * @as(f64, @floatCast(dt)));
    vx = narrowF32(vx * move_scale);
    vx = narrowF32(vx * move_speed);
    vx = narrowF32(vx * creature_speed_scale);

    var vy = narrowF32(std.math.sin(radians) * @as(f64, @floatCast(dt)));
    vy = narrowF32(vy * move_scale);
    vy = narrowF32(vy * move_speed);
    vy = narrowF32(vy * creature_speed_scale);

    return .{
        .x = vx,
        .y = vy,
    };
}

fn advancePosByDeltaF32(
    pos: state_mod.Vec2,
    delta: state_mod.Vec2,
) state_mod.Vec2 {
    return .{
        .x = narrowF32(pos.x + delta.x),
        .y = narrowF32(pos.y + delta.y),
    };
}

const SpawnStats = struct {
    type_id: spawn_mod.CreatureTypeId,
    health: f32,
    move_speed: f32,
    reward_value: f32,
    size: f32,
    contact_damage: f32,
};

const BasicRandomCallers = struct {
    size: rng_callers.Caller,
    move_speed: rng_callers.Caller,
    tint: ?rng_callers.Caller,
    contact_damage: rng_callers.Caller,
};

fn randfTagged(
    rng: *spawn_mod.Crand,
    caller: rng_callers.Caller,
    mod: u32,
    scale: f32,
    base: f32,
) f32 {
    return @as(f32, @floatFromInt(rng.randTagged(caller) % mod)) * scale + base;
}

fn drawPhaseSeedWithTransientHeading(rng: *spawn_mod.Crand) f32 {
    const phase_seed = @as(f32, @floatFromInt(rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f));
    _ = rng.randTagged(rng_callers.creature_spawn_template_base_heading) % 314;
    return phase_seed;
}

fn applyUnhandledCreatureTypeFallback(creature: *CreatureState) void {
    creature.type_id = @intFromEnum(spawn_mod.CreatureTypeId.alien);
    creature.hp = 20.0;
    creature.max_hp = 20.0;
}

fn applySpiderSp1Ai7Tail(creature: *CreatureState) void {
    if (creature.type_id != @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)) return;
    if ((creature.flags & spawn_mod.CreatureFlags.ranged_attack_shock) != 0) return;
    if ((creature.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0) return;

    creature.flags |= spawn_mod.CreatureFlags.ai7_link_timer;
    creature.link_index = 0;
    creature.move_speed = narrowF32(creature.move_speed * 1.2);
}

fn hitRadiusFor(creature: CreatureState) f32 {
    return @max(@as(f32, 0.0), narrowF32(creature.size * 0.14285715 + 3.0));
}

fn projectileHitDamage(origin: state_mod.Vec2, hit: state_mod.Vec2, damage_scale: f32) f32 {
    var dist = state_mod.Vec2.sub(hit, origin).length();
    if (dist < 50.0) dist = 50.0;
    const scaled = narrowF32((100.0 / dist) * damage_scale * 30.0 + 10.0);
    return narrowF32(scaled * 0.95);
}

fn perkActive(player: *const state_mod.PlayerState, perk_id: PerkId) bool {
    return player.perk_counts.get(perk_id) > 0;
}

fn anyPlayerHasPerk(players: []const state_mod.PlayerState, perk_id: PerkId) bool {
    for (players) |*player| {
        if (perkActive(player, perk_id)) return true;
    }
    return false;
}

fn creatureFrozenByEvilEyes(
    state: *const state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    creature_index: usize,
) bool {
    if (players.len == 0) return false;
    const creature_index_i32: i32 = @intCast(creature_index);

    if (state.preserve_bugs) {
        const player0 = players[0];
        if (!perkActive(&player0, PerkId.evil_eyes)) return false;
        return player0.evil_eyes_target_creature == creature_index_i32;
    }

    for (players) |*player| {
        if (player.health <= 0.0) continue;
        if (!perkActive(player, PerkId.evil_eyes)) continue;
        if (player.evil_eyes_target_creature == creature_index_i32) return true;
    }
    return false;
}

pub fn consumeHitSfxRng(
    state: *state_mod.GameplayState,
    game_tune_started: *bool,
    projectile_type_id: i32,
) HitSfxPlan {
    // Mirrors plan_hit_sfx_keys: first eligible hit starts tune and consumes one RNG draw.
    if (!state.demo_mode_active and state.game_mode != .rush and !game_tune_started.*) {
        game_tune_started.* = true;
        return .{
            .trigger_game_tune = true,
            .game_tune_roll = state.rng.randTagged(rng_callers.sfx_play_exclusive_playlist_pick),
        };
    }
    if (projectile_type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) or
        projectile_type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_minigun) or
        projectile_type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_cannon))
    {
        return .{ .shock_hit = true };
    }
    return .{ .bullet_hit_roll = state.rng.randTagged(rng_callers.projectile_update_hit_sfx) };
}

pub const HitSfxPlan = struct {
    trigger_game_tune: bool = false,
    game_tune_roll: ?u32 = null,
    shock_hit: bool = false,
    bullet_hit_roll: ?u32 = null,
};

fn spreadPlagueInfection(
    creatures: []CreatureState,
    origin: *CreatureState,
) void {
    for (creatures) |*target| {
        if (!target.active) continue;
        const dist_sq = state_mod.Vec2.sub(target.pos, origin.pos).lengthSq();
        if (dist_sq >= 45.0 * 45.0) continue;
        if (target.plague_infected and origin.hp < 150.0) {
            origin.plague_infected = true;
        }
        if (origin.plague_infected and target.hp < 150.0) {
            target.plague_infected = true;
        }
        return;
    }
}

fn tickAi7LinkTimer(
    creature: *CreatureState,
    dt_ms: i32,
    rng: *spawn_mod.Crand,
) void {
    if ((creature.flags & spawn_mod.CreatureFlags.ai7_link_timer) == 0) return;

    if (creature.link_index < 0) {
        creature.link_index += dt_ms;
        if (creature.link_index >= 0) {
            creature.ai_mode = spawn_mod.CreatureAiMode.hold_timer;
            creature.link_index = @as(i32, @intCast((rng.randTagged(rng_callers.creature_update_all_ai7_link_timer_hold) & 0x1ff) + 500));
        }
        return;
    }

    creature.link_index -= dt_ms;
    if (creature.link_index < 1) {
        creature.link_index = -700 - @as(i32, @intCast(rng.randTagged(rng_callers.creature_update_all_ai7_link_timer_reset) & 0x3ff));
    }
}

fn ownerToPlayerIndex(owner: owner_ref.OwnerRef, player_count: usize) ?usize {
    return owner.playerIndexInBounds(player_count);
}

fn awardExperienceForOwner(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    owner: owner_ref.OwnerRef,
    reward_value: f32,
) i32 {
    const slot = ownerToPlayerIndex(owner, players.len) orelse return 0;
    return awardExperienceFromReward(state, &players[slot], reward_value);
}

fn awardExperienceFromReward(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    reward_value: f32,
) i32 {
    if (perkActive(player, PerkId.bloody_mess_quick_learner)) {
        const scaled_reward: i32 = @intFromFloat(narrowF32(reward_value * 1.3));
        return awardExperience(state, player, scaled_reward);
    }

    var gained = awardExperienceOnceFromReward(player, reward_value);
    if (gained <= 0) return 0;
    if (state.bonuses.double_experience > 0.0) {
        gained += awardExperienceOnceFromReward(player, reward_value);
    }
    return gained;
}

fn awardExperience(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    amount: i32,
) i32 {
    var xp = amount;
    if (xp <= 0) return 0;
    if (state.bonuses.double_experience > 0.0) {
        xp *%= 2;
    }
    const before = player.experience;
    player.experience += xp;
    return player.experience - before;
}

fn awardExperienceRaw(
    player: *state_mod.PlayerState,
    amount: i32,
) i32 {
    if (amount <= 0) return 0;
    const before = player.experience;
    const before_f32: f32 = @floatFromInt(before);
    const amount_f32: f32 = @floatFromInt(amount);
    const total_f32 = before_f32 + amount_f32;
    const after: i32 = @intFromFloat(total_f32);
    player.experience = after;
    return after - before;
}

fn wrapAngle(value: f32) f32 {
    var angle = narrowF32(value);
    while (angle <= -std.math.pi) {
        angle = narrowF32(angle + native_tau);
    }
    while (angle > std.math.pi) {
        angle = narrowF32(angle - native_tau);
    }
    return angle;
}

fn queueCreatureProjectile(
    state: *state_mod.GameplayState,
    pos: state_mod.Vec2,
    angle: f32,
    type_id: i32,
    owner: owner_ref.OwnerRef,
) void {
    if (type_id <= 0) return;
    if (state.pending_creature_projectile_count < 0) {
        state.pending_creature_projectile_count = 0;
    }
    const pending_count: usize = @intCast(state.pending_creature_projectile_count);
    if (pending_count >= state.pending_creature_projectiles.len) return;

    state.pending_creature_projectiles[pending_count] = .{
        .type_id = type_id,
        .owner = owner,
        .angle = narrowF32(angle),
        .pos = .{
            .x = narrowF32(pos.x),
            .y = narrowF32(pos.y),
        },
    };
    state.pending_creature_projectile_count += 1;
}

fn spawnSplitChildrenOnDeath(
    self: *CreaturePool,
    state: *state_mod.GameplayState,
    creature: *const CreatureState,
) void {
    const source = creature.*;
    if ((source.flags & spawn_mod.CreatureFlags.split_on_death) == 0) return;
    if (!(source.size > 35.0)) return;

    const heading_offsets = [_]f32{ -native_half_pi, native_half_pi };
    for (heading_offsets) |heading_offset| {
        const child_idx = allocCreatureSlot(self, &state.rng);
        // Native creature_alloc_slot draws a phase seed (rand & 0x17f) that the
        // struct copy from the parent immediately overwrites; only the draw
        // itself matters for the stream.
        _ = state.rng.randTagged(rng_callers.creature_alloc_slot_phase_seed);
        var child = source;
        child.active = true;
        child.phase_seed = @floatFromInt(state.rng.randTagged(if (heading_offset < 0.0) rng_callers.creature_handle_death_split_child_1_phase_seed else rng_callers.creature_handle_death_split_child_2_phase_seed) & 0xff);
        child.heading = wrapAngle(narrowF32(source.heading + heading_offset));
        child.target_heading = child.heading;
        child.hp = narrowF32(source.max_hp * 0.25);
        child.reward_value = narrowF32(source.reward_value * (2.0 / 3.0));
        child.size = narrowF32(source.size - 8.0);
        child.move_speed = narrowF32(source.move_speed + 0.1);
        child.contact_damage = narrowF32(source.contact_damage * 0.7);
        child.lifecycle_stage = creature_lifecycle.alive;
        self.entries[child_idx] = child;
    }

    const effects = self.effects orelse unreachable;
    effects.spawnBurst(
        state,
        source.pos,
        8,
        5,
        0.4,
        null,
        .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
    );
}

fn allocCreatureSlot(
    self: *CreaturePool,
    rng: ?*spawn_mod.Crand,
) usize {
    var slot: usize = self.entries.len - 1;
    for (self.entries, 0..) |entry, idx| {
        if (!entry.active) {
            slot = idx;
            break;
        }
    }
    if (slot == self.entries.len - 1 and self.entries[slot].active) {
        if (rng) |r| {
            if (self.entries.len == 0) return 0;
            const roll: u32 = @intCast(r.rand());
            slot = @intCast(roll % @as(u32, @intCast(self.entries.len)));
        }
    }
    return slot;
}

fn emitDeathSideEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    bonus_pool: *bonus_runtime.BonusPool,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    creature_flags: u32,
    creature_link_index: i32,
    death_pos: state_mod.Vec2,
    world_size: f32,
    plan_death_sfx: bool,
) void {
    if ((creature_flags & spawn_mod.CreatureFlags.bonus_on_death) != 0) {
        if (unpackBonusOnDeathArgs(creature_link_index)) |drop| {
            _ = bonus_pool.spawnAt(
                .{
                    .x = narrowF32(death_pos.x),
                    .y = narrowF32(death_pos.y),
                },
                drop.bonus_id,
                drop.amount_override,
                state,
                world_size,
            );
        }
    }
    const spawned_bonus = bonus_pool.trySpawnOnKill(
        .{
            .x = narrowF32(death_pos.x),
            .y = narrowF32(death_pos.y),
        },
        state,
        players,
        world_size,
    );
    if (spawned_bonus) |_| {
        effects.spawnBurstWithCallers(
            state,
            death_pos,
            16,
            5,
            0.4,
            null,
            .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
            effects_mod.EffectPool.bonus_on_kill_burst_callers,
        );
    }
    if (state.bonuses.freeze > 0.0) {
        for (0..8) |_| {
            const angle = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.creature_handle_death_freeze_shard_angle) % 612)) * 0.01;
            effects.spawnFreezeShard(state, death_pos, angle, 5);
        }
        const shatter_angle = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.creature_handle_death_freeze_shatter_angle) % 612)) * 0.01;
        effects.spawnFreezeShatter(state, death_pos, shatter_angle, 5);
        _ = terrain_fx.decals.addRandom(state, death_pos);
    }
    if (plan_death_sfx) {
        // plan_death_sfx_keys chooses one death sample per death.
        _ = state.rng.randTagged(rng_callers.creature_apply_damage_death_sfx);
    }
}

fn tickDead(
    creature: *CreatureState,
    dt: f32,
    kill_count: *i32,
    state: *state_mod.GameplayState,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
) void {
    if (!(dt > 0.0)) return;
    const hitbox = narrowF32(creature.lifecycle_stage);
    if (hitbox <= 0.0) {
        creature.lifecycle_stage = narrowF32(hitbox - dt * 20.0);
        return;
    }
    const long_strip =
        (creature.flags & spawn_mod.CreatureFlags.anim_ping_pong) == 0 or
        (creature.flags & spawn_mod.CreatureFlags.anim_long_strip) != 0;
    const next_lifecycle_stage = narrowF32(hitbox - dt * 28.0);
    creature.lifecycle_stage = narrowF32(next_lifecycle_stage);
    if (next_lifecycle_stage > 0.0) {
        if (long_strip) {
            const slide = narrowF32(next_lifecycle_stage * dt * 9.0);
            const direction = headingDirectionF32(creature.heading);
            creature.vel = .{
                .x = narrowF32(direction.x * slide),
                .y = narrowF32(direction.y * slide),
            };
            creature.pos = .{
                .x = narrowF32(creature.pos.x - creature.vel.x),
                .y = narrowF32(creature.pos.y - creature.vel.y),
            };
        } else {
            creature.vel = .{};
        }
        return;
    }
    if (state.gore_disabled == 0) {
        const corpse_size = @max(1.0, creature.size);
        const corpse_type_id = if (long_strip) creature.type_id else 7;
        const corpse_ok = terrain_fx.corpses.add(
            .{
                .x = creature.pos.x - corpse_size * 0.5,
                .y = creature.pos.y - corpse_size * 0.5,
            },
            .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
            creature.heading,
            corpse_size,
            corpse_type_id,
        );
        if (!corpse_ok) {
            creature.lifecycle_stage = 0.001;
            return;
        }
    }
    kill_count.* += 1;
    if (state.gore_disabled == 0 and
        (creature.flags & spawn_mod.CreatureFlags.anim_ping_pong) != 0)
    {
        const burst_sets = [_]struct { count: usize, age: f32, caller: rng_callers.Caller }{
            .{ .count = 8, .age = 0.0, .caller = rng_callers.creature_update_all_ping_pong_blood_8_angle },
            .{ .count = 6, .age = -0.07, .caller = rng_callers.creature_update_all_ping_pong_blood_6_angle },
            .{ .count = 5, .age = -0.12, .caller = rng_callers.creature_update_all_ping_pong_blood_5_angle },
        };
        for (burst_sets) |entry| {
            for (0..entry.count) |_| {
                const angle = @as(f32, @floatFromInt(state.rng.randTagged(entry.caller) % 612)) * 0.01;
                effects.spawnBloodSplatter(state, creature.pos, angle, entry.age, 5, state.gore_disabled);
            }
        }
    }
}

fn selfDamageTickAmount(flags: u32, dt: f32) f32 {
    if (!(dt > 0.0)) return 0.0;
    if ((flags & spawn_mod.CreatureFlags.self_damage_tick_strong) != 0) {
        return narrowF32(dt * 180.0);
    }
    if ((flags & spawn_mod.CreatureFlags.self_damage_tick) != 0) {
        return narrowF32(dt * 60.0);
    }
    return 0.0;
}

fn applySelfDamageTickToDead(
    creature: *CreatureState,
    dt: f32,
) void {
    if (!(selfDamageTickAmount(creature.flags, dt) > 0.0)) return;
    if (dt > 0.0) {
        creature.lifecycle_stage = narrowF32(creature.lifecycle_stage - dt * 15.0);
    }
}

fn headingDirectionF32(heading: f32) state_mod.Vec2 {
    const radians = heading - native_half_pi;
    return .{
        .x = narrowF32(math.cos(radians)),
        .y = narrowF32(math.sin(radians)),
    };
}

fn awardExperienceOnceFromReward(
    player: *state_mod.PlayerState,
    reward_value: f32,
) i32 {
    const reward_f32 = reward_value;
    if (!(reward_f32 > 0.0)) return 0;

    const before = player.experience;
    const before_f32: f32 = @floatFromInt(before);
    const total_f32 = before_f32 + reward_f32;
    const after: i32 = @intFromFloat(total_f32);
    player.experience = after;
    return after - before;
}

fn awardBaseExperienceFromReward(
    player: *state_mod.PlayerState,
    reward_value: f32,
) void {
    const reward_f32 = reward_value;
    if (!(reward_f32 > 0.0)) return;
    const before_f32: f32 = @floatFromInt(player.experience);
    const total_f32 = before_f32 + reward_f32;
    player.experience = @intFromFloat(total_f32);
}

fn dot(a: state_mod.Vec2, b: state_mod.Vec2) f32 {
    return a.x * b.x + a.y * b.y;
}

const thick_skinned_damage_scale_f32: f32 = 0.6660000085830688;

fn creatureTypeHasContactSfx(type_id: i32) bool {
    return type_id == @intFromEnum(spawn_mod.CreatureTypeId.zombie) or
        type_id == @intFromEnum(spawn_mod.CreatureTypeId.lizard) or
        type_id == @intFromEnum(spawn_mod.CreatureTypeId.alien) or
        type_id == @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1) or
        type_id == @intFromEnum(spawn_mod.CreatureTypeId.spider_sp2);
}

fn consumeContactSfxRng(state: *state_mod.GameplayState, creature_type_id: i32) void {
    if (!creatureTypeHasContactSfx(creature_type_id)) return;
    _ = state.rng.randTagged(rng_callers.creature_update_all_contact_sfx) & 1;
}

pub fn applyPlayerContactDamage(
    state: *state_mod.GameplayState,
    player: *state_mod.PlayerState,
    damage: f32,
    dt: f32,
) void {
    if (!(damage > 0.0)) return;
    if (perkActive(player, PerkId.death_clock)) return;

    var damage_scaled: f32 = damage;
    if (perkActive(player, PerkId.tough_reloader) and player.weapon.reload_active) {
        damage_scaled = narrowF32(damage_scaled * 0.5);
    }
    const spread_heat_damage = damage_scaled;

    state.survival_reward_damage_seen = true;
    if (player.shield_timer > 0.0) return;

    var dodged = false;
    if (perkActive(player, PerkId.ninja)) {
        dodged = (state.rng.randTagged(rng_callers.player_take_damage_ninja) % 3) == 0;
    } else if (perkActive(player, PerkId.dodger)) {
        dodged = (state.rng.randTagged(rng_callers.player_take_damage_dodger) % 5) == 0;
    }

    if (perkActive(player, PerkId.thick_skinned)) {
        damage_scaled = narrowF32(damage_scaled * thick_skinned_damage_scale_f32);
    }

    if (!dodged) {
        if (perkActive(player, PerkId.highlander)) {
            if ((state.rng.randTagged(rng_callers.player_take_damage_highlander) % 10) == 0) {
                player.health = 0.0;
            }
        } else {
            player.health = narrowF32(player.health - damage_scaled);
            if (player.health < 0.0 and dt > 0.0) {
                player.death_timer = narrowF32(player.death_timer - dt * 28.0);
            }
        }
    }

    if (player.health >= 0.0) {
        const pain_roll = state.rng.randTagged(rng_callers.player_take_damage_pain_sfx) % 3;
        state.sfx_queue.append(switch (pain_roll) {
            0 => .trooper_inpain_01,
            1 => .trooper_inpain_02,
            else => .trooper_inpain_03,
        });
    } else if (!perkActive(player, PerkId.final_revenge)) {
        const death_roll = state.rng.randTagged(rng_callers.player_take_damage_death_sfx) & 1;
        state.sfx_queue.append(if (death_roll == 0) .trooper_die_01 else .trooper_die_02);
    }

    if (!dodged) {
        if (!perkActive(player, PerkId.unstoppable)) {
            const jitter_i32: i32 = @as(i32, @intCast(state.rng.randTagged(rng_callers.player_take_damage_heading) % 100)) - 50;
            player.heading = narrowF32(player.heading + @as(f32, @floatFromInt(jitter_i32)) * 0.04);
            player.spread_heat = narrowF32(@min(
                0.48,
                narrowF32(player.spread_heat + spread_heat_damage * 0.01),
            ));
        }
        if (player.health <= 20.0 and (state.rng.randTagged(rng_callers.player_take_damage_low_health) & 7) == 3) {
            player.low_health_timer = 0.0;
        }
    }
}

fn expectFloatClose(expected: f32, actual: f32) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "bloody mess quick learner reward is still doubled by double experience bonus" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    state.bonuses.double_experience = 5.0;
    var bonuses: bonus_runtime.BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .experience = 100,
        },
    };
    players[0].perk_counts.set(PerkId.bloody_mess_quick_learner, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 140.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 12.7,
        .contact_damage = 0.0,
    });

    const xp_gained = pool.applyDamage(
        &state,
        players[0..],
        &bonuses,
        &terrain_fx,
        0,
        50.0,
        .{},
        owner_local_player,
        1.0 / 60.0,
        1024.0,
    );

    try std.testing.expectEqual(@as(i32, 32), xp_gained);
    try std.testing.expectEqual(@as(i32, 132), players[0].experience);
}

test "split-on-death children use original source when first child reuses source slot" {
    const seed: u32 = 243_988;

    var pool: CreaturePool = .{};
    for (&pool.entries) |*entry| {
        entry.* = .{
            .active = true,
            .hp = 100.0,
            .max_hp = 100.0,
            .size = 32.0,
            .reward_value = 50.0,
        };
    }
    pool.entries[0] = .{
        .active = true,
        .flags = spawn_mod.CreatureFlags.split_on_death,
        .hp = -5.0,
        .max_hp = 400.0,
        .size = 40.0,
        .reward_value = 131.687241,
        .move_speed = 2.0,
        .contact_damage = 10.0,
    };

    var state = state_mod.GameplayState.init(seed);
    spawnSplitChildrenOnDeath(&pool, &state, &pool.entries[0]);

    try expectFloatClose(32.0, pool.entries[0].size);
    try expectFloatClose(32.0, pool.entries[1].size);
    try expectFloatClose(100.0, pool.entries[0].hp);
    try expectFloatClose(100.0, pool.entries[1].hp);
    try expectFloatClose(87.791496, pool.entries[0].reward_value);
    try expectFloatClose(87.791496, pool.entries[1].reward_value);
}

test "explosion xp uses pre-split reward when source slot is reused by split child" {
    const seed: u32 = 243_988;

    var pool: CreaturePool = .{};
    for (&pool.entries) |*entry| {
        entry.* = .{
            .active = true,
            .hp = 100.0,
            .max_hp = 100.0,
            .size = 32.0,
            .reward_value = 50.0,
        };
    }
    pool.entries[0] = .{
        .active = true,
        .flags = spawn_mod.CreatureFlags.split_on_death,
        .hp = 5.0,
        .max_hp = 400.0,
        .size = 40.0,
        .reward_value = 131.687241,
        .move_speed = 2.0,
        .contact_damage = 10.0,
    };

    var state = state_mod.GameplayState.init(seed);
    var bonuses: bonus_runtime.BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
        },
    };
    players[0].perk_counts.set(PerkId.bloody_mess_quick_learner, 1);

    const gained = pool.applyExplosionDamage(
        &state,
        players[0..],
        &bonuses,
        &terrain_fx,
        0,
        10.0,
        .{},
        owner_local_player,
        1.0 / 60.0,
        1024.0,
        null,
    );
    try std.testing.expectEqual(@as(i32, 171), gained);
}

test "applyDamage skips death side effects when lifecycle is already below alive sentinel" {
    var pool: CreaturePool = .{};
    pool.entries[0] = .{
        .active = true,
        .flags = spawn_mod.CreatureFlags.split_on_death,
        .hp = 5.0,
        .max_hp = 400.0,
        .size = 40.0,
        .reward_value = 131.687241,
        .lifecycle_stage = 15.0,
    };

    var state = state_mod.GameplayState.init(1234);
    var bonuses: bonus_runtime.BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .experience = 100,
        },
    };

    const gained = pool.applyDamage(
        &state,
        players[0..],
        &bonuses,
        &terrain_fx,
        0,
        10.0,
        .{},
        owner_local_player,
        1.0 / 60.0,
        1024.0,
    );

    try std.testing.expectEqual(@as(i32, 0), gained);
    try std.testing.expectEqual(@as(i32, 100), players[0].experience);
    try expectFloatClose(40.0, pool.entries[0].size);
    try expectFloatClose(131.687241, pool.entries[0].reward_value);
    try std.testing.expect(pool.entries[0].active);
    try std.testing.expect(!pool.entries[1].active);
}

test "applyExplosionDamage skips first death side effects when lifecycle is below alive sentinel" {
    var pool: CreaturePool = .{};
    pool.entries[0] = .{
        .active = true,
        .flags = spawn_mod.CreatureFlags.split_on_death,
        .hp = 5.0,
        .max_hp = 400.0,
        .size = 40.0,
        .reward_value = 131.687241,
        .lifecycle_stage = 15.0,
    };

    var state = state_mod.GameplayState.init(1234);
    var bonuses: bonus_runtime.BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .experience = 100,
        },
    };

    var killed_now = false;
    const gained = pool.applyExplosionDamage(
        &state,
        players[0..],
        &bonuses,
        &terrain_fx,
        0,
        10.0,
        .{},
        owner_local_player,
        1.0 / 60.0,
        1024.0,
        &killed_now,
    );

    try std.testing.expect(killed_now);
    try std.testing.expectEqual(@as(i32, 0), gained);
    try std.testing.expectEqual(@as(i32, 100), players[0].experience);
    try expectFloatClose(40.0, pool.entries[0].size);
    try expectFloatClose(131.687241, pool.entries[0].reward_value);
    try std.testing.expect(pool.entries[0].active);
    try std.testing.expect(!pool.entries[1].active);
}

test "template spawn supports survival early-stage templates" {
    var pool: CreaturePool = .{};
    var rng = spawn_mod.Crand.init(7);

    try pool.spawnTemplateCall(
        .{
            .template_id = @intFromEnum(spawn_mod.SpawnId.formation_ring_alien_8_12),
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = std.math.pi,
        },
        &rng,
    );
    try std.testing.expectEqual(@as(usize, 9), pool.activeCount());
    const parent = pool.entries[0];
    try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), parent.type_id);
    try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player, parent.ai_mode);
    try expectFloatClose(200.0, parent.hp);
    try expectFloatClose(2.2, parent.move_speed);
    try expectFloatClose(600.0, parent.reward_value);
    try expectFloatClose(55.0, parent.size);
    try expectFloatClose(14.0, parent.contact_damage);
    const child = pool.entries[1];
    try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), child.type_id);
    try std.testing.expectEqual(spawn_mod.CreatureAiMode.follow_link, child.ai_mode);
    try std.testing.expectEqual(@as(i32, 0), child.link_index);
    try expectFloatClose(40.0, child.hp);
    try expectFloatClose(2.4, child.move_speed);
    try expectFloatClose(60.0, child.reward_value);
    try expectFloatClose(50.0, child.size);
    try expectFloatClose(4.0, child.contact_damage);
    try expectFloatClose(100.0, child.target_offset.x);
    try expectFloatClose(0.0, child.target_offset.y);
}

test "template spawn supports survival late-stage templates" {
    var pool: CreaturePool = .{};
    var rng = spawn_mod.Crand.init(1);

    try pool.spawnTemplateCall(
        .{
            .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_red_fast_2b),
            .pos = .{ .x = 10.0, .y = 20.0 },
            .heading = 1.23,
        },
        &rng,
    );
    const red_fast_entry = pool.entries[0];
    try std.testing.expect(red_fast_entry.active);
    try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), red_fast_entry.type_id);
    try std.testing.expectEqual(@as(u32, 0), red_fast_entry.flags);
    try expectFloatClose(30.0, red_fast_entry.hp);
    try expectFloatClose(3.6, red_fast_entry.move_speed);
    try expectFloatClose(450.0, red_fast_entry.reward_value);
    try expectFloatClose(35.0, red_fast_entry.size);
    try expectFloatClose(20.0, red_fast_entry.contact_damage);

    try pool.spawnTemplateCall(
        .{
            .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_red_boss_2c),
            .pos = .{ .x = 20.0, .y = 30.0 },
            .heading = 1.78,
        },
        &rng,
    );
    const red_boss_entry = pool.entries[1];
    try std.testing.expect(red_boss_entry.active);
    try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), red_boss_entry.type_id);
    try std.testing.expectEqual(@as(u32, 0), red_boss_entry.flags);
    try expectFloatClose(3800.0, red_boss_entry.hp);
    try expectFloatClose(2.0, red_boss_entry.move_speed);
    try expectFloatClose(1500.0, red_boss_entry.reward_value);
    try expectFloatClose(80.0, red_boss_entry.size);
    try expectFloatClose(40.0, red_boss_entry.contact_damage);

    try pool.spawnTemplateCall(
        .{
            .template_id = @intFromEnum(spawn_mod.SpawnId.spider_sp2_splitter_01),
            .pos = .{ .x = 10.0, .y = 20.0 },
            .heading = 1.23,
        },
        &rng,
    );
    const split_entry = pool.entries[2];
    try std.testing.expect(split_entry.active);
    try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp2)), split_entry.type_id);
    try std.testing.expect((split_entry.flags & spawn_mod.CreatureFlags.split_on_death) != 0);
    try expectFloatClose(400.0, split_entry.hp);
    try expectFloatClose(2.0, split_entry.move_speed);
    try expectFloatClose(1000.0, split_entry.reward_value);
    try expectFloatClose(80.0, split_entry.size);
    try expectFloatClose(17.0, split_entry.contact_damage);

    try pool.spawnTemplateCall(
        .{
            .template_id = @intFromEnum(spawn_mod.SpawnId.spider_sp1_const_shock_boss_3a),
            .pos = .{ .x = 30.0, .y = 40.0 },
            .heading = 2.34,
        },
        &rng,
    );
    const shock_entry = pool.entries[3];
    try std.testing.expect(shock_entry.active);
    try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), shock_entry.type_id);
    try std.testing.expect((shock_entry.flags & spawn_mod.CreatureFlags.ranged_attack_shock) != 0);
    try expectFloatClose(4500.0, shock_entry.hp);
    try expectFloatClose(2.0, shock_entry.move_speed);
    try expectFloatClose(4500.0, shock_entry.reward_value);
    try expectFloatClose(64.0, shock_entry.size);
    try expectFloatClose(50.0, shock_entry.contact_damage);
    try expectFloatClose(0.9, shock_entry.orbit_angle);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), shock_entry.ranged_projectile_type);

    try pool.spawnTemplateCall(
        .{
            .template_id = @intFromEnum(spawn_mod.SpawnId.spider_sp1_const_ranged_variant_3c),
            .pos = .{ .x = 50.0, .y = 60.0 },
            .heading = 3.45,
        },
        &rng,
    );
    const ranged_entry = pool.entries[4];
    try std.testing.expect(ranged_entry.active);
    try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), ranged_entry.type_id);
    try std.testing.expect((ranged_entry.flags & spawn_mod.CreatureFlags.ranged_attack_variant) != 0);
    try std.testing.expect((ranged_entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
    try std.testing.expectEqual(spawn_mod.CreatureAiMode.chase_player, ranged_entry.ai_mode);
    try std.testing.expectEqual(@as(i32, 0), ranged_entry.link_index);
    try expectFloatClose(200.0, ranged_entry.hp);
    try expectFloatClose(2.4, ranged_entry.move_speed);
    try expectFloatClose(200.0, ranged_entry.reward_value);
    try expectFloatClose(40.0, ranged_entry.size);
    try expectFloatClose(20.0, ranged_entry.contact_damage);
    try expectFloatClose(0.4, ranged_entry.orbit_angle);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.spider_plasma), ranged_entry.ranged_projectile_type);
}

test "template spawn supports quest random and ai7 templates" {
    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x03,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player, entry.ai_mode);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(68.0, entry.hp);
        try expectFloatClose(1.8, entry.move_speed);
        try expectFloatClose(134.0, entry.reward_value);
        try expectFloatClose(42.0, entry.size);
        try expectFloatClose(8.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x04,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.lizard)), entry.type_id);
        try std.testing.expectEqual(@as(u32, 0), entry.flags);
        try expectFloatClose(68.0, entry.hp);
        try expectFloatClose(1.5, entry.move_speed);
        try expectFloatClose(134.0, entry.reward_value);
        try expectFloatClose(42.0, entry.size);
        try expectFloatClose(13.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x05,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp2)), entry.type_id);
        try std.testing.expectEqual(@as(u32, 0), entry.flags);
        try expectFloatClose(68.0, entry.hp);
        try expectFloatClose(1.5, entry.move_speed);
        try expectFloatClose(134.0, entry.reward_value);
        try expectFloatClose(42.0, entry.size);
        try expectFloatClose(8.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x06,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), entry.type_id);
        try std.testing.expectEqual(@as(u32, 0), entry.flags);
        try expectFloatClose(68.0, entry.hp);
        try expectFloatClose(1.5, entry.move_speed);
        try expectFloatClose(134.0, entry.reward_value);
        try expectFloatClose(42.0, entry.size);
        try expectFloatClose(8.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x36,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), entry.type_id);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.hold_timer, entry.ai_mode);
        try std.testing.expectEqual(@as(u32, 0), entry.flags);
        try expectFloatClose(10.0, entry.hp);
        try expectFloatClose(1.8, entry.move_speed);
        try expectFloatClose(150.0, entry.reward_value);
        try expectFloatClose(50.0, entry.size);
        try expectFloatClose(40.0, entry.contact_damage);
        try expectFloatClose(1.5, entry.orbit_radius);
    }
}

test "template spawn supports quest spider and zombie late templates" {
    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = @intFromEnum(spawn_mod.SpawnId.spider_sp2_random_35),
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp2)), entry.type_id);
        try std.testing.expectEqual(@as(u32, 0), entry.flags);
        try expectFloatClose(58.85714340209961, entry.hp);
        try expectFloatClose(1.5, entry.move_speed);
        try expectFloatClose(118.0, entry.reward_value);
        try expectFloatClose(34.0, entry.size);
        try expectFloatClose(8.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = @intFromEnum(spawn_mod.SpawnId.spider_sp1_ai7_timer_38),
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player, entry.ai_mode);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(50.0, entry.hp);
        try expectFloatClose(4.8, entry.move_speed);
        try expectFloatClose(433.0, entry.reward_value);
        try expectFloatClose(43.0, entry.size);
        try expectFloatClose(10.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x37,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp2)), entry.type_id);
        try std.testing.expectEqual(@as(u32, spawn_mod.CreatureFlags.ranged_attack_variant), entry.flags);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player, entry.ai_mode);
        try expectFloatClose(50.0, entry.hp);
        try expectFloatClose(3.2, entry.move_speed);
        try expectFloatClose(433.0, entry.reward_value);
        try expectFloatClose(43.0, entry.size);
        try expectFloatClose(10.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x39,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(4.0, entry.hp);
        try expectFloatClose(4.8, entry.move_speed);
        try expectFloatClose(50.0, entry.reward_value);
        try expectFloatClose(28.0, entry.size);
        try expectFloatClose(10.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x3B,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(1200.0, entry.hp);
        try expectFloatClose(2.4, entry.move_speed);
        try expectFloatClose(4000.0, entry.reward_value);
        try expectFloatClose(70.0, entry.size);
        try expectFloatClose(20.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x3D,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(70.0, entry.hp);
        try expectFloatClose(3.12, entry.move_speed);
        try expectFloatClose(120.0, entry.reward_value);
        try expectFloatClose(50.0, entry.size);
        try expectFloatClose(11.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x3E,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(1000.0, entry.hp);
        try expectFloatClose(3.36, entry.move_speed);
        try expectFloatClose(500.0, entry.reward_value);
        try expectFloatClose(64.0, entry.size);
        try expectFloatClose(40.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x3F,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(200.0, entry.hp);
        try expectFloatClose(2.76, entry.move_speed);
        try expectFloatClose(210.0, entry.reward_value);
        try expectFloatClose(35.0, entry.size);
        try expectFloatClose(20.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x40,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(70.0, entry.hp);
        try expectFloatClose(2.64, entry.move_speed);
        try expectFloatClose(160.0, entry.reward_value);
        try expectFloatClose(45.0, entry.size);
        try expectFloatClose(5.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x41,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.zombie)), entry.type_id);
        try std.testing.expectEqual(@as(u32, 0), entry.flags);
        try expectFloatClose(60.28571701049805, entry.hp);
        try expectFloatClose(1.01, entry.move_speed);
        try expectFloatClose(138.0, entry.reward_value);
        try expectFloatClose(44.0, entry.size);
        try expectFloatClose(13.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x42,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.zombie)), entry.type_id);
        try std.testing.expectEqual(@as(u32, 0), entry.flags);
        try expectFloatClose(200.0, entry.hp);
        try expectFloatClose(1.7, entry.move_speed);
        try expectFloatClose(160.0, entry.reward_value);
        try expectFloatClose(45.0, entry.size);
        try expectFloatClose(15.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x43,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.zombie)), entry.type_id);
        try std.testing.expectEqual(@as(u32, 0), entry.flags);
        try expectFloatClose(2000.0, entry.hp);
        try expectFloatClose(2.1, entry.move_speed);
        try expectFloatClose(460.0, entry.reward_value);
        try expectFloatClose(70.0, entry.size);
        try expectFloatClose(15.0, entry.contact_damage);
    }
}

test "template spawn supports quest mid-tier random templates" {
    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x1A,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), entry.type_id);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player_tight, entry.ai_mode);
        try expectFloatClose(50.0, entry.hp);
        try expectFloatClose(2.4, entry.move_speed);
        try expectFloatClose(125.0, entry.reward_value);
        try expectFloatClose(50.0, entry.size);
        try expectFloatClose(5.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x1B,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player_tight, entry.ai_mode);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(40.0, entry.hp);
        try expectFloatClose(2.88, entry.move_speed);
        try expectFloatClose(125.0, entry.reward_value);
        try expectFloatClose(50.0, entry.size);
        try expectFloatClose(5.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x1C,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.lizard)), entry.type_id);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player_tight, entry.ai_mode);
        try expectFloatClose(50.0, entry.hp);
        try expectFloatClose(2.4, entry.move_speed);
        try expectFloatClose(125.0, entry.reward_value);
        try expectFloatClose(50.0, entry.size);
        try expectFloatClose(5.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x1D,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), entry.type_id);
        try expectFloatClose(66.0, entry.hp);
        try expectFloatClose(2.1, entry.move_speed);
        try expectFloatClose(119.0, entry.reward_value);
        try expectFloatClose(49.0, entry.size);
        try expectFloatClose(6.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x1E,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), entry.type_id);
        try expectFloatClose(99.14286041259766, entry.hp);
        try expectFloatClose(2.9, entry.move_speed);
        try expectFloatClose(219.0, entry.reward_value);
        try expectFloatClose(39.0, entry.size);
        try expectFloatClose(26.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x1F,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), entry.type_id);
        try expectFloatClose(212.0, entry.hp);
        try expectFloatClose(3.5, entry.move_speed);
        try expectFloatClose(249.0, entry.reward_value);
        try expectFloatClose(49.0, entry.size);
        try expectFloatClose(20.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x20,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), entry.type_id);
        try expectFloatClose(70.28572082519531, entry.hp);
        try expectFloatClose(1.5, entry.move_speed);
        try expectFloatClose(138.0, entry.reward_value);
        try expectFloatClose(44.0, entry.size);
        try expectFloatClose(8.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x2E,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.lizard)), entry.type_id);
        try expectFloatClose(70.28572082519531, entry.hp);
        try expectFloatClose(1.5, entry.move_speed);
        try expectFloatClose(138.0, entry.reward_value);
        try expectFloatClose(44.0, entry.size);
        try expectFloatClose(12.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x31,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.lizard)), entry.type_id);
        try expectFloatClose(60.28571701049805, entry.hp);
        try expectFloatClose(1.5, entry.move_speed);
        try expectFloatClose(138.0, entry.reward_value);
        try expectFloatClose(44.0, entry.size);
        try expectFloatClose(10.16, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x32,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(59.0, entry.hp);
        try expectFloatClose(3.0, entry.move_speed);
        try expectFloatClose(148.0, entry.reward_value);
        try expectFloatClose(49.0, entry.size);
        try expectFloatClose(10.86, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x33,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(76.0, entry.hp);
        try expectFloatClose(1.8, entry.move_speed);
        try expectFloatClose(148.0, entry.reward_value);
        try expectFloatClose(49.0, entry.size);
        try expectFloatClose(8.0, entry.contact_damage);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x34,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), entry.type_id);
        try std.testing.expect((entry.flags & spawn_mod.CreatureFlags.ai7_link_timer) != 0);
        try std.testing.expectEqual(@as(i32, 0), entry.link_index);
        try expectFloatClose(81.71428680419922, entry.hp);
        try expectFloatClose(1.8, entry.move_speed);
        try expectFloatClose(158.0, entry.reward_value);
        try expectFloatClose(54.0, entry.size);
        try expectFloatClose(8.0, entry.contact_damage);
    }
}

test "template spawn supports quest constant alien templates" {
    const template_ids = [_]i32{ 0x0F, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2D };
    const expected_health = [_]f32{ 20.0, 53.0, 25.0, 5.0, 20.0, 25.0, 50.0, 50.0, 50.0, 800.0, 50.0, 45.0 };
    const expected_speed = [_]f32{ 2.9, 1.7, 1.7, 1.7, 2.0, 2.5, 2.2, 2.1, 1.7, 2.5, 3.1, 3.1 };
    const expected_reward = [_]f32{ 60.0, 120.0, 150.0, 180.0, 110.0, 125.0, 125.0, 125.0, 150.0, 450.0, 300.0, 200.0 };
    const expected_size = [_]f32{ 50.0, 55.0, 50.0, 45.0, 50.0, 30.0, 45.0, 45.0, 55.0, 70.0, 60.0, 38.0 };
    const expected_contact = [_]f32{ 35.0, 8.0, 8.0, 8.0, 4.0, 3.0, 10.0, 10.0, 8.0, 20.0, 8.0, 3.0 };
    const expected_flags = [_]u32{ 0, 0, 0, 0, 0, 0, 0, spawn_mod.CreatureFlags.bonus_on_death, 0, 0, 0, 0 };
    const expected_ai_mode = [_]spawn_mod.CreatureAiMode{
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.orbit_player,
        spawn_mod.CreatureAiMode.chase_player,
    };

    for (template_ids, 0..) |template_id, idx| {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = template_id,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), entry.type_id);
        try std.testing.expectEqual(expected_ai_mode[idx], entry.ai_mode);
        try std.testing.expectEqual(expected_flags[idx], entry.flags);
        try expectFloatClose(expected_health[idx], entry.hp);
        try expectFloatClose(expected_speed[idx], entry.move_speed);
        try expectFloatClose(expected_reward[idx], entry.reward_value);
        try expectFloatClose(expected_size[idx], entry.size);
        try expectFloatClose(expected_contact[idx], entry.contact_damage);
    }
}

test "template spawn supports quest constant lizard templates" {
    const template_ids = [_]i32{ 0x2F, 0x30 };
    const expected_health = [_]f32{ 20.0, 1000.0 };
    const expected_speed = [_]f32{ 2.5, 2.0 };
    const expected_reward = [_]f32{ 150.0, 400.0 };
    const expected_size = [_]f32{ 45.0, 65.0 };
    const expected_contact = [_]f32{ 4.0, 10.0 };

    for (template_ids, 0..) |template_id, idx| {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = template_id,
                .pos = .{ .x = 10.0, .y = 20.0 },
                .heading = 1.23,
            },
            &rng,
        );
        const entry = pool.entries[0];
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.lizard)), entry.type_id);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player, entry.ai_mode);
        try std.testing.expectEqual(@as(u32, 0), entry.flags);
        try expectFloatClose(expected_health[idx], entry.hp);
        try expectFloatClose(expected_speed[idx], entry.move_speed);
        try expectFloatClose(expected_reward[idx], entry.reward_value);
        try expectFloatClose(expected_size[idx], entry.size);
        try expectFloatClose(expected_contact[idx], entry.contact_damage);
    }
}

test "template spawn supports quest formation templates" {
    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x14,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 82), pool.activeCount());
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.chase_player, pool.entries[0].ai_mode);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.follow_link_tethered, pool.entries[1].ai_mode);
        try std.testing.expectEqual(@as(i32, 0), pool.entries[1].link_index);
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), pool.entries[81].type_id);
        try expectFloatClose(20.0, pool.entries[81].hp);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x11,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 5), pool.activeCount());
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.lizard)), pool.entries[0].type_id);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player_tight, pool.entries[0].ai_mode);
        try std.testing.expectEqual(@as(i32, 4), pool.entries[0].link_index);
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), pool.entries[4].type_id);
        try expectFloatClose(20.0, pool.entries[4].hp);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x13,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 11), pool.activeCount());
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_link, pool.entries[0].ai_mode);
        try expectFloatClose(768.0, pool.entries[0].pos.x);
        try std.testing.expectEqual(@as(i32, 10), pool.entries[0].link_index);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_link, pool.entries[1].ai_mode);
        try std.testing.expectEqual(@as(i32, 0), pool.entries[1].link_index);
        try expectFloatClose(std.math.pi, pool.entries[1].orbit_angle);
        try expectFloatClose(10.0, pool.entries[1].orbit_radius);
        try expectFloatClose(20.0, pool.entries[10].hp);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x15,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 82), pool.activeCount());
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.chase_player, pool.entries[0].ai_mode);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.link_guard, pool.entries[1].ai_mode);
        try std.testing.expectEqual(@as(i32, 0), pool.entries[1].link_index);
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), pool.entries[81].type_id);
        try expectFloatClose(20.0, pool.entries[81].hp);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x16,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 82), pool.activeCount());
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.lizard)), pool.entries[0].type_id);
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.lizard)), pool.entries[1].type_id);
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), pool.entries[81].type_id);
        try expectFloatClose(20.0, pool.entries[81].hp);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x17,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 82), pool.activeCount());
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), pool.entries[0].type_id);
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.spider_sp1)), pool.entries[1].type_id);
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), pool.entries[81].type_id);
        try expectFloatClose(20.0, pool.entries[81].hp);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x18,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 82), pool.activeCount());
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.chase_player, pool.entries[0].ai_mode);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.follow_link, pool.entries[1].ai_mode);
        try expectFloatClose(260.0, pool.entries[81].hp);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x19,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 6), pool.activeCount());
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player, pool.entries[0].ai_mode);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.follow_link_tethered, pool.entries[1].ai_mode);
        try std.testing.expectEqual(@as(i32, 0), pool.entries[1].link_index);
        try expectFloatClose(110.0, pool.entries[1].target_offset.x);
        try expectFloatClose(0.0, pool.entries[1].target_offset.y);
        try expectFloatClose(622.0, pool.entries[1].pos.x);
        try expectFloatClose(512.0, pool.entries[1].pos.y);
    }
}

test "template spawn supports quest spawner templates and slot ticks" {
    const spawners = [_]struct {
        template_id: i32,
        expected_type_id: i32,
        expected_flags: u32,
        expected_health: f32,
        expected_move_speed: f32,
        expected_reward: f32,
        expected_size: f32,
        expected_contact: f32,
        expected_timer: f32,
        expected_limit: i32,
        expected_interval: f32,
        expected_child_template: i32,
    }{
        .{ .template_id = 0x00, .expected_type_id = @intFromEnum(spawn_mod.CreatureTypeId.zombie), .expected_flags = spawn_mod.CreatureFlags.anim_ping_pong | spawn_mod.CreatureFlags.anim_long_strip, .expected_health = 8500.0, .expected_move_speed = 1.3, .expected_reward = 6600.0, .expected_size = 64.0, .expected_contact = 50.0, .expected_timer = 1.0, .expected_limit = 812, .expected_interval = 0.7, .expected_child_template = 0x41 },
        .{ .template_id = 0x07, .expected_type_id = @intFromEnum(spawn_mod.CreatureTypeId.alien), .expected_flags = spawn_mod.CreatureFlags.anim_ping_pong, .expected_health = 1000.0, .expected_move_speed = 2.0, .expected_reward = 3000.0, .expected_size = 50.0, .expected_contact = 0.0, .expected_timer = 1.0, .expected_limit = 100, .expected_interval = 2.2, .expected_child_template = 0x1D },
        .{ .template_id = 0x08, .expected_type_id = @intFromEnum(spawn_mod.CreatureTypeId.alien), .expected_flags = spawn_mod.CreatureFlags.anim_ping_pong, .expected_health = 1000.0, .expected_move_speed = 2.0, .expected_reward = 3000.0, .expected_size = 50.0, .expected_contact = 0.0, .expected_timer = 1.0, .expected_limit = 100, .expected_interval = 2.8, .expected_child_template = 0x1D },
        .{ .template_id = 0x09, .expected_type_id = @intFromEnum(spawn_mod.CreatureTypeId.alien), .expected_flags = spawn_mod.CreatureFlags.anim_ping_pong, .expected_health = 450.0, .expected_move_speed = 2.0, .expected_reward = 1000.0, .expected_size = 40.0, .expected_contact = 0.0, .expected_timer = 1.0, .expected_limit = 16, .expected_interval = 2.0, .expected_child_template = 0x1D },
        .{ .template_id = 0x0A, .expected_type_id = @intFromEnum(spawn_mod.CreatureTypeId.alien), .expected_flags = spawn_mod.CreatureFlags.anim_ping_pong, .expected_health = 1000.0, .expected_move_speed = 1.5, .expected_reward = 3000.0, .expected_size = 55.0, .expected_contact = 0.0, .expected_timer = 2.0, .expected_limit = 100, .expected_interval = 5.0, .expected_child_template = 0x32 },
        .{ .template_id = 0x0B, .expected_type_id = @intFromEnum(spawn_mod.CreatureTypeId.alien), .expected_flags = spawn_mod.CreatureFlags.anim_ping_pong, .expected_health = 3500.0, .expected_move_speed = 1.5, .expected_reward = 5000.0, .expected_size = 65.0, .expected_contact = 0.0, .expected_timer = 2.0, .expected_limit = 100, .expected_interval = 6.0, .expected_child_template = 0x3C },
        .{ .template_id = 0x0C, .expected_type_id = @intFromEnum(spawn_mod.CreatureTypeId.alien), .expected_flags = spawn_mod.CreatureFlags.anim_ping_pong, .expected_health = 50.0, .expected_move_speed = 2.8, .expected_reward = 1000.0, .expected_size = 32.0, .expected_contact = 0.0, .expected_timer = 1.5, .expected_limit = 100, .expected_interval = 2.0, .expected_child_template = 0x31 },
        .{ .template_id = 0x0D, .expected_type_id = @intFromEnum(spawn_mod.CreatureTypeId.alien), .expected_flags = spawn_mod.CreatureFlags.anim_ping_pong, .expected_health = 50.0, .expected_move_speed = 1.3, .expected_reward = 1000.0, .expected_size = 32.0, .expected_contact = 0.0, .expected_timer = 2.0, .expected_limit = 100, .expected_interval = 6.0, .expected_child_template = 0x31 },
        .{ .template_id = 0x10, .expected_type_id = @intFromEnum(spawn_mod.CreatureTypeId.alien), .expected_flags = spawn_mod.CreatureFlags.anim_ping_pong, .expected_health = 50.0, .expected_move_speed = 2.8, .expected_reward = 800.0, .expected_size = 32.0, .expected_contact = 0.0, .expected_timer = 1.5, .expected_limit = 100, .expected_interval = 2.3, .expected_child_template = 0x32 },
    };

    for (spawners) |spawner| {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = spawner.template_id,
                .pos = .{ .x = 256.0, .y = 128.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 1), pool.activeCount());
        const parent = pool.entries[0];
        try std.testing.expectEqual(spawner.expected_type_id, parent.type_id);
        try std.testing.expectEqual(spawner.expected_flags, parent.flags);
        try expectFloatClose(spawner.expected_health, parent.hp);
        try expectFloatClose(spawner.expected_move_speed, parent.move_speed);
        try expectFloatClose(spawner.expected_reward, parent.reward_value);
        try expectFloatClose(spawner.expected_size, parent.size);
        try expectFloatClose(spawner.expected_contact, parent.contact_damage);
        try std.testing.expectEqual(@as(usize, 1), pool.spawn_slot_count);
        const slot = pool.spawn_slots[0];
        try std.testing.expectEqual(@as(i32, 0), slot.owner_creature);
        try expectFloatClose(spawner.expected_timer, slot.timer);
        try std.testing.expectEqual(spawner.expected_limit, slot.limit);
        try expectFloatClose(spawner.expected_interval, slot.interval);
        try std.testing.expectEqual(spawner.expected_child_template, slot.child_template_id);
    }

    {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(1);
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x0E,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &rng,
        );
        try std.testing.expectEqual(@as(usize, 25), pool.activeCount());
        try std.testing.expectEqual(@as(usize, 1), pool.spawn_slot_count);
        try std.testing.expectEqual(@as(i32, 0x1C), pool.spawn_slots[0].child_template_id);
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), pool.entries[0].type_id);
        try std.testing.expectEqual(spawn_mod.CreatureAiMode.follow_link, pool.entries[1].ai_mode);
    }

    {
        var pool: CreaturePool = .{};
        var state = state_mod.GameplayState.init(1);
        var bonuses: bonus_runtime.BonusPool = .{};
        var players = [_]state_mod.PlayerState{
            .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
        };
        try pool.spawnTemplateCall(
            .{
                .template_id = 0x07,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = std.math.pi,
            },
            &state.rng,
        );
        try std.testing.expectEqual(@as(usize, 1), pool.activeCount());

        try pool.update(&state, players[0..], 1.1, 1024.0, &bonuses);

        try std.testing.expectEqual(@as(usize, 2), pool.activeCount());
        try std.testing.expectEqual(@as(i32, 1), pool.spawn_slots[0].count);
        try std.testing.expectEqual(@as(i32, @intFromEnum(spawn_mod.CreatureTypeId.alien)), pool.entries[1].type_id);
    }
}

test "template spawn rejects invalid template ids" {
    var pool: CreaturePool = .{};
    var rng = spawn_mod.Crand.init(1);

    try std.testing.expectError(
        error.InvalidSpawnTemplate,
        pool.spawnTemplateCall(
            .{
                .template_id = 0x44,
                .pos = .{ .x = 0.0, .y = 0.0 },
                .heading = 0.0,
            },
            &rng,
        ),
    );
}

test "runtime-context template spawn enqueues presentation burst" {
    var pool: CreaturePool = .{};
    var effects: effects_mod.EffectPool = .{};
    var state = state_mod.GameplayState.init(1);
    pool.effects = &effects;

    try pool.spawnTemplateCallWithRuntimeContext(
        .{
            .template_id = 0x24,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
        },
        &state.rng,
        &state,
        1024.0,
    );

    try std.testing.expectEqual(effects_mod.effect_pool_size - @as(usize, 8), effects.free_len);
}

test "creature update fails on invalid spawn slot child template" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };

    pool.entries[0] = .{
        .active = true,
        .pos = .{ .x = 512.0, .y = 512.0 },
        .heading = 0.0,
    };
    pool.spawn_slot_count = 1;
    pool.spawn_slots[0] = .{
        .owner_creature = 0,
        .timer = 0.0,
        .count = 0,
        .limit = 1,
        .interval = 1.0,
        .child_template_id = 0x44,
    };

    try std.testing.expectError(
        error.InvalidSpawnTemplate,
        pool.update(&state, players[0..], 0.1, 1024.0, &bonuses),
    );
}

test "template spawn supports all documented template ids except unused 0x02" {
    var template_id: i32 = 0;
    while (template_id < 0x44) : (template_id += 1) {
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(0xBEEF);
        if (template_id == 0x02) {
            try std.testing.expectError(
                error.InvalidSpawnTemplate,
                pool.spawnTemplateCall(
                    .{
                        .template_id = template_id,
                        .pos = .{ .x = 512.0, .y = 512.0 },
                        .heading = 0.0,
                    },
                    &rng,
                ),
            );
            continue;
        }
        try pool.spawnTemplateCall(
            .{
                .template_id = template_id,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = 0.0,
            },
            &rng,
        );
    }
}

test "template spawn child references resolve to known template ids" {
    var template_id: i32 = 0;
    while (template_id < 0x44) : (template_id += 1) {
        if (template_id == 0x02) continue;
        var pool: CreaturePool = .{};
        var rng = spawn_mod.Crand.init(0xBEEF);
        try pool.spawnTemplateCall(
            .{
                .template_id = template_id,
                .pos = .{ .x = 512.0, .y = 512.0 },
                .heading = 0.0,
            },
            &rng,
        );
        for (pool.spawn_slots[0..pool.spawn_slot_count]) |slot| {
            try std.testing.expect(isKnownTemplateId(slot.child_template_id));
        }
    }
}

fn isKnownTemplateId(template_id: i32) bool {
    return template_id == 0x00 or
        template_id == 0x01 or
        (template_id >= 0x03 and template_id <= 0x43);
}

test "creature update applies contact damage and movement" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
        },
    };
    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 120.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 40.0,
        .max_health = 40.0,
        .reward_value = 60.0,
        .contact_damage = 7.0,
    });

    try pool.update(&state, players[0..], 1.0 / 60.0, 1024.0, &bonuses);
    try std.testing.expect(players[0].health < 100.0);
    try std.testing.expect(state.survival_reward_damage_seen);
    try expectFloatClose(1.0, pool.entries[0].attack_cooldown);
}

test "veins of poison sets self-damage flag on contact hit" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
        },
    };
    players[0].perk_counts.set(PerkId.veins_of_poison, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 60.0,
        .contact_damage = 10.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try std.testing.expect((pool.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick) != 0);
}

test "veins of poison skips self-damage flag when shielded" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
            .shield_timer = 1.0,
        },
    };
    players[0].perk_counts.set(PerkId.veins_of_poison, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 60.0,
        .contact_damage = 10.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try std.testing.expect((pool.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick) == 0);
}

test "toxic avenger sets strong self-damage flags on contact hit" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
        },
    };
    players[0].perk_counts.set(PerkId.toxic_avenger, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 60.0,
        .contact_damage = 10.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try std.testing.expect((pool.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick) != 0);
    try std.testing.expect((pool.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick_strong) != 0);
}

test "toxic avenger strong self-damage tick overrides weak tick" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 500.0, .y = 500.0 },
            .health = 100.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong |
            spawn_mod.CreatureFlags.self_damage_tick |
            spawn_mod.CreatureFlags.self_damage_tick_strong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 60.0,
        .contact_damage = 10.0,
    });

    try pool.update(&state, players[0..], 0.1, 1024.0, &bonuses);
    try expectFloatClose(82.0, pool.entries[0].hp);
}

test "toxic avenger skips strong self-damage flag when shielded" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
            .shield_timer = 1.0,
        },
    };
    players[0].perk_counts.set(PerkId.toxic_avenger, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 60.0,
        .contact_damage = 10.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try std.testing.expect((pool.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick_strong) == 0);
}

test "radioactive tick deals damage and wraps collision timer" {
    const dt = 0.2;
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
        },
    };
    players[0].perk_counts.set(PerkId.radioactive, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 46.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 50.0,
        .max_health = 50.0,
        .reward_value = 0.0,
        .contact_damage = 0.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], dt, 1024.0, &bonuses);

    const dist_after_move = state_mod.Vec2.sub(pool.entries[0].pos, players[0].pos).length();
    const expected_damage = narrowF32(narrowF32(100.0 - dist_after_move) * 0.3);
    try expectFloatClose(0.5, pool.entries[0].collision_timer);
    try expectFloatClose(narrowF32(50.0 - expected_damage), pool.entries[0].hp);
}

test "radioactive kill awards base xp without death multipliers" {
    const dt = 0.2;
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    state.bonuses.double_experience = 5.0;
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .experience = 100,
        },
    };
    players[0].perk_counts.set(PerkId.radioactive, 1);
    players[0].perk_counts.set(PerkId.bloody_mess_quick_learner, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 46.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 5.0,
        .max_health = 5.0,
        .reward_value = 12.7,
        .contact_damage = 0.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], dt, 1024.0, &bonuses);

    try std.testing.expectEqual(@as(i32, 112), players[0].experience);
    try std.testing.expect(pool.entries[0].hp < 0.0);
    try expectFloatClose(creature_lifecycle.alive - dt, pool.entries[0].lifecycle_stage);
}

test "radioactive sets hp to one for lizard type creatures" {
    const dt = 0.2;
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .experience = 100,
        },
    };
    players[0].perk_counts.set(PerkId.radioactive, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 46.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .lizard,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 5.0,
        .max_health = 5.0,
        .reward_value = 12.7,
        .contact_damage = 0.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], dt, 1024.0, &bonuses);

    try std.testing.expectEqual(@as(i32, 100), players[0].experience);
    try expectFloatClose(1.0, pool.entries[0].hp);
    try expectFloatClose(creature_lifecycle.alive, pool.entries[0].lifecycle_stage);
    try expectFloatClose(0.5, pool.entries[0].collision_timer);
}

test "mr melee damages attacking creature on contact tick" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
        },
    };
    players[0].perk_counts.set(PerkId.mr_melee, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 60.0,
        .contact_damage = 10.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try expectFloatClose(75.0, pool.entries[0].hp);
}

test "mr melee does not prevent player damage when attacker dies" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
        },
    };
    players[0].perk_counts.set(PerkId.mr_melee, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 60.0,
        .contact_damage = 10.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try expectFloatClose(90.0, players[0].health);
}

test "mr melee is inert when perk is not active" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = 100.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 60.0,
        .contact_damage = 10.0,
    });
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try expectFloatClose(100.0, pool.entries[0].hp);
}

test "evil eyes freezes targeted creature movement" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 300.0, .y = 100.0 },
            .health = 100.0,
        },
    };
    players[0].perk_counts.set(PerkId.evil_eyes, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 1.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 60.0,
        .contact_damage = 0.0,
    });
    players[0].evil_eyes_target_creature = 0;

    const before_x = pool.entries[0].pos.x;
    const before_y = pool.entries[0].pos.y;
    try pool.update(&state, players[0..], 0.5, 1024.0, &bonuses);

    try expectFloatClose(before_x, pool.entries[0].pos.x);
    try expectFloatClose(before_y, pool.entries[0].pos.y);
}

test "ai7 link timer consumes rng when timer crosses zero" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(99);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .health = 100.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .spider_sp1,
        .ai_mode = spawn_mod.CreatureAiMode.orbit_player,
        .flags = spawn_mod.CreatureFlags.ai7_link_timer,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 25.0,
        .max_health = 25.0,
        .reward_value = 50.0,
        .contact_damage = 3.0,
    });

    var expected_rng = state.rng;
    _ = expected_rng.rand();

    try pool.update(&state, players[0..], 0.017, 1024.0, &bonuses);

    try std.testing.expectEqual(expected_rng.state, state.rng.state);
    try std.testing.expectEqual(spawn_mod.CreatureAiMode.hold_timer, pool.entries[0].ai_mode);
    try std.testing.expect(pool.entries[0].link_index >= 500);
    try std.testing.expect(pool.entries[0].link_index <= 1011);
}

test "tough reloader halves damage while reloading" {
    var state = state_mod.GameplayState.init(1);
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .weapon = .{ .weapon_id = .pistol, .reload_active = true },
    };
    player.perk_counts.set(PerkId.tough_reloader, 1);

    applyPlayerContactDamage(
        &state,
        &player,
        10.0,
        0.1,
    );

    try expectFloatClose(95.0, player.health);
}

test "highlander prevents contact damage except 1-in-10 lethal roll" {
    const safe_seed: u32 = 1;
    const lethal_seed: u32 = 16;

    var safe_state = state_mod.GameplayState.init(safe_seed);
    var safe_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
    };
    safe_player.perk_counts.set(PerkId.highlander, 1);
    safe_player.perk_counts.set(PerkId.unstoppable, 1);
    applyPlayerContactDamage(&safe_state, &safe_player, 10.0, 0.1);
    try expectFloatClose(100.0, safe_player.health);

    var lethal_state = state_mod.GameplayState.init(lethal_seed);
    var lethal_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
    };
    lethal_player.perk_counts.set(PerkId.highlander, 1);
    lethal_player.perk_counts.set(PerkId.unstoppable, 1);
    applyPlayerContactDamage(&lethal_state, &lethal_player, 10.0, 0.1);
    try expectFloatClose(0.0, lethal_player.health);
}

test "unstoppable suppresses heading jitter and spread heat on damage" {
    const jitter_seed: u32 = 42;

    var base_state = state_mod.GameplayState.init(jitter_seed);
    var base_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .heading = 1.0,
        .spread_heat = 0.1,
    };
    applyPlayerContactDamage(&base_state, &base_player, 10.0, 0.1);
    try expectFloatClose(90.0, base_player.health);
    try expectFloatClose(-1.0, base_player.heading);
    try expectFloatClose(0.2, base_player.spread_heat);

    var perk_state = state_mod.GameplayState.init(jitter_seed);
    var perk_player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .heading = 1.0,
        .spread_heat = 0.1,
    };
    perk_player.perk_counts.set(PerkId.unstoppable, 1);
    applyPlayerContactDamage(&perk_state, &perk_player, 10.0, 0.1);
    try expectFloatClose(90.0, perk_player.health);
    try expectFloatClose(1.0, perk_player.heading);
    try expectFloatClose(0.1, perk_player.spread_heat);
}

test "tough reloader spread heat uses post-reload damage before thick skinned" {
    var state = state_mod.GameplayState.init(1);
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{},
        .health = 100.0,
        .weapon = .{ .weapon_id = .pistol, .reload_active = true },
        .spread_heat = 0.1,
    };
    player.perk_counts.set(PerkId.tough_reloader, 1);
    player.perk_counts.set(PerkId.thick_skinned, 1);

    applyPlayerContactDamage(
        &state,
        &player,
        10.0,
        0.1,
    );

    try expectFloatClose(0.15, player.spread_heat);
}

test "doctor increases projectile damage by 20 percent" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    players[0].perk_counts.set(PerkId.doctor, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    _ = pool.applyProjectileDamage(
        &state,
        players[0..],
        &bonuses,
        0,
        10.0,
        .{},
        owner_local_player,
        0.016,
        10_000.0,
    );
    try expectFloatClose(88.0, pool.entries[0].hp);
}

test "pyromaniac increases fire damage and consumes rng" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
        },
    };
    players[0].perk_counts.set(PerkId.pyromaniac, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    const before_rng = state.rng.state;
    _ = pool.applyFireDamage(
        &state,
        players[0..],
        &bonuses,
        0,
        10.0,
        .{},
        owner_local_player,
        0.016,
        1024.0,
    );

    try expectFloatClose(85.0, pool.entries[0].hp);
    try std.testing.expect(before_rng != state.rng.state);
}

test "fire damage without pyromaniac keeps base damage and rng state" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    const before_rng = state.rng.state;
    _ = pool.applyFireDamage(
        &state,
        players[0..],
        &bonuses,
        0,
        10.0,
        .{},
        owner_local_player,
        0.016,
        1024.0,
    );

    try expectFloatClose(90.0, pool.entries[0].hp);
    try std.testing.expectEqual(before_rng, state.rng.state);
}

test "living fortress scales projectile damage by alive player timers" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
    };
    players[0].perk_counts.set(PerkId.living_fortress, 1);
    players[0].living_fortress_timer = 10.0;
    players[1].living_fortress_timer = 20.0;

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    _ = pool.applyProjectileDamage(
        &state,
        players[0..],
        &bonuses,
        0,
        10.0,
        .{},
        owner_local_player,
        0.016,
        10_000.0,
    );
    try expectFloatClose(70.0, pool.entries[0].hp);
}

test "barrel greaser increases projectile damage by 40 percent" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    players[0].perk_counts.set(PerkId.barrel_greaser, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    _ = pool.applyProjectileDamage(
        &state,
        players[0..],
        &bonuses,
        &terrain_fx,
        0,
        10.0,
        .{},
        owner_local_player,
        0.016,
        10_000.0,
    );
    try expectFloatClose(86.0, pool.entries[0].hp);
}

test "ion gun master increases ion damage by 20 percent" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    players[0].perk_counts.set(PerkId.ion_gun_master, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    _ = pool.applyIonDamage(
        &state,
        players[0..],
        &bonuses,
        &terrain_fx,
        0,
        10.0,
        .{},
        owner_local_player,
        0.016,
        10_000.0,
    );
    try expectFloatClose(88.0, pool.entries[0].hp);
}

test "uranium filled bullets doubles projectile damage" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    players[0].perk_counts.set(PerkId.uranium_filled_bullets, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 10.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    _ = pool.applyProjectileDamage(
        &state,
        players[0..],
        &bonuses,
        &terrain_fx,
        0,
        10.0,
        .{},
        owner_local_player,
        0.016,
        10_000.0,
    );
    try expectFloatClose(80.0, pool.entries[0].hp);
}

test "split on death spawns two smaller children" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(0);
    var bonuses: bonus_runtime.BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .spider_sp2,
        .flags = spawn_mod.CreatureFlags.split_on_death,
        .size = 40.0,
        .move_speed = 2.0,
        .health = 400.0,
        .max_health = 400.0,
        .reward_value = 90.0,
        .contact_damage = 10.0,
    });

    _ = pool.killNoCorpse(
        &state,
        players[0..],
        &bonuses,
        &terrain_fx,
        0,
        owner_local_player,
        0.016,
        10_000.0,
    );

    const child1 = pool.entries[1];
    const child2 = pool.entries[2];
    try std.testing.expect(child1.active and child2.active);
    try expectFloatClose(creature_lifecycle.alive, child1.lifecycle_stage);
    try expectFloatClose(creature_lifecycle.alive, child2.lifecycle_stage);
    try std.testing.expect(child1.phase_seed >= 0.0 and child1.phase_seed <= 255.0);
    try std.testing.expect(child2.phase_seed >= 0.0 and child2.phase_seed <= 255.0);
    try expectFloatClose(-native_half_pi, child1.heading);
    try expectFloatClose(native_half_pi, child2.heading);
    try expectFloatClose(100.0, child1.hp);
    try expectFloatClose(100.0, child2.hp);
    try expectFloatClose(32.0, child1.size);
    try expectFloatClose(32.0, child2.size);
    try expectFloatClose(2.1, child1.move_speed);
    try expectFloatClose(2.1, child2.move_speed);
    try expectFloatClose(7.0, child1.contact_damage);
    try expectFloatClose(7.0, child2.contact_damage);
    try expectFloatClose(60.0, child1.reward_value);
    try expectFloatClose(60.0, child2.reward_value);
}

test "kill no corpse does not award xp for non-player owner" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 40.0,
        .move_speed = 2.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 90.0,
        .contact_damage = 10.0,
    });

    const gained = pool.killNoCorpse(
        &state,
        players[0..],
        &bonuses,
        &terrain_fx,
        0,
        owner_ref.OwnerRef.fromCreature(0),
        0.016,
        10_000.0,
    );

    try std.testing.expectEqual(@as(i32, 0), gained);
    try std.testing.expectEqual(@as(i32, 0), players[0].experience);
}

test "ranged shock creature queues projectile along heading not direct aim" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 0.0, .y = 200.0 },
            .health = 100.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 0.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .ai_mode = spawn_mod.CreatureAiMode.chase_player,
        .flags = spawn_mod.CreatureFlags.ranged_attack_shock,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });

    try pool.update(&state, players[0..], 0.001, 1024.0, &bonuses);

    try std.testing.expectEqual(@as(i32, 1), state.pending_creature_projectile_count);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), state.pending_creature_projectiles[0].type_id);
    try std.testing.expectEqual(@as(i32, 0), state.pending_creature_projectiles[0].owner.toLegacy());
    try expectFloatClose(pool.entries[0].heading, state.pending_creature_projectiles[0].angle);

    const direct_aim = narrowF32(math.atan2(
        players[0].pos.y - pool.entries[0].pos.y,
        players[0].pos.x - pool.entries[0].pos.x,
    ) + native_half_pi);
    try std.testing.expect(@abs(wrapAngle(state.pending_creature_projectiles[0].angle - direct_aim)) > 0.1);
}

test "ranged shock creature does not fire when too close" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 0.0, .y = 64.0 },
            .health = 100.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 0.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .ai_mode = spawn_mod.CreatureAiMode.chase_player,
        .flags = spawn_mod.CreatureFlags.ranged_attack_shock,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });

    try pool.update(&state, players[0..], 0.001, 1024.0, &bonuses);
    try std.testing.expectEqual(@as(i32, 0), state.pending_creature_projectile_count);
}

test "ranged variant uses explicit projectile type and random cooldown" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(3);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 0.0, .y = 200.0 },
            .health = 100.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 0.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .spider_sp1,
        .ai_mode = spawn_mod.CreatureAiMode.chase_player,
        .flags = spawn_mod.CreatureFlags.ranged_attack_variant,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });
    pool.entries[0].ranged_projectile_type = @intFromEnum(game_ids.ProjectileTypeId.spider_plasma);
    pool.entries[0].orbit_angle = 0.4;

    try pool.update(&state, players[0..], 0.001, 1024.0, &bonuses);
    try std.testing.expectEqual(@as(i32, 1), state.pending_creature_projectile_count);
    try std.testing.expectEqual(@as(i32, 26), state.pending_creature_projectiles[0].type_id);
    try expectFloatClose(0.4, pool.entries[0].attack_cooldown);
}

test "freeze stops creature movement" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .health = 100.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    const moved_x = pool.entries[0].pos.x;
    const moved_y = pool.entries[0].pos.y;
    try std.testing.expect(!(moved_x == 100.0 and moved_y == 200.0));

    state.bonuses.freeze = 5.0;
    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try expectFloatClose(moved_x, pool.entries[0].pos.x);
    try expectFloatClose(moved_y, pool.entries[0].pos.y);
}

test "plaguebearer infects weak creatures near player" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .plaguebearer_active = true,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 120.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 10.0,
        .contact_damage = 4.0,
    });

    try pool.update(&state, players[0..], 0.016, 1024.0, &bonuses);
    try std.testing.expect(pool.entries[0].plague_infected);
}

test "plaguebearer infection timer wrap applies damage" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 500.0, .y = 500.0 },
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 10.0,
        .contact_damage = 4.0,
    });
    pool.entries[0].plague_infected = true;
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try expectFloatClose(0.4, pool.entries[0].collision_timer);
    try expectFloatClose(85.0, pool.entries[0].hp);
}

test "plaguebearer spreads between nearby creatures" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 500.0, .y = 500.0 },
        },
    };
    players[0].perk_counts.set(PerkId.plaguebearer, 1);

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 10.0,
        .contact_damage = 4.0,
    });
    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 130.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 10.0,
        .contact_damage = 4.0,
    });
    pool.entries[0].plague_infected = true;

    try pool.update(&state, players[0..], 0.016, 1024.0, &bonuses);
    try std.testing.expect(pool.entries[1].plague_infected);
}

test "plaguebearer infection kill increments global count" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    state.bonus_spawn_guard = true;
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 500.0, .y = 500.0 },
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 4.0,
    });
    pool.entries[0].plague_infected = true;
    pool.entries[0].collision_timer = 0.1;

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);
    try std.testing.expectEqual(@as(i32, 1), state.plaguebearer_infection_count);
    try std.testing.expect(players[0].experience > 0);
}

test "plague timer kill preserves split-on-death child spawn behavior" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    state.bonus_spawn_guard = true;
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 500.0, .y = 500.0 },
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong | spawn_mod.CreatureFlags.split_on_death,
        .size = 48.0,
        .move_speed = 1.0,
        .health = 10.0,
        .max_health = 400.0,
        .reward_value = 90.0,
        .contact_damage = 4.0,
    });
    pool.entries[0].plague_infected = true;
    pool.entries[0].collision_timer = 0.01;
    pool.entries[0].last_hit_owner = owner_ref.OwnerRef.fromPlayer(0);

    try pool.update(&state, players[0..], 0.2, 1024.0, &bonuses);

    try std.testing.expectEqual(@as(i32, 1), state.plaguebearer_infection_count);
    var active_count: usize = 0;
    for (pool.entries) |entry| {
        if (entry.active) active_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), active_count);
    try std.testing.expect(pool.entries[0].active);
    try std.testing.expect(pool.entries[0].hp < 0.0);
    try expectFloatClose(creature_lifecycle.alive - 0.2, pool.entries[0].lifecycle_stage);
    try std.testing.expect(pool.entries[1].active);
    try std.testing.expect(pool.entries[2].active);
    try expectFloatClose(40.0, pool.entries[1].size);
    try expectFloatClose(40.0, pool.entries[2].size);
    try expectFloatClose(60.0, pool.entries[1].reward_value);
    try expectFloatClose(60.0, pool.entries[2].reward_value);
    try expectFloatClose(100.0, pool.entries[1].hp);
    try expectFloatClose(100.0, pool.entries[2].hp);
}

test "plaguebearer infection kill does not apply immediate dead decay" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    state.bonus_spawn_guard = true;
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 500.0, .y = 500.0 },
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 120.0, .y = 370.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 4.0,
    });
    pool.entries[0].plague_infected = true;
    pool.entries[0].collision_timer = 0.01;

    const dt = 0.063;
    try pool.update(&state, players[0..], dt, 1024.0, &bonuses);
    try expectFloatClose(creature_lifecycle.alive - dt, pool.entries[0].lifecycle_stage);
}

test "single-player dead player uses dead-target AI position" {
    var pool: CreaturePool = .{};
    var state = state_mod.GameplayState.init(1);
    var bonuses: bonus_runtime.BonusPool = .{};
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 900.0, .y = 900.0 },
            .health = 0.0,
        },
    };

    _ = pool.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 500.0, .y = 500.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 45.0,
        .move_speed = 2.0,
        .health = 50.0,
        .max_health = 50.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });

    const start_pos = pool.entries[0].pos;
    try pool.update(&state, players[0..], 1.0 / 60.0, 1024.0, &bonuses);

    const expected_dead_target: state_mod.Vec2 = .{
        .x = 1024.0 * (27.0 / 64.0),
        .y = 1024.0 * (27.0 / 64.0),
    };
    const creature = pool.entries[0];
    const dead_target_dist_sq = state_mod.Vec2.sub(creature.target, expected_dead_target).lengthSq();
    const dead_player_dist_sq = state_mod.Vec2.sub(creature.target, players[0].pos).lengthSq();
    try std.testing.expect(dead_target_dist_sq < dead_player_dist_sq);
    try std.testing.expect(creature.pos.y < start_pos.y);
    try expectFloatClose(0.0, players[0].health);
}
