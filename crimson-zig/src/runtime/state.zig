const std = @import("std");
const game_ids = @import("../game_ids.zig");
const owner_ref = @import("owner_ref.zig");
const math = @import("math.zig");

const spawn_mod = @import("spawn.zig");

pub const WeaponId = game_ids.WeaponId;
pub const PerkId = game_ids.PerkId;
pub const GameModeId = game_ids.GameModeId;

pub const max_players: usize = 4;
pub const weapon_count_size: usize = 54;
pub const perk_count_size: usize = @typeInfo(PerkId).@"enum".fields.len;
const PerkCounts = std.EnumArray(PerkId, i32);
pub const WeaponUsageCounts = std.EnumArray(WeaponId, u32);
pub const WeaponAvailability = std.EnumArray(WeaponId, bool);
pub const PerkAvailability = std.EnumArray(PerkId, bool);

pub const Vec2 = struct {
    x: f32 = 0.0,
    y: f32 = 0.0,

    pub fn add(a: Vec2, b: Vec2) Vec2 {
        return .{
            .x = a.x + b.x,
            .y = a.y + b.y,
        };
    }

    pub fn sub(a: Vec2, b: Vec2) Vec2 {
        return .{
            .x = a.x - b.x,
            .y = a.y - b.y,
        };
    }

    pub fn mul(self: Vec2, scalar: f32) Vec2 {
        return .{
            .x = self.x * scalar,
            .y = self.y * scalar,
        };
    }

    pub fn lengthSq(self: Vec2) f32 {
        return self.x * self.x + self.y * self.y;
    }

    pub fn length(self: Vec2) f32 {
        return std.math.sqrt(self.lengthSq());
    }

    pub fn clampRect(
        self: Vec2,
        min_x: f32,
        min_y: f32,
        max_x: f32,
        max_y: f32,
    ) Vec2 {
        return .{
            .x = std.math.clamp(self.x, min_x, max_x),
            .y = std.math.clamp(self.y, min_y, max_y),
        };
    }

    pub fn fromAngle(angle: f32) Vec2 {
        return .{
            .x = math.cos(angle),
            .y = math.sin(angle),
        };
    }

    pub fn toAngle(self: Vec2) f32 {
        return math.atan2(self.y, self.x);
    }

    pub fn toHeading(self: Vec2) f32 {
        return self.toAngle() + std.math.pi / 2.0;
    }
};

pub const PlayerState = struct {
    index: i32,
    pos: Vec2,
    health: f32 = 100.0,
    size: f32 = 48.0,

    speed_multiplier: f32 = 2.0,
    move_speed: f32 = 0.0,
    move_phase: f32 = 0.0,
    heading: f32 = 0.0,
    turn_speed: f32 = 1.0,
    death_timer: f32 = 16.0,
    low_health_timer: f32 = 100.0,

    aim: Vec2 = .{},
    aim_heading: f32 = 0.0,
    aim_dir: Vec2 = .{ .x = 1.0, .y = 0.0 },

    weapon_id: WeaponId = .pistol,
    clip_size: i32 = 0,
    ammo: f32 = 0.0,
    reload_active: bool = false,
    reload_timer: f32 = 0.0,
    reload_timer_max: f32 = 0.0,
    shot_cooldown: f32 = 0.0,
    shot_seq: i32 = 0,
    weapon_reset_latch: i32 = 0,
    aux_timer: f32 = 0.0,
    spread_heat: f32 = 0.01,
    muzzle_flash_alpha: f32 = 0.0,

    alt_weapon_id: ?WeaponId = null,
    alt_clip_size: i32 = 0,
    alt_ammo: f32 = 0.0,
    alt_reload_active: bool = false,
    alt_reload_timer: f32 = 0.0,
    alt_reload_timer_max: f32 = 0.0,
    alt_shot_cooldown: f32 = 0.0,
    reload_stationary_latch: bool = true,

    experience: i32 = 0,
    level: i32 = 1,

    perk_counts: PerkCounts = PerkCounts.initFill(0),
    evil_eyes_target_creature: i32 = -1,
    plaguebearer_active: bool = false,
    hot_tempered_timer: f32 = 0.0,
    man_bomb_timer: f32 = 0.0,
    living_fortress_timer: f32 = 0.0,
    fire_cough_timer: f32 = 0.0,
    speed_bonus_timer: f32 = 0.0,
    shield_timer: f32 = 0.0,
    fire_bullets_timer: f32 = 0.0,
    bonus_aim_hover_index: i32 = -1,
    bonus_aim_hover_timer_ms: f32 = 0.0,
};

pub const PerkSelectionState = struct {
    pending_count: i32 = 0,
    choices: [7]PerkId = [_]PerkId{.antiperk} ** 7,
    choice_count: usize = 0,
    choices_dirty: bool = true,
};

pub const BonusTimers = struct {
    weapon_power_up: f32 = 0.0,
    reflex_boost: f32 = 0.0,
    energizer: f32 = 0.0,
    double_experience: f32 = 0.0,
    freeze: f32 = 0.0,
};

pub const PendingCreatureProjectile = struct {
    type_id: i32 = 0,
    owner: owner_ref.OwnerRef = .{ .none = {} },
    angle: f32 = 0.0,
    pos: Vec2 = .{},
};

pub const GameplayState = struct {
    rng: spawn_mod.Crand,
    fx_toggle: i32 = 0,
    bonuses: BonusTimers = .{},
    plaguebearer_infection_count: i32 = 0,
    time_scale_active: bool = false,
    perk_selection: PerkSelectionState = .{},
    demo_mode_active: bool = false,
    game_tune_started: bool = false,
    hardcore: bool = false,
    preserve_bugs: bool = false,
    game_mode: GameModeId = .survival,
    friendly_fire_enabled: bool = false,
    lean_mean_exp_timer: f32 = 0.25,
    jinxed_timer: f32 = 0.0,
    perk_interval_man_bomb: f32 = 4.0,
    perk_interval_fire_cough: f32 = 2.0,
    perk_interval_hot_tempered: f32 = 2.0,
    quest_stage_major: i32 = 0,
    quest_stage_minor: i32 = 0,
    status_quest_unlock_index: i32 = 0,
    status_quest_unlock_index_full: i32 = 0,
    status_weapon_usage_counts: WeaponUsageCounts = WeaponUsageCounts.initFill(0),
    weapon_available: WeaponAvailability = WeaponAvailability.initFill(false),
    weapon_available_game_mode: ?GameModeId = null,
    weapon_available_unlock_index: i32 = -1,
    weapon_available_unlock_index_full: i32 = -1,
    perk_available: PerkAvailability = PerkAvailability.initFill(false),
    perk_available_unlock_index: i32 = -1,

    survival_reward_weapon_guard_id: WeaponId = .pistol,
    survival_reward_handout_enabled: bool = true,
    survival_reward_fire_seen: bool = false,
    survival_reward_damage_seen: bool = false,
    survival_recent_death_pos: [3]Vec2 = [_]Vec2{ .{}, .{}, .{} },
    survival_recent_death_count: i32 = 0,

    shots_fired: [max_players]i32 = [_]i32{0} ** max_players,
    shots_fired_total: i32 = 0,
    shots_hit: [max_players]i32 = [_]i32{0} ** max_players,
    weapon_shots_fired: [max_players][weapon_count_size]i32 = [_][weapon_count_size]i32{[_]i32{0} ** weapon_count_size} ** max_players,
    bonus_spawn_guard: bool = false,
    camera_shake_pulses: i32 = 0,
    camera_shake_timer: f32 = 0.0,
    camera_shake_offset: Vec2 = .{},
    shock_chain_links_left: i32 = 0,
    shock_chain_projectile_id: i32 = -1,
    pending_creature_projectile_count: i32 = 0,
    pending_creature_projectiles: [64]PendingCreatureProjectile = [_]PendingCreatureProjectile{.{}} ** 64,
    pending_nuke_count: i32 = 0,
    pending_nuke_origins: [8]Vec2 = [_]Vec2{.{}} ** 8,
    pending_fireblast_count: i32 = 0,
    pending_fireblast_origins: [8]Vec2 = [_]Vec2{.{}} ** 8,
    pending_shock_chain_count: i32 = 0,
    pending_shock_chain_origins: [8]Vec2 = [_]Vec2{.{}} ** 8,
    debug_nuke_kills_last: i32 = 0,
    debug_nuke_tick_last: i32 = -1,
    debug_nuke_kill_index_sum: i32 = 0,
    debug_last_picked_bonus_id: game_ids.BonusId = .unused,
    debug_last_picked_bonus_amount: i32 = 0,
    player_alt_weapon_swap_cooldown_ms: i32 = 0,
    player_spread_damping_scalar: f32 = 1.0,
    player_spread_damping_gate: f32 = 0.0,

    pub fn init(seed: u32) GameplayState {
        return .{
            .rng = spawn_mod.Crand.init(seed),
        };
    }
};

pub const PlayerShots = struct {
    fired: i32,
    hit: i32,
};

comptime {
    std.debug.assert(weapon_count_size == @typeInfo(WeaponId).@"enum".fields.len);
    for (@typeInfo(PerkId).@"enum".fields, 0..) |field, idx| {
        std.debug.assert(field.value == idx);
    }
    std.debug.assert(perk_count_size == @typeInfo(PerkId).@"enum".fields.len);
}
