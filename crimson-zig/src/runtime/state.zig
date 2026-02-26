const std = @import("std");
const game_ids = @import("../game_ids.zig");
const survival_math = @import("math.zig");

const survival_spawn = @import("spawn.zig");

pub const max_players: usize = 4;
pub const weapon_count_size: usize = 54;
pub const perk_count_size: usize = 0x80;

pub const WeaponId = game_ids.WeaponId;

const ProjectileTypeId = struct {
    pub const pistol: i32 = @intFromEnum(game_ids.ProjectileTypeId.pistol);
    pub const assault_rifle: i32 = @intFromEnum(game_ids.ProjectileTypeId.assault_rifle);
    pub const shotgun: i32 = @intFromEnum(game_ids.ProjectileTypeId.shotgun);
    pub const submachine_gun: i32 = @intFromEnum(game_ids.ProjectileTypeId.submachine_gun);
    pub const gauss_gun: i32 = @intFromEnum(game_ids.ProjectileTypeId.gauss_gun);
    pub const plasma_rifle: i32 = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle);
    pub const plasma_minigun: i32 = @intFromEnum(game_ids.ProjectileTypeId.plasma_minigun);
    pub const pulse_gun: i32 = @intFromEnum(game_ids.ProjectileTypeId.pulse_gun);
    pub const ion_rifle: i32 = @intFromEnum(game_ids.ProjectileTypeId.ion_rifle);
    pub const ion_minigun: i32 = @intFromEnum(game_ids.ProjectileTypeId.ion_minigun);
    pub const ion_cannon: i32 = @intFromEnum(game_ids.ProjectileTypeId.ion_cannon);
    pub const shrinkifier: i32 = @intFromEnum(game_ids.ProjectileTypeId.shrinkifier);
    pub const blade_gun: i32 = @intFromEnum(game_ids.ProjectileTypeId.blade_gun);
    pub const plasma_cannon: i32 = @intFromEnum(game_ids.ProjectileTypeId.plasma_cannon);
    pub const splitter_gun: i32 = @intFromEnum(game_ids.ProjectileTypeId.splitter_gun);
    pub const plague_spreader: i32 = @intFromEnum(game_ids.ProjectileTypeId.plague_spreader);
    pub const rainbow_gun: i32 = @intFromEnum(game_ids.ProjectileTypeId.rainbow_gun);
    pub const fire_bullets: i32 = @intFromEnum(game_ids.ProjectileTypeId.fire_bullets);
};

const BonusId = struct {
    pub const unused: i32 = @intFromEnum(game_ids.BonusId.unused);
    pub const points: i32 = @intFromEnum(game_ids.BonusId.points);
    pub const energizer: i32 = @intFromEnum(game_ids.BonusId.energizer);
    pub const weapon: i32 = @intFromEnum(game_ids.BonusId.weapon);
    pub const weapon_power_up: i32 = @intFromEnum(game_ids.BonusId.weapon_power_up);
    pub const nuke: i32 = @intFromEnum(game_ids.BonusId.nuke);
    pub const double_experience: i32 = @intFromEnum(game_ids.BonusId.double_experience);
    pub const shock_chain: i32 = @intFromEnum(game_ids.BonusId.shock_chain);
    pub const fireblast: i32 = @intFromEnum(game_ids.BonusId.fireblast);
    pub const reflex_boost: i32 = @intFromEnum(game_ids.BonusId.reflex_boost);
    pub const shield: i32 = @intFromEnum(game_ids.BonusId.shield);
    pub const freeze: i32 = @intFromEnum(game_ids.BonusId.freeze);
    pub const medikit: i32 = @intFromEnum(game_ids.BonusId.medikit);
    pub const speed: i32 = @intFromEnum(game_ids.BonusId.speed);
    pub const fire_bullets: i32 = @intFromEnum(game_ids.BonusId.fire_bullets);
};

pub const Vec2 = struct {
    x: f64 = 0.0,
    y: f64 = 0.0,

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

    pub fn mul(self: Vec2, scalar: f64) Vec2 {
        return .{
            .x = self.x * scalar,
            .y = self.y * scalar,
        };
    }

    pub fn lengthSq(self: Vec2) f64 {
        return self.x * self.x + self.y * self.y;
    }

    pub fn length(self: Vec2) f64 {
        return std.math.sqrt(self.lengthSq());
    }

    pub fn clampRect(
        self: Vec2,
        min_x: f64,
        min_y: f64,
        max_x: f64,
        max_y: f64,
    ) Vec2 {
        return .{
            .x = std.math.clamp(self.x, min_x, max_x),
            .y = std.math.clamp(self.y, min_y, max_y),
        };
    }

    pub fn fromAngle(angle: f64) Vec2 {
        return .{
            .x = survival_math.cos(angle),
            .y = survival_math.sin(angle),
        };
    }

    pub fn toAngle(self: Vec2) f64 {
        return survival_math.atan2(self.y, self.x);
    }

    pub fn toHeading(self: Vec2) f64 {
        return self.toAngle() + std.math.pi / 2.0;
    }
};

pub const PlayerState = struct {
    index: i32,
    pos: Vec2,
    health: f64 = 100.0,
    size: f64 = 48.0,

    speed_multiplier: f64 = 2.0,
    move_speed: f64 = 0.0,
    move_phase: f64 = 0.0,
    heading: f64 = 0.0,
    turn_speed: f64 = 1.0,
    death_timer: f64 = 16.0,
    low_health_timer: f64 = 100.0,

    aim: Vec2 = .{},
    aim_heading: f64 = 0.0,
    aim_dir: Vec2 = .{ .x = 1.0, .y = 0.0 },

    weapon_id: WeaponId = .pistol,
    clip_size: i32 = 0,
    ammo: f64 = 0.0,
    reload_active: bool = false,
    reload_timer: f64 = 0.0,
    reload_timer_max: f64 = 0.0,
    shot_cooldown: f64 = 0.0,
    shot_seq: i32 = 0,
    weapon_reset_latch: i32 = 0,
    aux_timer: f64 = 0.0,
    spread_heat: f64 = 0.01,
    muzzle_flash_alpha: f64 = 0.0,

    alt_weapon_id: ?WeaponId = null,
    alt_clip_size: i32 = 0,
    alt_ammo: f64 = 0.0,
    alt_reload_active: bool = false,
    alt_reload_timer: f64 = 0.0,
    alt_reload_timer_max: f64 = 0.0,
    alt_shot_cooldown: f64 = 0.0,
    reload_stationary_latch: bool = true,

    experience: i32 = 0,
    level: i32 = 1,

    perk_counts: [perk_count_size]i32 = [_]i32{0} ** perk_count_size,
    evil_eyes_target_creature: i32 = -1,
    plaguebearer_active: bool = false,
    hot_tempered_timer: f64 = 0.0,
    man_bomb_timer: f64 = 0.0,
    living_fortress_timer: f64 = 0.0,
    fire_cough_timer: f64 = 0.0,
    speed_bonus_timer: f64 = 0.0,
    shield_timer: f64 = 0.0,
    fire_bullets_timer: f64 = 0.0,
    bonus_aim_hover_index: i32 = -1,
    bonus_aim_hover_timer_ms: f64 = 0.0,
};

pub const PerkSelectionState = struct {
    pending_count: i32 = 0,
    choices: [7]i32 = [_]i32{0} ** 7,
    choice_count: usize = 0,
    choices_dirty: bool = true,
};

pub const BonusTimers = struct {
    weapon_power_up: f64 = 0.0,
    reflex_boost: f64 = 0.0,
    energizer: f64 = 0.0,
    double_experience: f64 = 0.0,
    freeze: f64 = 0.0,
};

pub const GameplayState = struct {
    rng: survival_spawn.Crand,
    fx_toggle: i32 = 0,
    bonuses: BonusTimers = .{},
    plaguebearer_infection_count: i32 = 0,
    time_scale_active: bool = false,
    perk_selection: PerkSelectionState = .{},
    demo_mode_active: bool = false,
    game_tune_started: bool = false,
    hardcore: bool = false,
    preserve_bugs: bool = false,
    game_mode: i32 = 1,
    friendly_fire_enabled: bool = false,
    lean_mean_exp_timer: f64 = 0.25,
    jinxed_timer: f64 = 0.0,
    perk_interval_man_bomb: f64 = 4.0,
    perk_interval_fire_cough: f64 = 2.0,
    perk_interval_hot_tempered: f64 = 2.0,
    quest_stage_major: i32 = 0,
    quest_stage_minor: i32 = 0,
    status_quest_unlock_index: i32 = 0,
    status_quest_unlock_index_full: i32 = 0,
    status_weapon_usage_counts: [weapon_count_size]u32 = [_]u32{0} ** weapon_count_size,
    weapon_available: [weapon_count_size]bool = [_]bool{false} ** weapon_count_size,
    weapon_available_game_mode: i32 = -1,
    weapon_available_unlock_index: i32 = -1,
    weapon_available_unlock_index_full: i32 = -1,
    perk_available: [perk_count_size]bool = [_]bool{false} ** perk_count_size,
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
    camera_shake_timer: f64 = 0.0,
    camera_shake_offset: Vec2 = .{},
    shock_chain_links_left: i32 = 0,
    shock_chain_projectile_id: i32 = -1,
    pending_creature_projectile_count: i32 = 0,
    pending_creature_projectile_type_ids: [64]i32 = [_]i32{0} ** 64,
    pending_creature_projectile_owner_ids: [64]i32 = [_]i32{0} ** 64,
    pending_creature_projectile_angles: [64]f64 = [_]f64{0.0} ** 64,
    pending_creature_projectile_positions: [64]Vec2 = [_]Vec2{.{}} ** 64,
    pending_nuke_count: i32 = 0,
    pending_nuke_origins: [8]Vec2 = [_]Vec2{.{}} ** 8,
    pending_fireblast_count: i32 = 0,
    pending_fireblast_origins: [8]Vec2 = [_]Vec2{.{}} ** 8,
    pending_shock_chain_count: i32 = 0,
    pending_shock_chain_origins: [8]Vec2 = [_]Vec2{.{}} ** 8,
    debug_nuke_kills_last: i32 = 0,
    debug_nuke_tick_last: i32 = -1,
    debug_nuke_kill_index_sum: i32 = 0,
    debug_last_picked_bonus_id: i32 = 0,
    debug_last_picked_bonus_amount: i32 = 0,
    player_alt_weapon_swap_cooldown_ms: i32 = 0,
    player_spread_damping_scalar: f64 = 1.0,
    player_spread_damping_gate: f64 = 0.0,

    pub fn init(seed: u32) GameplayState {
        return .{
            .rng = survival_spawn.Crand.init(seed),
        };
    }
};

pub const PlayerShots = struct {
    fired: i32,
    hit: i32,
};

pub const WeaponStats = struct {
    clip_size: i32,
    reload_time: f64,
    shot_cooldown: f64,
    pellet_count: i32,
    projectile_meta: f64,
    damage_scale: f64,
    flags: u32,
    spread_heat_inc: f64,
};

pub const weapon_stats = std.EnumArray(WeaponId, WeaponStats).init(.{
    .none = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .pistol = .{ .clip_size = 10, .reload_time = 1.2, .shot_cooldown = 0.7117, .pellet_count = 1, .projectile_meta = 55.0, .damage_scale = 4.1, .flags = 5, .spread_heat_inc = 0.22 },
    .assault_rifle = .{ .clip_size = 25, .reload_time = 1.2, .shot_cooldown = 0.117, .pellet_count = 1, .projectile_meta = 50.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.09 },
    .shotgun = .{ .clip_size = 12, .reload_time = 1.9, .shot_cooldown = 0.85, .pellet_count = 12, .projectile_meta = 60.0, .damage_scale = 1.2, .flags = 1, .spread_heat_inc = 0.27 },
    .sawed_off_shotgun = .{ .clip_size = 12, .reload_time = 1.9, .shot_cooldown = 0.87, .pellet_count = 12, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.13 },
    .submachine_gun = .{ .clip_size = 30, .reload_time = 1.2, .shot_cooldown = 0.088117, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 5, .spread_heat_inc = 0.082 },
    .gauss_gun = .{ .clip_size = 6, .reload_time = 1.6, .shot_cooldown = 0.6, .pellet_count = 1, .projectile_meta = 215.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.42 },
    .mean_minigun = .{ .clip_size = 120, .reload_time = 4.0, .shot_cooldown = 0.09, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 3, .spread_heat_inc = 0.062 },
    .flamethrower = .{ .clip_size = 30, .reload_time = 2.0, .shot_cooldown = 0.008113, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.015 },
    .plasma_rifle = .{ .clip_size = 20, .reload_time = 1.2, .shot_cooldown = 0.2908117, .pellet_count = 1, .projectile_meta = 30.0, .damage_scale = 5.0, .flags = 0, .spread_heat_inc = 0.182 },
    .multi_plasma = .{ .clip_size = 8, .reload_time = 1.4, .shot_cooldown = 0.6208117, .pellet_count = 3, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.32 },
    .plasma_minigun = .{ .clip_size = 30, .reload_time = 1.3, .shot_cooldown = 0.11, .pellet_count = 1, .projectile_meta = 35.0, .damage_scale = 2.1, .flags = 0, .spread_heat_inc = 0.097 },
    .rocket_launcher = .{ .clip_size = 5, .reload_time = 1.2, .shot_cooldown = 0.7408117, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.42 },
    .seeker_rockets = .{ .clip_size = 8, .reload_time = 1.2, .shot_cooldown = 0.3108117, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.32 },
    .plasma_shotgun = .{ .clip_size = 8, .reload_time = 3.1, .shot_cooldown = 0.48, .pellet_count = 14, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.11 },
    .blow_torch = .{ .clip_size = 30, .reload_time = 1.5, .shot_cooldown = 0.006113, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.01 },
    .hr_flamer = .{ .clip_size = 30, .reload_time = 1.8, .shot_cooldown = 0.0085, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.01 },
    .mini_rocket_swarmers = .{ .clip_size = 5, .reload_time = 1.8, .shot_cooldown = 1.8, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.12 },
    .rocket_minigun = .{ .clip_size = 16, .reload_time = 1.8, .shot_cooldown = 0.12, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.12 },
    .pulse_gun = .{ .clip_size = 16, .reload_time = 0.1, .shot_cooldown = 0.1, .pellet_count = 1, .projectile_meta = 20.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.0 },
    .jackhammer = .{ .clip_size = 16, .reload_time = 3.0, .shot_cooldown = 0.14, .pellet_count = 4, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.16 },
    .ion_rifle = .{ .clip_size = 8, .reload_time = 1.35, .shot_cooldown = 0.4, .pellet_count = 1, .projectile_meta = 15.0, .damage_scale = 3.0, .flags = 8, .spread_heat_inc = 0.112 },
    .ion_minigun = .{ .clip_size = 20, .reload_time = 1.8, .shot_cooldown = 0.1, .pellet_count = 1, .projectile_meta = 20.0, .damage_scale = 1.4, .flags = 8, .spread_heat_inc = 0.09 },
    .ion_cannon = .{ .clip_size = 3, .reload_time = 3.0, .shot_cooldown = 1.0, .pellet_count = 1, .projectile_meta = 10.0, .damage_scale = 16.7, .flags = 0, .spread_heat_inc = 0.68 },
    .shrinkifier_5k = .{ .clip_size = 8, .reload_time = 1.22, .shot_cooldown = 0.21, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.04 },
    .blade_gun = .{ .clip_size = 6, .reload_time = 3.5, .shot_cooldown = 0.35, .pellet_count = 1, .projectile_meta = 20.0, .damage_scale = 11.0, .flags = 8, .spread_heat_inc = 0.04 },
    .spider_plasma = .{ .clip_size = 5, .reload_time = 1.2, .shot_cooldown = 0.2, .pellet_count = 1, .projectile_meta = 10.0, .damage_scale = 0.5, .flags = 8, .spread_heat_inc = 0.04 },
    .evil_scythe = .{ .clip_size = 3, .reload_time = 3.0, .shot_cooldown = 1.0, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.68 },
    .plasma_cannon = .{ .clip_size = 3, .reload_time = 2.7, .shot_cooldown = 0.9, .pellet_count = 1, .projectile_meta = 10.0, .damage_scale = 28.0, .flags = 0, .spread_heat_inc = 0.6 },
    .splitter_gun = .{ .clip_size = 6, .reload_time = 2.2, .shot_cooldown = 0.7, .pellet_count = 1, .projectile_meta = 30.0, .damage_scale = 6.0, .flags = 0, .spread_heat_inc = 0.28 },
    .gauss_shotgun = .{ .clip_size = 4, .reload_time = 2.1, .shot_cooldown = 1.05, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.27 },
    .ion_shotgun = .{ .clip_size = 10, .reload_time = 1.9, .shot_cooldown = 0.85, .pellet_count = 8, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.27 },
    .flameburst = .{ .clip_size = 60, .reload_time = 3.0, .shot_cooldown = 0.02, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.18 },
    .raygun = .{ .clip_size = 12, .reload_time = 2.0, .shot_cooldown = 0.7, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.38 },
    .unknown_34 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_35 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_36 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_37 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_38 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_39 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_40 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .plague_spreader_gun = .{ .clip_size = 5, .reload_time = 1.2, .shot_cooldown = 0.2, .pellet_count = 1, .projectile_meta = 15.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.04 },
    .bubblegun = .{ .clip_size = 15, .reload_time = 1.2, .shot_cooldown = 0.1613, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.05 },
    .rainbow_gun = .{ .clip_size = 10, .reload_time = 1.2, .shot_cooldown = 0.2, .pellet_count = 1, .projectile_meta = 10.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.09 },
    .grim_weapon = .{ .clip_size = 3, .reload_time = 1.2, .shot_cooldown = 0.5, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.4 },
    .fire_bullets = .{ .clip_size = 112, .reload_time = 1.2, .shot_cooldown = 0.14, .pellet_count = 1, .projectile_meta = 60.0, .damage_scale = 0.25, .flags = 1, .spread_heat_inc = 0.22 },
    .unknown_46 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_47 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_48 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_49 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .projectile_meta = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .transmutator = .{ .clip_size = 50, .reload_time = 5.0, .shot_cooldown = 0.04, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 9, .spread_heat_inc = 0.04 },
    .blaster_r_300 = .{ .clip_size = 20, .reload_time = 2.0, .shot_cooldown = 0.08, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 9, .spread_heat_inc = 0.05 },
    .lightning_rifle = .{ .clip_size = 500, .reload_time = 8.0, .shot_cooldown = 4.0, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 1.0 },
    .nuke_launcher = .{ .clip_size = 1, .reload_time = 8.0, .shot_cooldown = 4.0, .pellet_count = 1, .projectile_meta = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 1.0 },
});

comptime {
    std.debug.assert(weapon_count_size == @typeInfo(WeaponId).@"enum".fields.len);
}

pub inline fn weaponIdToInt(weapon_id: WeaponId) i32 {
    return @intFromEnum(weapon_id);
}

pub fn weaponIdFromInt(value: i32) ?WeaponId {
    if (value < 0 or value >= weapon_count_size) return null;
    return @enumFromInt(value);
}

pub fn weaponClipSize(weapon_id: WeaponId) i32 {
    return weapon_stats.get(weapon_id).clip_size;
}

pub fn weaponReloadTime(weapon_id: WeaponId) f64 {
    return weapon_stats.get(weapon_id).reload_time;
}

pub fn weaponShotCooldown(weapon_id: WeaponId) f64 {
    return weapon_stats.get(weapon_id).shot_cooldown;
}

pub fn weaponPelletCount(weapon_id: WeaponId) i32 {
    return weapon_stats.get(weapon_id).pellet_count;
}

pub fn weaponProjectileMeta(weapon_id: i32) f64 {
    const weapon_enum = weaponIdFromInt(weapon_id) orelse return 45.0;
    return weapon_stats.get(weapon_enum).projectile_meta;
}

pub fn weaponDamageScale(weapon_id: i32) f64 {
    const weapon_enum = weaponIdFromInt(weapon_id) orelse return 1.0;
    return weapon_stats.get(weapon_enum).damage_scale;
}

pub fn weaponFlags(weapon_id: i32) u32 {
    const weapon_enum = weaponIdFromInt(weapon_id) orelse return 0;
    return weapon_stats.get(weapon_enum).flags;
}

pub fn weaponSpreadHeatInc(weapon_id: i32) f64 {
    const weapon_enum = weaponIdFromInt(weapon_id) orelse return 0.0;
    return weapon_stats.get(weapon_enum).spread_heat_inc;
}

pub fn weaponFlagsById(weapon_id: WeaponId) u32 {
    return weapon_stats.get(weapon_id).flags;
}

pub fn weaponSpreadHeatIncById(weapon_id: WeaponId) f64 {
    return weapon_stats.get(weapon_id).spread_heat_inc;
}

pub fn projectileTypeIdFromWeaponId(weapon_id: WeaponId) ?i32 {
    return switch (weapon_id) {
        .pistol => ProjectileTypeId.pistol,
        .assault_rifle => ProjectileTypeId.assault_rifle,
        .shotgun => ProjectileTypeId.shotgun,
        .sawed_off_shotgun => ProjectileTypeId.shotgun,
        .submachine_gun => ProjectileTypeId.submachine_gun,
        .gauss_gun => ProjectileTypeId.gauss_gun,
        .mean_minigun => ProjectileTypeId.pistol,
        .flamethrower => null,
        .plasma_rifle => ProjectileTypeId.plasma_rifle,
        .multi_plasma => ProjectileTypeId.plasma_rifle,
        .plasma_minigun => ProjectileTypeId.plasma_minigun,
        .rocket_launcher => null,
        .seeker_rockets => null,
        .plasma_shotgun => ProjectileTypeId.plasma_minigun,
        .blow_torch => null,
        .hr_flamer => null,
        .mini_rocket_swarmers => null,
        .rocket_minigun => null,
        .pulse_gun => ProjectileTypeId.pulse_gun,
        .jackhammer => ProjectileTypeId.shotgun,
        .ion_rifle => ProjectileTypeId.ion_rifle,
        .ion_minigun => ProjectileTypeId.ion_minigun,
        .ion_cannon => ProjectileTypeId.ion_cannon,
        .shrinkifier_5k => ProjectileTypeId.shrinkifier,
        .blade_gun => ProjectileTypeId.blade_gun,
        .plasma_cannon => ProjectileTypeId.plasma_cannon,
        .splitter_gun => ProjectileTypeId.splitter_gun,
        .gauss_shotgun => ProjectileTypeId.gauss_gun,
        .ion_shotgun => ProjectileTypeId.ion_minigun,
        .plague_spreader_gun => ProjectileTypeId.plague_spreader,
        .bubblegun => null,
        .rainbow_gun => ProjectileTypeId.rainbow_gun,
        .fire_bullets => ProjectileTypeId.fire_bullets,
        else => @intFromEnum(weapon_id),
    };
}

pub const ProjectileTypeIds = struct {
    count: usize = 0,
    values: [2]i32 = .{ 0, 0 },

    pub fn slice(self: *const ProjectileTypeIds) []const i32 {
        return self.values[0..self.count];
    }
};

pub fn projectileTypeIdsFromWeaponId(weapon_id: WeaponId) ProjectileTypeIds {
    if (weapon_id == .none) {
        return .{};
    }
    if (weapon_id == .multi_plasma) {
        return .{
            .count = 2,
            .values = .{ ProjectileTypeId.plasma_rifle, ProjectileTypeId.plasma_minigun },
        };
    }

    const type_id = projectileTypeIdFromWeaponId(weapon_id) orelse return .{};
    return .{
        .count = 1,
        .values = .{ type_id, 0 },
    };
}

pub fn weaponAssignPlayer(
    player: *PlayerState,
    weapon_id: WeaponId,
) void {
    var clip_size = @max(0, weaponClipSize(weapon_id));
    if (playerPerkActive(player, 12)) {
        clip_size += @max(1, @divTrunc(clip_size, 4));
    }
    if (playerPerkActive(player, 48)) {
        clip_size += 2;
    }

    player.weapon_id = weapon_id;
    player.clip_size = clip_size;
    player.ammo = @floatFromInt(clip_size);
    player.weapon_reset_latch = 0;
    player.reload_active = false;
    player.reload_timer = 0.0;
    player.reload_timer_max = 0.0;
    player.shot_cooldown = 0.0;
    player.aux_timer = 2.0;
}

pub fn incrementWeaponUsage(
    state: *GameplayState,
    weapon_id: WeaponId,
) void {
    if (state.demo_mode_active) return;
    const idx: usize = @intCast(@intFromEnum(weapon_id));
    state.status_weapon_usage_counts[idx] +%= 1;
}

pub fn weaponAssignPlayerWithState(
    player: *PlayerState,
    weapon_id: WeaponId,
    state: *GameplayState,
) void {
    incrementWeaponUsage(state, weapon_id);
    weaponAssignPlayer(player, weapon_id);
}

pub fn playerSwapAltWeapon(player: *PlayerState) bool {
    const alt_weapon_id = player.alt_weapon_id orelse return false;
    const old_weapon_id = player.weapon_id;
    const old_clip_size = player.clip_size;
    const old_reload_active = player.reload_active;
    const old_ammo = player.ammo;
    const old_reload_timer = player.reload_timer;
    const old_shot_cooldown = player.shot_cooldown;
    const old_reload_timer_max = player.reload_timer_max;

    player.weapon_id = alt_weapon_id;
    player.clip_size = player.alt_clip_size;
    player.reload_active = player.alt_reload_active;
    player.ammo = player.alt_ammo;
    player.reload_timer = player.alt_reload_timer;
    player.shot_cooldown = player.alt_shot_cooldown;
    player.reload_timer_max = player.alt_reload_timer_max;

    player.alt_weapon_id = old_weapon_id;
    player.alt_clip_size = old_clip_size;
    player.alt_reload_active = old_reload_active;
    player.alt_ammo = old_ammo;
    player.alt_reload_timer = old_reload_timer;
    player.alt_shot_cooldown = old_shot_cooldown;
    player.alt_reload_timer_max = old_reload_timer_max;
    return true;
}

pub fn playerStartReload(player: *PlayerState, state: *GameplayState) void {
    var reload_time = weaponReloadTime(player.weapon_id);
    if (player.reload_active and (playerPerkActive(player, 35) or playerPerkActive(player, 23))) {
        return;
    }
    if (!player.reload_active) {
        player.reload_active = true;
    }
    if (playerPerkActive(player, 3)) {
        reload_time = asF32F64(reload_time * 0.7);
    }
    if (state.bonuses.weapon_power_up > 0.0) {
        reload_time = asF32F64(reload_time * 0.6);
    }
    player.reload_timer = @max(0.0, reload_time);
    player.reload_timer_max = player.reload_timer;
}

fn playerPerkActive(player: *const PlayerState, perk_id: i32) bool {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return false;
    return player.perk_counts[@intCast(perk_id)] > 0;
}

pub fn resetPlayers(
    players: []PlayerState,
    world_size: f64,
    spawn_pos: ?Vec2,
) void {
    if (players.len == 0) return;

    const base = spawn_pos orelse Vec2{
        .x = world_size * 0.5,
        .y = world_size * 0.5,
    };

    if (players.len == 1) {
        players[0] = .{
            .index = 0,
            .pos = base.clampRect(0.0, 0.0, world_size, world_size),
        };
        weaponAssignPlayer(&players[0], WeaponId.pistol);
        return;
    }

    const radius: f64 = 32.0;
    const step = std.math.tau / @as(f64, @floatFromInt(players.len));
    for (players, 0..) |*player, idx| {
        const offset = Vec2.fromAngle(@as(f64, @floatFromInt(idx)) * step).mul(radius);
        player.* = .{
            .index = @intCast(idx),
            .pos = Vec2.add(base, offset).clampRect(0.0, 0.0, world_size, world_size),
        };
        weaponAssignPlayer(player, WeaponId.pistol);
    }
}

pub fn player0Shots(state: GameplayState) PlayerShots {
    var fired: i32 = 0;
    var hit: i32 = 0;

    if (state.shots_fired.len > 0) fired = @max(0, state.shots_fired[0]);
    if (state.shots_hit.len > 0) hit = @max(0, state.shots_hit[0]);
    if (hit > fired) hit = fired;

    return .{
        .fired = fired,
        .hit = hit,
    };
}

pub fn mostUsedWeaponIdForPlayer(
    state: GameplayState,
    player_index: i32,
    fallback_weapon_id: i32,
) i32 {
    if (player_index < 0 or player_index >= state.weapon_shots_fired.len) {
        return fallback_weapon_id;
    }

    const counts = state.weapon_shots_fired[@intCast(player_index)];
    if (counts.len == 0) return fallback_weapon_id;

    const start: usize = if (counts.len > 1) 1 else 0;
    var best = start;
    var best_count = counts[start];

    var idx = start + 1;
    while (idx < counts.len) : (idx += 1) {
        if (counts[idx] > best_count) {
            best = idx;
            best_count = counts[idx];
        }
    }

    if (best_count > 0) return @intCast(best);
    return fallback_weapon_id;
}

pub fn timeScaleReflexBoostBonus(
    reflex_boost_timer: f64,
    time_scale_active: bool,
    dt: f64,
) f64 {
    const dt_f32 = asF32F64(dt);
    if (!(dt_f32 > 0.0)) return dt_f32;
    if (!time_scale_active) return dt_f32;

    const reflex_f32 = asF32F64(reflex_boost_timer);
    var time_scale_factor = asF32F64(0.3);
    if (reflex_f32 < 1.0) {
        time_scale_factor = asF32F64((1.0 - reflex_f32) * 0.7 + 0.3);
    }
    return asF32F64(dt_f32 * time_scale_factor);
}

pub fn survivalLevelThreshold(level_in: i32) i32 {
    const level = @max(1, level_in);
    const level_f64: f64 = @floatFromInt(level);
    const value = 1000.0 + std.math.pow(f64, level_f64, 1.8) * 1000.0;
    return @intFromFloat(value);
}

pub fn survivalCheckLevelUp(
    player: *PlayerState,
    perk_state: *PerkSelectionState,
) i32 {
    if (player.experience > survivalLevelThreshold(player.level)) {
        player.level += 1;
        perk_state.pending_count += 1;
        perk_state.choices_dirty = true;
        return 1;
    }
    return 0;
}

pub fn survivalProgressionUpdate(
    state: *GameplayState,
    players: []PlayerState,
) i32 {
    if (players.len == 0) return 0;
    return survivalCheckLevelUp(&players[0], &state.perk_selection);
}

pub fn survivalRecordRecentDeath(
    state: *GameplayState,
    pos: Vec2,
) void {
    var recent_count = state.survival_recent_death_count;
    if (recent_count >= 6) return;

    if (recent_count < 3) {
        const idx: usize = @intCast(recent_count);
        state.survival_recent_death_pos[idx] = .{
            .x = asF32F64(pos.x),
            .y = asF32F64(pos.y),
        };
    }

    recent_count += 1;
    state.survival_recent_death_count = recent_count;
    if (recent_count == 3) {
        state.survival_reward_fire_seen = false;
        state.survival_reward_handout_enabled = false;
    }
}

pub fn survivalUpdateWeaponHandouts(
    state: *GameplayState,
    players: []PlayerState,
    survival_elapsed_ms: f64,
) void {
    if (players.len != 1) return;
    const player = &players[0];

    if (!state.survival_reward_damage_seen and
        !state.survival_reward_fire_seen and
        @as(i32, @intFromFloat(survival_elapsed_ms)) > 64_000 and
        state.survival_reward_handout_enabled)
    {
        if (player.weapon_id == WeaponId.pistol) {
            weaponAssignPlayerWithState(player, WeaponId.shrinkifier_5k, state);
            state.survival_reward_weapon_guard_id = WeaponId.shrinkifier_5k;
        }
        state.survival_reward_handout_enabled = false;
        state.survival_reward_damage_seen = true;
        state.survival_reward_fire_seen = true;
    }

    if (state.survival_recent_death_count == 3 and !state.survival_reward_fire_seen) {
        const pos0 = state.survival_recent_death_pos[0];
        const pos1 = state.survival_recent_death_pos[1];
        const pos2 = state.survival_recent_death_pos[2];

        const centroid_scale = asF32F64(0.33333334);
        const centroid_x = asF32F64(asF32F64(pos0.x + pos1.x + pos2.x) * centroid_scale);
        const centroid_y = asF32F64(asF32F64(pos0.y + pos1.y + pos2.y) * centroid_scale);

        const dx = player.pos.x - centroid_x;
        const dy = player.pos.y - centroid_y;
        const distance = std.math.sqrt(dx * dx + dy * dy);
        if (distance < 16.0 and player.health < 15.0) {
            weaponAssignPlayerWithState(player, WeaponId.blade_gun, state);
            state.survival_reward_weapon_guard_id = WeaponId.blade_gun;
            state.survival_reward_fire_seen = true;
            state.survival_reward_handout_enabled = false;
        }
    }
}

pub fn survivalEnforceRewardWeaponGuard(
    state: GameplayState,
    players: []PlayerState,
) void {
    const guard_id = state.survival_reward_weapon_guard_id;
    for (players) |*player| {
        if (player.weapon_id == WeaponId.blade_gun and guard_id != WeaponId.blade_gun) {
            weaponAssignPlayer(player, WeaponId.pistol);
        }
        if (player.weapon_id == WeaponId.shrinkifier_5k and guard_id != WeaponId.shrinkifier_5k) {
            weaponAssignPlayer(player, WeaponId.pistol);
        }
    }
}

fn asF32F64(value: f64) f64 {
    const rounded: f32 = @floatCast(value);
    return @floatCast(rounded);
}

fn expectFloatClose(expected: f64, actual: f64) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "projectile type id mapping mirrors native fire paths" {
    const cases = [_]struct {
        weapon_id: i32,
        type_id: i32,
    }{
        .{ .weapon_id = 1, .type_id = 0x01 },
        .{ .weapon_id = 2, .type_id = 0x02 },
        .{ .weapon_id = 3, .type_id = 0x03 },
        .{ .weapon_id = 4, .type_id = 0x03 },
        .{ .weapon_id = 5, .type_id = 0x05 },
        .{ .weapon_id = 6, .type_id = 0x06 },
        .{ .weapon_id = 7, .type_id = 0x01 },
        .{ .weapon_id = 9, .type_id = 0x09 },
        .{ .weapon_id = 10, .type_id = 0x09 },
        .{ .weapon_id = 11, .type_id = 0x0B },
        .{ .weapon_id = 14, .type_id = 0x0B },
        .{ .weapon_id = 19, .type_id = 0x13 },
        .{ .weapon_id = 20, .type_id = 0x03 },
        .{ .weapon_id = 21, .type_id = 0x15 },
        .{ .weapon_id = 22, .type_id = 0x16 },
        .{ .weapon_id = 23, .type_id = 0x17 },
        .{ .weapon_id = 24, .type_id = 0x18 },
        .{ .weapon_id = 25, .type_id = 0x19 },
        .{ .weapon_id = 28, .type_id = 0x1C },
        .{ .weapon_id = 29, .type_id = 0x1D },
        .{ .weapon_id = 30, .type_id = 0x06 },
        .{ .weapon_id = 31, .type_id = 0x16 },
        .{ .weapon_id = 41, .type_id = 0x29 },
        .{ .weapon_id = 43, .type_id = 0x2B },
        .{ .weapon_id = 45, .type_id = 0x2D },
    };

    for (cases) |case| {
        const weapon_id = weaponIdFromInt(case.weapon_id).?;
        try std.testing.expectEqual(case.type_id, projectileTypeIdFromWeaponId(weapon_id).?);
    }

    const multi_plasma_types = projectileTypeIdsFromWeaponId(.multi_plasma).slice();
    try std.testing.expectEqual(@as(usize, 2), multi_plasma_types.len);
    try std.testing.expectEqual(@as(i32, 0x09), multi_plasma_types[0]);
    try std.testing.expectEqual(@as(i32, 0x0B), multi_plasma_types[1]);
}

test "non projectile weapons map to empty projectile type ids" {
    const non_projectile_weapons = [_]i32{ 8, 12, 13, 15, 16, 17, 18, 42 };
    for (non_projectile_weapons) |weapon_id| {
        const id = weaponIdFromInt(weapon_id).?;
        try std.testing.expectEqual(@as(?i32, null), projectileTypeIdFromWeaponId(id));
        try std.testing.expectEqual(@as(usize, 0), projectileTypeIdsFromWeaponId(id).slice().len);
    }
}

test "survival level up advances one threshold per tick" {
    var player = PlayerState{
        .index = 0,
        .pos = .{},
        .level = 1,
        .experience = 5000,
    };
    var perks = PerkSelectionState{};

    const advanced_0 = survivalCheckLevelUp(&player, &perks);
    try std.testing.expectEqual(@as(i32, 1), advanced_0);
    try std.testing.expectEqual(@as(i32, 2), player.level);
    try std.testing.expectEqual(@as(i32, 1), perks.pending_count);
    try std.testing.expect(perks.choices_dirty);

    const advanced_1 = survivalCheckLevelUp(&player, &perks);
    try std.testing.expectEqual(@as(i32, 1), advanced_1);
    try std.testing.expectEqual(@as(i32, 3), player.level);
    try std.testing.expectEqual(@as(i32, 2), perks.pending_count);
}

test "survival level threshold smoke values" {
    try std.testing.expectEqual(@as(i32, 2000), survivalLevelThreshold(1));
    try std.testing.expectEqual(@as(i32, 4482), survivalLevelThreshold(2));
    try std.testing.expectEqual(@as(i32, 64095), survivalLevelThreshold(10));
}

test "survival handout time gate assigns shrinkifier" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    weaponAssignPlayer(&players[0], WeaponId.pistol);

    survivalUpdateWeaponHandouts(&state, players[0..], 64_001.0);

    try std.testing.expectEqual(WeaponId.shrinkifier_5k, players[0].weapon_id);
    try std.testing.expectEqual(WeaponId.shrinkifier_5k, state.survival_reward_weapon_guard_id);
    try std.testing.expect(!state.survival_reward_handout_enabled);
    try std.testing.expect(state.survival_reward_damage_seen);
    try std.testing.expect(state.survival_reward_fire_seen);
}

test "survival handout time gate consumes without pistol" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    weaponAssignPlayer(&players[0], WeaponId.assault_rifle);

    survivalUpdateWeaponHandouts(&state, players[0..], 64_001.0);

    try std.testing.expectEqual(WeaponId.assault_rifle, players[0].weapon_id);
    try std.testing.expectEqual(WeaponId.pistol, state.survival_reward_weapon_guard_id);
    try std.testing.expect(!state.survival_reward_handout_enabled);
    try std.testing.expect(state.survival_reward_damage_seen);
    try std.testing.expect(state.survival_reward_fire_seen);
}

test "survival handouts are single player only" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
        .{ .index = 1, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    weaponAssignPlayer(&players[0], WeaponId.pistol);
    weaponAssignPlayer(&players[1], WeaponId.pistol);

    survivalUpdateWeaponHandouts(&state, players[0..], 64_001.0);

    try std.testing.expectEqual(WeaponId.pistol, players[0].weapon_id);
    try std.testing.expectEqual(WeaponId.pistol, players[1].weapon_id);
    try std.testing.expect(state.survival_reward_handout_enabled);
    try std.testing.expect(!state.survival_reward_damage_seen);
    try std.testing.expect(!state.survival_reward_fire_seen);
}

test "survival handout centroid gate assigns blade gun" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{ .x = 100.0, .y = 100.0 }, .health = 14.0 },
    };
    weaponAssignPlayer(&players[0], WeaponId.pistol);

    state.survival_reward_handout_enabled = false;
    state.survival_reward_damage_seen = true;
    state.survival_reward_fire_seen = false;
    state.survival_recent_death_count = 3;
    state.survival_recent_death_pos = .{
        .{ .x = 90.0, .y = 100.0 },
        .{ .x = 100.0, .y = 90.0 },
        .{ .x = 110.0, .y = 110.0 },
    };

    survivalUpdateWeaponHandouts(&state, players[0..], 0.0);

    try std.testing.expectEqual(WeaponId.blade_gun, players[0].weapon_id);
    try std.testing.expectEqual(WeaponId.blade_gun, state.survival_reward_weapon_guard_id);
    try std.testing.expect(state.survival_reward_fire_seen);
    try std.testing.expect(!state.survival_reward_handout_enabled);
}

test "survival record recent death latches handout gate at 3" {
    var state = GameplayState.init(1);
    state.survival_reward_fire_seen = true;
    state.survival_reward_handout_enabled = true;

    survivalRecordRecentDeath(&state, .{ .x = 10.0, .y = 20.0 });
    survivalRecordRecentDeath(&state, .{ .x = 30.0, .y = 40.0 });
    survivalRecordRecentDeath(&state, .{ .x = 50.0, .y = 60.0 });

    try std.testing.expectEqual(@as(i32, 3), state.survival_recent_death_count);
    try expectFloatClose(10.0, state.survival_recent_death_pos[0].x);
    try expectFloatClose(20.0, state.survival_recent_death_pos[0].y);
    try expectFloatClose(30.0, state.survival_recent_death_pos[1].x);
    try expectFloatClose(40.0, state.survival_recent_death_pos[1].y);
    try expectFloatClose(50.0, state.survival_recent_death_pos[2].x);
    try expectFloatClose(60.0, state.survival_recent_death_pos[2].y);
    try std.testing.expect(!state.survival_reward_fire_seen);
    try std.testing.expect(!state.survival_reward_handout_enabled);
}

test "survival reward guard reverts temporary weapons" {
    var state = GameplayState.init(1);
    var players = [_]PlayerState{
        .{ .index = 0, .pos = .{} },
        .{ .index = 1, .pos = .{} },
    };
    weaponAssignPlayer(&players[0], WeaponId.shrinkifier_5k);
    weaponAssignPlayer(&players[1], WeaponId.blade_gun);
    state.survival_reward_weapon_guard_id = WeaponId.shrinkifier_5k;

    survivalEnforceRewardWeaponGuard(state, players[0..]);

    try std.testing.expectEqual(WeaponId.shrinkifier_5k, players[0].weapon_id);
    try std.testing.expectEqual(WeaponId.pistol, players[1].weapon_id);
}

test "time scale reflex boost bonus mirrors f32 latch" {
    try expectFloatClose(0.01666666753590107, timeScaleReflexBoostBonus(0.0, false, 1.0 / 60.0));
    try expectFloatClose(0.01666666753590107, timeScaleReflexBoostBonus(0.0, true, 1.0 / 60.0));
    try expectFloatClose(0.010833333246409893, timeScaleReflexBoostBonus(0.5, true, 1.0 / 60.0));
}

test "fastloader scales reload timer" {
    const weapon_id = WeaponId.assault_rifle;
    const reload_time = weaponReloadTime(weapon_id);
    try std.testing.expect(reload_time > 0.0);

    var base_state = GameplayState.init(1);
    var perk_state = GameplayState.init(1);
    var base_player = PlayerState{
        .index = 0,
        .pos = .{},
        .weapon_id = weapon_id,
    };
    var perk_player = PlayerState{
        .index = 0,
        .pos = .{},
        .weapon_id = weapon_id,
    };
    perk_player.perk_counts[3] = 1;

    playerStartReload(&base_player, &base_state);
    playerStartReload(&perk_player, &perk_state);

    try std.testing.expect(base_player.reload_active);
    try std.testing.expect(perk_player.reload_active);
    try expectFloatClose(reload_time, base_player.reload_timer);
    try expectFloatClose(asF32F64(reload_time * 0.7), perk_player.reload_timer);
    try expectFloatClose(perk_player.reload_timer, perk_player.reload_timer_max);
}

test "weapon assign with state resets latch, sets aux timer, and records usage" {
    var state = GameplayState.init(1);
    var player = PlayerState{
        .index = 0,
        .pos = .{},
    };
    player.weapon_reset_latch = 7;
    player.aux_timer = 0.0;

    weaponAssignPlayerWithState(&player, WeaponId.shotgun, &state);

    try std.testing.expectEqual(@as(i32, 0), player.weapon_reset_latch);
    try expectFloatClose(2.0, player.aux_timer);
    try std.testing.expectEqual(@as(u32, 1), state.status_weapon_usage_counts[@intCast(weaponIdToInt(WeaponId.shotgun))]);
}
