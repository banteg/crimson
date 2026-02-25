const std = @import("std");
const survival_math = @import("survival_math.zig");

const survival_spawn = @import("survival_spawn.zig");

pub const max_players: usize = 4;
pub const weapon_count_size: usize = 54;
pub const perk_count_size: usize = 0x80;

pub const WeaponId = struct {
    pub const none: i32 = 0;
    pub const pistol: i32 = 1;
    pub const assault_rifle: i32 = 2;
    pub const shotgun: i32 = 3;
    pub const submachine_gun: i32 = 5;
    pub const ion_cannon: i32 = 23;
    pub const splitter_gun: i32 = 29;
    pub const flamethrower: i32 = 8;
    pub const mean_minigun: i32 = 7;
    pub const shrinkifier_5k: i32 = 24;
    pub const blade_gun: i32 = 25;
};

pub const ProjectileTypeId = struct {
    pub const pistol: i32 = 0x01;
    pub const assault_rifle: i32 = 0x02;
    pub const shotgun: i32 = 0x03;
    pub const submachine_gun: i32 = 0x05;
    pub const gauss_gun: i32 = 0x06;
    pub const plasma_rifle: i32 = 0x09;
    pub const plasma_minigun: i32 = 0x0B;
    pub const pulse_gun: i32 = 0x13;
    pub const ion_rifle: i32 = 0x15;
    pub const ion_minigun: i32 = 0x16;
    pub const ion_cannon: i32 = 0x17;
    pub const shrinkifier: i32 = 0x18;
    pub const blade_gun: i32 = 0x19;
    pub const plasma_cannon: i32 = 0x1C;
    pub const splitter_gun: i32 = 0x1D;
    pub const plague_spreader: i32 = 0x29;
    pub const rainbow_gun: i32 = 0x2B;
    pub const fire_bullets: i32 = 0x2D;
};

pub const BonusId = struct {
    pub const unused: i32 = 0;
    pub const points: i32 = 1;
    pub const energizer: i32 = 2;
    pub const weapon: i32 = 3;
    pub const weapon_power_up: i32 = 4;
    pub const nuke: i32 = 5;
    pub const double_experience: i32 = 6;
    pub const shock_chain: i32 = 7;
    pub const fireblast: i32 = 8;
    pub const reflex_boost: i32 = 9;
    pub const shield: i32 = 10;
    pub const freeze: i32 = 11;
    pub const medikit: i32 = 12;
    pub const speed: i32 = 13;
    pub const fire_bullets: i32 = 14;
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

    weapon_id: i32 = WeaponId.pistol,
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

    alt_weapon_id: ?i32 = null,
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

    survival_reward_weapon_guard_id: i32 = WeaponId.pistol,
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

pub const weapon_clip_sizes = [_]i32{
    0,  10, 25, 12, 12, 30, 6,  120, 30, 20,  8, 30, 5, 8,  8,  30, 30,  5,
    16, 16, 16, 8,  20, 3,  8,  6,   5,  3,   3, 6,  4, 10, 60, 12, 0,   0,
    0,  0,  0,  0,  0,  5,  15, 10,  3,  112, 0, 0,  0, 0,  50, 20, 500, 1,
};

pub const weapon_reload_times = [_]f64{
    0.0, 1.2, 1.2, 1.9,  1.9, 1.2, 1.6,  4.0, 2.0, 1.2, 1.4, 1.3, 1.2, 1.2, 3.1, 1.5, 1.8, 1.8,
    1.8, 0.1, 3.0, 1.35, 1.8, 3.0, 1.22, 3.5, 1.2, 3.0, 2.7, 2.2, 2.1, 1.9, 3.0, 2.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0,  0.0, 1.2, 1.2,  1.2, 1.2, 1.2, 0.0, 0.0, 0.0, 0.0, 5.0, 2.0, 8.0, 8.0,
};

pub const weapon_shot_cooldowns = [_]f64{
    0.0,  0.7117, 0.117, 0.85, 0.87, 0.088117, 0.6,    0.09, 0.008113, 0.2908117, 0.6208117, 0.11, 0.7408117, 0.3108117, 0.48, 0.006113, 0.0085, 1.8,
    0.12, 0.1,    0.14,  0.4,  0.1,  1.0,      0.21,   0.35, 0.2,      1.0,       0.9,       0.7,  1.05,      0.85,      0.02, 0.7,      0.0,    0.0,
    0.0,  0.0,    0.0,   0.0,  0.0,  0.2,      0.1613, 0.2,  0.5,      0.14,      0.0,       0.0,  0.0,       0.0,       0.04, 0.08,     4.0,    4.0,
};

pub const weapon_pellet_counts = [_]i32{
    0, 1, 1, 12, 12, 1, 1, 1, 1, 1, 3, 1, 1, 1, 14, 1, 1, 1,
    1, 1, 4, 1,  1,  1, 1, 1, 1, 1, 1, 1, 1, 8, 1,  1, 0, 0,
    0, 0, 0, 0,  0,  1, 1, 1, 1, 1, 0, 0, 0, 0, 1,  1, 1, 1,
};

pub const weapon_projectile_meta = [_]f64{
    0.0,  55.0, 50.0, 60.0, 45.0, 45.0, 215.0, 45.0, 45.0, 30.0, 45.0, 35.0, 45.0, 45.0, 45.0, 45.0, 45.0, 45.0,
    45.0, 20.0, 45.0, 15.0, 20.0, 10.0, 45.0,  20.0, 10.0, 45.0, 10.0, 30.0, 45.0, 45.0, 45.0, 45.0, 0.0,  0.0,
    0.0,  0.0,  0.0,  0.0,  0.0,  15.0, 45.0,  10.0, 45.0, 60.0, 0.0,  0.0,  0.0,  0.0,  45.0, 45.0, 45.0, 45.0,
};

pub const weapon_damage_scales = [_]f64{
    0.0, 4.1, 1.0, 1.2, 1.0, 1.0,  1.0, 1.0,  1.0, 5.0,  1.0,  2.1, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
    1.0, 1.0, 1.0, 3.0, 1.4, 16.7, 1.0, 11.0, 0.5, 1.0,  28.0, 6.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 1.0,  1.0, 1.0,  1.0, 0.25, 0.0,  0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0,
};

pub const weapon_flags = [_]u32{
    0, 5, 1, 1, 1, 5, 1, 3, 8, 0, 0, 0, 8, 8, 0, 8, 8, 8,
    8, 8, 1, 8, 8, 0, 8, 8, 8, 0, 0, 0, 1, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 8, 8, 8, 0, 1, 0, 0, 0, 0, 9, 9, 8, 8,
};

pub const weapon_spread_heat_inc = [_]f64{
    0.0, 0.22, 0.09, 0.27, 0.13, 0.082, 0.42, 0.062, 0.015, 0.182, 0.32, 0.097, 0.42, 0.32, 0.11, 0.01, 0.01, 0.12,
    0.12, 0.0, 0.16, 0.112, 0.09, 0.68, 0.04, 0.04, 0.04, 0.68, 0.6, 0.28, 0.27, 0.27, 0.18, 0.38, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.04, 0.05, 0.09, 0.4, 0.22, 0.0, 0.0, 0.0, 0.0, 0.04, 0.05, 1.0, 1.0,
};

pub fn weaponClipSize(weapon_id: i32) i32 {
    if (weapon_id < 0 or weapon_id >= weapon_clip_sizes.len) return 0;
    return weapon_clip_sizes[@intCast(weapon_id)];
}

pub fn weaponReloadTime(weapon_id: i32) f64 {
    if (weapon_id < 0 or weapon_id >= weapon_reload_times.len) return 0.0;
    return weapon_reload_times[@intCast(weapon_id)];
}

pub fn weaponShotCooldown(weapon_id: i32) f64 {
    if (weapon_id < 0 or weapon_id >= weapon_shot_cooldowns.len) return 0.0;
    return weapon_shot_cooldowns[@intCast(weapon_id)];
}

pub fn weaponPelletCount(weapon_id: i32) i32 {
    if (weapon_id < 0 or weapon_id >= weapon_pellet_counts.len) return 0;
    return weapon_pellet_counts[@intCast(weapon_id)];
}

pub fn weaponProjectileMeta(weapon_id: i32) f64 {
    if (weapon_id < 0 or weapon_id >= weapon_projectile_meta.len) return 45.0;
    return weapon_projectile_meta[@intCast(weapon_id)];
}

pub fn weaponDamageScale(weapon_id: i32) f64 {
    if (weapon_id < 0 or weapon_id >= weapon_damage_scales.len) return 1.0;
    return weapon_damage_scales[@intCast(weapon_id)];
}

pub fn weaponFlags(weapon_id: i32) u32 {
    if (weapon_id < 0 or weapon_id >= weapon_flags.len) return 0;
    return weapon_flags[@intCast(weapon_id)];
}

pub fn weaponSpreadHeatInc(weapon_id: i32) f64 {
    if (weapon_id < 0 or weapon_id >= weapon_spread_heat_inc.len) return 0.0;
    return weapon_spread_heat_inc[@intCast(weapon_id)];
}

pub fn projectileTypeIdFromWeaponId(weapon_id: i32) ?i32 {
    return switch (weapon_id) {
        1 => ProjectileTypeId.pistol,
        2 => ProjectileTypeId.assault_rifle,
        3 => ProjectileTypeId.shotgun,
        4 => ProjectileTypeId.shotgun,
        5 => ProjectileTypeId.submachine_gun,
        6 => ProjectileTypeId.gauss_gun,
        7 => ProjectileTypeId.pistol,
        8 => null,
        9 => ProjectileTypeId.plasma_rifle,
        10 => ProjectileTypeId.plasma_rifle,
        11 => ProjectileTypeId.plasma_minigun,
        12 => null,
        13 => null,
        14 => ProjectileTypeId.plasma_minigun,
        15 => null,
        16 => null,
        17 => null,
        18 => null,
        19 => ProjectileTypeId.pulse_gun,
        20 => ProjectileTypeId.shotgun,
        21 => ProjectileTypeId.ion_rifle,
        22 => ProjectileTypeId.ion_minigun,
        23 => ProjectileTypeId.ion_cannon,
        24 => ProjectileTypeId.shrinkifier,
        25 => ProjectileTypeId.blade_gun,
        28 => ProjectileTypeId.plasma_cannon,
        29 => ProjectileTypeId.splitter_gun,
        30 => ProjectileTypeId.gauss_gun,
        31 => ProjectileTypeId.ion_minigun,
        41 => ProjectileTypeId.plague_spreader,
        42 => null,
        43 => ProjectileTypeId.rainbow_gun,
        45 => ProjectileTypeId.fire_bullets,
        else => if (weapon_id >= 0 and weapon_id < weapon_count_size) weapon_id else null,
    };
}

pub fn weaponAssignPlayer(
    player: *PlayerState,
    weapon_id: i32,
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
    weapon_id: i32,
) void {
    if (state.demo_mode_active) return;
    if (weapon_id < 0 or weapon_id >= state.status_weapon_usage_counts.len) return;
    const idx: usize = @intCast(weapon_id);
    state.status_weapon_usage_counts[idx] +%= 1;
}

pub fn weaponAssignPlayerWithState(
    player: *PlayerState,
    weapon_id: i32,
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
