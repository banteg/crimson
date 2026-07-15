const std = @import("std");
const game_ids = @import("../game_ids.zig");

pub const WeaponId = game_ids.WeaponId;
const ProjectileTypeId = game_ids.ProjectileTypeId;

pub const weapon_count_size: usize = @typeInfo(WeaponId).@"enum".fields.len;

pub const WeaponStats = struct {
    clip_size: i32,
    reload_time: f32,
    shot_cooldown: f32,
    pellet_count: i32,
    travel_budget: f32,
    damage_scale: f32,
    flags: u32,
    spread_heat_inc: f32,
};

pub const weapon_stats = std.EnumArray(WeaponId, WeaponStats).init(.{
    .none = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .pistol = .{ .clip_size = 12, .reload_time = 1.2, .shot_cooldown = 0.7117, .pellet_count = 1, .travel_budget = 55.0, .damage_scale = 4.1, .flags = 5, .spread_heat_inc = 0.22 },
    .assault_rifle = .{ .clip_size = 25, .reload_time = 1.2, .shot_cooldown = 0.117, .pellet_count = 1, .travel_budget = 50.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.09 },
    .shotgun = .{ .clip_size = 12, .reload_time = 1.9, .shot_cooldown = 0.85, .pellet_count = 12, .travel_budget = 60.0, .damage_scale = 1.2, .flags = 1, .spread_heat_inc = 0.27 },
    .sawed_off_shotgun = .{ .clip_size = 12, .reload_time = 1.9, .shot_cooldown = 0.87, .pellet_count = 12, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.13 },
    .submachine_gun = .{ .clip_size = 30, .reload_time = 1.2, .shot_cooldown = 0.088117, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 5, .spread_heat_inc = 0.082 },
    .gauss_gun = .{ .clip_size = 6, .reload_time = 1.6, .shot_cooldown = 0.6, .pellet_count = 1, .travel_budget = 215.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.42 },
    .mean_minigun = .{ .clip_size = 120, .reload_time = 4.0, .shot_cooldown = 0.09, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 3, .spread_heat_inc = 0.062 },
    .flamethrower = .{ .clip_size = 30, .reload_time = 2.0, .shot_cooldown = 0.008113, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.015 },
    .plasma_rifle = .{ .clip_size = 20, .reload_time = 1.2, .shot_cooldown = 0.2908117, .pellet_count = 1, .travel_budget = 30.0, .damage_scale = 5.0, .flags = 0, .spread_heat_inc = 0.182 },
    .multi_plasma = .{ .clip_size = 8, .reload_time = 1.4, .shot_cooldown = 0.6208117, .pellet_count = 3, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.32 },
    .plasma_minigun = .{ .clip_size = 30, .reload_time = 1.3, .shot_cooldown = 0.11, .pellet_count = 1, .travel_budget = 35.0, .damage_scale = 2.1, .flags = 0, .spread_heat_inc = 0.097 },
    .rocket_launcher = .{ .clip_size = 5, .reload_time = 1.2, .shot_cooldown = 0.7408117, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.42 },
    .seeker_rockets = .{ .clip_size = 8, .reload_time = 1.2, .shot_cooldown = 0.3108117, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.32 },
    .plasma_shotgun = .{ .clip_size = 8, .reload_time = 3.1, .shot_cooldown = 0.48, .pellet_count = 14, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.11 },
    .blow_torch = .{ .clip_size = 30, .reload_time = 1.5, .shot_cooldown = 0.006113, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.01 },
    .hr_flamer = .{ .clip_size = 30, .reload_time = 1.8, .shot_cooldown = 0.0085, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.01 },
    .mini_rocket_swarmers = .{ .clip_size = 5, .reload_time = 1.8, .shot_cooldown = 1.8, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.12 },
    .rocket_minigun = .{ .clip_size = 16, .reload_time = 1.8, .shot_cooldown = 0.12, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.12 },
    .pulse_gun = .{ .clip_size = 16, .reload_time = 0.1, .shot_cooldown = 0.1, .pellet_count = 1, .travel_budget = 20.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.0 },
    .jackhammer = .{ .clip_size = 16, .reload_time = 3.0, .shot_cooldown = 0.14, .pellet_count = 4, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.16 },
    .ion_rifle = .{ .clip_size = 8, .reload_time = 1.35, .shot_cooldown = 0.4, .pellet_count = 1, .travel_budget = 15.0, .damage_scale = 3.0, .flags = 8, .spread_heat_inc = 0.112 },
    .ion_minigun = .{ .clip_size = 20, .reload_time = 1.8, .shot_cooldown = 0.1, .pellet_count = 1, .travel_budget = 20.0, .damage_scale = 1.4, .flags = 8, .spread_heat_inc = 0.09 },
    .ion_cannon = .{ .clip_size = 3, .reload_time = 3.0, .shot_cooldown = 1.0, .pellet_count = 1, .travel_budget = 10.0, .damage_scale = 16.7, .flags = 0, .spread_heat_inc = 0.68 },
    .shrinkifier_5k = .{ .clip_size = 8, .reload_time = 1.22, .shot_cooldown = 0.21, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 0.0, .flags = 8, .spread_heat_inc = 0.04 },
    .blade_gun = .{ .clip_size = 6, .reload_time = 3.5, .shot_cooldown = 0.35, .pellet_count = 1, .travel_budget = 20.0, .damage_scale = 11.0, .flags = 8, .spread_heat_inc = 0.04 },
    .spider_plasma = .{ .clip_size = 5, .reload_time = 1.2, .shot_cooldown = 0.2, .pellet_count = 1, .travel_budget = 10.0, .damage_scale = 0.5, .flags = 8, .spread_heat_inc = 0.04 },
    .evil_scythe = .{ .clip_size = 3, .reload_time = 3.0, .shot_cooldown = 1.0, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.68 },
    .plasma_cannon = .{ .clip_size = 3, .reload_time = 2.7, .shot_cooldown = 0.9, .pellet_count = 1, .travel_budget = 10.0, .damage_scale = 28.0, .flags = 0, .spread_heat_inc = 0.6 },
    .splitter_gun = .{ .clip_size = 6, .reload_time = 2.2, .shot_cooldown = 0.7, .pellet_count = 1, .travel_budget = 30.0, .damage_scale = 6.0, .flags = 0, .spread_heat_inc = 0.28 },
    .gauss_shotgun = .{ .clip_size = 4, .reload_time = 2.1, .shot_cooldown = 1.05, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.27 },
    .ion_shotgun = .{ .clip_size = 10, .reload_time = 1.9, .shot_cooldown = 0.85, .pellet_count = 8, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 1, .spread_heat_inc = 0.27 },
    .flameburst = .{ .clip_size = 60, .reload_time = 3.0, .shot_cooldown = 0.02, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.18 },
    .raygun = .{ .clip_size = 12, .reload_time = 2.0, .shot_cooldown = 0.7, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.38 },
    .unknown_34 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_35 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_36 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_37 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_38 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_39 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_40 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .plague_spreader_gun = .{ .clip_size = 5, .reload_time = 1.2, .shot_cooldown = 0.2, .pellet_count = 1, .travel_budget = 15.0, .damage_scale = 0.0, .flags = 8, .spread_heat_inc = 0.04 },
    .bubblegun = .{ .clip_size = 15, .reload_time = 1.2, .shot_cooldown = 0.1613, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.05 },
    .rainbow_gun = .{ .clip_size = 10, .reload_time = 1.2, .shot_cooldown = 0.2, .pellet_count = 1, .travel_budget = 10.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 0.09 },
    .grim_weapon = .{ .clip_size = 3, .reload_time = 1.2, .shot_cooldown = 0.5, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 0, .spread_heat_inc = 0.4 },
    .fire_bullets = .{ .clip_size = 112, .reload_time = 1.2, .shot_cooldown = 0.14, .pellet_count = 1, .travel_budget = 60.0, .damage_scale = 0.25, .flags = 1, .spread_heat_inc = 0.22 },
    .unknown_46 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_47 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_48 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .unknown_49 = .{ .clip_size = 0, .reload_time = 0.0, .shot_cooldown = 0.0, .pellet_count = 0, .travel_budget = 0.0, .damage_scale = 0.0, .flags = 0, .spread_heat_inc = 0.0 },
    .transmutator = .{ .clip_size = 50, .reload_time = 5.0, .shot_cooldown = 0.04, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 9, .spread_heat_inc = 0.04 },
    .blaster_r_300 = .{ .clip_size = 20, .reload_time = 2.0, .shot_cooldown = 0.08, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 9, .spread_heat_inc = 0.05 },
    .lightning_rifle = .{ .clip_size = 500, .reload_time = 8.0, .shot_cooldown = 4.0, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 1.0 },
    .nuke_launcher = .{ .clip_size = 1, .reload_time = 8.0, .shot_cooldown = 4.0, .pellet_count = 1, .travel_budget = 45.0, .damage_scale = 1.0, .flags = 8, .spread_heat_inc = 1.0 },
});

pub const weapon_icon_index = std.EnumArray(WeaponId, i32).initDefault(-1, .{
    .pistol = 0,
    .assault_rifle = 1,
    .shotgun = 2,
    .sawed_off_shotgun = 3,
    .submachine_gun = 4,
    .gauss_gun = 5,
    .mean_minigun = 6,
    .flamethrower = 7,
    .plasma_rifle = 8,
    .multi_plasma = 9,
    .plasma_minigun = 10,
    .rocket_launcher = 11,
    .seeker_rockets = 12,
    .plasma_shotgun = 13,
    .blow_torch = 14,
    .hr_flamer = 15,
    .mini_rocket_swarmers = 16,
    .rocket_minigun = 17,
    .pulse_gun = 18,
    .jackhammer = 19,
    .ion_rifle = 20,
    .ion_minigun = 21,
    .ion_cannon = 22,
    .shrinkifier_5k = 23,
    .blade_gun = 24,
    .spider_plasma = 25,
    .evil_scythe = 25,
    .plasma_cannon = 25,
    .splitter_gun = 28,
    .gauss_shotgun = 30,
    .ion_shotgun = 31,
    .flameburst = 29,
    .raygun = 30,
    .plague_spreader_gun = 40,
    .bubblegun = 41,
    .rainbow_gun = 42,
    .grim_weapon = 43,
    .fire_bullets = 44,
    .transmutator = 49,
    .blaster_r_300 = 50,
    .lightning_rifle = 51,
    .nuke_launcher = 52,
});

pub inline fn weaponIconIndex(weapon_id: WeaponId) i32 {
    return weapon_icon_index.get(weapon_id);
}

pub inline fn weaponIdToInt(weapon_id: WeaponId) i32 {
    return @intFromEnum(weapon_id);
}

pub fn weaponIdFromInt(value: i32) WeaponId {
    if (value < 0 or value >= weapon_count_size) @panic("invalid weapon id");
    return @enumFromInt(value);
}

// Mirror Python/native `PROJECTILE_TEMPLATE_OVERRIDES`: explicit remaps and
// non-primary paths live here; other projectile-backed weapons default to
// `type_id == weapon_id` when the projectile enum has that slot.
pub fn projectileTypeIdFromWeaponId(weapon_id: WeaponId) ?ProjectileTypeId {
    return switch (weapon_id) {
        .pistol => ProjectileTypeId.pistol,
        .assault_rifle => ProjectileTypeId.assault_rifle,
        .shotgun => ProjectileTypeId.shotgun,
        .sawed_off_shotgun => ProjectileTypeId.shotgun,
        .submachine_gun => ProjectileTypeId.submachine_gun,
        .gauss_gun => ProjectileTypeId.gauss_gun,
        .mean_minigun => ProjectileTypeId.pistol,
        .flamethrower => null,
        .multi_plasma => ProjectileTypeId.plasma_rifle,
        .plasma_rifle => ProjectileTypeId.plasma_rifle,
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
        .spider_plasma => ProjectileTypeId.spider_plasma,
        .evil_scythe => ProjectileTypeId.evil_scythe,
        .plasma_cannon => ProjectileTypeId.plasma_cannon,
        .splitter_gun => ProjectileTypeId.splitter_gun,
        .gauss_shotgun => ProjectileTypeId.gauss_gun,
        .ion_shotgun => ProjectileTypeId.ion_minigun,
        .flameburst => ProjectileTypeId.flameburst,
        .raygun => ProjectileTypeId.raygun,
        .plague_spreader_gun => ProjectileTypeId.plague_spreader,
        .bubblegun => null,
        .rainbow_gun => ProjectileTypeId.rainbow_gun,
        .grim_weapon => ProjectileTypeId.grim_weapon,
        .fire_bullets => ProjectileTypeId.fire_bullets,
        .transmutator => ProjectileTypeId.transmutator,
        .blaster_r_300 => ProjectileTypeId.blaster_r_300,
        .lightning_rifle => ProjectileTypeId.lightning_rifle,
        .nuke_launcher => ProjectileTypeId.nuke_launcher,
        else => null,
    };
}

pub const ProjectileTypeIds = struct {
    count: usize = 0,
    values: [2]ProjectileTypeId = .{ .pistol, .pistol },

    pub fn slice(self: *const ProjectileTypeIds) []const ProjectileTypeId {
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
        .values = .{ type_id, .pistol },
    };
}

test "projectile type id mapping mirrors native fire paths" {
    const cases = [_]struct {
        weapon_id: i32,
        type_id: ProjectileTypeId,
    }{
        .{ .weapon_id = 1, .type_id = .pistol },
        .{ .weapon_id = 2, .type_id = .assault_rifle },
        .{ .weapon_id = 3, .type_id = .shotgun },
        .{ .weapon_id = 4, .type_id = .shotgun },
        .{ .weapon_id = 5, .type_id = .submachine_gun },
        .{ .weapon_id = 6, .type_id = .gauss_gun },
        .{ .weapon_id = 7, .type_id = .pistol },
        .{ .weapon_id = 9, .type_id = .plasma_rifle },
        .{ .weapon_id = 10, .type_id = .plasma_rifle },
        .{ .weapon_id = 11, .type_id = .plasma_minigun },
        .{ .weapon_id = 14, .type_id = .plasma_minigun },
        .{ .weapon_id = 19, .type_id = .pulse_gun },
        .{ .weapon_id = 20, .type_id = .shotgun },
        .{ .weapon_id = 21, .type_id = .ion_rifle },
        .{ .weapon_id = 22, .type_id = .ion_minigun },
        .{ .weapon_id = 23, .type_id = .ion_cannon },
        .{ .weapon_id = 24, .type_id = .shrinkifier },
        .{ .weapon_id = 25, .type_id = .blade_gun },
        .{ .weapon_id = 26, .type_id = .spider_plasma },
        .{ .weapon_id = 27, .type_id = .evil_scythe },
        .{ .weapon_id = 28, .type_id = .plasma_cannon },
        .{ .weapon_id = 29, .type_id = .splitter_gun },
        .{ .weapon_id = 30, .type_id = .gauss_gun },
        .{ .weapon_id = 31, .type_id = .ion_minigun },
        .{ .weapon_id = 32, .type_id = .flameburst },
        .{ .weapon_id = 33, .type_id = .raygun },
        .{ .weapon_id = 41, .type_id = .plague_spreader },
        .{ .weapon_id = 43, .type_id = .rainbow_gun },
        .{ .weapon_id = 44, .type_id = .grim_weapon },
        .{ .weapon_id = 45, .type_id = .fire_bullets },
        .{ .weapon_id = 50, .type_id = .transmutator },
        .{ .weapon_id = 51, .type_id = .blaster_r_300 },
        .{ .weapon_id = 52, .type_id = .lightning_rifle },
        .{ .weapon_id = 53, .type_id = .nuke_launcher },
    };

    for (cases) |case| {
        const weapon_id = weaponIdFromInt(case.weapon_id);
        try std.testing.expectEqual(case.type_id, projectileTypeIdFromWeaponId(weapon_id).?);
    }

    const multi_plasma_types = projectileTypeIdsFromWeaponId(.multi_plasma).slice();
    try std.testing.expectEqual(@as(usize, 2), multi_plasma_types.len);
    try std.testing.expectEqual(ProjectileTypeId.plasma_rifle, multi_plasma_types[0]);
    try std.testing.expectEqual(ProjectileTypeId.plasma_minigun, multi_plasma_types[1]);
}

test "non projectile weapons map to empty projectile type ids" {
    const non_projectile_weapons = [_]i32{ 8, 12, 13, 15, 16, 17, 18, 42 };
    for (non_projectile_weapons) |weapon_id| {
        const id = weaponIdFromInt(weapon_id);
        try std.testing.expectEqual(@as(?ProjectileTypeId, null), projectileTypeIdFromWeaponId(id));
        try std.testing.expectEqual(@as(usize, 0), projectileTypeIdsFromWeaponId(id).slice().len);
    }
}

test "weapon icon indices mirror runtime ui wicon metadata" {
    try std.testing.expectEqual(@as(i32, 0), weaponIconIndex(.pistol));
    try std.testing.expectEqual(@as(i32, 25), weaponIconIndex(.evil_scythe));
    try std.testing.expectEqual(@as(i32, 30), weaponIconIndex(.raygun));
    try std.testing.expectEqual(@as(i32, 52), weaponIconIndex(.nuke_launcher));
    try std.testing.expectEqual(@as(i32, -1), weaponIconIndex(.unknown_34));
}

test "non-damaging weapon templates preserve native damage scales" {
    try std.testing.expectEqual(@as(f32, 0.0), weapon_stats.get(.shrinkifier_5k).damage_scale);
    try std.testing.expectEqual(@as(f32, 0.0), weapon_stats.get(.plague_spreader_gun).damage_scale);
}
