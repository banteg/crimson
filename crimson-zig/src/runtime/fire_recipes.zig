const game_ids = @import("../game_ids.zig");

const particles_mod = @import("particles.zig");
const secondary_projectiles_mod = @import("secondary_projectiles.zig");
const weapon_data = @import("weapon_data.zig");

pub const WeaponId = game_ids.WeaponId;
pub const ProjectileTypeId = game_ids.ProjectileTypeId;

pub const PelletJitterRule = union(enum) {
    none,
    modulo_centered: struct {
        modulo: u32,
        center: i32,
        step: f32,
    },
    mask_centered: struct {
        mask: u32,
        center: i32,
        step: f32,
    },
};

pub const SpeedScaleRule = union(enum) {
    none,
    modulo: struct {
        base: f32,
        modulo: u32,
        step: f32,
    },
};

pub const SecondaryTargetingPolicy = enum {
    none,
    use_aim_target_hint,
};

pub const PrimaryPelletsMode = struct {
    type_id: ProjectileTypeId,
    count: i32,
    jitter: PelletJitterRule,
    speed_scale: SpeedScaleRule,
};

pub const SecondaryShotMode = struct {
    type_id: secondary_projectiles_mod.SecondaryProjectileTypeId,
    targeting: SecondaryTargetingPolicy = .none,
};

pub const ParticleStreamMode = struct {
    style: ?particles_mod.ParticleStyleId = null,
    slow: bool = false,
};

pub const FireMode = union(enum) {
    primary_pellets: PrimaryPelletsMode,
    secondary_shot: SecondaryShotMode,
    particle_stream: ParticleStreamMode,
    multi_plasma_fan: void,
    swarmer_dump: void,
};

pub const FireRecipe = struct {
    mode: FireMode,
    ammo_cost: f32 = 1.0,
};

const default_spread_jitter: PelletJitterRule = .{
    .modulo_centered = .{
        .modulo = 200,
        .center = 100,
        .step = 0.0015,
    },
};

const default_speed_scale: SpeedScaleRule = .{
    .modulo = .{
        .base = 1.0,
        .modulo = 100,
        .step = 0.01,
    },
};

const gauss_ion_speed_scale: SpeedScaleRule = .{
    .modulo = .{
        .base = 1.4,
        .modulo = 0x50,
        .step = 0.01,
    },
};

pub fn pelletJitterStepForWeapon(weapon_id: WeaponId) f32 {
    return switch (weapon_id) {
        .shotgun, .jackhammer => 0.0013,
        .sawed_off_shotgun => 0.004,
        else => 0.0015,
    };
}

pub fn resolveFireRecipe(
    weapon_id: WeaponId,
    pellet_count: i32,
    fire_bullets_active: bool,
) FireRecipe {
    if (fire_bullets_active) {
        return .{
            .mode = .{
                .primary_pellets = .{
                    .type_id = .fire_bullets,
                    .count = @max(0, pellet_count),
                    .jitter = default_spread_jitter,
                    .speed_scale = .none,
                },
            },
        };
    }

    return switch (weapon_id) {
        .rocket_launcher => .{
            .mode = .{
                .secondary_shot = .{
                    .type_id = .rocket,
                },
            },
        },
        .seeker_rockets => .{
            .mode = .{
                .secondary_shot = .{
                    .type_id = .homing_rocket,
                    .targeting = .use_aim_target_hint,
                },
            },
        },
        .rocket_minigun => .{
            .mode = .{
                .secondary_shot = .{
                    .type_id = .rocket_minigun,
                },
            },
        },
        .flamethrower => .{
            .mode = .{
                .particle_stream = .{},
            },
            .ammo_cost = 0.1,
        },
        .blow_torch => .{
            .mode = .{
                .particle_stream = .{
                    .style = .blow_torch,
                },
            },
            .ammo_cost = 0.05,
        },
        .hr_flamer => .{
            .mode = .{
                .particle_stream = .{
                    .style = .hr_flamer,
                },
            },
            .ammo_cost = 0.1,
        },
        .bubblegun => .{
            .mode = .{
                .particle_stream = .{
                    .slow = true,
                },
            },
            .ammo_cost = 0.15,
        },
        .multi_plasma => .{
            .mode = .{ .multi_plasma_fan = {} },
        },
        .mini_rocket_swarmers => .{
            .mode = .{ .swarmer_dump = {} },
        },
        .plasma_shotgun => .{
            .mode = .{
                .primary_pellets = .{
                    .type_id = .plasma_minigun,
                    .count = 14,
                    .jitter = .{
                        .mask_centered = .{
                            .mask = 0xff,
                            .center = 0x80,
                            .step = 0.002,
                        },
                    },
                    .speed_scale = default_speed_scale,
                },
            },
        },
        .gauss_shotgun => .{
            .mode = .{
                .primary_pellets = .{
                    .type_id = .gauss_gun,
                    .count = 6,
                    .jitter = .{
                        .modulo_centered = .{
                            .modulo = 200,
                            .center = 100,
                            .step = 0.002,
                        },
                    },
                    .speed_scale = gauss_ion_speed_scale,
                },
            },
        },
        .ion_shotgun => .{
            .mode = .{
                .primary_pellets = .{
                    .type_id = .ion_minigun,
                    .count = 8,
                    .jitter = .{
                        .modulo_centered = .{
                            .modulo = 200,
                            .center = 100,
                            .step = 0.0026,
                        },
                    },
                    .speed_scale = gauss_ion_speed_scale,
                },
            },
        },
        else => blk: {
            const pellets = @max(1, pellet_count);
            const jitter: PelletJitterRule = if (pellets > 1)
                .{
                    .modulo_centered = .{
                        .modulo = 200,
                        .center = 100,
                        .step = pelletJitterStepForWeapon(weapon_id),
                    },
                }
            else
                .none;

            const speed_scale: SpeedScaleRule = if (pellets > 1 and
                (weapon_id == .shotgun or weapon_id == .sawed_off_shotgun or weapon_id == .jackhammer))
                default_speed_scale
            else
                .none;

            break :blk .{
                .mode = .{
                    .primary_pellets = .{
                        .type_id = weapon_data.projectileTypeIdFromWeaponId(weapon_id) orelse unreachable,
                        .count = pellets,
                        .jitter = jitter,
                        .speed_scale = speed_scale,
                    },
                },
            };
        },
    };
}
