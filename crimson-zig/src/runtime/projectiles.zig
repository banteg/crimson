const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const bonus_runtime = @import("bonuses.zig");
const creatures_mod = @import("creatures.zig");
const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const effects_mod = @import("effects.zig");
const owner_ref = @import("owner_ref.zig");
const perks = @import("perks.zig");
const rng_callers = @import("../rng_caller_static.zig");
const runtime_helpers = @import("helpers.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");
const terrain_fx_mod = @import("terrain_fx.zig");
const weapon_data = @import("weapon_data.zig");
const math = @import("math.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;
const WeaponId = state_mod.WeaponId;

pub const main_projectile_pool_size: usize = 0x60;
const native_half_pi: f32 = native_math.roundF32(native_math.native_half_pi);

pub const Projectile = struct {
    active: bool = false,
    angle: f32 = 0.0,
    pos: state_mod.Vec2 = .{},
    origin: state_mod.Vec2 = .{},
    vel: state_mod.Vec2 = .{},
    type_id: i32 = 0,
    life_timer: f32 = 0.0,
    reserved: f32 = 0.0,
    speed_scale: f32 = 1.0,
    damage_pool: f32 = 1.0,
    hit_radius: f32 = 1.0,
    travel_budget: f32 = 0.0,
    owner: owner_ref.OwnerRef = .{ .none = {} },
    hits_players: bool = false,
};

pub const ProjectileTickStats = struct {
    hit_count: i32 = 0,
    hit_audio_event_count: usize = 0,
    hit_audio_trigger_game_tune: bool = false,
    hit_audio_events: [4]creatures_mod.HitSfxPlan = [_]creatures_mod.HitSfxPlan{.{}} ** 4,
    first_hit_creature_index: i32 = -1,
    first_hit_projectile_index: i32 = -1,
    first_hit_type_id: i32 = 0,
    first_hit_origin: state_mod.Vec2 = .{},
    first_hit_pos: state_mod.Vec2 = .{},
    first_hit_target_size: f32 = 0.0,
    first_hit_target_x: f32 = 0.0,
    first_hit_target_y: f32 = 0.0,
};

pub const ProjectilePool = struct {
    entries: [main_projectile_pool_size]Projectile = [_]Projectile{.{}} ** main_projectile_pool_size,

    pub fn reset(self: *ProjectilePool) void {
        self.entries = [_]Projectile{.{}} ** main_projectile_pool_size;
    }

    pub fn spawn(
        self: *ProjectilePool,
        pos: state_mod.Vec2,
        angle: f32,
        type_id: i32,
        owner: owner_ref.OwnerRef,
        travel_budget: f32,
        hits_players: bool,
    ) usize {
        var index: usize = self.entries.len - 1;
        for (self.entries, 0..) |entry, idx| {
            if (!entry.active) {
                index = idx;
                break;
            }
        }

        const budget = if (travel_budget > 0.0) travel_budget else projectileTravelBudgetFromRawId(type_id);
        var entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .angle = angle,
            .pos = .{ .x = pos.x, .y = pos.y },
            .origin = .{ .x = pos.x, .y = pos.y },
            // Native writes vel = (cos(angle), sin(angle)) * 1.5 - the raw
            // trig components, not the heading-rotated direction.
            .vel = .{
                .x = narrowF32(@cos(@as(f64, @floatCast(angle))) * 1.5),
                .y = narrowF32(@sin(@as(f64, @floatCast(angle))) * 1.5),
            },
            .type_id = type_id,
            .life_timer = 0.4,
            .reserved = 0.0,
            .speed_scale = 1.0,
            .damage_pool = 1.0,
            .hit_radius = 1.0,
            .travel_budget = budget,
            .owner = owner,
            .hits_players = hits_players,
        };

        if (type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_minigun)) {
            entry.hit_radius = 3.0;
            return index;
        }
        if (type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_rifle)) {
            entry.hit_radius = 5.0;
            return index;
        }
        if (type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) or
            type_id == @intFromEnum(game_ids.ProjectileTypeId.plasma_cannon))
        {
            entry.hit_radius = 10.0;
        } else {
            entry.hit_radius = 1.0;
            if (type_id == @intFromEnum(game_ids.ProjectileTypeId.gauss_gun)) {
                entry.damage_pool = 300.0;
                return index;
            }
            if (type_id == @intFromEnum(game_ids.ProjectileTypeId.fire_bullets)) {
                entry.damage_pool = 240.0;
                return index;
            }
            if (type_id == @intFromEnum(game_ids.ProjectileTypeId.blade_gun)) {
                entry.damage_pool = 50.0;
                return index;
            }
        }
        return index;
    }

    pub fn update(
        self: *ProjectilePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        creatures: *creatures_mod.CreaturePool,
        bonuses: *bonus_runtime.BonusPool,
        dt: f32,
        world_size: f32,
    ) ProjectileTickStats {
        var effects: effects_mod.EffectPool = .{};
        var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
        return self.updateWithEffects(state, players, creatures, bonuses, &effects, &terrain_fx, 5, dt, world_size);
    }

    pub fn updateWithEffects(
        self: *ProjectilePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        creatures: *creatures_mod.CreaturePool,
        bonuses: *bonus_runtime.BonusPool,
        effects: *effects_mod.EffectPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        detail_preset: i32,
        dt: f32,
        world_size: f32,
    ) ProjectileTickStats {
        if (!(dt > 0.0)) return .{};
        const margin: f32 = 64.0;
        var barrel_greaser_active = false;
        var ion_gun_master_active = false;
        var ion_scale: f32 = 1.0;
        for (players) |*player| {
            if (perks.perkActive(player, PerkId.barrel_greaser)) {
                barrel_greaser_active = true;
            }
            if (perks.perkActive(player, PerkId.ion_gun_master)) {
                ion_gun_master_active = true;
            }
            if (barrel_greaser_active and ion_gun_master_active) {
                break;
            }
        }
        if (ion_scale == 1.0 and ion_gun_master_active) {
            ion_scale = 1.2;
        }
        var hit_audio_game_tune_started = state.game_tune_started;
        var tick_stats: ProjectileTickStats = .{};
        // Mirror Python/native spatial-hash behavior for one projectile update pass:
        // candidate slots are seeded from collidable-at-pass-start state and only
        // synced for indices touched by damage resolution.
        var collidable_snapshot = [_]bool{false} ** creatures_mod.max_creatures;
        var candidate_cell_x = [_]i32{0} ** creatures_mod.max_creatures;
        var candidate_cell_y = [_]i32{0} ** creatures_mod.max_creatures;
        var candidate_has_cell = [_]bool{false} ** creatures_mod.max_creatures;
        var max_find_margin: f32 = 0.0;
        const bucket_size: f32 = 64.0;
        for (creatures.entries, 0..) |creature, idx| {
            collidable_snapshot[idx] = creature.active and
                creature_lifecycle.isCollidable(creature.lifecycle_stage);
            if (!collidable_snapshot[idx]) continue;
            candidate_has_cell[idx] = true;
            candidate_cell_x[idx] = @intFromFloat(@floor(creature.pos.x / bucket_size));
            candidate_cell_y[idx] = @intFromFloat(@floor(creature.pos.y / bucket_size));
            const find_margin = narrowF32(creature.size * 0.14285715 + 3.0);
            if (find_margin > max_find_margin) {
                max_find_margin = find_margin;
            }
        }

        for (&self.entries, 0..) |*proj, proj_idx| {
            if (!proj.active) continue;

            if (proj.life_timer <= 0.0) {
                proj.active = false;
            }

            if (proj.life_timer < 0.4) {
                if (proj.type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) or
                    proj.type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_minigun))
                {
                    resetShockChainIfOwner(state, proj_idx);
                }
                const linger_decay: f32 = switch (proj.type_id) {
                    @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) => native_math.pc24Mul(dt, @as(f32, 0.1)),
                    @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) => native_math.pc24Mul(dt, @as(f32, 0.7)),
                    else => dt,
                };
                proj.life_timer = native_math.pc24Sub(proj.life_timer, linger_decay);
                applyIonLingerDamage(
                    state,
                    players,
                    creatures,
                    bonuses,
                    terrain_fx,
                    proj,
                    dt,
                    ion_scale,
                    world_size,
                );
                continue;
            }

            if (proj.pos.x < -margin or proj.pos.y < -margin or
                proj.pos.x > world_size + margin or proj.pos.y > world_size + margin)
            {
                proj.life_timer = narrowF32(proj.life_timer - dt);
                continue;
            }

            var steps: i32 = @intFromFloat(proj.travel_budget);
            if (barrel_greaser_active and proj.owner.isPlayer()) {
                steps *= 2;
            }
            const heading_radians = native_math.pc24Sub(proj.angle, native_half_pi);
            const dir_x_ext = std.math.cos(@as(f64, @floatCast(heading_radians)));
            const dir_y_ext = std.math.sin(@as(f64, @floatCast(heading_radians)));
            const step_x = native_math.pc24Mul(
                native_math.pc24Mul(
                    native_math.pc24Mul(
                        native_math.pc24Mul(dir_x_ext, dt),
                        @as(f32, 20.0),
                    ),
                    proj.speed_scale,
                ),
                @as(f32, 3.0),
            );
            const step_y = native_math.pc24Mul(
                native_math.pc24Mul(
                    native_math.pc24Mul(
                        native_math.pc24Mul(dir_y_ext, dt),
                        @as(f32, 20.0),
                    ),
                    proj.speed_scale,
                ),
                @as(f32, 3.0),
            );
            var acc: state_mod.Vec2 = .{};

            var step: i32 = 0;
            while (step < steps) : (step += 3) {
                acc = .{
                    .x = native_math.pc24Add(acc.x, step_x),
                    .y = native_math.pc24Add(acc.y, step_y),
                };

                if (!(acc.length() >= 4.0 or steps <= step + 3)) continue;

                const move = acc;
                proj.pos = .{
                    .x = narrowF32(proj.pos.x + move.x),
                    .y = narrowF32(proj.pos.y + move.y),
                };
                acc = .{};

                var hit_idx: ?usize = null;
                const proj_cell_x: i32 = @intFromFloat(@floor(proj.pos.x / bucket_size));
                const proj_cell_y: i32 = @intFromFloat(@floor(proj.pos.y / bucket_size));
                const max_axis_delta = narrowF32(proj.hit_radius + max_find_margin + 0.001);
                const cell_span: i32 = @intFromFloat(@ceil(max_axis_delta / bucket_size));
                for (creatures.entries, 0..) |creature, idx| {
                    if (!collidable_snapshot[idx]) continue;
                    if (!candidate_has_cell[idx]) continue;
                    if (!(creature.active and creature_lifecycle.isCollidable(creature.lifecycle_stage))) continue;
                    const in_span =
                        @abs(candidate_cell_x[idx] - proj_cell_x) <= cell_span and
                        @abs(candidate_cell_y[idx] - proj_cell_y) <= cell_span;
                    if (!in_span) continue;
                    if (runtime_helpers.withinNativeFindRadius(
                        proj.pos,
                        creature.pos,
                        proj.hit_radius,
                        creature.size,
                    )) {
                        hit_idx = idx;
                        break;
                    }
                }

                if (hit_idx) |idx| {
                    if (proj.owner.creatureIndexInBounds(creatures.entries.len)) |owner_idx| {
                        if (idx == owner_idx) {
                            hit_idx = null;
                        }
                    }
                }
                if (hit_idx == null) {
                    var can_hit_players = true;
                    if (state.shock_chain_projectile_id == @as(i32, @intCast(proj_idx))) {
                        can_hit_players = false;
                    }

                    if (proj.hits_players and can_hit_players) {
                        var hit_player_idx: ?usize = null;
                        const owner_player_idx = proj.owner.playerIndexInBounds(players.len);

                        for (players, 0..) |player, idx| {
                            if (owner_player_idx) |owner_idx| {
                                if (owner_idx == idx) continue;
                            }
                            if (!(player.health > 0.0)) continue;
                            if (runtime_helpers.withinNativeFindRadius(
                                proj.pos,
                                player.pos,
                                proj.hit_radius,
                                player.size,
                            )) {
                                hit_player_idx = idx;
                                break;
                            }
                        }

                        if (hit_player_idx) |player_idx| {
                            proj.life_timer = 0.25;
                            if (players[player_idx].shield_timer <= 0.0) {
                                players[player_idx].health = narrowF32(players[player_idx].health - 10.0);
                            }
                        }
                    }
                    continue;
                }
                tick_stats.hit_count += 1;
                if (tick_stats.first_hit_creature_index < 0) {
                    tick_stats.first_hit_creature_index = @intCast(hit_idx.?);
                    tick_stats.first_hit_projectile_index = @intCast(proj_idx);
                    tick_stats.first_hit_type_id = proj.type_id;
                    tick_stats.first_hit_origin = .{
                        .x = narrowF32(proj.origin.x),
                        .y = narrowF32(proj.origin.y),
                    };
                    tick_stats.first_hit_pos = .{
                        .x = narrowF32(proj.pos.x),
                        .y = narrowF32(proj.pos.y),
                    };
                    tick_stats.first_hit_target_size = narrowF32(creatures.entries[hit_idx.?].size);
                    tick_stats.first_hit_target_x = narrowF32(creatures.entries[hit_idx.?].pos.x);
                    tick_stats.first_hit_target_y = narrowF32(creatures.entries[hit_idx.?].pos.y);
                }

                const owner_player_idx = proj.owner.playerIndexInBounds(players.len);
                const presentation_player = if (owner_player_idx) |idx| &players[idx] else if (players.len > 0) &players[0] else null;

                // Native gates on the global perk count, so the rand is drawn for
                // every projectile hit while any player owns the perk - including
                // creature-owned projectiles such as splitter children.
                var poison_bullets_active = false;
                for (players) |*player| {
                    if (perks.perkActive(player, PerkId.poison_bullets)) {
                        poison_bullets_active = true;
                        break;
                    }
                }
                if (poison_bullets_active) {
                    const poison_roll = state.rng.randTagged(rng_callers.projectile_update_poison_bullets_gate);
                    if ((poison_roll & 7) == 1) {
                        creatures.entries[hit_idx.?].flags |= spawn_mod.CreatureFlags.self_damage_tick;
                    }
                }
                if (presentation_player) |player| {
                    emitProjectileHitPresentationPre(
                        state,
                        player,
                        proj.type_id,
                        proj.origin,
                        proj.pos,
                        creatures.entries[hit_idx.?].pos,
                        effects,
                        terrain_fx,
                        detail_preset,
                    );
                }

                // Native increments the global shots-hit counter for any owner
                // (creature-owned splitter children included); non-player owners
                // map to the player-1 global slot.
                {
                    const hit_slot: usize = owner_player_idx orelse 0;
                    if (hit_slot < state.shots_hit.len and creature_lifecycle.isAlive(creatures.entries[hit_idx.?].lifecycle_stage)) {
                        state.shots_hit[hit_slot] += 1;
                    }
                }

                if (proj.life_timer != 0.25 and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets) and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.blade_gun))
                {
                    proj.life_timer = 0.25;
                    const jitter = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_stop_on_hit_jitter) & 3));
                    // Native rounds the multiply and add as separate PC24 operations.
                    proj.pos = .{
                        .x = native_math.pc24Add(native_math.pc24Mul(dir_x_ext, jitter), proj.pos.x),
                        .y = native_math.pc24Add(native_math.pc24Mul(dir_y_ext, jitter), proj.pos.y),
                    };
                }

                if (proj.type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_rifle)) {
                    postHitIonRifleShockChain(
                        state,
                        self,
                        creatures,
                        proj_idx,
                        proj,
                        hit_idx.?,
                    );
                }
                if (proj.type_id == @intFromEnum(game_ids.ProjectileTypeId.pulse_gun)) {
                    // Native pulse-gun post-hit behavior pushes the target using the
                    // current projectile move delta before damage resolution.
                    creatures.entries[hit_idx.?].pos = .{
                        .x = narrowF32(creatures.entries[hit_idx.?].pos.x + move.x * 3.0),
                        .y = narrowF32(creatures.entries[hit_idx.?].pos.y + move.y * 3.0),
                    };
                }
                emitProjectileTypeHitEffects(
                    state,
                    proj.type_id,
                    proj.pos,
                    effects,
                    detail_preset,
                );

                var dist = state_mod.Vec2.sub(proj.origin, proj.pos).length();
                if (dist < 50.0) dist = 50.0;
                const damage_scale = damageScaleFromRawId(proj.type_id);
                const damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95;
                const impulse_axis = projectileImpulseAxisF32(proj.angle, proj.speed_scale);
                const impulse: state_mod.Vec2 = .{
                    .x = impulse_axis,
                    .y = impulse_axis,
                };

                if (damage_amount > 0.0 and creatures.entries[hit_idx.?].hp > 0.0) {
                    const remaining = proj.damage_pool - 1.0;
                    proj.damage_pool = remaining;
                    if (remaining <= 0.0) {
                        _ = creatures.applyProjectileDamage(
                            state,
                            players,
                            bonuses,
                            terrain_fx,
                            hit_idx.?,
                            narrowF32(damage_amount),
                            impulse,
                            proj.owner,
                            narrowF32(dt),
                            narrowF32(world_size),
                        );
                        if (proj.life_timer != 0.25) {
                            proj.life_timer = 0.25;
                        }
                    } else {
                        _ = creatures.applyProjectileDamage(
                            state,
                            players,
                            bonuses,
                            terrain_fx,
                            hit_idx.?,
                            remaining,
                            impulse,
                            proj.owner,
                            narrowF32(dt),
                            narrowF32(world_size),
                        );
                        proj.damage_pool -= narrowF32(creatures.entries[hit_idx.?].hp);
                    }
                    const idx = hit_idx.?;
                    collidable_snapshot[idx] = creatures.entries[idx].active and
                        creature_lifecycle.isCollidable(creatures.entries[idx].lifecycle_stage);
                    if (!collidable_snapshot[idx]) {
                        candidate_has_cell[idx] = false;
                    } else {
                        candidate_has_cell[idx] = true;
                        candidate_cell_x[idx] = @intFromFloat(@floor(creatures.entries[idx].pos.x / bucket_size));
                        candidate_cell_y[idx] = @intFromFloat(@floor(creatures.entries[idx].pos.y / bucket_size));
                        const find_margin = narrowF32(creatures.entries[idx].size * 0.14285715 + 3.0);
                        if (find_margin > max_find_margin) {
                            max_find_margin = find_margin;
                        }
                    }
                }

                // The default single freeze shard is presentation: it spawns inside
                // the post-hit decal branch, after the burn draw, in
                // emitProjectileHitPresentationPost.

                if (proj.damage_pool == 1.0) {
                    const life_before = proj.life_timer;
                    proj.damage_pool = 0.0;
                    if (life_before != 0.25) {
                        proj.life_timer = 0.25;
                    }
                }

                if (proj.life_timer == 0.25 and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets) and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.blade_gun))
                {
                    if (presentation_player != null) {
                        emitProjectileHitPresentationPost(
                            state,
                            proj.type_id,
                            proj.origin,
                            proj.pos,
                            creatures.entries[hit_idx.?].pos,
                            effects,
                            terrain_fx,
                            detail_preset,
                        );
                        const hit_sfx_plan = creatures_mod.consumeHitSfxRng(
                            state,
                            &hit_audio_game_tune_started,
                            proj.type_id,
                        );
                        if (hit_sfx_plan.trigger_game_tune) {
                            tick_stats.hit_audio_trigger_game_tune = true;
                        }
                        if (tick_stats.hit_audio_event_count < tick_stats.hit_audio_events.len) {
                            tick_stats.hit_audio_events[tick_stats.hit_audio_event_count] = hit_sfx_plan;
                            tick_stats.hit_audio_event_count += 1;
                        }
                    }
                    break;
                }
                if (presentation_player != null) {
                    emitProjectileHitPresentationPost(
                        state,
                        proj.type_id,
                        proj.origin,
                        proj.pos,
                        creatures.entries[hit_idx.?].pos,
                        effects,
                        terrain_fx,
                        detail_preset,
                    );
                    const hit_sfx_plan = creatures_mod.consumeHitSfxRng(
                        state,
                        &hit_audio_game_tune_started,
                        proj.type_id,
                    );
                    if (hit_sfx_plan.trigger_game_tune) {
                        tick_stats.hit_audio_trigger_game_tune = true;
                    }
                    if (tick_stats.hit_audio_event_count < tick_stats.hit_audio_events.len) {
                        tick_stats.hit_audio_events[tick_stats.hit_audio_event_count] = hit_sfx_plan;
                        tick_stats.hit_audio_event_count += 1;
                    }
                }
                if (proj.damage_pool <= 0.0) break;
            }
        }
        state.game_tune_started = hit_audio_game_tune_started;
        return tick_stats;
    }
};

fn resetShockChainIfOwner(
    state: *state_mod.GameplayState,
    proj_index: usize,
) void {
    if (state.shock_chain_projectile_id != @as(i32, @intCast(proj_index))) return;
    state.shock_chain_projectile_id = -1;
    state.shock_chain_links_left = 0;
}

fn applyIonLingerDamage(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    bonus_pool: *bonus_runtime.BonusPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    proj: *Projectile,
    dt: f32,
    ion_scale: f32,
    world_size: f32,
) void {
    var damage: f32 = 0.0;
    var radius: f32 = 0.0;
    switch (proj.type_id) {
        @intFromEnum(game_ids.ProjectileTypeId.ion_minigun) => {
            damage = native_math.pc24Mul(dt, @as(f32, 40.0));
            radius = native_math.pc24Mul(ion_scale, @as(f32, 60.0));
        },
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) => {
            damage = native_math.pc24Mul(dt, @as(f32, 100.0));
            radius = native_math.pc24Mul(ion_scale, @as(f32, 88.0));
        },
        @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) => {
            damage = native_math.pc24Mul(dt, @as(f32, 300.0));
            radius = native_math.pc24Mul(ion_scale, @as(f32, 128.0));
        },
        else => return,
    }

    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!creature_lifecycle.isCollidable(creature.lifecycle_stage)) continue;
        const creature_radius = creatureHitRadius(creature.size);
        const hit_radius = radius + creature_radius;
        if (runtime_helpers.distanceSq(proj.pos, creature.pos) <= hit_radius * hit_radius) {
            _ = creatures.applyIonDamage(
                state,
                players,
                bonus_pool,
                terrain_fx,
                idx,
                narrowF32(damage),
                .{},
                proj.owner,
                dt,
                world_size,
            );
        }
    }
}

fn emitProjectileHitPresentationPre(
    state: *state_mod.GameplayState,
    player: *const state_mod.PlayerState,
    projectile_type_id: i32,
    hit_origin: state_mod.Vec2,
    hit_pos: state_mod.Vec2,
    hit_target: state_mod.Vec2,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    detail_preset: i32,
) void {
    const freeze_active = state.bonuses.freeze > 0.0;
    const base_angle = state_mod.Vec2.sub(hit_pos, hit_origin).toAngle();

    if (projectile_type_id == @intFromEnum(game_ids.ProjectileTypeId.blade_gun)) {
        for (0..8) |_| {
            const angle = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_blade_gun_splatter_angle) & 0xff)) * 0.024543693;
            effects.spawnBloodSplatter(state, hit_pos, angle, 0.0, detail_preset, state.gore_disabled);
        }
    }

    // Native wraps the splatter block (including its spread / reverse-gate rand
    // draws) in `if (config_violence_disabled == '\0')`; the bloody-mess decal
    // loop below runs regardless of the violence setting.
    if (perks.perkActive(player, PerkId.bloody_mess_quick_learner)) {
        if (state.gore_disabled == 0) {
            for (0..8) |_| {
                const spread = (@as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_bloody_mess_spread) & 0x1f)) - 16.0) * 0.0625;
                effects.spawnBloodSplatter(state, hit_pos, base_angle + spread, 0.0, detail_preset, state.gore_disabled);
            }
            effects.spawnBloodSplatter(state, hit_pos, base_angle + std.math.pi, 0.0, detail_preset, state.gore_disabled);
        }

        var lo: i32 = -30;
        var hi: i32 = 30;
        while (lo > -60) {
            const span: u32 = @intCast(hi - lo);
            for (0..2) |_| {
                const dx = @as(f32, @floatFromInt(@as(i32, @intCast(state.rng.randTagged(rng_callers.projectile_update_bloody_mess_decal_dx_1) % span)) + lo));
                const dy = @as(f32, @floatFromInt(@as(i32, @intCast(state.rng.randTagged(rng_callers.projectile_update_bloody_mess_decal_dy_1) % span)) + lo));
                _ = terrain_fx.decals.addRandom(state, .{
                    .x = hit_target.x + dx,
                    .y = hit_target.y + dy,
                });
            }
            lo -= 10;
            hi += 10;
        }
    } else if (!freeze_active and state.gore_disabled == 0) {
        for (0..2) |_| {
            effects.spawnBloodSplatter(state, hit_pos, base_angle, 0.0, detail_preset, state.gore_disabled);
            if ((state.rng.randTagged(rng_callers.projectile_update_default_reverse_splatter_gate) & 7) == 2) {
                effects.spawnBloodSplatter(state, hit_pos, base_angle + std.math.pi, 0.0, detail_preset, state.gore_disabled);
            }
        }
    }
}

fn emitProjectileHitPresentationPost(
    state: *state_mod.GameplayState,
    projectile_type_id: i32,
    hit_origin: state_mod.Vec2,
    hit_pos: state_mod.Vec2,
    hit_target: state_mod.Vec2,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    detail_preset: i32,
) void {
    const freeze_active = state.bonuses.freeze > 0.0;
    const base_angle = state_mod.Vec2.sub(hit_pos, hit_origin).toAngle();

    _ = state.rng.randTagged(rng_callers.projectile_update_post_hit_decal_burn);

    if (projectile_type_id == @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) or
        projectile_type_id == @intFromEnum(game_ids.ProjectileTypeId.fire_bullets))
    {
        queueLargeHitStreakDecal(state, hit_target, base_angle, effects, terrain_fx, detail_preset);
        return;
    }
    if (freeze_active) {
        // Native: with Freeze active, default hits spawn one freeze shard here,
        // after the burn draw, instead of the streak decal loop.
        const shard_angle = base_angle + @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_default_freeze_shard_angle) % 100)) * 0.01;
        effects.spawnFreezeShard(state, hit_pos, shard_angle, detail_preset);
        return;
    }

    var streak_idx: usize = 0;
    while (streak_idx < 3) : (streak_idx += 1) {
        const spread = (@as(f32, @floatFromInt(@as(i32, @intCast(state.rng.randTagged(rng_callers.projectile_update_decal_spread) % 20)) - 10))) * 0.1;
        const angle = base_angle + spread;
        const direction = state_mod.Vec2.fromAngle(angle).mul(20.0);
        _ = terrain_fx.decals.addRandom(state, hit_target);
        _ = terrain_fx.decals.addRandom(state, state_mod.Vec2.add(hit_target, direction.mul(1.5)));
        _ = terrain_fx.decals.addRandom(state, state_mod.Vec2.add(hit_target, direction.mul(2.0)));
        _ = terrain_fx.decals.addRandom(state, state_mod.Vec2.add(hit_target, direction.mul(2.5)));
    }
}

fn queueLargeHitStreakDecal(
    state: *state_mod.GameplayState,
    hit_target: state_mod.Vec2,
    base_angle: f32,
    effects: *effects_mod.EffectPool,
    terrain_fx: *terrain_fx_mod.TerrainFxScratch,
    detail_preset: i32,
) void {
    const direction = state_mod.Vec2.fromAngle(base_angle);
    const freeze_active = state.bonuses.freeze > 0.0;
    for (0..6) |_| {
        var dist = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_large_streak_dist) % 100)) * 0.1;
        if (dist > 4.0) {
            dist = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_large_streak_dist_gt4) % 90 + 10)) * 0.1;
        }
        if (dist > 7.0) {
            dist = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_large_streak_dist_gt7) % 80 + 20)) * 0.1;
        }
        _ = state.rng.randTagged(rng_callers.projectile_update_large_streak_burn);
        const decal_pos = state_mod.Vec2.add(hit_target, direction.mul(dist * 20.0));
        if (freeze_active) {
            const freeze_angle = base_angle + @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_large_streak_freeze_angle) % 100)) * 0.01;
            effects.spawnFreezeShard(state, decal_pos, freeze_angle, detail_preset);
        }
        _ = terrain_fx.decals.addRandom(state, decal_pos);
    }
}

fn emitProjectileTypeHitEffects(
    state: *state_mod.GameplayState,
    projectile_type_id: i32,
    pos: state_mod.Vec2,
    effects: *effects_mod.EffectPool,
    detail_preset: i32,
) void {
    switch (projectile_type_id) {
        @intFromEnum(game_ids.ProjectileTypeId.shrinkifier) => {
            _ = effects.spawn(
                @intFromEnum(effects_mod.EffectId.ring),
                pos,
                .{},
                0.0,
                1.0,
                36.0,
                36.0,
                0.0,
                0.3,
                0x19,
                .{ .r = 0.3, .g = 0.6, .b = 0.9, .a = 1.0 },
                0.0,
                -4.0,
                detail_preset,
            );
            const count: usize = if (detail_preset < 3) 2 else 4;
            for (0..count) |_| {
                effects.spawnBurstParticle(
                    pos,
                    state.rng.randTagged(rng_callers.shrinkifier_hit_rotation),
                    state.rng.randTagged(rng_callers.shrinkifier_hit_vel_x),
                    state.rng.randTagged(rng_callers.shrinkifier_hit_vel_y),
                    state.rng.randTagged(rng_callers.shrinkifier_hit_scale_step),
                    null,
                    0.3,
                    .{ .r = 0.4, .g = 0.5, .b = 1.0, .a = 0.5 },
                    detail_preset,
                );
            }
        },
        @intFromEnum(game_ids.ProjectileTypeId.ion_minigun),
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle),
        @intFromEnum(game_ids.ProjectileTypeId.ion_cannon),
        => {
            if (projectile_type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_cannon)) {
                state.sfx_queue.append(.shockwave);
            }
            const ring_scale: f32 = switch (projectile_type_id) {
                @intFromEnum(game_ids.ProjectileTypeId.ion_minigun) => 1.5,
                @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) => 1.2,
                @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) => 1.0,
                else => 0.0,
            };
            const ring_strength: f32 = switch (projectile_type_id) {
                @intFromEnum(game_ids.ProjectileTypeId.ion_minigun) => 0.1,
                @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) => 0.4,
                @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) => 1.0,
                else => 0.0,
            };
            const burst_scale: f32 = switch (projectile_type_id) {
                @intFromEnum(game_ids.ProjectileTypeId.ion_minigun) => 0.8,
                @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) => 1.2,
                @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) => 2.2,
                else => 0.0,
            };
            spawnProjectileImpactRing(
                effects,
                pos,
                detail_preset,
                .{ .r = 0.6, .g = 0.6, .b = 0.9, .a = 1.0 },
                0.0,
                ring_strength * 0.8,
                ring_scale * 45.0,
            );
            const burst = burst_scale * 0.8;
            var count: i32 = @intFromFloat(burst * 5.0);
            if (detail_preset < 3) count = @divTrunc(count, 2);
            var idx: i32 = 0;
            while (idx < count) : (idx += 1) {
                const rotation = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.ion_hit_spark_rotation) & 0x7f)) * 0.049087387;
                const vel: state_mod.Vec2 = .{
                    .x = (@as(f32, @floatFromInt(state.rng.randTagged(rng_callers.ion_hit_spark_vel_x) & 0x7f)) - 64.0) * burst * 1.4,
                    .y = (@as(f32, @floatFromInt(state.rng.randTagged(rng_callers.ion_hit_spark_vel_y) & 0x7f)) - 64.0) * burst * 1.4,
                };
                const scale_step = (@as(f32, @floatFromInt(state.rng.randTagged(rng_callers.ion_hit_spark_scale_step) % 100)) * 0.01 + 0.1) * burst;
                _ = effects.spawn(
                    @intFromEnum(effects_mod.EffectId.burst),
                    pos,
                    vel,
                    rotation,
                    1.0,
                    burst * 32.0,
                    burst * 32.0,
                    0.0,
                    @min(burst * 0.7, 1.1),
                    0x1D,
                    .{ .r = 0.4, .g = 0.5, .b = 1.0, .a = 0.5 },
                    0.0,
                    scale_step,
                    detail_preset,
                );
            }
        },
        @intFromEnum(game_ids.ProjectileTypeId.plasma_cannon) => {
            state.sfx_queue.append(.explosion_medium);
            state.sfx_queue.append(.shockwave);
            spawnProjectileImpactRing(
                effects,
                pos,
                detail_preset,
                .{ .r = 0.9, .g = 0.6, .b = 0.3, .a = 1.0 },
                0.1,
                1.0,
                1.5 * 45.0,
            );
            spawnProjectileImpactRing(
                effects,
                pos,
                detail_preset,
                .{ .r = 0.9, .g = 0.6, .b = 0.3, .a = 1.0 },
                0.1,
                1.0,
                1.0 * 45.0,
            );
        },
        @intFromEnum(game_ids.ProjectileTypeId.splitter_gun) => {
            for (0..3) |_| {
                const angle = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.splitter_hit_angle) & 0x1ff)) * (std.math.tau / 512.0);
                const radius = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.splitter_hit_radius) % 26));
                const jitter_age = -@as(f32, @floatFromInt(state.rng.randTagged(rng_callers.splitter_hit_age) & 0xff)) * 0.0012;
                const offset = state_mod.Vec2.fromAngle(angle).mul(radius);
                _ = effects.spawn(
                    @intFromEnum(effects_mod.EffectId.burst),
                    state_mod.Vec2.add(pos, offset),
                    .{},
                    0.0,
                    1.0,
                    4.0,
                    4.0,
                    jitter_age,
                    0.1 - jitter_age,
                    0x19,
                    .{ .r = 1.0, .g = 0.9, .b = 0.1, .a = 1.0 },
                    0.0,
                    55.0,
                    detail_preset,
                );
            }
        },
        else => {},
    }
}

fn spawnProjectileImpactRing(
    effects: *effects_mod.EffectPool,
    pos: state_mod.Vec2,
    detail_preset: i32,
    color: effects_mod.Color,
    age: f32,
    lifetime: f32,
    scale_step: f32,
) void {
    _ = effects.spawn(
        @intFromEnum(effects_mod.EffectId.ring),
        pos,
        .{},
        0.0,
        1.0,
        4.0,
        4.0,
        age,
        lifetime,
        0x19,
        color,
        0.0,
        scale_step,
        detail_preset,
    );
}

fn creatureHitRadius(size: f32) f32 {
    const radius = narrowF32(size * 0.14285715 + 3.0);
    if (radius < 0.0) return 0.0;
    return radius;
}

fn postHitIonRifleShockChain(
    state: *state_mod.GameplayState,
    pool: *ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    proj_index: usize,
    proj: *const Projectile,
    hit_idx: usize,
) void {
    if (state.shock_chain_projectile_id != @as(i32, @intCast(proj_index))) return;
    if (hit_idx >= creatures.entries.len) return;

    const links_left = state.shock_chain_links_left;
    if (links_left <= 0) return;
    state.shock_chain_links_left = links_left - 1;

    const origin_pos = proj.pos;
    const min_dist_sq = 100.0 * 100.0;
    var best_idx: usize = 0;
    var best_dist_sq: f32 = 1e12;
    for (creatures.entries, 0..) |creature, idx| {
        if (idx == hit_idx) continue;
        if (!creature.active) continue;
        const d_sq = runtime_helpers.distanceSq(origin_pos, creature.pos);
        if (d_sq <= min_dist_sq) continue;
        if (d_sq < best_dist_sq) {
            best_dist_sq = d_sq;
            best_idx = idx;
        }
    }

    const origin_creature = creatures.entries[hit_idx];
    const target = creatures.entries[best_idx];
    // Native stores (float)(atan2(dy, dx) - 1.5707964 - 3.1415927) with a
    // single f32 spill (differs from toHeading() by 2*pi).
    const delta = state_mod.Vec2.sub(target.pos, origin_creature.pos);
    const angle: f32 = @floatCast(std.math.atan2(@as(f64, delta.y), @as(f64, delta.x)) - @as(f64, native_half_pi) - @as(f64, native_math.roundF32(native_math.native_pi)));

    const prev_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_guard;

    const spawned_idx = pool.spawn(
        origin_pos,
        angle,
        proj.type_id,
        owner_ref.OwnerRef.fromCreature(hit_idx),
        proj.travel_budget,
        false,
    );
    state.shock_chain_projectile_id = @intCast(spawned_idx);
}

fn consumeIonHitEffectsRng(
    state: *state_mod.GameplayState,
    projectile_type_id: i32,
) void {
    var burst_scale: f32 = 0.0;
    switch (projectile_type_id) {
        @intFromEnum(game_ids.ProjectileTypeId.ion_minigun) => burst_scale = 0.8,
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) => burst_scale = 1.2,
        @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) => burst_scale = 2.2,
        else => return,
    }

    const burst = burst_scale * 0.8;
    var count: i32 = @intFromFloat(burst * 5.0);
    if (count < 0) count = 0;
    var idx: i32 = 0;
    while (idx < count) : (idx += 1) {
        _ = state.rng.randTagged(rng_callers.ion_hit_spark_rotation);
        _ = state.rng.randTagged(rng_callers.ion_hit_spark_vel_x);
        _ = state.rng.randTagged(rng_callers.ion_hit_spark_vel_y);
        _ = state.rng.randTagged(rng_callers.ion_hit_spark_scale_step);
    }
}

fn projectileTravelBudgetFromRawId(raw_id: i32) f32 {
    const weapon_id = weapon_data.weaponIdFromInt(raw_id);
    return weapon_data.weapon_stats.get(weapon_id).travel_budget;
}

fn damageScaleFromRawId(raw_id: i32) f32 {
    const weapon_id = weapon_data.weaponIdFromInt(raw_id);
    return weapon_data.weapon_stats.get(weapon_id).damage_scale;
}

fn projectileImpulseAxisF32(angle: f32, speed_scale: f32) f32 {
    const impulse_angle = native_math.pc24Sub(angle, native_half_pi);
    return native_math.pc24Mul(
        std.math.cos(@as(f64, @floatCast(impulse_angle))),
        speed_scale,
    );
}

fn expectFloatClose(expected: f32, actual: f32) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "projectile spawn keeps trig wide until velocity store" {
    var pool: ProjectilePool = .{};
    const index = pool.spawn(
        .{},
        -1.4083715677261353,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        55.0,
        false,
    );

    try std.testing.expectEqual(@as(f32, 0.2425672858953476), pool.entries[index].vel.x);
    try std.testing.expectEqual(@as(f32, -1.4802571535110474), pool.entries[index].vel.y);
}

test "projectile impulse keeps trig wide until scale multiply" {
    const impulse = projectileImpulseAxisF32(4.929999828338623, 0.8400000333786011);
    try std.testing.expectEqual(@as(f32, -0.8201895356178284), impulse);
    try std.testing.expectEqual(
        @as(f32, 3.125081777572632),
        native_math.pc24Sub(2.3048923015594482, impulse),
    );
}

test "projectile hit consumes hit-presentation rng" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 102.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var pool: ProjectilePool = .{};
    _ = pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        owner_ref.OwnerRef.fromPlayer(0),
        55.0,
        false,
    );
    const rng_before = state.rng.state;
    _ = pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    try std.testing.expect(rng_before != state.rng.state);
}

test "ion and plasma hit rings use native small impact geometry" {
    var state = state_mod.GameplayState.init(1);
    var effects: effects_mod.EffectPool = .{};
    const pos: state_mod.Vec2 = .{ .x = 100.0, .y = 120.0 };
    var expected_rng = state.rng;
    const burst: f32 = 1.2 * 0.8;
    const expected_rotation = @as(f32, @floatFromInt(expected_rng.rand() & 0x7f)) * 0.049087387;
    const expected_vel: state_mod.Vec2 = .{
        .x = (@as(f32, @floatFromInt(expected_rng.rand() & 0x7f)) - 64.0) * burst * 1.4,
        .y = (@as(f32, @floatFromInt(expected_rng.rand() & 0x7f)) - 64.0) * burst * 1.4,
    };
    const expected_scale_step = (@as(f32, @floatFromInt(expected_rng.rand() % 100)) * 0.01 + 0.1) * burst;
    for (0..12) |_| _ = expected_rng.rand();

    emitProjectileTypeHitEffects(
        &state,
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle),
        pos,
        &effects,
        5,
    );

    var ion_ring: ?effects_mod.EffectEntry = null;
    for (effects.entries) |entry| {
        if (entry.flags == 0) continue;
        if (entry.effect_id != @intFromEnum(effects_mod.EffectId.ring)) continue;
        ion_ring = entry;
        break;
    }
    try std.testing.expect(ion_ring != null);
    try expectFloatClose(4.0, ion_ring.?.half_width);
    try expectFloatClose(4.0, ion_ring.?.half_height);
    try expectFloatClose(0.0, ion_ring.?.age);
    try expectFloatClose(0.32, ion_ring.?.lifetime);
    try expectFloatClose(54.0, ion_ring.?.scale_step);
    const first_spark = effects.entries[1];
    try expectFloatClose(expected_rotation, first_spark.rotation);
    try expectFloatClose(expected_vel.x, first_spark.vel.x);
    try expectFloatClose(expected_vel.y, first_spark.vel.y);
    try expectFloatClose(expected_scale_step, first_spark.scale_step);
    try std.testing.expectEqual(expected_rng.state, state.rng.state);

    effects.reset();
    emitProjectileTypeHitEffects(
        &state,
        @intFromEnum(game_ids.ProjectileTypeId.plasma_cannon),
        pos,
        &effects,
        5,
    );

    var plasma_ring_count: usize = 0;
    for (effects.entries) |entry| {
        if (entry.flags == 0) continue;
        if (entry.effect_id != @intFromEnum(effects_mod.EffectId.ring)) continue;
        plasma_ring_count += 1;
        try expectFloatClose(4.0, entry.half_width);
        try expectFloatClose(4.0, entry.half_height);
        try expectFloatClose(0.1, entry.age);
        try expectFloatClose(1.0, entry.lifetime);
    }
    try std.testing.expectEqual(@as(usize, 2), plasma_ring_count);
}

test "pulse gun hit applies post-hit target push" {
    var state = state_mod.GameplayState.init(1);
    const initial_creature_x = 102.0;
    const initial_creature_y = 100.0;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = initial_creature_x, .y = initial_creature_y },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 1000.0,
        .max_health = 1000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var base_pool: ProjectilePool = .{};
    _ = base_pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        45.0,
        false,
    );
    _ = base_pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    const base_dx = creatures.entries[0].pos.x - initial_creature_x;
    const base_dy = creatures.entries[0].pos.y - initial_creature_y;
    const base_displacement = std.math.sqrt(base_dx * base_dx + base_dy * base_dy);

    creatures.entries[0].pos = .{ .x = initial_creature_x, .y = initial_creature_y };
    creatures.entries[0].hp = 1000.0;
    creatures.entries[0].lifecycle_stage = creature_lifecycle.alive;
    creatures.entries[0].active = true;

    var pulse_pool: ProjectilePool = .{};
    _ = pulse_pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pulse_gun),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        45.0,
        false,
    );
    const pulse_tick = pulse_pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    const pulse_dx = creatures.entries[0].pos.x - initial_creature_x;
    const pulse_dy = creatures.entries[0].pos.y - initial_creature_y;
    const pulse_displacement = std.math.sqrt(pulse_dx * pulse_dx + pulse_dy * pulse_dy);
    try std.testing.expect(pulse_tick.hit_count > 0);
    try std.testing.expect(pulse_displacement > base_displacement + 1.5);
}

test "projectile hit pass does not retarget newly spawned split children in new slots" {
    var state = state_mod.GameplayState.init(1);
    state.bonus_spawn_guard = true;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong | spawn_mod.CreatureFlags.split_on_death,
        .size = 40.0,
        .move_speed = 1.0,
        .health = 18.0,
        .max_health = 400.0,
        .reward_value = 131.68724279835388,
        .contact_damage = 4.0,
    });
    creatures.entries[39] = creatures.entries[0];
    creatures.entries[0] = .{};

    var pool: ProjectilePool = .{};
    const proj_idx = pool.spawn(
        .{ .x = 100.0, .y = 100.0 },
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.fire_bullets),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        300.0,
        false,
    );
    pool.entries[proj_idx].hit_radius = 8.0;

    const tick = pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    try std.testing.expect(tick.hit_count > 2);
    try std.testing.expect(creatures.entries[39].active);
    try std.testing.expect(creatures.entries[39].hp < 0.0);
    // Child spawned into previously inactive index 0 should not be retargeted until next update pass.
    try std.testing.expect(creatures.entries[0].active);
    try expectFloatClose(100.0, creatures.entries[0].hp);
}

test "poison bullets sets weak self-damage flag when rng roll hits" {
    var state = state_mod.GameplayState.init(1);
    state.rng.state = 1; // First rand() == 41 => (41 & 7) == 1.
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    players[0].perk_counts.set(PerkId.poison_bullets, 1);

    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 102.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 1000.0,
        .max_health = 1000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var pool: ProjectilePool = .{};
    _ = pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        45.0,
        false,
    );

    const tick = pool.update(&state, players[0..], &creatures, &bonuses, 0.016, 1024.0);
    try std.testing.expect(tick.hit_count > 0);
    try std.testing.expect((creatures.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick) != 0);
}

test "poison bullets does not set self-damage flag when rng roll misses" {
    var state = state_mod.GameplayState.init(1);
    state.rng.state = 0; // First rand() == 38 => (38 & 7) != 1.
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    players[0].perk_counts.set(PerkId.poison_bullets, 1);

    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 102.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 1000.0,
        .max_health = 1000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var pool: ProjectilePool = .{};
    _ = pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        45.0,
        false,
    );

    const tick = pool.update(&state, players[0..], &creatures, &bonuses, 0.016, 1024.0);
    try std.testing.expect(tick.hit_count > 0);
    try std.testing.expect((creatures.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick) == 0);
}

test "poison bullets with toxic avenger still applies weak bullet poison only" {
    var state = state_mod.GameplayState.init(1);
    state.rng.state = 1; // First rand() == 41 => (41 & 7) == 1.
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    players[0].perk_counts.set(PerkId.poison_bullets, 1);
    players[0].perk_counts.set(PerkId.toxic_avenger, 1);

    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 300.0, .y = 300.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 1000.0,
        .max_health = 1000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var pool: ProjectilePool = .{};
    _ = pool.spawn(
        creatures.entries[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        45.0,
        false,
    );

    _ = pool.update(&state, players[0..], &creatures, &bonuses, 0.016, 1024.0);
    try std.testing.expect((creatures.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick) != 0);
    try std.testing.expect((creatures.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick_strong) == 0);
}

test "barrel greaser doubles pistol projectile movement steps" {
    var base_state = state_mod.GameplayState.init(1);
    var base_players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    var base_pool: ProjectilePool = .{};
    _ = base_pool.spawn(
        .{},
        std.math.pi / 2.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        weapon_data.weapon_stats.get(WeaponId.pistol).travel_budget,
        false,
    );
    _ = base_pool.update(
        &base_state,
        base_players[0..],
        &creatures,
        &bonuses,
        0.016,
        10_000.0,
    );
    const base_x = base_pool.entries[0].pos.x;

    var greased_state = state_mod.GameplayState.init(1);
    var greased_players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    greased_players[0].perk_counts.set(PerkId.barrel_greaser, 1);
    var greased_pool: ProjectilePool = .{};
    _ = greased_pool.spawn(
        .{},
        std.math.pi / 2.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        weapon_data.weapon_stats.get(WeaponId.pistol).travel_budget,
        false,
    );
    _ = greased_pool.update(
        &greased_state,
        greased_players[0..],
        &creatures,
        &bonuses,
        0.016,
        10_000.0,
    );
    const greased_x = greased_pool.entries[0].pos.x;

    try expectFloatClose(18.240001678466797, base_x);
    try expectFloatClose(35.519996643066406, greased_x);
    try std.testing.expect(greased_x > base_x);
}

test "ion linger damage stores rate product at native precision" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{},
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 12.0,
        .max_health = 12.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });
    var pool: ProjectilePool = .{};
    const idx = pool.spawn(
        .{},
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        45.0,
        false,
    );
    pool.entries[idx].life_timer = 0.39;

    const dt: f32 = 0.0950000062584877;
    _ = pool.update(
        &state,
        players[0..],
        &creatures,
        &bonuses,
        dt,
        10_000.0,
    );

    const damage = native_math.pc24Mul(dt, @as(f32, 100.0));
    const expected = native_math.pc24Sub(@as(f32, 12.0), damage);
    try std.testing.expectEqual(@as(u32, @bitCast(expected)), @as(u32, @bitCast(creatures.entries[0].hp)));
}

test "ion gun master increases ion rifle linger radius" {
    var state_without = state_mod.GameplayState.init(1);
    var players_without = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    var creatures_without: creatures_mod.CreaturePool = .{};
    var bonuses_without: bonus_runtime.BonusPool = .{};
    _ = creatures_without.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 105.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });
    var pool_without: ProjectilePool = .{};
    const idx_without = pool_without.spawn(
        .{},
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        45.0,
        false,
    );
    pool_without.entries[idx_without].life_timer = 0.39;
    _ = pool_without.update(
        &state_without,
        players_without[0..],
        &creatures_without,
        &bonuses_without,
        0.016,
        10_000.0,
    );
    try expectFloatClose(10.0, creatures_without.entries[0].hp);

    var state_with = state_mod.GameplayState.init(1);
    var players_with = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    players_with[0].perk_counts.set(PerkId.ion_gun_master, 1);
    var creatures_with: creatures_mod.CreaturePool = .{};
    var bonuses_with: bonus_runtime.BonusPool = .{};
    _ = creatures_with.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 105.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });
    var pool_with: ProjectilePool = .{};
    const idx_with = pool_with.spawn(
        .{},
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle),
        owner_ref.OwnerRef.fromLocalPlayer(0),
        45.0,
        false,
    );
    pool_with.entries[idx_with].life_timer = 0.39;
    _ = pool_with.update(
        &state_with,
        players_with[0..],
        &creatures_with,
        &bonuses_with,
        0.016,
        10_000.0,
    );
    try std.testing.expect(creatures_with.entries[0].hp < 10.0);
}

test "ranged projectile can damage player when no creature is hit" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 4.0, .y = 0.0 },
            .health = 100.0,
        },
    };
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    var pool: ProjectilePool = .{};

    _ = pool.spawn(
        .{},
        native_half_pi,
        @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle),
        owner_ref.OwnerRef.fromCreature(0),
        45.0,
        true,
    );

    _ = pool.update(
        &state,
        players[0..],
        &creatures,
        &bonuses,
        0.001,
        1024.0,
    );

    try std.testing.expect(players[0].health < 100.0);
}

test "ranged projectile can damage creature before player collision" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 4.0, .y = 0.0 },
            .health = 100.0,
        },
    };
    var creatures: creatures_mod.CreaturePool = .{};
    var bonuses: bonus_runtime.BonusPool = .{};
    var pool: ProjectilePool = .{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = -200.0, .y = -200.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 4.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });

    _ = pool.spawn(
        .{},
        native_half_pi,
        @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle),
        owner_ref.OwnerRef.fromCreature(0),
        45.0,
        true,
    );

    _ = pool.update(
        &state,
        players[0..],
        &creatures,
        &bonuses,
        0.1,
        1024.0,
    );

    try std.testing.expect(creatures.entries[1].hp < 100.0);
    try expectFloatClose(100.0, players[0].health);
}
