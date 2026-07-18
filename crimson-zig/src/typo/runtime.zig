const std = @import("std");
const rng_callers = @import("../rng_caller_static.zig");
const creatures_mod = @import("../runtime/creatures.zig");
const player_runtime = @import("../runtime/player.zig");
const state_mod = @import("../runtime/state.zig");
const spawn_mod = @import("../runtime/spawn.zig");
const typo_names = @import("names.zig");
const typo_player = @import("player.zig");
const typo_spawns = @import("spawns.zig");

fn typeclickSfx(
    state: *state_mod.GameplayState,
    caller: rng_callers.Caller,
) state_mod.SfxId {
    if ((state.rng.randTagged(caller) & 1) == 0) return .ui_typeclick_01;
    return .ui_typeclick_02;
}

pub fn applyCharCommand(state: *state_mod.GameplayState, ch: u8) void {
    if (ch == 0) return;
    state.typo.typing.pushChar(ch);
    state.sfx_queue.append(typeclickSfx(state, rng_callers.typo_gameplay_typeclick_char));
}

pub fn applyBackspaceCommand(state: *state_mod.GameplayState) void {
    state.typo.typing.backspace();
    state.sfx_queue.append(typeclickSfx(state, rng_callers.typo_gameplay_typeclick_backspace));
}

pub fn applySubmitCommand(
    state: *state_mod.GameplayState,
    creatures: *const creatures_mod.CreaturePool,
) void {
    const entered = state.typo.typing.submit(false) orelse return;
    state.sfx_queue.append(.ui_typeenter);

    var active_mask = [_]bool{false} ** creatures_mod.max_creatures;
    for (creatures.entries, 0..) |entry, idx| {
        active_mask[idx] = entry.active;
    }

    if (std.mem.eql(u8, entered, "reload")) {
        state.typo.pending_reload = true;
        return;
    }

    if (state.typo.names.findByName(entered, active_mask[0..])) |idx| {
        const creature = creatures.entries[idx];
        if (creature.active) {
            state.typo.pending_fire_target_active = true;
            state.typo.pending_fire_target_x = creature.pos.x;
            state.typo.pending_fire_target_y = creature.pos.y;
            state.typo.typing.match_count += 1;
        }
    }
}

pub fn beforeStep(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
) void {
    for (players) |*player| {
        typo_player.enforceTypoPlayerFrame(player, state);
    }
}

pub fn transformPrimaryInput(
    state: *state_mod.GameplayState,
    input: player_runtime.GameInput,
) player_runtime.GameInput {
    var transformed = input;
    transformed.move_x = 0.0;
    transformed.move_y = 0.0;
    transformed.flags.fire_down = false;
    transformed.flags.fire_pressed = false;
    transformed.flags.reload_pressed = false;
    transformed.flags.reload_down = false;

    if (state.typo.pending_fire_target_active) {
        transformed.aim_x = state.typo.pending_fire_target_x;
        transformed.aim_y = state.typo.pending_fire_target_y;
        transformed.flags.fire_down = true;
        transformed.flags.fire_pressed = true;
    }
    if (state.typo.pending_reload) {
        transformed.flags.reload_pressed = true;
    }

    state.typo.pending_fire_target_active = false;
    state.typo.pending_reload = false;
    return transformed;
}

pub fn midStep(
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    elapsed_before_ms: f32,
    dt_sim_ms: f32,
    world_size: f32,
) void {
    const batch = typo_spawns.tickTypoSpawns(
        @intFromFloat(elapsed_before_ms),
        state.typo.spawn_cooldown_ms,
        @intFromFloat(dt_sim_ms),
        @intCast(players.len),
        world_size,
        world_size,
    );
    state.typo.spawn_cooldown_ms = batch.cooldown_ms;

    var active_mask = [_]bool{false} ** creatures_mod.max_creatures;
    for (creatures.entries, 0..) |entry, idx| {
        active_mask[idx] = entry.active;
    }

    const score_xp: i32 = if (players.len > 0) players[0].experience else 0;
    var dict_storage: [typo_names.max_dictionary_words][]const u8 = undefined;
    for (0..state.typo.dictionary_word_count) |idx| {
        dict_storage[idx] = state.typo.dictionaryWordSlice(idx);
    }
    var hs_storage: [typo_names.max_highscore_names][]const u8 = undefined;
    for (0..state.typo.highscore_name_count) |idx| {
        hs_storage[idx] = state.typo.highscoreNameSlice(idx);
    }

    for (batch.slice()) |call| {
        if (creatures.activeCount() == creatures_mod.max_creatures) break;
        // creature_spawn_tinted allocates via creature_alloc_slot, which seeds
        // phase_seed = crt_rand() & 0x17f before the heading/size draws.
        const phase_seed: i32 = @intCast(state.rng.randTagged(rng_callers.creature_alloc_slot_phase_seed) & 0x17f);
        const heading = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.creature_spawn_tinted_heading) % 314)) * 0.01;
        var size = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.creature_spawn_tinted_size) % 20 + 47));
        var flags: i32 = 0;
        var move_speed: f32 = 1.7;
        if (call.type_id == .spider_sp1 or call.type_id == .spider_sp2) {
            flags |= spawn_mod.CreatureFlags.ai7_link_timer;
            move_speed *= 1.2;
            size *= 0.8;
        }

        const creature_idx = creatures.spawnInit(.{
            .origin_template_id = 0,
            .pos = .{ .x = call.pos_x, .y = call.pos_y },
            .heading = heading,
            .phase_seed = phase_seed,
            .type_id = call.type_id,
            .flags = @bitCast(flags),
            .ai_mode = .chase_player,
            .health = 1.0,
            .max_health = 1.0,
            .move_speed = move_speed,
            .reward_value = 1.0,
            .size = size,
            .contact_damage = 100.0,
            .tint = .{ call.tint_r, call.tint_g, call.tint_b, 1.0 },
        }) orelse continue;
        active_mask[creature_idx] = true;
        _ = state.typo.names.assignRandom(
            creature_idx,
            &state.rng,
            score_xp,
            active_mask[0..],
            dict_storage[0..state.typo.dictionary_word_count],
            hs_storage[0..state.typo.highscore_name_count],
        );
    }
}

pub fn postStep(state: *state_mod.GameplayState) void {
    state.bonuses.weapon_power_up = 0.0;
    state.bonuses.reflex_boost = 0.0;
    state.time_scale_active = false;
}
