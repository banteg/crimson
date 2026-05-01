const std = @import("std");

const creatures_runtime = @import("runtime/creatures.zig");
const spawn_runtime = @import("runtime/spawn.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const schema_version: i32 = 1;

const OutputFormat = enum {
    human,
    json,
};

const SpawnPlanRequest = struct {
    template_id: i32,
    output_format: OutputFormat = .human,
    seed: u32 = 0xBEEF,
    pos: spawn_runtime.Vec2 = .{ .x = 512.0, .y = 512.0 },
    heading: f32 = 0.0,
    hardcore: bool = false,
    quest_fail_retry_count: i32 = 0,
};

const ParseOutcome = union(enum) {
    ok: SpawnPlanRequest,
    invalid: []const u8,
};

const CreaturePayload = struct {
    index: usize,
    type_id: i32,
    ai_mode: i32,
    flags: u32,
    pos: struct {
        x: f32,
        y: f32,
    },
    target_offset: struct {
        x: f32,
        y: f32,
    },
    heading: f32,
    link_index: i32,
    orbit_angle: f32,
    orbit_radius: f32,
    ranged_projectile_type: i32,
    health: f32,
    max_health: f32,
    move_speed: f32,
    reward_value: f32,
    size: f32,
    contact_damage: f32,
};

const SpawnSlotPayload = struct {
    owner_creature: i32,
    timer: f32,
    count: i32,
    limit: i32,
    interval: f32,
    child_template_id: i32,
};

const SpawnPlanPayload = struct {
    schema_version: i32,
    status: []const u8,
    template_id: i32,
    seed: u32,
    rng_state: u32,
    pos: struct {
        x: f32,
        y: f32,
    },
    heading: f32,
    hardcore: bool,
    quest_fail_retry_count: i32,
    active_count: usize,
    spawn_slot_count: usize,
    creatures: []const CreaturePayload,
    spawn_slots: []const SpawnSlotPayload,
};

pub fn runSpawnPlan(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| return runSpawnPlanRequest(allocator, request),
        .invalid => |detail| return buildInvalidOutput(allocator, detail),
    }
}

fn runSpawnPlanRequest(
    allocator: std.mem.Allocator,
    request: SpawnPlanRequest,
) !CommandOutput {
    const maybe_spawn_id = std.enums.fromInt(spawn_runtime.SpawnId, request.template_id);
    if (maybe_spawn_id == null) return buildInvalidOutput(allocator, "invalid spawn template id");

    var pool: creatures_runtime.CreaturePool = .{};
    pool.hardcore = request.hardcore;
    pool.quest_fail_retry_count = request.quest_fail_retry_count;

    var rng = spawn_runtime.Crand.init(request.seed);
    pool.spawnTemplateCall(
        .{
            .template_id = request.template_id,
            .pos = request.pos,
            .heading = request.heading,
        },
        &rng,
    ) catch |err| switch (err) {
        error.InvalidSpawnTemplate => return buildInvalidOutput(allocator, "unsupported spawn template id"),
    };

    const stdout = switch (request.output_format) {
        .human => try buildHumanOutput(allocator, request, &pool, rng.state),
        .json => try buildJsonOutput(allocator, request, &pool, rng.state),
    };
    errdefer allocator.free(stdout);

    return .{
        .stdout = stdout,
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildHumanOutput(
    allocator: std.mem.Allocator,
    request: SpawnPlanRequest,
    pool: *const creatures_runtime.CreaturePool,
    rng_state: u32,
) ![]u8 {
    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;

    try writer.print(
        "template_id=0x{x:0>2} ({d})\n",
        .{ @as(u32, @intCast(request.template_id)), request.template_id },
    );
    try writer.print(
        "pos=({d:.1},{d:.1}) heading={d:.6} seed=0x{x:0>8} rng_state=0x{x:0>8}\n",
        .{ request.pos.x, request.pos.y, request.heading, request.seed, rng_state },
    );
    try writer.print(
        "active={d} slots={d} hardcore={} quest_fail_retry_count={d}\n\n",
        .{ pool.activeCount(), pool.spawn_slot_count, request.hardcore, request.quest_fail_retry_count },
    );

    try writer.writeAll("creatures:\n");
    for (pool.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        try writer.print(
            " {d:0>2} type={d} ai={d} flags=0x{x:0>3} pos=({d: >7.1},{d: >7.1}) hp={d: >7.1} size={d: >6.1} link={d}\n",
            .{
                idx,
                creature.type_id,
                @intFromEnum(creature.ai_mode),
                creature.flags,
                creature.pos.x,
                creature.pos.y,
                creature.hp,
                creature.size,
                creature.link_index,
            },
        );
    }

    if (pool.spawn_slot_count > 0) {
        try writer.writeAll("\nspawn_slots:\n");
        for (pool.spawn_slots[0..pool.spawn_slot_count], 0..) |slot, idx| {
            try writer.print(
                " {d:0>2} owner={d} timer={d:.3} count={d} limit={d} interval={d:.3} child=0x{x:0>2}\n",
                .{
                    idx,
                    slot.owner_creature,
                    slot.timer,
                    slot.count,
                    slot.limit,
                    slot.interval,
                    @as(u32, @intCast(slot.child_template_id)),
                },
            );
        }
    }

    return stdout_buf.toOwnedSlice();
}

fn buildJsonOutput(
    allocator: std.mem.Allocator,
    request: SpawnPlanRequest,
    pool: *const creatures_runtime.CreaturePool,
    rng_state: u32,
) ![]u8 {
    var creatures_storage: [creatures_runtime.max_creatures]CreaturePayload = undefined;
    var creature_len: usize = 0;
    for (pool.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        creatures_storage[creature_len] = .{
            .index = idx,
            .type_id = creature.type_id,
            .ai_mode = @intFromEnum(creature.ai_mode),
            .flags = creature.flags,
            .pos = .{ .x = creature.pos.x, .y = creature.pos.y },
            .target_offset = .{ .x = creature.target_offset.x, .y = creature.target_offset.y },
            .heading = creature.heading,
            .link_index = creature.link_index,
            .orbit_angle = creature.orbit_angle,
            .orbit_radius = creature.orbit_radius,
            .ranged_projectile_type = creature.ranged_projectile_type,
            .health = creature.hp,
            .max_health = creature.max_hp,
            .move_speed = creature.move_speed,
            .reward_value = creature.reward_value,
            .size = creature.size,
            .contact_damage = creature.contact_damage,
        };
        creature_len += 1;
    }

    var slots_storage: [creatures_runtime.max_creatures]SpawnSlotPayload = undefined;
    for (pool.spawn_slots[0..pool.spawn_slot_count], 0..) |slot, idx| {
        slots_storage[idx] = .{
            .owner_creature = slot.owner_creature,
            .timer = slot.timer,
            .count = slot.count,
            .limit = slot.limit,
            .interval = slot.interval,
            .child_template_id = slot.child_template_id,
        };
    }

    const payload: SpawnPlanPayload = .{
        .schema_version = schema_version,
        .status = "ok",
        .template_id = request.template_id,
        .seed = request.seed,
        .rng_state = rng_state,
        .pos = .{ .x = request.pos.x, .y = request.pos.y },
        .heading = request.heading,
        .hardcore = request.hardcore,
        .quest_fail_retry_count = request.quest_fail_retry_count,
        .active_count = creature_len,
        .spawn_slot_count = pool.spawn_slot_count,
        .creatures = creatures_storage[0..creature_len],
        .spawn_slots = slots_storage[0..pool.spawn_slot_count],
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    defer payload_writer.deinit();
    try std.json.Stringify.value(payload, .{}, &payload_writer.writer);
    try payload_writer.writer.writeByte('\n');
    return payload_writer.toOwnedSlice();
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    if (args.len == 0) return .{ .invalid = "missing spawn template id" };

    const template_id = parseTemplateId(args[0]) orelse return .{ .invalid = "invalid spawn template id" };
    var request: SpawnPlanRequest = .{
        .template_id = template_id,
    };

    var idx: usize = 1;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--json")) {
            request.output_format = .json;
            continue;
        }
        if (std.mem.eql(u8, arg, "--format")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --format" };
            idx += 1;
            request.output_format = parseOutputFormat(args[idx]) orelse return .{ .invalid = "invalid --format value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--format=")) {
            request.output_format = parseOutputFormat(arg["--format=".len..]) orelse return .{ .invalid = "invalid --format value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--seed")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --seed" };
            idx += 1;
            request.seed = parseSeed(args[idx]) orelse return .{ .invalid = "invalid --seed value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            request.seed = parseSeed(arg["--seed=".len..]) orelse return .{ .invalid = "invalid --seed value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--pos")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --pos" };
            idx += 1;
            request.pos = parseVec2(args[idx]) orelse return .{ .invalid = "invalid --pos value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--pos=")) {
            request.pos = parseVec2(arg["--pos=".len..]) orelse return .{ .invalid = "invalid --pos value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--heading")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --heading" };
            idx += 1;
            request.heading = parseFiniteFloat(args[idx]) orelse return .{ .invalid = "invalid --heading value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--heading=")) {
            request.heading = parseFiniteFloat(arg["--heading=".len..]) orelse return .{ .invalid = "invalid --heading value" };
            continue;
        }
        if (std.mem.eql(u8, arg, "--hardcore")) {
            request.hardcore = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--quest-fail-retry-count")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --quest-fail-retry-count" };
            idx += 1;
            request.quest_fail_retry_count = parseRetryCount(args[idx]) orelse return .{ .invalid = "invalid --quest-fail-retry-count value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--quest-fail-retry-count=")) {
            request.quest_fail_retry_count = parseRetryCount(arg["--quest-fail-retry-count=".len..]) orelse return .{ .invalid = "invalid --quest-fail-retry-count value" };
            continue;
        }

        return .{ .invalid = "unknown argument" };
    }

    return .{ .ok = request };
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
}

fn parseTemplateId(raw: []const u8) ?i32 {
    const value = std.fmt.parseInt(i64, raw, 0) catch return null;
    if (value < 0 or value > std.math.maxInt(i32)) return null;
    return @intCast(value);
}

fn parseSeed(raw: []const u8) ?u32 {
    const value = std.fmt.parseInt(u64, raw, 0) catch return null;
    if (value > std.math.maxInt(u32)) return null;
    return @intCast(value);
}

fn parseFiniteFloat(raw: []const u8) ?f32 {
    const value = std.fmt.parseFloat(f32, raw) catch return null;
    if (!std.math.isFinite(value)) return null;
    return value;
}

fn parseRetryCount(raw: []const u8) ?i32 {
    const value = std.fmt.parseInt(i32, raw, 10) catch return null;
    if (value < 0) return null;
    return value;
}

fn parseVec2(raw: []const u8) ?spawn_runtime.Vec2 {
    const comma = std.mem.indexOfScalar(u8, raw, ',') orelse return null;
    if (std.mem.indexOfScalar(u8, raw[comma + 1 ..], ',') != null) return null;
    const x = parseFiniteFloat(raw[0..comma]) orelse return null;
    const y = parseFiniteFloat(raw[comma + 1 ..]) orelse return null;
    return .{ .x = x, .y = y };
}

fn buildInvalidOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    const stderr = try std.fmt.allocPrint(allocator, "invalid spawn-plan args: {s}\n", .{detail});
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = stderr,
        .exit_code = 1,
    };
}

test "spawn-plan parser accepts json options" {
    const parsed = parseArgs(&.{
        "0x12",
        "--json",
        "--seed",
        "0x1234",
        "--pos",
        "100,200",
        "--heading",
        "1.5",
        "--hardcore",
        "--quest-fail-retry-count=2",
    });
    try std.testing.expect(parsed == .ok);
    const request = parsed.ok;
    try std.testing.expectEqual(@as(i32, 0x12), request.template_id);
    try std.testing.expectEqual(OutputFormat.json, request.output_format);
    try std.testing.expectEqual(@as(u32, 0x1234), request.seed);
    try std.testing.expectEqual(@as(f32, 100.0), request.pos.x);
    try std.testing.expectEqual(@as(f32, 200.0), request.pos.y);
    try std.testing.expectEqual(@as(f32, 1.5), request.heading);
    try std.testing.expect(request.hardcore);
    try std.testing.expectEqual(@as(i32, 2), request.quest_fail_retry_count);
}

test "spawn-plan rejects unknown template id" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const output = try runSpawnPlan(arena.allocator(), &.{ "0x02", "--json" });
    try std.testing.expectEqual(@as(u8, 1), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "invalid spawn template id") != null);
}
