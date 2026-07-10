const std = @import("std");

const cdt_trace = @import("cdt_trace.zig");
const dbg_record_native = @import("dbg_record_native.zig");
const replay_codec = @import("replay_codec.zig");
const verify_native = @import("verify_native.zig");

pub const CommandOutput = verify_native.CommandOutput;

const Request = struct {
    trace_path: []const u8,
    expression: []const u8,
    query: cdt_trace.QueryRequest,
    json: bool = false,
    json_out: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: Request,
    help,
    invalid: []const u8,
};

const QueryJsonPayload = struct {
    schema_version: i32 = 1,
    trace: []const u8,
    scope: []const u8,
    expression: []const u8,
    limit: usize,
    match_count: usize,
    truncated: bool,
    rows: []const cdt_trace.QueryRow,
};

const usage =
    \\Usage:
    \\  crimson-zig dbg query <trace.cdt> <expression> [query options]
    \\
    \\Options:
    \\  --limit <n>        Maximum rows included in output.
    \\  --json             Print JSON payload to stdout.
    \\  --json-out <path>  Also write the JSON report to a file.
    \\  -h, --help         Show this help.
    \\
    \\Expressions:
    \\  ticks where checkpoint.kills >= 0
    \\  ticks where rng_stream_count > 0
    \\  entities where uid == 1001000000
    \\  entities where pool_kind == creature
    \\
;

pub fn runDbgQuery(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| {
            var result = cdt_trace.queryTraceFile(
                allocator,
                std.Io.Threaded.global_single_threaded.io(),
                request.trace_path,
                request.query,
            ) catch |err| return buildQueryFailedOutput(allocator, queryErrorDetail(err));
            defer result.deinit(allocator);
            return buildQueryOutput(allocator, request, result);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn buildQueryOutput(
    allocator: std.mem.Allocator,
    request: Request,
    result: cdt_trace.QueryResult,
) !CommandOutput {
    const json_payload = try buildQueryJson(allocator, request.trace_path, result);
    errdefer allocator.free(json_payload);

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, json_payload) catch |err| {
            allocator.free(json_payload);
            return buildQueryFailedOutput(allocator, queryErrorDetail(err));
        };
    }

    const stdout = if (request.json) json_payload else stdout: {
        const human = try buildQueryHuman(allocator, result, request.json_out);
        allocator.free(json_payload);
        break :stdout human;
    };
    errdefer allocator.free(stdout);

    return .{
        .stdout = stdout,
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildQueryJson(
    allocator: std.mem.Allocator,
    trace_path: []const u8,
    result: cdt_trace.QueryResult,
) ![]u8 {
    const payload: QueryJsonPayload = .{
        .trace = trace_path,
        .scope = result.scope,
        .expression = result.expression,
        .limit = result.limit,
        .match_count = result.match_count,
        .truncated = result.truncated,
        .rows = result.rows,
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{}, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn buildQueryHuman(
    allocator: std.mem.Allocator,
    result: cdt_trace.QueryResult,
    json_out: ?[]const u8,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;

    try writer.print(
        "scope={s} match_count={d} truncated={}\n",
        .{ result.scope, result.match_count, result.truncated },
    );
    for (result.rows[0..@min(result.rows.len, 32)]) |row| {
        try writer.writeAll("row=");
        try std.json.Stringify.value(row, .{ .emit_null_optional_fields = false }, writer);
        try writer.writeByte('\n');
    }
    if (json_out) |path| {
        try writer.print("json_report={s}\n", .{path});
    }
    return out.toOwnedSlice();
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    var trace_path: ?[]const u8 = null;
    var expression: ?[]const u8 = null;
    var json = false;
    var json_out: ?[]const u8 = null;
    var limit: usize = 256;

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return .help;
        if (std.mem.eql(u8, arg, "--json")) {
            json = true;
            continue;
        }
        if (takeValue(args, &idx, arg, "--json-out")) |value| {
            if (value.len == 0) return .{ .invalid = "missing value for --json-out" };
            json_out = value;
            continue;
        }
        if (takeValue(args, &idx, arg, "--limit")) |value| {
            limit = parseLimit(value) orelse return .{ .invalid = "invalid --limit value" };
            continue;
        }
        if (trace_path == null) {
            if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
            trace_path = arg;
            continue;
        }
        if (expression == null) {
            if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
            expression = arg;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
        return .{ .invalid = "too many positional arguments" };
    }

    const trace = trace_path orelse return .{ .invalid = "missing trace file argument" };
    const expr = expression orelse return .{ .invalid = "missing expression argument" };
    var query = parseExpression(expr) orelse return .{ .invalid = "invalid query expression" };
    query.limit = limit;
    return .{
        .ok = .{
            .trace_path = trace,
            .expression = expr,
            .query = query,
            .json = json,
            .json_out = json_out,
        },
    };
}

fn parseExpression(expression: []const u8) ?cdt_trace.QueryRequest {
    const trimmed = std.mem.trim(u8, expression, " \t");
    const ticks_prefix = "ticks where ";
    const entities_prefix = "entities where ";
    const ScopedCondition = struct {
        scope: cdt_trace.QueryScope,
        condition: []const u8,
    };
    const scoped: ScopedCondition = if (std.mem.startsWith(u8, trimmed, ticks_prefix))
        .{ .scope = .ticks, .condition = trimmed[ticks_prefix.len..] }
    else if (std.mem.startsWith(u8, trimmed, entities_prefix))
        .{ .scope = .entities, .condition = trimmed[entities_prefix.len..] }
    else
        return null;

    const parsed = parseCondition(scoped.condition) orelse return null;
    return .{
        .scope = scoped.scope,
        .expression = expression,
        .field = parsed.field,
        .op = parsed.op,
        .literal = parsed.literal,
    };
}

const ParsedCondition = struct {
    field: cdt_trace.QueryField,
    op: cdt_trace.QueryOp,
    literal: cdt_trace.QueryLiteral,
};

fn parseCondition(condition: []const u8) ?ParsedCondition {
    const operators = [_]struct {
        token: []const u8,
        op: cdt_trace.QueryOp,
    }{
        .{ .token = "==", .op = .eq },
        .{ .token = "!=", .op = .ne },
        .{ .token = ">=", .op = .ge },
        .{ .token = "<=", .op = .le },
        .{ .token = ">", .op = .gt },
        .{ .token = "<", .op = .lt },
    };

    for (operators) |candidate| {
        if (std.mem.indexOf(u8, condition, candidate.token)) |op_index| {
            const field_text = std.mem.trim(u8, condition[0..op_index], " \t");
            const literal_text = std.mem.trim(u8, condition[op_index + candidate.token.len ..], " \t");
            return .{
                .field = parseField(field_text) orelse return null,
                .op = candidate.op,
                .literal = parseLiteral(literal_text) orelse return null,
            };
        }
    }
    return null;
}

fn parseField(field: []const u8) ?cdt_trace.QueryField {
    inline for (field_aliases) |alias| {
        if (std.mem.eql(u8, field, alias.name)) return alias.field;
    }
    return null;
}

const field_aliases = [_]struct {
    name: []const u8,
    field: cdt_trace.QueryField,
}{
    .{ .name = "tick_index", .field = .tick_index },
    .{ .name = "mode_id", .field = .mode_id },
    .{ .name = "dt_ms_i32", .field = .dt_ms_i32 },
    .{ .name = "checkpoint.score_xp", .field = .checkpoint_score_xp },
    .{ .name = "checkpoint.kills", .field = .checkpoint_kills },
    .{ .name = "checkpoint.creature_count", .field = .checkpoint_creature_count },
    .{ .name = "checkpoint.perk_pending", .field = .checkpoint_perk_pending },
    .{ .name = "entity_counts.creatures", .field = .entity_count_creatures },
    .{ .name = "entity_counts.projectiles", .field = .entity_count_projectiles },
    .{ .name = "entity_counts.secondary_projectiles", .field = .entity_count_secondary_projectiles },
    .{ .name = "entity_counts.bonuses", .field = .entity_count_bonuses },
    .{ .name = "rng_stream_count", .field = .rng_stream_count },
    .{ .name = "timing_samples_count", .field = .timing_samples_count },
    .{ .name = "event_count_total", .field = .event_count_total },
    .{ .name = "uid", .field = .uid },
    .{ .name = "generation", .field = .generation },
    .{ .name = "index", .field = .index },
    .{ .name = "type_id", .field = .type_id },
    .{ .name = "hp", .field = .hp },
    .{ .name = "pool_kind", .field = .pool_kind },
};

fn parseLiteral(raw: []const u8) ?cdt_trace.QueryLiteral {
    if (raw.len == 0) return null;
    const unquoted = stripQuotes(raw);
    if (std.fmt.parseInt(i64, unquoted, 10)) |int_value| {
        return .{ .int = int_value };
    } else |_| {}
    if (std.fmt.parseFloat(f64, unquoted)) |float_value| {
        return .{ .float = float_value };
    } else |_| {}
    return .{ .string = unquoted };
}

fn stripQuotes(raw: []const u8) []const u8 {
    if (raw.len >= 2 and ((raw[0] == '"' and raw[raw.len - 1] == '"') or (raw[0] == '\'' and raw[raw.len - 1] == '\''))) {
        return raw[1 .. raw.len - 1];
    }
    return raw;
}

fn takeValue(args: []const []const u8, idx: *usize, arg: []const u8, name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, arg, name)) {
        if (idx.* + 1 >= args.len) return "";
        idx.* += 1;
        return args[idx.*];
    }
    if (arg.len > name.len and arg[name.len] == '=' and std.mem.startsWith(u8, arg, name)) {
        return arg[name.len + 1 ..];
    }
    return null;
}

fn parseLimit(value: []const u8) ?usize {
    if (value.len == 0) return null;
    const parsed = std.fmt.parseInt(usize, value, 10) catch return null;
    if (parsed == 0) return null;
    return parsed;
}

fn buildUsageOutput(allocator: std.mem.Allocator, exit_code: u8, detail: []const u8) !CommandOutput {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = if (detail.len == 0)
        try allocator.dupe(u8, usage)
    else
        try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ detail, usage });
    return .{ .stdout = stdout, .stderr = stderr, .exit_code = exit_code };
}

fn buildQueryFailedOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try std.fmt.allocPrint(allocator, "dbg query failed: {s}\n", .{detail}),
        .exit_code = 1,
    };
}

fn queryErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "trace file not found",
        error.AccessDenied => "trace file access denied",
        error.InvalidQueryLimit => "invalid query limit",
        error.InvalidTraceMagic,
        error.InvalidTraceHeader,
        error.InvalidTraceChunkHeader,
        error.InvalidTraceChunkFlags,
        error.InvalidTracePayload,
        error.InvalidTraceTrailer,
        error.InvalidTraceFooterOffset,
        error.InvalidTraceMetaChunk,
        error.InvalidTraceFooterChunk,
        error.InvalidTraceTickChunk,
        error.InvalidTraceTickBlock,
        error.InvalidTraceFooter,
        error.InvalidTraceBlockOffset,
        error.InvalidTraceChecksum,
        error.InvalidTraceChunkLayout,
        => "invalid CDT trace",
        error.UnsupportedTraceFormatVersion => "unsupported CDT trace format version",
        error.UnsupportedTraceSchemaVersion => "unsupported CDT trace schema version",
        error.UnsupportedTraceCompression => "compressed CDT trace chunks are not supported",
        error.OutOfMemory => "out of memory",
        else => @errorName(err),
    };
}

fn writeFileWithParents(path: []const u8, bytes: []const u8) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.Io.Dir.cwd().createDirPath(io, dir);
    }
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes,
    });
}

test "dbg query parser accepts tick expression and output options" {
    const parsed = parseArgs(&.{ "sample.cdt", "ticks where checkpoint.kills >= 0", "--limit", "8", "--json", "--json-out=out/query.json" });
    switch (parsed) {
        .ok => |request| {
            try std.testing.expectEqualStrings("ticks where checkpoint.kills >= 0", request.expression);
            try std.testing.expectEqual(@as(usize, 8), request.query.limit);
            try std.testing.expectEqual(cdt_trace.QueryScope.ticks, request.query.scope);
            try std.testing.expectEqual(cdt_trace.QueryField.checkpoint_kills, request.query.field);
            try std.testing.expect(request.json);
            try std.testing.expectEqualStrings("out/query.json", request.json_out.?);
        },
        else => return error.TestExpectedValidArgs,
    }
}

test "dbg query rejects unsupported expression" {
    const parsed = parseArgs(&.{ "sample.cdt", "bad where checkpoint.kills >= 0" });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("invalid query expression", detail),
        else => return error.TestExpectedInvalidArgs,
    }
}

test "dbg query summarizes native CDT trace" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);
    const replay_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.crd" });
    defer allocator.free(replay_path);
    const trace_path = try std.fs.path.join(allocator, &.{ base_dir, "sample.cdt" });
    defer allocator.free(trace_path);
    const json_path = try std.fs.path.join(allocator, &.{ base_dir, "reports", "query.json" });
    defer allocator.free(json_path);

    const replay_bytes = try replay_codec.buildSmokeTestReplayFile(allocator);
    defer allocator.free(replay_bytes);

    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = replay_path,
        .data = replay_bytes,
    });

    const record_output = try dbg_record_native.runDbgRecord(allocator, &.{ replay_path, "--out", trace_path });
    defer record_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), record_output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, record_output.stdout, "trace=") != null);

    const query_output = try runDbgQuery(allocator, &.{ trace_path, "entities where uid == 1001000000", "--json", "--json-out", json_path });
    defer query_output.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), query_output.exit_code);
    try std.testing.expectEqualStrings("", query_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, query_output.stdout, "\"scope\":\"entities\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, query_output.stdout, "\"match_count\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, query_output.stdout, "\"uid\":1001000000") != null);

    const artifact = try std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024));
    defer allocator.free(artifact);
    try std.testing.expectEqualStrings(query_output.stdout, artifact);
}
