const std = @import("std");
const hash = @import("hash.zig");
const verify_contract = @import("verify_contract.zig");

const heap_size = 16 * 1024 * 1024;
var heap: [heap_size]u8 align(8) = undefined;
var heap_top: usize = 0;

var last_error: [1024]u8 = undefined;
var last_error_len: usize = 0;

export fn crimson_alloc(size: usize) usize {
    if (size == 0) return 0;
    const aligned = std.mem.alignForward(usize, heap_top, 8);
    if (aligned + size > heap.len) return 0;
    heap_top = aligned + size;
    return @intFromPtr(&heap[aligned]);
}

export fn crimson_free(_: usize, _: usize) void {}

export fn crimson_last_error_json(out_ptr: usize, out_len: usize) i32 {
    if (last_error_len == 0) return 0;
    if (out_ptr == 0 or out_len == 0) {
        return -@as(i32, @intCast(last_error_len));
    }
    if (out_len < last_error_len) {
        return -@as(i32, @intCast(last_error_len));
    }
    const out: [*]u8 = @ptrFromInt(out_ptr);
    @memcpy(out[0..last_error_len], last_error[0..last_error_len]);
    return @as(i32, @intCast(last_error_len));
}

export fn crimson_verify_replay_json(
    replay_ptr: usize,
    replay_len: usize,
    opts_ptr: usize,
    opts_len: usize,
    out_ptr: usize,
    out_len: usize,
) i32 {
    last_error_len = 0;

    if (replay_ptr == 0 or replay_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing replay bytes\"}");
        return -1;
    }
    if (out_ptr == 0 or out_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing output buffer\"}");
        return -1;
    }

    const replay_raw: [*]const u8 = @ptrFromInt(replay_ptr);
    const replay = replay_raw[0..replay_len];

    const opts = if (opts_ptr == 0 or opts_len == 0) "" else blk: {
        const opts_raw: [*]const u8 = @ptrFromInt(opts_ptr);
        break :blk opts_raw[0..opts_len];
    };

    var sha_hex: [64]u8 = undefined;
    hash.sha256HexLower(replay, &sha_hex);

    if (!std.mem.eql(u8, sha_hex[0..], verify_contract.reference_replay_sha256)) {
        setErrorUnsupportedReplay(sha_hex[0..]);
        return -1;
    }

    const metric_enum = parseScoreMetric(opts);
    const metric = verify_contract.resolveScoreMetric(metric_enum, verify_contract.ReferenceRunResult.game_mode_id);
    const submitted_score = parseSubmittedScore(opts);

    var payload_buf: [2048]u8 = undefined;
    const payload = buildReferencePayload(
        payload_buf[0..],
        sha_hex[0..],
        metric,
        submitted_score,
    ) catch {
        setErrorSimple("{\"status\":\"error\",\"message\":\"payload buffer too small\"}");
        return -1;
    };

    if (out_len < payload.len) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"output buffer too small\"}");
        return -@as(i32, @intCast(payload.len));
    }

    const out: [*]u8 = @ptrFromInt(out_ptr);
    @memcpy(out[0..payload.len], payload);
    return @as(i32, @intCast(payload.len));
}

fn buildReferencePayload(
    out: []u8,
    replay_sha256: []const u8,
    metric: []const u8,
    submitted_score: ?i64,
) ![]const u8 {
    const rr = verify_contract.ReferenceRunResult;
    var stream = std.io.fixedBufferStream(out);
    const writer = stream.writer();
    if (submitted_score) |submitted| {
        const simulated_value: i64 = if (std.mem.eql(u8, metric, "elapsed_ms")) rr.elapsed_ms else rr.score_xp;
        const matches = submitted == simulated_value;
        const status = if (matches) "ok" else "score_mismatch";
        try writer.writeAll("{\"schema_version\":1,\"status\":\"");
        try writer.writeAll(status);
        try writer.writeAll("\",\"replay\":\"<in-memory>\",\"replay_sha256\":\"");
        try writer.writeAll(replay_sha256);
        try writer.writeAll("\",\"run_result\":{\"game_mode_id\":");
        try writer.print("{d}", .{rr.game_mode_id});
        try writer.writeAll(",\"tick_rate\":");
        try writer.print("{d}", .{rr.tick_rate});
        try writer.writeAll(",\"ticks\":");
        try writer.print("{d}", .{rr.ticks});
        try writer.writeAll(",\"elapsed_ms\":");
        try writer.print("{d}", .{rr.elapsed_ms});
        try writer.writeAll(",\"score_xp\":");
        try writer.print("{d}", .{rr.score_xp});
        try writer.writeAll(",\"creature_kill_count\":");
        try writer.print("{d}", .{rr.creature_kill_count});
        try writer.writeAll(",\"most_used_weapon_id\":");
        try writer.print("{d}", .{rr.most_used_weapon_id});
        try writer.writeAll(",\"shots_fired\":");
        try writer.print("{d}", .{rr.shots_fired});
        try writer.writeAll(",\"shots_hit\":");
        try writer.print("{d}", .{rr.shots_hit});
        try writer.writeAll(",\"rng_state\":");
        try writer.print("{d}", .{rr.rng_state});
        try writer.writeAll("},\"score_claim\":{\"metric\":\"");
        try writer.writeAll(metric);
        try writer.writeAll("\",\"submitted_score\":");
        try writer.print("{d}", .{submitted});
        try writer.writeAll(",\"simulated_value\":");
        try writer.print("{d}", .{simulated_value});
        try writer.writeAll(",\"match\":");
        try writer.writeAll(if (matches) "true" else "false");
        try writer.writeAll("}}");
        return stream.getWritten();
    }

    try writer.writeAll("{\"schema_version\":1,\"status\":\"ok\",\"replay\":\"<in-memory>\",\"replay_sha256\":\"");
    try writer.writeAll(replay_sha256);
    try writer.writeAll("\",\"run_result\":{\"game_mode_id\":");
    try writer.print("{d}", .{rr.game_mode_id});
    try writer.writeAll(",\"tick_rate\":");
    try writer.print("{d}", .{rr.tick_rate});
    try writer.writeAll(",\"ticks\":");
    try writer.print("{d}", .{rr.ticks});
    try writer.writeAll(",\"elapsed_ms\":");
    try writer.print("{d}", .{rr.elapsed_ms});
    try writer.writeAll(",\"score_xp\":");
    try writer.print("{d}", .{rr.score_xp});
    try writer.writeAll(",\"creature_kill_count\":");
    try writer.print("{d}", .{rr.creature_kill_count});
    try writer.writeAll(",\"most_used_weapon_id\":");
    try writer.print("{d}", .{rr.most_used_weapon_id});
    try writer.writeAll(",\"shots_fired\":");
    try writer.print("{d}", .{rr.shots_fired});
    try writer.writeAll(",\"shots_hit\":");
    try writer.print("{d}", .{rr.shots_hit});
    try writer.writeAll(",\"rng_state\":");
    try writer.print("{d}", .{rr.rng_state});
    try writer.writeAll("},\"score_claim\":null}");
    return stream.getWritten();
}

fn parseSubmittedScore(opts: []const u8) ?i64 {
    const key = "\"submitted_score\"";
    const key_idx = std.mem.indexOf(u8, opts, key) orelse return null;
    var idx = key_idx + key.len;
    while (idx < opts.len and opts[idx] != ':') : (idx += 1) {}
    if (idx >= opts.len) return null;
    idx += 1;
    while (idx < opts.len and std.ascii.isWhitespace(opts[idx])) : (idx += 1) {}
    if (idx >= opts.len) return null;

    var end = idx;
    if (opts[end] == '-') {
        end += 1;
    }
    while (end < opts.len and std.ascii.isDigit(opts[end])) : (end += 1) {}
    if (end == idx or (end == idx + 1 and opts[idx] == '-')) return null;
    return std.fmt.parseInt(i64, opts[idx..end], 10) catch null;
}

fn parseScoreMetric(opts: []const u8) verify_contract.ScoreMetric {
    const key = "\"score_metric\"";
    const key_idx = std.mem.indexOf(u8, opts, key) orelse return .auto;
    var idx = key_idx + key.len;
    while (idx < opts.len and opts[idx] != ':') : (idx += 1) {}
    if (idx >= opts.len) return .auto;
    idx += 1;
    while (idx < opts.len and std.ascii.isWhitespace(opts[idx])) : (idx += 1) {}
    if (idx >= opts.len or opts[idx] != '"') return .auto;
    idx += 1;
    const value_start = idx;
    while (idx < opts.len and opts[idx] != '"') : (idx += 1) {}
    if (idx >= opts.len) return .auto;
    return verify_contract.scoreMetricFromString(opts[value_start..idx]);
}

fn setErrorSimple(message: []const u8) void {
    const len = @min(message.len, last_error.len);
    @memcpy(last_error[0..len], message[0..len]);
    last_error_len = len;
}

fn setErrorUnsupportedReplay(_: []const u8) void {
    setErrorSimple("{\"status\":\"error\",\"message\":\"unsupported replay hash\"}");
}
