const std = @import("std");
const msgpack = @import("msgpack");
const crimson_zig = @import("crimson_zig");
const checkpoint_diff_native = crimson_zig.checkpoint_diff_native;
const replay_codec = crimson_zig.replay_codec;
const replay_benchmark_native = crimson_zig.replay_benchmark_native;
const replay_info_native = crimson_zig.replay_info_native;
const verify_native = crimson_zig.verify_native;

const heap_size = 16 * 1024 * 1024;
const fallback_error_json = "{\"status\":\"error\",\"message\":\"failed to encode error payload\"}";
const oversized_error_json = "{\"status\":\"error\",\"message\":\"error payload exceeded wasm buffer\"}";

// Transient bump arena for wasm interop buffers.
// Contract: pointers returned by `crimson_alloc` stay valid only until the next
// replay-processing call, which resets `heap_top` back to zero.
var heap: [heap_size]u8 align(8) = undefined;
var heap_top: usize = 0;

var last_error: [1024]u8 = undefined;
var last_error_len: usize = 0;

const WasmVerifyOptions = struct {
    max_ticks: ?usize = null,
};

const WasmInfoOptions = struct {
    max_ticks: ?usize = null,
    player_index: ?i32 = null,
    include_extra_events: bool = false,
    verbose: bool = false,
};

const WasmBenchmarkOptions = struct {
    max_ticks: ?usize = null,
    runs: usize = 1,
    warmup_runs: usize = 0,
    trace_rng: bool = false,
};

export fn crimson_alloc(size: usize) usize {
    // ABI contract: pointer is into `heap` and must be treated as transient.
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
    return @intCast(last_error_len);
}

export fn crimson_verify_replay_json(
    replay_ptr: usize,
    replay_len: usize,
    opts_ptr: usize,
    opts_len: usize,
    out_ptr: usize,
    out_len: usize,
) i32 {
    // Keep arena behavior identical to native shim: every verify call starts a
    // new transient allocation epoch and clears previous error payload state.
    last_error_len = 0;
    heap_top = 0;

    if (replay_ptr == 0 or replay_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing replay bytes\"}");
        return -1;
    }

    const replay: [*]const u8 = @ptrFromInt(replay_ptr);
    const replay_bytes = replay[0..replay_len];

    const options = parseVerifyOptions(opts_ptr, opts_len) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };

    const output = verify_native.runReplayVerifyBytesJson(
        std.heap.page_allocator,
        "<wasm>",
        replay_bytes,
        options.max_ticks,
    ) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };
    defer output.deinit(std.heap.page_allocator);

    if (output.exit_code == 1 and output.stdout.len == 0 and output.stderr.len > 0) {
        setErrorMessage(std.heap.page_allocator, std.mem.trimEnd(u8, output.stderr, "\n"));
        return -1;
    }

    return copyOutputPayload(output.stdout, out_ptr, out_len);
}

export fn crimson_info_replay_json(
    replay_ptr: usize,
    replay_len: usize,
    opts_ptr: usize,
    opts_len: usize,
    out_ptr: usize,
    out_len: usize,
) i32 {
    last_error_len = 0;
    heap_top = 0;

    if (replay_ptr == 0 or replay_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing replay bytes\"}");
        return -1;
    }

    const replay: [*]const u8 = @ptrFromInt(replay_ptr);
    const replay_bytes = replay[0..replay_len];

    const options = parseInfoOptions(opts_ptr, opts_len) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };

    const output = replay_info_native.runReplayInfoBytesJson(
        std.heap.page_allocator,
        "<wasm>",
        replay_bytes,
        options.max_ticks,
        options.player_index,
        options.include_extra_events or options.verbose,
    ) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };
    defer output.deinit(std.heap.page_allocator);

    if (output.exit_code == 1 and output.stdout.len == 0 and output.stderr.len > 0) {
        setErrorMessage(std.heap.page_allocator, std.mem.trimEnd(u8, output.stderr, "\n"));
        return -1;
    }

    return copyOutputPayload(output.stdout, out_ptr, out_len);
}

export fn crimson_benchmark_replay_json(
    replay_ptr: usize,
    replay_len: usize,
    opts_ptr: usize,
    opts_len: usize,
    out_ptr: usize,
    out_len: usize,
) i32 {
    last_error_len = 0;
    heap_top = 0;

    if (replay_ptr == 0 or replay_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing replay bytes\"}");
        return -1;
    }

    const replay: [*]const u8 = @ptrFromInt(replay_ptr);
    const replay_bytes = replay[0..replay_len];

    const options = parseBenchmarkOptions(opts_ptr, opts_len) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };

    const output = replay_benchmark_native.runReplayBenchmarkBytesJson(
        std.heap.page_allocator,
        "<wasm>",
        replay_bytes,
        options.max_ticks,
        options.runs,
        options.warmup_runs,
        options.trace_rng,
    ) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };
    defer output.deinit(std.heap.page_allocator);

    if (output.exit_code == 1 and output.stdout.len == 0 and output.stderr.len > 0) {
        setErrorMessage(std.heap.page_allocator, std.mem.trimEnd(u8, output.stderr, "\n"));
        return -1;
    }

    return copyOutputPayload(output.stdout, out_ptr, out_len);
}

export fn crimson_diff_checkpoints_text(
    expected_ptr: usize,
    expected_len: usize,
    actual_ptr: usize,
    actual_len: usize,
    out_ptr: usize,
    out_len: usize,
) i32 {
    last_error_len = 0;
    heap_top = 0;

    if (expected_ptr == 0 or expected_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing expected checkpoint bytes\"}");
        return -1;
    }
    if (actual_ptr == 0 or actual_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing actual checkpoint bytes\"}");
        return -1;
    }

    const expected: [*]const u8 = @ptrFromInt(expected_ptr);
    const actual: [*]const u8 = @ptrFromInt(actual_ptr);

    const output = checkpoint_diff_native.runReplayDiffCheckpointsBytes(
        std.heap.page_allocator,
        expected[0..expected_len],
        actual[0..actual_len],
    ) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };
    defer output.deinit(std.heap.page_allocator);

    if (output.exit_code == 1 and output.stdout.len == 0 and output.stderr.len > 0) {
        setErrorMessage(std.heap.page_allocator, std.mem.trimEnd(u8, output.stderr, "\n"));
        return -1;
    }

    return copyOutputPayload(output.stdout, out_ptr, out_len);
}

export fn crimson_diff_checkpoints_json(
    expected_ptr: usize,
    expected_len: usize,
    actual_ptr: usize,
    actual_len: usize,
    out_ptr: usize,
    out_len: usize,
) i32 {
    last_error_len = 0;
    heap_top = 0;

    if (expected_ptr == 0 or expected_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing expected checkpoint bytes\"}");
        return -1;
    }
    if (actual_ptr == 0 or actual_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing actual checkpoint bytes\"}");
        return -1;
    }

    const expected: [*]const u8 = @ptrFromInt(expected_ptr);
    const actual: [*]const u8 = @ptrFromInt(actual_ptr);

    const output = checkpoint_diff_native.runReplayDiffCheckpointsBytesJson(
        std.heap.page_allocator,
        "<expected>",
        expected[0..expected_len],
        "<actual>",
        actual[0..actual_len],
    ) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };
    defer output.deinit(std.heap.page_allocator);

    if (output.exit_code == 1 and output.stdout.len == 0 and output.stderr.len > 0) {
        setErrorMessage(std.heap.page_allocator, std.mem.trimEnd(u8, output.stderr, "\n"));
        return -1;
    }

    return copyOutputPayload(output.stdout, out_ptr, out_len);
}

export fn crimson_verify_checkpoints_text(
    replay_ptr: usize,
    replay_len: usize,
    checkpoints_ptr: usize,
    checkpoints_len: usize,
    opts_ptr: usize,
    opts_len: usize,
    out_ptr: usize,
    out_len: usize,
) i32 {
    last_error_len = 0;
    heap_top = 0;

    if (replay_ptr == 0 or replay_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing replay bytes\"}");
        return -1;
    }
    if (checkpoints_ptr == 0 or checkpoints_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing checkpoint bytes\"}");
        return -1;
    }

    const options = parseVerifyOptions(opts_ptr, opts_len) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };

    const replay: [*]const u8 = @ptrFromInt(replay_ptr);
    const checkpoints: [*]const u8 = @ptrFromInt(checkpoints_ptr);

    const output = checkpoint_diff_native.runReplayVerifyCheckpointsBytes(
        std.heap.page_allocator,
        replay[0..replay_len],
        checkpoints[0..checkpoints_len],
        options.max_ticks,
        false,
    ) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };
    defer output.deinit(std.heap.page_allocator);

    if (output.exit_code == 1 and output.stdout.len == 0 and output.stderr.len > 0) {
        setErrorMessage(std.heap.page_allocator, std.mem.trimEnd(u8, output.stderr, "\n"));
        return -1;
    }

    return copyOutputPayload(output.stdout, out_ptr, out_len);
}

export fn crimson_verify_checkpoints_json(
    replay_ptr: usize,
    replay_len: usize,
    checkpoints_ptr: usize,
    checkpoints_len: usize,
    opts_ptr: usize,
    opts_len: usize,
    out_ptr: usize,
    out_len: usize,
) i32 {
    last_error_len = 0;
    heap_top = 0;

    if (replay_ptr == 0 or replay_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing replay bytes\"}");
        return -1;
    }
    if (checkpoints_ptr == 0 or checkpoints_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing checkpoint bytes\"}");
        return -1;
    }

    const options = parseVerifyOptions(opts_ptr, opts_len) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };

    const replay: [*]const u8 = @ptrFromInt(replay_ptr);
    const checkpoints: [*]const u8 = @ptrFromInt(checkpoints_ptr);

    const output = checkpoint_diff_native.runReplayVerifyCheckpointsBytesJson(
        std.heap.page_allocator,
        "<wasm>",
        replay[0..replay_len],
        "<checkpoints>",
        checkpoints[0..checkpoints_len],
        options.max_ticks,
        false,
    ) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };
    defer output.deinit(std.heap.page_allocator);

    if (output.exit_code == 1 and output.stdout.len == 0 and output.stderr.len > 0) {
        setErrorMessage(std.heap.page_allocator, std.mem.trimEnd(u8, output.stderr, "\n"));
        return -1;
    }

    return copyOutputPayload(output.stdout, out_ptr, out_len);
}

fn parseVerifyOptions(opts_ptr: usize, opts_len: usize) !WasmVerifyOptions {
    if (opts_len == 0) return .{};
    if (opts_ptr == 0) return error.InvalidVerifyOptionsJson;

    const opts_raw: [*]const u8 = @ptrFromInt(opts_ptr);
    const parsed = std.json.parseFromSlice(
        WasmVerifyOptions,
        std.heap.page_allocator,
        opts_raw[0..opts_len],
        .{
            .ignore_unknown_fields = true,
        },
    ) catch return error.InvalidVerifyOptionsJson;
    defer parsed.deinit();
    return parsed.value;
}

fn parseInfoOptions(opts_ptr: usize, opts_len: usize) !WasmInfoOptions {
    if (opts_len == 0) return .{};
    if (opts_ptr == 0) return error.InvalidInfoOptionsJson;

    const opts_raw: [*]const u8 = @ptrFromInt(opts_ptr);
    const parsed = std.json.parseFromSlice(
        WasmInfoOptions,
        std.heap.page_allocator,
        opts_raw[0..opts_len],
        .{
            .ignore_unknown_fields = true,
        },
    ) catch return error.InvalidInfoOptionsJson;
    defer parsed.deinit();
    return parsed.value;
}

fn parseBenchmarkOptions(opts_ptr: usize, opts_len: usize) !WasmBenchmarkOptions {
    if (opts_len == 0) return .{};
    if (opts_ptr == 0) return error.InvalidBenchmarkOptionsJson;

    const opts_raw: [*]const u8 = @ptrFromInt(opts_ptr);
    const parsed = std.json.parseFromSlice(
        WasmBenchmarkOptions,
        std.heap.page_allocator,
        opts_raw[0..opts_len],
        .{
            .ignore_unknown_fields = true,
        },
    ) catch return error.InvalidBenchmarkOptionsJson;
    defer parsed.deinit();
    return parsed.value;
}

fn copyOutputPayload(payload: []const u8, out_ptr: usize, out_len: usize) i32 {
    if (out_ptr == 0 or out_len < payload.len) {
        return -@as(i32, @intCast(payload.len));
    }

    const out: [*]u8 = @ptrFromInt(out_ptr);
    @memcpy(out[0..payload.len], payload);
    return @intCast(payload.len);
}

fn setErrorMessage(allocator: std.mem.Allocator, message: []const u8) void {
    const payload = buildErrorPayload(allocator, message) catch {
        setErrorSimple(fallback_error_json);
        return;
    };
    defer allocator.free(payload);
    setErrorPayload(payload);
}

fn setErrorSimple(message: []const u8) void {
    setErrorPayload(message);
}

fn setErrorPayload(payload: []const u8) void {
    last_error_len = 0;
    if (payload.len > last_error.len) {
        const len = oversized_error_json.len;
        @memcpy(last_error[0..len], oversized_error_json[0..len]);
        last_error_len = len;
        return;
    }
    @memcpy(last_error[0..payload.len], payload[0..payload.len]);
    last_error_len = payload.len;
}

fn buildErrorPayload(allocator: std.mem.Allocator, message: []const u8) ![]u8 {
    const payload: struct {
        status: []const u8,
        message: []const u8,
    } = .{
        .status = "error",
        .message = message,
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{}, &writer.writer);
    return writer.toOwnedSlice();
}

test "crimson_verify_replay_json returns required size and copies payload for supported replay" {
    const replay_bytes = try replay_codec.buildSmokeTestReplayFile(std.testing.allocator);
    defer std.testing.allocator.free(replay_bytes);

    const required_or_error = crimson_verify_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        0,
        0,
        0,
        0,
    );
    try std.testing.expect(required_or_error < 0);
    const required_len: usize = @intCast(-required_or_error);

    const out = try std.testing.allocator.alloc(u8, required_len);
    defer std.testing.allocator.free(out);

    const copied = crimson_verify_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        0,
        0,
        @intFromPtr(out.ptr),
        out.len,
    );
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expectEqual(@as(i32, 0), crimson_last_error_json(0, 0));
    try std.testing.expect(std.mem.indexOf(u8, out, "\"schema_version\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"replay\":\"<wasm>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"run_result\":") != null);
}

test "crimson_verify_replay_json rejects invalid options json" {
    var invalid_opts = [_]u8{ '{', ']' };
    var replay_bytes = [_]u8{0x90};
    const result = crimson_verify_replay_json(
        @intFromPtr(&replay_bytes[0]),
        replay_bytes.len,
        @intFromPtr(&invalid_opts[0]),
        invalid_opts.len,
        0,
        0,
    );
    try std.testing.expectEqual(@as(i32, -1), result);

    const needed_or_error = crimson_last_error_json(0, 0);
    try std.testing.expect(needed_or_error < 0);
    const required_len: usize = @intCast(-needed_or_error);
    var out: [128]u8 = undefined;
    const copied = crimson_last_error_json(@intFromPtr(&out[0]), out.len);
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expect(std.mem.indexOf(u8, out[0..required_len], "\"message\":\"InvalidVerifyOptionsJson\"") != null);
}

test "crimson_verify_replay_json honors max_ticks option" {
    const replay_bytes = try replay_codec.buildSmokeTestReplayFile(std.testing.allocator);
    defer std.testing.allocator.free(replay_bytes);

    const opts = "{\"max_ticks\":1}";
    const required_or_error = crimson_verify_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        @intFromPtr(opts.ptr),
        opts.len,
        0,
        0,
    );
    try std.testing.expect(required_or_error < 0);
    const required_len: usize = @intCast(-required_or_error);

    const out = try std.testing.allocator.alloc(u8, required_len);
    defer std.testing.allocator.free(out);

    const copied = crimson_verify_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        @intFromPtr(opts.ptr),
        opts.len,
        @intFromPtr(out.ptr),
        out.len,
    );
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"ticks\":1") != null);
}

test "crimson_info_replay_json returns replay info payload" {
    const replay_bytes = try replay_codec.buildSmokeTestReplayFile(std.testing.allocator);
    defer std.testing.allocator.free(replay_bytes);

    const opts = "{\"max_ticks\":1}";
    const required_or_error = crimson_info_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        @intFromPtr(opts.ptr),
        opts.len,
        0,
        0,
    );
    try std.testing.expect(required_or_error < 0);
    const required_len: usize = @intCast(-required_or_error);

    const out = try std.testing.allocator.alloc(u8, required_len);
    defer std.testing.allocator.free(out);

    const copied = crimson_info_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        @intFromPtr(opts.ptr),
        opts.len,
        @intFromPtr(out.ptr),
        out.len,
    );
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expectEqual(@as(i32, 0), crimson_last_error_json(0, 0));
    try std.testing.expect(std.mem.indexOf(u8, out, "\"schema_version\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"replay\":\"<wasm>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"summary\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"ticks_simulated\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"timeline\":") != null);
}

test "crimson_info_replay_json accepts info-specific options" {
    const replay_bytes = try replay_codec.buildSmokeTestReplayFile(std.testing.allocator);
    defer std.testing.allocator.free(replay_bytes);

    const opts = "{\"player_index\":1,\"verbose\":true}";
    const result = crimson_info_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        @intFromPtr(opts.ptr),
        opts.len,
        0,
        0,
    );
    try std.testing.expectEqual(@as(i32, -1), result);

    const needed_or_error = crimson_last_error_json(0, 0);
    try std.testing.expect(needed_or_error < 0);
    const required_len: usize = @intCast(-needed_or_error);
    var out: [256]u8 = undefined;
    const copied = crimson_last_error_json(@intFromPtr(&out[0]), out.len);
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            out[0..required_len],
            "\"message\":\"replay info failed: player_index filter out of range: 1 (player_count=1)\"",
        ) != null,
    );
}

test "crimson_info_replay_json rejects invalid info options json" {
    var invalid_opts = [_]u8{ '{', ']' };
    var replay_bytes = [_]u8{0x90};
    const result = crimson_info_replay_json(
        @intFromPtr(&replay_bytes[0]),
        replay_bytes.len,
        @intFromPtr(&invalid_opts[0]),
        invalid_opts.len,
        0,
        0,
    );
    try std.testing.expectEqual(@as(i32, -1), result);

    const needed_or_error = crimson_last_error_json(0, 0);
    try std.testing.expect(needed_or_error < 0);
    const required_len: usize = @intCast(-needed_or_error);
    var out: [128]u8 = undefined;
    const copied = crimson_last_error_json(@intFromPtr(&out[0]), out.len);
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expect(std.mem.indexOf(u8, out[0..required_len], "\"message\":\"InvalidInfoOptionsJson\"") != null);
}

test "crimson_info_replay_json exposes detailed replay info failures" {
    const replay_bytes = try replay_codec.wrapZstdFilePayload(std.testing.allocator, "not msgpack");
    defer std.testing.allocator.free(replay_bytes);
    const result = crimson_info_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        0,
        0,
        0,
        0,
    );
    try std.testing.expectEqual(@as(i32, -1), result);

    const needed_or_error = crimson_last_error_json(0, 0);
    try std.testing.expect(needed_or_error < 0);
    const required_len: usize = @intCast(-needed_or_error);
    var out: [128]u8 = undefined;
    const copied = crimson_last_error_json(@intFromPtr(&out[0]), out.len);
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            out[0..required_len],
            "\"message\":\"replay info failed: replay payload does not match format 17 msgpack schema\"",
        ) != null,
    );
}

test "crimson_benchmark_replay_json returns benchmark payload" {
    const replay_bytes = try replay_codec.buildSmokeTestReplayFile(std.testing.allocator);
    defer std.testing.allocator.free(replay_bytes);

    const opts = "{\"max_ticks\":1,\"runs\":1,\"warmup_runs\":0}";
    const required_or_error = crimson_benchmark_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        @intFromPtr(opts.ptr),
        opts.len,
        0,
        0,
    );
    try std.testing.expect(required_or_error < 0);
    const required_len: usize = @intCast(-required_or_error);

    const out = try std.testing.allocator.alloc(u8, required_len + 1024);
    defer std.testing.allocator.free(out);

    const copied = crimson_benchmark_replay_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        @intFromPtr(opts.ptr),
        opts.len,
        @intFromPtr(out.ptr),
        out.len,
    );
    try std.testing.expect(copied > 0);
    try std.testing.expectEqual(@as(i32, 0), crimson_last_error_json(0, 0));
    const payload = out[0..@as(usize, @intCast(copied))];
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"schema_version\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"replay\":\"<wasm>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"runs\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"warmup_runs\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"sample_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"ticks\":1") != null);
}

test "crimson_benchmark_replay_json rejects invalid options json" {
    var invalid_opts = [_]u8{ '{', ']' };
    var replay_bytes = [_]u8{0x90};
    const result = crimson_benchmark_replay_json(
        @intFromPtr(&replay_bytes[0]),
        replay_bytes.len,
        @intFromPtr(&invalid_opts[0]),
        invalid_opts.len,
        0,
        0,
    );
    try std.testing.expectEqual(@as(i32, -1), result);

    const needed_or_error = crimson_last_error_json(0, 0);
    try std.testing.expect(needed_or_error < 0);
    const required_len: usize = @intCast(-needed_or_error);
    var out: [128]u8 = undefined;
    const copied = crimson_last_error_json(@intFromPtr(&out[0]), out.len);
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expect(std.mem.indexOf(u8, out[0..required_len], "\"message\":\"InvalidBenchmarkOptionsJson\"") != null);
}

test "crimson_diff_checkpoints_text returns checkpoint diff payload" {
    const checkpoints = try buildTestCheckpointsPayload(std.testing.allocator, 1);
    defer std.testing.allocator.free(checkpoints);

    const required_or_error = crimson_diff_checkpoints_text(
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        0,
        0,
    );
    try std.testing.expect(required_or_error < 0);
    const required_len: usize = @intCast(-required_or_error);

    const out = try std.testing.allocator.alloc(u8, required_len);
    defer std.testing.allocator.free(out);

    const copied = crimson_diff_checkpoints_text(
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        @intFromPtr(out.ptr),
        out.len,
    );
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expectEqual(@as(i32, 0), crimson_last_error_json(0, 0));
    try std.testing.expectEqualStrings("ok: 1 checkpoints match\n", out);
}

test "crimson_diff_checkpoints_json returns checkpoint diff payload" {
    const checkpoints = try buildTestCheckpointsPayload(std.testing.allocator, 1);
    defer std.testing.allocator.free(checkpoints);

    const required_or_error = crimson_diff_checkpoints_json(
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        0,
        0,
    );
    try std.testing.expect(required_or_error < 0);
    const required_len: usize = @intCast(-required_or_error);

    const out = try std.testing.allocator.alloc(u8, required_len);
    defer std.testing.allocator.free(out);

    const copied = crimson_diff_checkpoints_json(
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        @intFromPtr(out.ptr),
        out.len,
    );
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expectEqual(@as(i32, 0), crimson_last_error_json(0, 0));
    try std.testing.expect(std.mem.indexOf(u8, out, "\"schema_version\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"command\":\"diff-checkpoints\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"expected\":\"<expected>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"actual\":\"<actual>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"checked_count\":1") != null);
}

test "crimson_verify_checkpoints_text reports checkpoint mismatch through last error" {
    const replay_bytes = try replay_codec.buildSmokeTestReplayFile(std.testing.allocator);
    defer std.testing.allocator.free(replay_bytes);
    const checkpoints = try buildTestCheckpointsPayload(std.testing.allocator, 999);
    defer std.testing.allocator.free(checkpoints);

    const opts = "{\"max_ticks\":1}";
    const result = crimson_verify_checkpoints_text(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        @intFromPtr(opts.ptr),
        opts.len,
        0,
        0,
    );
    try std.testing.expectEqual(@as(i32, -1), result);

    const needed_or_error = crimson_last_error_json(0, 0);
    try std.testing.expect(needed_or_error < 0);
    const required_len: usize = @intCast(-needed_or_error);
    const out = try std.testing.allocator.alloc(u8, required_len);
    defer std.testing.allocator.free(out);
    const copied = crimson_last_error_json(@intFromPtr(out.ptr), out.len);
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"message\":\"checkpoint missing at tick=999") != null);
}

test "crimson_verify_checkpoints_json reports checkpoint mismatch through last error" {
    const replay_bytes = try replay_codec.buildSmokeTestReplayFile(std.testing.allocator);
    defer std.testing.allocator.free(replay_bytes);
    const checkpoints = try buildTestCheckpointsPayload(std.testing.allocator, 999);
    defer std.testing.allocator.free(checkpoints);

    const opts = "{\"max_ticks\":1}";
    const result = crimson_verify_checkpoints_json(
        @intFromPtr(replay_bytes.ptr),
        replay_bytes.len,
        @intFromPtr(checkpoints.ptr),
        checkpoints.len,
        @intFromPtr(opts.ptr),
        opts.len,
        0,
        0,
    );
    try std.testing.expectEqual(@as(i32, -1), result);

    const needed_or_error = crimson_last_error_json(0, 0);
    try std.testing.expect(needed_or_error < 0);
    const required_len: usize = @intCast(-needed_or_error);
    const out = try std.testing.allocator.alloc(u8, required_len);
    defer std.testing.allocator.free(out);
    const copied = crimson_last_error_json(@intFromPtr(out.ptr), out.len);
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"message\":\"checkpoint missing at tick=999") != null);
}

test "crimson_alloc pointers are transient across verify calls" {
    _ = crimson_verify_replay_json(0, 0, 0, 0, 0, 0);

    const first_ptr = crimson_alloc(3);
    const second_ptr = crimson_alloc(5);
    try std.testing.expect(first_ptr != 0);
    try std.testing.expect(second_ptr != 0);
    try std.testing.expectEqual(@as(usize, 0), first_ptr & 7);
    try std.testing.expectEqual(@as(usize, 0), second_ptr & 7);
    try std.testing.expect(second_ptr > first_ptr);

    _ = crimson_verify_replay_json(0, 0, 0, 0, 0, 0);
    const first_after_reset = crimson_alloc(3);
    try std.testing.expectEqual(first_ptr, first_after_reset);
}

test "crimson_last_error_json reports required size and copies payload" {
    _ = crimson_verify_replay_json(0, 0, 0, 0, 0, 0);

    const needed_or_error = crimson_last_error_json(0, 0);
    try std.testing.expect(needed_or_error < 0);
    const required_len: usize = @intCast(-needed_or_error);

    var out: [128]u8 = undefined;
    const copied = crimson_last_error_json(@intFromPtr(&out[0]), out.len);
    try std.testing.expectEqual(@as(i32, @intCast(required_len)), copied);
    try std.testing.expect(std.mem.eql(
        u8,
        out[0..required_len],
        "{\"status\":\"error\",\"message\":\"missing replay bytes\"}",
    ));

    const truncated = crimson_last_error_json(@intFromPtr(&out[0]), required_len - 1);
    try std.testing.expectEqual(-@as(i32, @intCast(required_len)), truncated);
}

fn buildTestCheckpointsPayload(allocator: std.mem.Allocator, tick_index: i32) ![]u8 {
    const Player = struct {
        pos: struct {
            x: f64,
            y: f64,
        },
        health: f64,
        weapon_id: i32,
        ammo: f64,
        experience: i32,
        level: i32,
    };
    const BonusTimers = struct {
        @"1": i32,
        @"3": i32,
    };
    const Death = struct {
        creature_index: i32,
        type_id: i32,
        reward_value: f64,
        xp_awarded: i32,
        owner_id: i32,
    };
    const HitSummaryEntry = struct {
        type_id: i32,
        origin: struct {
            x: f64,
            y: f64,
        },
        hit: struct {
            x: f64,
            y: f64,
        },
        target: struct {
            x: f64,
            y: f64,
        },
    };
    const Perk = struct {
        pending_count: i32,
        choices_dirty: bool,
        choices: []const i32,
        player_nonzero_counts: []const []const []const i32,
    };
    const Events = struct {
        hit_count: i32,
        pickup_count: i32,
        sfx_count: i32,
        sfx_head: []const []const u8,
        hit_head: []const HitSummaryEntry,
    };
    const Checkpoint = struct {
        tick_index: i32,
        rng_state: u32,
        elapsed_ms: i32,
        score_xp: i32,
        kills: i32,
        creature_count: i32,
        perk_pending: i32,
        players: []const Player,
        bonus_timers: BonusTimers,
        deaths: []const Death,
        perk: Perk,
        events: Events,
        tutorial: ?struct {} = null,
        typo: ?struct {} = null,
    };
    const Payload = struct {
        version: i32,
        sample_rate: i32,
        checkpoints: []const Checkpoint,
    };

    const players = [_]Player{.{
        .pos = .{ .x = 512.0, .y = 513.0 },
        .health = 100.0,
        .weapon_id = 1,
        .ammo = 10.0,
        .experience = 42,
        .level = 1,
    }};
    const choices: [replay_codec.perk_choice_slot_count]i32 =
        [_]i32{0} ** replay_codec.perk_choice_slot_count;
    const player_nonzero_counts: [0][]const []const i32 = .{};
    const deaths: [0]Death = .{};
    const sfx_head: [0][]const u8 = .{};
    const hit_head: [0]HitSummaryEntry = .{};
    const checkpoints = [_]Checkpoint{.{
        .tick_index = tick_index,
        .rng_state = 0x1234,
        .elapsed_ms = 17,
        .score_xp = 42,
        .kills = 2,
        .creature_count = 3,
        .perk_pending = 0,
        .players = players[0..],
        .bonus_timers = .{ .@"1" = 0, .@"3" = 0 },
        .deaths = deaths[0..],
        .perk = .{
            .pending_count = 0,
            .choices_dirty = false,
            .choices = choices[0..],
            .player_nonzero_counts = player_nonzero_counts[0..],
        },
        .events = .{
            .hit_count = 0,
            .pickup_count = 0,
            .sfx_count = 0,
            .sfx_head = sfx_head[0..],
            .hit_head = hit_head[0..],
        },
    }};
    const payload: Payload = .{
        .version = 5,
        .sample_rate = 1,
        .checkpoints = checkpoints[0..],
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try msgpack.encode(payload, &writer.writer);
    const raw = try writer.toOwnedSlice();
    defer allocator.free(raw);
    return replay_codec.wrapZstdFilePayload(allocator, raw);
}
