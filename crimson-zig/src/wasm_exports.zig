const std = @import("std");
const replay_codec = @import("replay_codec.zig");
const replay_info_native = @import("replay_info_native.zig");
const verify_native = @import("verify_native.zig");

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

    const options = parseVerifyOptions(opts_ptr, opts_len) catch |err| {
        setErrorMessage(std.heap.page_allocator, @errorName(err));
        return -1;
    };

    const output = replay_info_native.runReplayInfoBytesJson(
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
    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(std.testing.allocator);
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
    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(std.testing.allocator);
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
    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(std.testing.allocator);
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
