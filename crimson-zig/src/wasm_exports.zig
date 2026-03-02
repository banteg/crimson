const std = @import("std");

const heap_size = 16 * 1024 * 1024;
// Transient bump arena for wasm interop buffers.
// Contract: pointers returned by `crimson_alloc` stay valid only until the next
// `crimson_verify_replay_json` call, which resets `heap_top` back to zero.
var heap: [heap_size]u8 align(8) = undefined;
var heap_top: usize = 0;

var last_error: [1024]u8 = undefined;
var last_error_len: usize = 0;

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
    _ = opts_ptr;
    _ = opts_len;
    _ = out_ptr;
    _ = out_len;
    // Keep arena behavior identical to native shim: every verify call starts a
    // new transient allocation epoch and clears previous error payload state.
    last_error_len = 0;
    heap_top = 0;

    if (replay_ptr == 0 or replay_len == 0) {
        setErrorSimple("{\"status\":\"error\",\"message\":\"missing replay bytes\"}");
        return -1;
    }

    setErrorSimple(
        "{\"status\":\"error\",\"message\":\"replay verification path not yet ported for wasm target\"}",
    );
    return -1;
}

fn setErrorSimple(message: []const u8) void {
    const len = @min(message.len, last_error.len);
    @memcpy(last_error[0..len], message[0..len]);
    last_error_len = len;
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
