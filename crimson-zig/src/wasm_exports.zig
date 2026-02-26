const std = @import("std");

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
    _ = opts_ptr;
    _ = opts_len;
    _ = out_ptr;
    _ = out_len;
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
