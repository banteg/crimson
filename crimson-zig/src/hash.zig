const std = @import("std");

const hex = "0123456789abcdef";

pub fn sha256HexLower(bytes: []const u8, out: *[64]u8) void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    for (digest, 0..) |b, idx| {
        out[idx * 2] = hex[(b >> 4) & 0x0f];
        out[idx * 2 + 1] = hex[b & 0x0f];
    }
}

test "sha256 hex length" {
    var out: [64]u8 = undefined;
    sha256HexLower("abc", &out);
    try std.testing.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        out[0..],
    );
}
