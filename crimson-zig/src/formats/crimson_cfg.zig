const std = @import("std");
const binary = @import("binary.zig");

pub const file_size: usize = 0x480;

pub const CrimsonCfgError = binary.BinaryError || error{
    InvalidSize,
};

pub const CrimsonCfg = struct {
    sound_disable: u8,
    music_disable: u8,
    highscore_date_mode: u8,
    highscore_duplicate_mode: u8,
    hud_indicators: [2]u8,
    unknown_06: [2]u8,
    unknown_08: u32,
    unknown_0c: [2]u8,
    fx_detail_0: u8,
    unknown_0f: u8,
    fx_detail_1: u8,
    fx_detail_2: u8,
    unknown_12: [2]u8,
    player_count: u32,
    game_mode: u32,
    player_mode_flag_p1: u32,
    player_mode_flag_p2: u32,
    player_mode_flag_p3: u32,
    player_mode_flag_p4: u32,
    player_mode_flags_reserved: [0x18]u8,
    aim_scheme_p1: u32,
    aim_scheme_p2: u32,
    aim_scheme_p3: u32,
    aim_scheme_p4: u32,
    aim_schemes_reserved: [0x18]u8,
    unknown_6c: u32,
    texture_scale: f32,
    name_tag: [12]u8,
    selected_name_slot: u32,
    saved_name_index: u32,
    saved_name_order: [0x20]u8,
    saved_names: [0xD8]u8,
    player_name: [0x20]u8,
    player_name_len: u32,
    unknown_1a4: u32,
    unknown_1a8: u32,
    unknown_1ac: u32,
    aim_pov_right: u32,
    aim_pov_left: u32,
    screen_bpp: u32,
    screen_width: u32,
    screen_height: u32,
    windowed_flag: u8,
    unknown_1c5: [3]u8,
    keybinds: [0x80]u8,
    unknown_248: [0x1F8]u8,
    unknown_440: u32,
    unknown_444: u32,
    hardcore_flag: u8,
    ui_info_texts: u8,
    unknown_44a: [2]u8,
    perk_prompt_counter: u32,
    unknown_450: u32,
    unknown_454: [0x0C]u8,
    unknown_460: u32,
    sfx_volume: f32,
    music_volume: f32,
    gore_disabled: u8,
    score_load_gate: u8,
    unknown_46e: u8,
    unknown_46f: u8,
    detail_preset: u32,
    mouse_sensitivity: f32,
    keybind_pick_perk: u32,
    keybind_reload: u32,
};

pub fn decode(bytes: []const u8) CrimsonCfgError!CrimsonCfg {
    if (bytes.len != file_size) return error.InvalidSize;

    var reader = binary.Reader.init(bytes);

    return .{
        .sound_disable = try reader.readU8(),
        .music_disable = try reader.readU8(),
        .highscore_date_mode = try reader.readU8(),
        .highscore_duplicate_mode = try reader.readU8(),
        .hud_indicators = try reader.readArray(2),
        .unknown_06 = try reader.readArray(2),
        .unknown_08 = try reader.readU32Le(),
        .unknown_0c = try reader.readArray(2),
        .fx_detail_0 = try reader.readU8(),
        .unknown_0f = try reader.readU8(),
        .fx_detail_1 = try reader.readU8(),
        .fx_detail_2 = try reader.readU8(),
        .unknown_12 = try reader.readArray(2),
        .player_count = try reader.readU32Le(),
        .game_mode = try reader.readU32Le(),
        .player_mode_flag_p1 = try reader.readU32Le(),
        .player_mode_flag_p2 = try reader.readU32Le(),
        .player_mode_flag_p3 = try reader.readU32Le(),
        .player_mode_flag_p4 = try reader.readU32Le(),
        .player_mode_flags_reserved = try reader.readArray(0x18),
        .aim_scheme_p1 = try reader.readU32Le(),
        .aim_scheme_p2 = try reader.readU32Le(),
        .aim_scheme_p3 = try reader.readU32Le(),
        .aim_scheme_p4 = try reader.readU32Le(),
        .aim_schemes_reserved = try reader.readArray(0x18),
        .unknown_6c = try reader.readU32Le(),
        .texture_scale = try reader.readF32Le(),
        .name_tag = try reader.readArray(12),
        .selected_name_slot = try reader.readU32Le(),
        .saved_name_index = try reader.readU32Le(),
        .saved_name_order = try reader.readArray(0x20),
        .saved_names = try reader.readArray(0xD8),
        .player_name = try reader.readArray(0x20),
        .player_name_len = try reader.readU32Le(),
        .unknown_1a4 = try reader.readU32Le(),
        .unknown_1a8 = try reader.readU32Le(),
        .unknown_1ac = try reader.readU32Le(),
        .aim_pov_right = try reader.readU32Le(),
        .aim_pov_left = try reader.readU32Le(),
        .screen_bpp = try reader.readU32Le(),
        .screen_width = try reader.readU32Le(),
        .screen_height = try reader.readU32Le(),
        .windowed_flag = try reader.readU8(),
        .unknown_1c5 = try reader.readArray(3),
        .keybinds = try reader.readArray(0x80),
        .unknown_248 = try reader.readArray(0x1F8),
        .unknown_440 = try reader.readU32Le(),
        .unknown_444 = try reader.readU32Le(),
        .hardcore_flag = try reader.readU8(),
        .ui_info_texts = try reader.readU8(),
        .unknown_44a = try reader.readArray(2),
        .perk_prompt_counter = try reader.readU32Le(),
        .unknown_450 = try reader.readU32Le(),
        .unknown_454 = try reader.readArray(0x0C),
        .unknown_460 = try reader.readU32Le(),
        .sfx_volume = try reader.readF32Le(),
        .music_volume = try reader.readF32Le(),
        .gore_disabled = try reader.readU8(),
        .score_load_gate = try reader.readU8(),
        .unknown_46e = try reader.readU8(),
        .unknown_46f = try reader.readU8(),
        .detail_preset = try reader.readU32Le(),
        .mouse_sensitivity = try reader.readF32Le(),
        .keybind_pick_perk = try reader.readU32Le(),
        .keybind_reload = try reader.readU32Le(),
    };
}

pub fn encode(cfg: CrimsonCfg) [file_size]u8 {
    var bytes: [file_size]u8 = undefined;
    var writer = binary.Writer.init(bytes[0..]);

    writer.writeU8(cfg.sound_disable) catch unreachable;
    writer.writeU8(cfg.music_disable) catch unreachable;
    writer.writeU8(cfg.highscore_date_mode) catch unreachable;
    writer.writeU8(cfg.highscore_duplicate_mode) catch unreachable;
    writer.writeBytes(&cfg.hud_indicators) catch unreachable;
    writer.writeBytes(&cfg.unknown_06) catch unreachable;
    writer.writeU32Le(cfg.unknown_08) catch unreachable;
    writer.writeBytes(&cfg.unknown_0c) catch unreachable;
    writer.writeU8(cfg.fx_detail_0) catch unreachable;
    writer.writeU8(cfg.unknown_0f) catch unreachable;
    writer.writeU8(cfg.fx_detail_1) catch unreachable;
    writer.writeU8(cfg.fx_detail_2) catch unreachable;
    writer.writeBytes(&cfg.unknown_12) catch unreachable;
    writer.writeU32Le(cfg.player_count) catch unreachable;
    writer.writeU32Le(cfg.game_mode) catch unreachable;
    writer.writeU32Le(cfg.player_mode_flag_p1) catch unreachable;
    writer.writeU32Le(cfg.player_mode_flag_p2) catch unreachable;
    writer.writeU32Le(cfg.player_mode_flag_p3) catch unreachable;
    writer.writeU32Le(cfg.player_mode_flag_p4) catch unreachable;
    writer.writeBytes(&cfg.player_mode_flags_reserved) catch unreachable;
    writer.writeU32Le(cfg.aim_scheme_p1) catch unreachable;
    writer.writeU32Le(cfg.aim_scheme_p2) catch unreachable;
    writer.writeU32Le(cfg.aim_scheme_p3) catch unreachable;
    writer.writeU32Le(cfg.aim_scheme_p4) catch unreachable;
    writer.writeBytes(&cfg.aim_schemes_reserved) catch unreachable;
    writer.writeU32Le(cfg.unknown_6c) catch unreachable;
    writer.writeF32Le(cfg.texture_scale) catch unreachable;
    writer.writeBytes(&cfg.name_tag) catch unreachable;
    writer.writeU32Le(cfg.selected_name_slot) catch unreachable;
    writer.writeU32Le(cfg.saved_name_index) catch unreachable;
    writer.writeBytes(&cfg.saved_name_order) catch unreachable;
    writer.writeBytes(&cfg.saved_names) catch unreachable;
    writer.writeBytes(&cfg.player_name) catch unreachable;
    writer.writeU32Le(cfg.player_name_len) catch unreachable;
    writer.writeU32Le(cfg.unknown_1a4) catch unreachable;
    writer.writeU32Le(cfg.unknown_1a8) catch unreachable;
    writer.writeU32Le(cfg.unknown_1ac) catch unreachable;
    writer.writeU32Le(cfg.aim_pov_right) catch unreachable;
    writer.writeU32Le(cfg.aim_pov_left) catch unreachable;
    writer.writeU32Le(cfg.screen_bpp) catch unreachable;
    writer.writeU32Le(cfg.screen_width) catch unreachable;
    writer.writeU32Le(cfg.screen_height) catch unreachable;
    writer.writeU8(cfg.windowed_flag) catch unreachable;
    writer.writeBytes(&cfg.unknown_1c5) catch unreachable;
    writer.writeBytes(&cfg.keybinds) catch unreachable;
    writer.writeBytes(&cfg.unknown_248) catch unreachable;
    writer.writeU32Le(cfg.unknown_440) catch unreachable;
    writer.writeU32Le(cfg.unknown_444) catch unreachable;
    writer.writeU8(cfg.hardcore_flag) catch unreachable;
    writer.writeU8(cfg.ui_info_texts) catch unreachable;
    writer.writeBytes(&cfg.unknown_44a) catch unreachable;
    writer.writeU32Le(cfg.perk_prompt_counter) catch unreachable;
    writer.writeU32Le(cfg.unknown_450) catch unreachable;
    writer.writeBytes(&cfg.unknown_454) catch unreachable;
    writer.writeU32Le(cfg.unknown_460) catch unreachable;
    writer.writeF32Le(cfg.sfx_volume) catch unreachable;
    writer.writeF32Le(cfg.music_volume) catch unreachable;
    writer.writeU8(cfg.gore_disabled) catch unreachable;
    writer.writeU8(cfg.score_load_gate) catch unreachable;
    writer.writeU8(cfg.unknown_46e) catch unreachable;
    writer.writeU8(cfg.unknown_46f) catch unreachable;
    writer.writeU32Le(cfg.detail_preset) catch unreachable;
    writer.writeF32Le(cfg.mouse_sensitivity) catch unreachable;
    writer.writeU32Le(cfg.keybind_pick_perk) catch unreachable;
    writer.writeU32Le(cfg.keybind_reload) catch unreachable;

    std.debug.assert(writer.pos == file_size);
    return bytes;
}

test "crimson.cfg rejects invalid size" {
    var short: [file_size - 1]u8 = [_]u8{0} ** (file_size - 1);
    try std.testing.expectError(error.InvalidSize, decode(short[0..]));
}

test "crimson.cfg patterned roundtrip preserves all bytes" {
    var bytes: [file_size]u8 = undefined;
    for (&bytes, 0..) |*b, idx| b.* = @truncate(idx);

    const parsed = try decode(bytes[0..]);
    const rebuilt = encode(parsed);
    try std.testing.expectEqualSlices(u8, bytes[0..], rebuilt[0..]);
}

test "crimson.cfg maps representative field offsets" {
    var bytes: [file_size]u8 = [_]u8{0} ** file_size;

    std.mem.writeInt(u32, bytes[0x70..0x74], @bitCast(@as(f32, 1.0)), .little);
    std.mem.writeInt(u32, bytes[0x1B8..0x1BC], 32, .little);
    std.mem.writeInt(u32, bytes[0x1BC..0x1C0], 1024, .little);
    std.mem.writeInt(u32, bytes[0x1C0..0x1C4], 768, .little);
    bytes[0x1C4] = 1;
    std.mem.writeInt(u32, bytes[0x478..0x47C], 0x101, .little);
    std.mem.writeInt(u32, bytes[0x47C..0x480], 0x102, .little);

    const parsed = try decode(bytes[0..]);
    try std.testing.expectEqual(@as(f32, 1.0), parsed.texture_scale);
    try std.testing.expectEqual(@as(u32, 32), parsed.screen_bpp);
    try std.testing.expectEqual(@as(u32, 1024), parsed.screen_width);
    try std.testing.expectEqual(@as(u32, 768), parsed.screen_height);
    try std.testing.expectEqual(@as(u8, 1), parsed.windowed_flag);
    try std.testing.expectEqual(@as(u32, 0x101), parsed.keybind_pick_perk);
    try std.testing.expectEqual(@as(u32, 0x102), parsed.keybind_reload);

    var cfg = std.mem.zeroes(CrimsonCfg);
    cfg.texture_scale = 1.0;
    cfg.screen_bpp = 32;
    cfg.screen_width = 1024;
    cfg.screen_height = 768;
    cfg.windowed_flag = 1;
    cfg.keybind_pick_perk = 0x101;
    cfg.keybind_reload = 0x102;

    const encoded = encode(cfg);
    try std.testing.expectEqual(@as(u32, @bitCast(@as(f32, 1.0))), std.mem.readInt(u32, encoded[0x70..0x74], .little));
    try std.testing.expectEqual(@as(u32, 32), std.mem.readInt(u32, encoded[0x1B8..0x1BC], .little));
    try std.testing.expectEqual(@as(u32, 1024), std.mem.readInt(u32, encoded[0x1BC..0x1C0], .little));
    try std.testing.expectEqual(@as(u32, 768), std.mem.readInt(u32, encoded[0x1C0..0x1C4], .little));
    try std.testing.expectEqual(@as(u8, 1), encoded[0x1C4]);
    try std.testing.expectEqual(@as(u32, 0x101), std.mem.readInt(u32, encoded[0x478..0x47C], .little));
    try std.testing.expectEqual(@as(u32, 0x102), std.mem.readInt(u32, encoded[0x47C..0x480], .little));
}
