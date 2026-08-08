const std = @import("std");
const binary = @import("binary.zig");

pub const file_size: usize = 0x480;
pub const player_name_size: usize = 0x20;
pub const player_name_max_bytes: usize = player_name_size - 1;
pub const saved_name_slot_count: usize = 8;
pub const saved_name_entry_size: usize = 0x1B;
pub const saved_names_blob_size: usize = saved_name_slot_count * saved_name_entry_size;
pub const player_bind_block_dwords: usize = 0x10;
pub const player_bind_block_size: usize = player_bind_block_dwords * 4;
pub const config_player_slot_count: usize = 10;
pub const port_player_slot_count: usize = 4;
pub const reserved_keybind_slot_count: usize = 2;
pub const padding_keybind_slot_count: usize = 3;
pub const keybind_unbound_code: i32 = 0x17E;

pub const CrimsonCfgError = binary.BinaryError || error{
    InvalidSize,
};

pub const PlayerBindBlock = struct {
    move_forward: i32,
    move_backward: i32,
    turn_left: i32,
    turn_right: i32,
    fire: i32,
    reserved_keys: [reserved_keybind_slot_count]i32,
    aim_left: i32,
    aim_right: i32,
    axis_aim_y: i32,
    axis_aim_x: i32,
    axis_move_y: i32,
    axis_move_x: i32,
    padding: [padding_keybind_slot_count]i32,
};

pub const CrimsonCfg = struct {
    sound_disabled: u8,
    music_disabled: u8,
    highscore_date_mode: u8,
    highscore_duplicate_mode: u8,
    direction_arrow_flags: [config_player_slot_count]u8,
    shadows_enabled: u8,
    sharp_ground_enabled: u8,
    flame_glow_enabled: u8,
    smoke_enabled: u8,
    padding_12: [2]u8,
    player_count: u32,
    game_mode: u32,
    movement_schemes: [config_player_slot_count]u32,
    aim_schemes: [config_player_slot_count]u32,
    config_for: u32,
    texture_scale: f32,
    player_name_buf: [12]u8,
    selected_saved_name_slot: u32,
    saved_name_count: u32,
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
    windowed_padding: [3]u8,
    input_config_storage: [config_player_slot_count * player_bind_block_size]u8,
    hardcore_flag: u8,
    ui_info_texts: u8,
    hardcore_info_padding: [2]u8,
    level_up_count: u32,
    ten_tons_logging_completed: u32,
    unique_id_1: u32,
    unique_id_2: u32,
    reserved_identity_word: u32,
    sound_frequency_adjustment_enabled: u8,
    sound_frequency_padding: [3]u8,
    sfx_volume: f32,
    music_volume: f32,
    violence_disabled: u8,
    show_online_scores: u8,
    safe_mode_backend_enabled: u8,
    detail_padding: u8,
    detail_preset: u32,
    mouse_sensitivity: f32,
    keybind_pick_perk: u32,
    keybind_reload: u32,
};

pub fn decodePlayerBindBlock(bytes: []const u8) CrimsonCfgError!PlayerBindBlock {
    if (bytes.len != player_bind_block_size) return error.InvalidSize;

    var reader = binary.Reader.init(bytes);
    return .{
        .move_forward = @bitCast(try reader.readU32Le()),
        .move_backward = @bitCast(try reader.readU32Le()),
        .turn_left = @bitCast(try reader.readU32Le()),
        .turn_right = @bitCast(try reader.readU32Le()),
        .fire = @bitCast(try reader.readU32Le()),
        .reserved_keys = .{
            @bitCast(try reader.readU32Le()),
            @bitCast(try reader.readU32Le()),
        },
        .aim_left = @bitCast(try reader.readU32Le()),
        .aim_right = @bitCast(try reader.readU32Le()),
        .axis_aim_y = @bitCast(try reader.readU32Le()),
        .axis_aim_x = @bitCast(try reader.readU32Le()),
        .axis_move_y = @bitCast(try reader.readU32Le()),
        .axis_move_x = @bitCast(try reader.readU32Le()),
        .padding = .{
            @bitCast(try reader.readU32Le()),
            @bitCast(try reader.readU32Le()),
            @bitCast(try reader.readU32Le()),
        },
    };
}

pub fn encodePlayerBindBlock(block: PlayerBindBlock) [player_bind_block_size]u8 {
    var bytes: [player_bind_block_size]u8 = undefined;
    var writer = binary.Writer.init(bytes[0..]);

    writer.writeU32Le(@bitCast(block.move_forward)) catch unreachable;
    writer.writeU32Le(@bitCast(block.move_backward)) catch unreachable;
    writer.writeU32Le(@bitCast(block.turn_left)) catch unreachable;
    writer.writeU32Le(@bitCast(block.turn_right)) catch unreachable;
    writer.writeU32Le(@bitCast(block.fire)) catch unreachable;
    for (block.reserved_keys) |value| {
        writer.writeU32Le(@bitCast(value)) catch unreachable;
    }
    writer.writeU32Le(@bitCast(block.aim_left)) catch unreachable;
    writer.writeU32Le(@bitCast(block.aim_right)) catch unreachable;
    writer.writeU32Le(@bitCast(block.axis_aim_y)) catch unreachable;
    writer.writeU32Le(@bitCast(block.axis_aim_x)) catch unreachable;
    writer.writeU32Le(@bitCast(block.axis_move_y)) catch unreachable;
    writer.writeU32Le(@bitCast(block.axis_move_x)) catch unreachable;
    for (block.padding) |value| {
        writer.writeU32Le(@bitCast(value)) catch unreachable;
    }

    std.debug.assert(writer.pos == player_bind_block_size);
    return bytes;
}

pub fn defaultPlayerBindBlock(player_index: usize) PlayerBindBlock {
    return switch (player_index) {
        0 => .{
            .move_forward = 0x11,
            .move_backward = 0x1F,
            .turn_left = 0x1E,
            .turn_right = 0x20,
            .fire = 0x100,
            .reserved_keys = [_]i32{ keybind_unbound_code, keybind_unbound_code },
            .aim_left = 0x10,
            .aim_right = 0x12,
            .axis_aim_y = 0x13F,
            .axis_aim_x = 0x140,
            .axis_move_y = 0x141,
            .axis_move_x = 0x153,
            .padding = [_]i32{ keybind_unbound_code, keybind_unbound_code, keybind_unbound_code },
        },
        1 => .{
            .move_forward = 0xC8,
            .move_backward = 0xD0,
            .turn_left = 0xCB,
            .turn_right = 0xCD,
            .fire = 0x9D,
            .reserved_keys = [_]i32{ keybind_unbound_code, keybind_unbound_code },
            .aim_left = 0xD3,
            .aim_right = 0xD1,
            .axis_aim_y = 0x13F,
            .axis_aim_x = 0x140,
            .axis_move_y = 0x141,
            .axis_move_x = 0x153,
            .padding = [_]i32{ keybind_unbound_code, keybind_unbound_code, keybind_unbound_code },
        },
        2 => .{
            .move_forward = 0x17,
            .move_backward = 0x25,
            .turn_left = 0x24,
            .turn_right = 0x26,
            .fire = 0x36,
            .reserved_keys = [_]i32{ keybind_unbound_code, keybind_unbound_code },
            .aim_left = 0x16,
            .aim_right = 0x18,
            .axis_aim_y = keybind_unbound_code,
            .axis_aim_x = keybind_unbound_code,
            .axis_move_y = keybind_unbound_code,
            .axis_move_x = keybind_unbound_code,
            .padding = [_]i32{ keybind_unbound_code, keybind_unbound_code, keybind_unbound_code },
        },
        3 => .{
            .move_forward = 0x131,
            .move_backward = 0x132,
            .turn_left = 0x133,
            .turn_right = 0x134,
            .fire = 0x11F,
            .reserved_keys = [_]i32{ keybind_unbound_code, keybind_unbound_code },
            .aim_left = keybind_unbound_code,
            .aim_right = keybind_unbound_code,
            .axis_aim_y = 0x140,
            .axis_aim_x = 0x13F,
            .axis_move_y = 0x153,
            .axis_move_x = 0x154,
            .padding = [_]i32{ keybind_unbound_code, keybind_unbound_code, keybind_unbound_code },
        },
        else => unreachable,
    };
}

fn playerBindBlockOffset(player_index: usize) usize {
    std.debug.assert(player_index < port_player_slot_count);
    return player_index * player_bind_block_size;
}

fn playerBindBlockBytes(cfg: *const CrimsonCfg, player_index: usize) [player_bind_block_size]u8 {
    const start = playerBindBlockOffset(player_index);
    var bytes: [player_bind_block_size]u8 = undefined;
    @memcpy(bytes[0..], cfg.input_config_storage[start .. start + player_bind_block_size]);
    return bytes;
}

fn playerBindBlockIsUninitialized(bytes: [player_bind_block_size]u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

pub fn playerBindBlock(cfg: *const CrimsonCfg, player_index: usize) PlayerBindBlock {
    const bytes = playerBindBlockBytes(cfg, player_index);
    if (playerBindBlockIsUninitialized(bytes)) {
        return defaultPlayerBindBlock(player_index);
    }
    return decodePlayerBindBlock(bytes[0..]) catch unreachable;
}

pub fn setPlayerBindBlock(cfg: *CrimsonCfg, player_index: usize, block: PlayerBindBlock) void {
    const start = playerBindBlockOffset(player_index);
    const bytes = encodePlayerBindBlock(block);
    @memcpy(cfg.input_config_storage[start .. start + player_bind_block_size], bytes[0..]);
}

pub fn playerMovement(cfg: *const CrimsonCfg, player_index: usize) u32 {
    std.debug.assert(player_index < port_player_slot_count);
    return cfg.movement_schemes[player_index];
}

pub fn playerAimScheme(cfg: *const CrimsonCfg, player_index: usize) u32 {
    std.debug.assert(player_index < port_player_slot_count);
    return cfg.aim_schemes[player_index];
}

pub fn playerShowDirectionArrow(cfg: *const CrimsonCfg, player_index: usize) bool {
    std.debug.assert(player_index < port_player_slot_count);
    return cfg.direction_arrow_flags[player_index] != 0;
}

pub fn setPlayerMovement(cfg: *CrimsonCfg, player_index: usize, value: u32) void {
    std.debug.assert(player_index < port_player_slot_count);
    cfg.movement_schemes[player_index] = value;
}

pub fn setPlayerAimScheme(cfg: *CrimsonCfg, player_index: usize, value: u32) void {
    std.debug.assert(player_index < port_player_slot_count);
    cfg.aim_schemes[player_index] = value;
}

pub fn setPlayerShowDirectionArrow(cfg: *CrimsonCfg, player_index: usize, enabled: bool) void {
    std.debug.assert(player_index < port_player_slot_count);
    cfg.direction_arrow_flags[player_index] = @intFromBool(enabled);
}

pub fn applyDetailPreset(cfg: *CrimsonCfg, preset: i32) u32 {
    const selected_i32 = std.math.clamp(preset, @as(i32, 1), @as(i32, 5));
    const selected: u32 = @intCast(selected_i32);
    cfg.detail_preset = selected;
    if (selected <= 1) {
        cfg.shadows_enabled = 0;
        cfg.flame_glow_enabled = 0;
        cfg.smoke_enabled = 0;
    } else if (selected == 2) {
        cfg.shadows_enabled = 0;
        cfg.flame_glow_enabled = 0;
        cfg.smoke_enabled = 1;
    } else {
        cfg.shadows_enabled = 1;
        cfg.flame_glow_enabled = 1;
        cfg.smoke_enabled = 1;
    }
    return selected;
}

pub fn defaultConfig() CrimsonCfg {
    var cfg = std.mem.zeroes(CrimsonCfg);
    for (cfg.direction_arrow_flags[0..port_player_slot_count]) |*flag| flag.* = 1;
    cfg.shadows_enabled = 1;
    cfg.flame_glow_enabled = 1;
    cfg.smoke_enabled = 1;
    cfg.player_count = 1;
    cfg.game_mode = 1;
    for (cfg.movement_schemes[0..port_player_slot_count]) |*scheme| scheme.* = 2;
    cfg.texture_scale = 1.0;
    cfg.selected_saved_name_slot = 0;
    cfg.saved_name_count = 1;
    cfg.player_name_len = 0;
    cfg.unknown_1a4 = 100;
    cfg.aim_pov_right = 9000;
    cfg.aim_pov_left = 27000;
    cfg.screen_bpp = 32;
    cfg.screen_width = 1024;
    cfg.screen_height = 768;
    cfg.windowed_flag = 1;
    cfg.hardcore_flag = 0;
    cfg.ui_info_texts = 1;
    cfg.ten_tons_logging_completed = 1;
    cfg.sound_frequency_adjustment_enabled = 1;
    cfg.sfx_volume = 1.0;
    cfg.music_volume = 1.0;
    cfg.violence_disabled = 0;
    cfg.show_online_scores = 0;
    cfg.detail_preset = 5;
    cfg.mouse_sensitivity = 0.5;
    cfg.keybind_pick_perk = 0x101;
    cfg.keybind_reload = 0x102;

    for (0..saved_name_slot_count) |idx| {
        std.mem.writeInt(u32, cfg.saved_name_order[idx * 4 ..][0..4], @intCast(idx), .little);
        const start = idx * saved_name_entry_size;
        @memset(cfg.saved_names[start .. start + saved_name_entry_size], 0);
        @memcpy(cfg.saved_names[start .. start + "default".len], "default");
    }

    @memset(cfg.player_name[0..], 0);
    @memcpy(cfg.player_name[0.."10tons".len], "10tons");

    inline for (0..port_player_slot_count) |idx| {
        setPlayerBindBlock(&cfg, idx, defaultPlayerBindBlock(idx));
    }

    return cfg;
}

pub fn playerName(cfg: *const CrimsonCfg) []const u8 {
    return std.mem.sliceTo(cfg.player_name[0..], 0);
}

pub fn setPlayerNameInput(cfg: *CrimsonCfg, name: []const u8) void {
    const len = @min(name.len, player_name_max_bytes);

    @memset(cfg.player_name[0..], 0);
    @memcpy(cfg.player_name[0..len], name[0..len]);
    cfg.player_name[@min(len, player_name_max_bytes)] = 0;
    cfg.player_name_len = @intCast(len);

    const raw = cfg.player_name[0..];
    const end = std.mem.indexOfScalar(u8, raw, 0) orelse raw.len;
    var i = end;
    while (i > 0 and raw[i - 1] == 0x20) : (i -= 1) {
        raw[i - 1] = 0;
    }
}

pub fn savedNameCount(cfg: *const CrimsonCfg) usize {
    const count: usize = @intCast(cfg.saved_name_count);
    return @min(@max(count, 1), saved_name_slot_count);
}

pub fn selectedSavedNameSlot(cfg: *const CrimsonCfg) usize {
    const selected: usize = @intCast(cfg.selected_saved_name_slot);
    return @min(selected, savedNameCount(cfg) - 1);
}

pub fn setSelectedSavedNameSlot(cfg: *CrimsonCfg, slot_index: usize) void {
    cfg.selected_saved_name_slot = @intCast(@min(slot_index, saved_name_slot_count - 1));
}

pub fn savedNameLabel(cfg: *const CrimsonCfg, slot_index: usize) []const u8 {
    const safe_index: usize = @min(slot_index, saved_name_slot_count - 1);
    const order_offset: usize = safe_index * 4;
    const raw_slot = std.mem.readInt(u32, cfg.saved_name_order[order_offset..][0..4], .little);
    const mapped_slot: usize = @min(@as(usize, raw_slot), saved_name_slot_count - 1);
    const start: usize = mapped_slot * saved_name_entry_size;
    const bytes = cfg.saved_names[start .. start + saved_name_entry_size];
    return std.mem.sliceTo(bytes, 0);
}

fn readU32Array(comptime count: usize, reader: *binary.Reader) binary.BinaryError![count]u32 {
    var values: [count]u32 = undefined;
    for (&values) |*value| value.* = try reader.readU32Le();
    return values;
}

pub fn decode(bytes: []const u8) CrimsonCfgError!CrimsonCfg {
    if (bytes.len != file_size) return error.InvalidSize;

    var reader = binary.Reader.init(bytes);

    var cfg: CrimsonCfg = .{
        .sound_disabled = try reader.readU8(),
        .music_disabled = try reader.readU8(),
        .highscore_date_mode = try reader.readU8(),
        .highscore_duplicate_mode = try reader.readU8(),
        .direction_arrow_flags = try reader.readArray(config_player_slot_count),
        .shadows_enabled = try reader.readU8(),
        .sharp_ground_enabled = try reader.readU8(),
        .flame_glow_enabled = try reader.readU8(),
        .smoke_enabled = try reader.readU8(),
        .padding_12 = try reader.readArray(2),
        .player_count = try reader.readU32Le(),
        .game_mode = try reader.readU32Le(),
        .movement_schemes = try readU32Array(config_player_slot_count, &reader),
        .aim_schemes = try readU32Array(config_player_slot_count, &reader),
        .config_for = try reader.readU32Le(),
        .texture_scale = try reader.readF32Le(),
        .player_name_buf = try reader.readArray(12),
        .selected_saved_name_slot = try reader.readU32Le(),
        .saved_name_count = try reader.readU32Le(),
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
        .windowed_padding = try reader.readArray(3),
        .input_config_storage = try reader.readArray(config_player_slot_count * player_bind_block_size),
        .hardcore_flag = try reader.readU8(),
        .ui_info_texts = try reader.readU8(),
        .hardcore_info_padding = try reader.readArray(2),
        .level_up_count = try reader.readU32Le(),
        .ten_tons_logging_completed = try reader.readU32Le(),
        .unique_id_1 = try reader.readU32Le(),
        .unique_id_2 = try reader.readU32Le(),
        .reserved_identity_word = try reader.readU32Le(),
        .sound_frequency_adjustment_enabled = try reader.readU8(),
        .sound_frequency_padding = try reader.readArray(3),
        .sfx_volume = try reader.readF32Le(),
        .music_volume = try reader.readF32Le(),
        .violence_disabled = try reader.readU8(),
        .show_online_scores = try reader.readU8(),
        .safe_mode_backend_enabled = try reader.readU8(),
        .detail_padding = try reader.readU8(),
        .detail_preset = try reader.readU32Le(),
        .mouse_sensitivity = try reader.readF32Le(),
        .keybind_pick_perk = try reader.readU32Le(),
        .keybind_reload = try reader.readU32Le(),
    };
    if (cfg.detail_preset == 0 and cfg.shadows_enabled == 0 and cfg.flame_glow_enabled == 0 and cfg.smoke_enabled == 0) {
        _ = applyDetailPreset(&cfg, 5);
    }
    return cfg;
}

pub fn encode(cfg: CrimsonCfg) [file_size]u8 {
    var bytes: [file_size]u8 = undefined;
    var writer = binary.Writer.init(bytes[0..]);

    writer.writeU8(cfg.sound_disabled) catch unreachable;
    writer.writeU8(cfg.music_disabled) catch unreachable;
    writer.writeU8(cfg.highscore_date_mode) catch unreachable;
    writer.writeU8(cfg.highscore_duplicate_mode) catch unreachable;
    writer.writeBytes(&cfg.direction_arrow_flags) catch unreachable;
    writer.writeU8(cfg.shadows_enabled) catch unreachable;
    writer.writeU8(cfg.sharp_ground_enabled) catch unreachable;
    writer.writeU8(cfg.flame_glow_enabled) catch unreachable;
    writer.writeU8(cfg.smoke_enabled) catch unreachable;
    writer.writeBytes(&cfg.padding_12) catch unreachable;
    writer.writeU32Le(cfg.player_count) catch unreachable;
    writer.writeU32Le(cfg.game_mode) catch unreachable;
    for (cfg.movement_schemes) |value| writer.writeU32Le(value) catch unreachable;
    for (cfg.aim_schemes) |value| writer.writeU32Le(value) catch unreachable;
    writer.writeU32Le(cfg.config_for) catch unreachable;
    writer.writeF32Le(cfg.texture_scale) catch unreachable;
    writer.writeBytes(&cfg.player_name_buf) catch unreachable;
    writer.writeU32Le(cfg.selected_saved_name_slot) catch unreachable;
    writer.writeU32Le(cfg.saved_name_count) catch unreachable;
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
    writer.writeBytes(&cfg.windowed_padding) catch unreachable;
    writer.writeBytes(&cfg.input_config_storage) catch unreachable;
    writer.writeU8(cfg.hardcore_flag) catch unreachable;
    writer.writeU8(cfg.ui_info_texts) catch unreachable;
    writer.writeBytes(&cfg.hardcore_info_padding) catch unreachable;
    writer.writeU32Le(cfg.level_up_count) catch unreachable;
    writer.writeU32Le(cfg.ten_tons_logging_completed) catch unreachable;
    writer.writeU32Le(cfg.unique_id_1) catch unreachable;
    writer.writeU32Le(cfg.unique_id_2) catch unreachable;
    writer.writeU32Le(cfg.reserved_identity_word) catch unreachable;
    writer.writeU8(cfg.sound_frequency_adjustment_enabled) catch unreachable;
    writer.writeBytes(&cfg.sound_frequency_padding) catch unreachable;
    writer.writeF32Le(cfg.sfx_volume) catch unreachable;
    writer.writeF32Le(cfg.music_volume) catch unreachable;
    writer.writeU8(cfg.violence_disabled) catch unreachable;
    writer.writeU8(cfg.show_online_scores) catch unreachable;
    writer.writeU8(cfg.safe_mode_backend_enabled) catch unreachable;
    writer.writeU8(cfg.detail_padding) catch unreachable;
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

test "crimson.cfg default config mirrors python defaults" {
    const cfg = defaultConfig();

    try std.testing.expectEqual(@as(u32, 1), cfg.player_count);
    try std.testing.expectEqual(@as(u32, 1), cfg.game_mode);
    try std.testing.expectEqual(@as(u32, 32), cfg.screen_bpp);
    try std.testing.expectEqual(@as(u32, 1024), cfg.screen_width);
    try std.testing.expectEqual(@as(u32, 768), cfg.screen_height);
    try std.testing.expectEqual(@as(u8, 1), cfg.windowed_flag);
    try std.testing.expectEqual(@as(u32, 5), cfg.detail_preset);
    try std.testing.expectEqual(@as(f32, 1.0), cfg.texture_scale);
    try std.testing.expectEqual(@as(f32, 0.5), cfg.mouse_sensitivity);
    try std.testing.expectEqual(@as(u32, 0x101), cfg.keybind_pick_perk);
    try std.testing.expectEqual(@as(u32, 0x102), cfg.keybind_reload);
    try std.testing.expectEqualStrings("10tons", std.mem.sliceTo(cfg.player_name[0..], 0));
    try std.testing.expectEqualStrings("default", cfg.saved_names[0.."default".len]);

    const p1 = playerBindBlock(&cfg, 0);
    try std.testing.expectEqual(defaultPlayerBindBlock(0).move_forward, p1.move_forward);
    try std.testing.expectEqual(defaultPlayerBindBlock(0).fire, p1.fire);

    const p4 = playerBindBlock(&cfg, 3);
    try std.testing.expectEqual(defaultPlayerBindBlock(3).move_forward, p4.move_forward);
    try std.testing.expectEqual(defaultPlayerBindBlock(3).fire, p4.fire);
    try std.testing.expect(playerShowDirectionArrow(&cfg, 3));
}

test "crimson.cfg player name input helper trims trailing spaces and preserves typed length" {
    var cfg = defaultConfig();
    setPlayerNameInput(&cfg, "Alpha   ");

    try std.testing.expectEqualStrings("Alpha", playerName(&cfg));
    try std.testing.expectEqual(@as(u32, 8), cfg.player_name_len);
}

test "crimson.cfg saved name count clamps the visible slot prefix" {
    var cfg = defaultConfig();

    try std.testing.expectEqual(@as(usize, 1), savedNameCount(&cfg));
    cfg.saved_name_count = 3;
    try std.testing.expectEqual(@as(usize, 3), savedNameCount(&cfg));
    cfg.selected_saved_name_slot = 7;
    try std.testing.expectEqual(@as(usize, 2), selectedSavedNameSlot(&cfg));
    cfg.saved_name_count = 0;
    try std.testing.expectEqual(@as(usize, 1), savedNameCount(&cfg));
    try std.testing.expectEqual(@as(usize, 0), selectedSavedNameSlot(&cfg));
    cfg.saved_name_count = 99;
    try std.testing.expectEqual(saved_name_slot_count, savedNameCount(&cfg));
}

test "crimson.cfg detail presets update fx detail flags" {
    var cfg = defaultConfig();

    try std.testing.expectEqual(@as(u32, 1), applyDetailPreset(&cfg, 0));
    try std.testing.expectEqual(@as(u8, 0), cfg.shadows_enabled);
    try std.testing.expectEqual(@as(u8, 0), cfg.flame_glow_enabled);
    try std.testing.expectEqual(@as(u8, 0), cfg.smoke_enabled);

    try std.testing.expectEqual(@as(u32, 2), applyDetailPreset(&cfg, 2));
    try std.testing.expectEqual(@as(u8, 0), cfg.shadows_enabled);
    try std.testing.expectEqual(@as(u8, 0), cfg.flame_glow_enabled);
    try std.testing.expectEqual(@as(u8, 1), cfg.smoke_enabled);

    try std.testing.expectEqual(@as(u32, 5), applyDetailPreset(&cfg, 9));
    try std.testing.expectEqual(@as(u8, 1), cfg.shadows_enabled);
    try std.testing.expectEqual(@as(u8, 1), cfg.flame_glow_enabled);
    try std.testing.expectEqual(@as(u8, 1), cfg.smoke_enabled);
}

test "crimson.cfg decode normalizes legacy empty detail preset" {
    var cfg = defaultConfig();
    cfg.detail_preset = 0;
    cfg.shadows_enabled = 0;
    cfg.flame_glow_enabled = 0;
    cfg.smoke_enabled = 0;

    const encoded = encode(cfg);
    const parsed = try decode(encoded[0..]);

    try std.testing.expectEqual(@as(u32, 5), parsed.detail_preset);
    try std.testing.expectEqual(@as(u8, 1), parsed.shadows_enabled);
    try std.testing.expectEqual(@as(u8, 1), parsed.flame_glow_enabled);
    try std.testing.expectEqual(@as(u8, 1), parsed.smoke_enabled);
}

test "crimson.cfg bind block helpers roundtrip" {
    const expected: PlayerBindBlock = .{
        .move_forward = 0x11,
        .move_backward = 0x1F,
        .turn_left = 0x1E,
        .turn_right = 0x20,
        .fire = 0x100,
        .reserved_keys = [_]i32{ keybind_unbound_code, keybind_unbound_code },
        .aim_left = 0x10,
        .aim_right = 0x12,
        .axis_aim_y = 0x13F,
        .axis_aim_x = 0x140,
        .axis_move_y = 0x141,
        .axis_move_x = 0x153,
        .padding = [_]i32{ keybind_unbound_code, keybind_unbound_code, keybind_unbound_code },
    };

    const encoded = encodePlayerBindBlock(expected);
    const decoded = try decodePlayerBindBlock(encoded[0..]);

    try std.testing.expectEqualDeep(expected, decoded);
}
