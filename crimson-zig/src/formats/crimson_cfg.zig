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
pub const player_bind_block_count_primary: usize = 2;
pub const player_bind_block_count_total: usize = 4;
pub const reserved_keybind_slot_count: usize = 2;
pub const padding_keybind_slot_count: usize = 3;
pub const extended_direction_arrow_flag_count: usize = 2;
pub const ext_direction_arrow_unset: u8 = 0;
pub const ext_direction_arrow_off: u8 = 1;
pub const ext_direction_arrow_on: u8 = 2;
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

fn playerBindBlockOffsets(player_index: usize) struct { start: usize, extended: bool } {
    return switch (player_index) {
        0 => .{ .start = 0, .extended = false },
        1 => .{ .start = player_bind_block_size, .extended = false },
        2 => .{ .start = 0, .extended = true },
        3 => .{ .start = player_bind_block_size, .extended = true },
        else => unreachable,
    };
}

fn playerBindBlockBytes(cfg: *const CrimsonCfg, player_index: usize) [player_bind_block_size]u8 {
    const offsets = playerBindBlockOffsets(player_index);
    var bytes: [player_bind_block_size]u8 = undefined;
    if (offsets.extended) {
        @memcpy(bytes[0..], cfg.unknown_248[offsets.start .. offsets.start + player_bind_block_size]);
    } else {
        @memcpy(bytes[0..], cfg.keybinds[offsets.start .. offsets.start + player_bind_block_size]);
    }
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
    const offsets = playerBindBlockOffsets(player_index);
    const bytes = encodePlayerBindBlock(block);
    if (offsets.extended) {
        @memcpy(cfg.unknown_248[offsets.start .. offsets.start + player_bind_block_size], bytes[0..]);
    } else {
        @memcpy(cfg.keybinds[offsets.start .. offsets.start + player_bind_block_size], bytes[0..]);
    }
}

pub fn playerMovement(cfg: *const CrimsonCfg, player_index: usize) u32 {
    return switch (player_index) {
        0 => cfg.player_mode_flag_p1,
        1 => cfg.player_mode_flag_p2,
        2 => cfg.player_mode_flag_p3,
        3 => cfg.player_mode_flag_p4,
        else => unreachable,
    };
}

pub fn playerAimScheme(cfg: *const CrimsonCfg, player_index: usize) u32 {
    return switch (player_index) {
        0 => cfg.aim_scheme_p1,
        1 => cfg.aim_scheme_p2,
        2 => cfg.aim_scheme_p3,
        3 => cfg.aim_scheme_p4,
        else => unreachable,
    };
}

pub fn playerShowDirectionArrow(cfg: *const CrimsonCfg, player_index: usize) bool {
    return switch (player_index) {
        0 => cfg.hud_indicators[0] != 0,
        1 => cfg.hud_indicators[1] != 0,
        2 => cfg.unknown_248[player_bind_block_size * 2] != ext_direction_arrow_off,
        3 => cfg.unknown_248[player_bind_block_size * 2 + 1] != ext_direction_arrow_off,
        else => unreachable,
    };
}

pub fn setPlayerMovement(cfg: *CrimsonCfg, player_index: usize, value: u32) void {
    switch (player_index) {
        0 => cfg.player_mode_flag_p1 = value,
        1 => cfg.player_mode_flag_p2 = value,
        2 => cfg.player_mode_flag_p3 = value,
        3 => cfg.player_mode_flag_p4 = value,
        else => unreachable,
    }
}

pub fn setPlayerAimScheme(cfg: *CrimsonCfg, player_index: usize, value: u32) void {
    switch (player_index) {
        0 => cfg.aim_scheme_p1 = value,
        1 => cfg.aim_scheme_p2 = value,
        2 => cfg.aim_scheme_p3 = value,
        3 => cfg.aim_scheme_p4 = value,
        else => unreachable,
    }
}

pub fn setPlayerShowDirectionArrow(cfg: *CrimsonCfg, player_index: usize, enabled: bool) void {
    const raw: u8 = if (enabled) ext_direction_arrow_on else ext_direction_arrow_off;
    switch (player_index) {
        0 => cfg.hud_indicators[0] = @intFromBool(enabled),
        1 => cfg.hud_indicators[1] = @intFromBool(enabled),
        2 => cfg.unknown_248[player_bind_block_size * 2] = raw,
        3 => cfg.unknown_248[player_bind_block_size * 2 + 1] = raw,
        else => unreachable,
    }
}

pub fn applyDetailPreset(cfg: *CrimsonCfg, preset: i32) u32 {
    const selected_i32 = std.math.clamp(preset, @as(i32, 1), @as(i32, 5));
    const selected: u32 = @intCast(selected_i32);
    cfg.detail_preset = selected;
    if (selected <= 1) {
        cfg.fx_detail_0 = 0;
        cfg.fx_detail_1 = 0;
        cfg.fx_detail_2 = 0;
    } else if (selected == 2) {
        cfg.fx_detail_0 = 0;
        cfg.fx_detail_1 = 0;
        cfg.fx_detail_2 = 1;
    } else {
        cfg.fx_detail_0 = 1;
        cfg.fx_detail_1 = 1;
        cfg.fx_detail_2 = 1;
    }
    return selected;
}

pub fn defaultConfig() CrimsonCfg {
    var cfg = std.mem.zeroes(CrimsonCfg);
    cfg.hud_indicators = [_]u8{ 1, 1 };
    cfg.fx_detail_0 = 1;
    cfg.fx_detail_1 = 1;
    cfg.fx_detail_2 = 1;
    cfg.player_count = 1;
    cfg.game_mode = 1;
    cfg.player_mode_flag_p1 = 2;
    cfg.player_mode_flag_p2 = 2;
    cfg.player_mode_flag_p3 = 2;
    cfg.player_mode_flag_p4 = 2;
    cfg.texture_scale = 1.0;
    cfg.selected_name_slot = 0;
    cfg.saved_name_index = 1;
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
    cfg.unknown_450 = 1;
    cfg.unknown_460 = 1;
    cfg.sfx_volume = 1.0;
    cfg.music_volume = 1.0;
    cfg.gore_disabled = 0;
    cfg.score_load_gate = 0;
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

    cfg.unknown_248[player_bind_block_size * 2] = ext_direction_arrow_on;
    cfg.unknown_248[player_bind_block_size * 2 + 1] = ext_direction_arrow_on;

    inline for (0..player_bind_block_count_total) |idx| {
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

pub fn selectedSavedNameSlot(cfg: *const CrimsonCfg) usize {
    return @min(cfg.selected_name_slot, saved_name_slot_count - 1);
}

pub fn setSelectedSavedNameSlot(cfg: *CrimsonCfg, slot_index: usize) void {
    cfg.selected_name_slot = @intCast(@min(slot_index, saved_name_slot_count - 1));
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

pub fn decode(bytes: []const u8) CrimsonCfgError!CrimsonCfg {
    if (bytes.len != file_size) return error.InvalidSize;

    var reader = binary.Reader.init(bytes);

    var cfg: CrimsonCfg = .{
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
    if (cfg.detail_preset == 0 and cfg.fx_detail_0 == 0 and cfg.fx_detail_1 == 0 and cfg.fx_detail_2 == 0) {
        _ = applyDetailPreset(&cfg, 5);
    }
    return cfg;
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

test "crimson.cfg detail presets update fx detail flags" {
    var cfg = defaultConfig();

    try std.testing.expectEqual(@as(u32, 1), applyDetailPreset(&cfg, 0));
    try std.testing.expectEqual(@as(u8, 0), cfg.fx_detail_0);
    try std.testing.expectEqual(@as(u8, 0), cfg.fx_detail_1);
    try std.testing.expectEqual(@as(u8, 0), cfg.fx_detail_2);

    try std.testing.expectEqual(@as(u32, 2), applyDetailPreset(&cfg, 2));
    try std.testing.expectEqual(@as(u8, 0), cfg.fx_detail_0);
    try std.testing.expectEqual(@as(u8, 0), cfg.fx_detail_1);
    try std.testing.expectEqual(@as(u8, 1), cfg.fx_detail_2);

    try std.testing.expectEqual(@as(u32, 5), applyDetailPreset(&cfg, 9));
    try std.testing.expectEqual(@as(u8, 1), cfg.fx_detail_0);
    try std.testing.expectEqual(@as(u8, 1), cfg.fx_detail_1);
    try std.testing.expectEqual(@as(u8, 1), cfg.fx_detail_2);
}

test "crimson.cfg decode normalizes legacy empty detail preset" {
    var cfg = defaultConfig();
    cfg.detail_preset = 0;
    cfg.fx_detail_0 = 0;
    cfg.fx_detail_1 = 0;
    cfg.fx_detail_2 = 0;

    const encoded = encode(cfg);
    const parsed = try decode(encoded[0..]);

    try std.testing.expectEqual(@as(u32, 5), parsed.detail_preset);
    try std.testing.expectEqual(@as(u8, 1), parsed.fx_detail_0);
    try std.testing.expectEqual(@as(u8, 1), parsed.fx_detail_1);
    try std.testing.expectEqual(@as(u8, 1), parsed.fx_detail_2);
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
