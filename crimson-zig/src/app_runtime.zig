const std = @import("std");

const cz = @import("crimson_zig");
const game_ids = cz.game_ids;
const formats = cz.formats;
const quest_status = @import("quest_status.zig");
const runtime_paths = cz.runtime_paths;
const runtime_session = cz.session;

pub const game_cfg_name = "game.cfg";
pub const crimson_cfg_name = "crimson.cfg";

pub const DesktopRuntimeError = std.mem.Allocator.Error ||
    std.process.Environ.GetAllocError ||
    std.Io.Dir.AccessError ||
    std.Io.Dir.CreateDirPathError ||
    std.Io.Dir.ReadFileAllocError ||
    std.Io.Dir.WriteFileError ||
    formats.crimson_cfg.CrimsonCfgError ||
    formats.game_cfg.GameCfgError ||
    error{
        MissingRuntimeDir,
        InvalidGameCfgChecksum,
    };

pub const DesktopRuntime = struct {
    allocator: std.mem.Allocator,
    base_dir: []u8,
    config_path: []u8,
    status_path: []u8,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
    config_dirty: bool = false,
    status_dirty: bool = false,

    pub fn init(allocator: std.mem.Allocator) DesktopRuntimeError!DesktopRuntime {
        const base_dir = (try runtime_paths.defaultRuntimeDir(allocator)) orelse return error.MissingRuntimeDir;
        errdefer allocator.free(base_dir);
        const io = std.Io.Threaded.global_single_threaded.io();
        try std.Io.Dir.cwd().createDirPath(io, base_dir);

        const config_path = try std.fs.path.join(allocator, &.{ base_dir, crimson_cfg_name });
        errdefer allocator.free(config_path);

        const status_path = try std.fs.path.join(allocator, &.{ base_dir, game_cfg_name });
        errdefer allocator.free(status_path);

        return .{
            .allocator = allocator,
            .base_dir = base_dir,
            .config_path = config_path,
            .status_path = status_path,
            .config = try loadOrCreateConfig(allocator, config_path),
            .status = try loadOrCreateStatus(allocator, status_path),
        };
    }

    pub fn deinit(self: *DesktopRuntime) void {
        self.allocator.free(self.status_path);
        self.allocator.free(self.config_path);
        self.allocator.free(self.base_dir);
        self.* = undefined;
    }

    pub fn saveConfigIfDirty(self: *DesktopRuntime) DesktopRuntimeError!void {
        if (!self.config_dirty) return;
        try writeConfig(self.config_path, self.config);
        self.config_dirty = false;
    }

    pub fn saveStatusIfDirty(self: *DesktopRuntime) DesktopRuntimeError!void {
        if (!self.status_dirty) return;
        try writeStatus(self.status_path, self.status);
        self.status_dirty = false;
    }

    pub fn saveAllIfDirty(self: *DesktopRuntime) DesktopRuntimeError!void {
        try self.saveConfigIfDirty();
        try self.saveStatusIfDirty();
    }

    pub fn primaryBindBlock(self: *const DesktopRuntime) formats.crimson_cfg.PlayerBindBlock {
        return formats.crimson_cfg.playerBindBlock(&self.config, 0);
    }

    pub fn recordModeStart(self: *DesktopRuntime, mode: game_ids.GameModeId) void {
        switch (mode) {
            .survival => self.status.mode_play_survival +%= 1,
            .rush => self.status.mode_play_rush +%= 1,
            .typo => self.status.mode_play_typo +%= 1,
            else => self.status.mode_play_other +%= 1,
        }
        self.status_dirty = true;
    }

    pub fn recordQuestStart(self: *DesktopRuntime, level_key: i32) void {
        const idx = quest_status.trackedQuestGamesCounterIndex(level_key) orelse return;
        self.status.quest_play_counts[idx] +%= 1;
        self.status_dirty = true;
    }

    pub fn recordQuestCompletion(self: *DesktopRuntime, level_key: i32) void {
        if (quest_status.trackedQuestCompletedCounterIndex(level_key)) |idx| {
            self.status.quest_play_counts[idx] +%= 1;
            self.status_dirty = true;
        }

        const global_index = quest_status.questLevelKeyGlobalIndex(level_key) orelse return;
        const next_unlock: u16 = @intCast(global_index + 1);
        if (next_unlock > self.status.quest_unlock_index) {
            self.status.quest_unlock_index = next_unlock;
            self.status_dirty = true;
        }
        if (self.config.hardcore_flag != 0) {
            if (next_unlock > self.status.quest_unlock_index_full) {
                self.status.quest_unlock_index_full = next_unlock;
                self.status_dirty = true;
            }
        }
    }

    pub fn recordGameplayFrame(self: *DesktopRuntime, frame_dt: f32) void {
        if (!(frame_dt > 0.0) or !std.math.isFinite(frame_dt)) return;
        const delta_ms_f32 = frame_dt * 1000.0;
        if (!(delta_ms_f32 > 0.0)) return;
        const delta_ms: u32 = @intFromFloat(delta_ms_f32);
        if (delta_ms == 0) return;
        self.status.play_time_ms +%= delta_ms;
        self.status_dirty = true;
    }

    pub fn absorbSessionState(self: *DesktopRuntime, session: *const runtime_session.DeterministicSession) void {
        const unlock_index: u16 = @intCast(std.math.clamp(session.state.status_quest_unlock_index, @as(i32, 0), @as(i32, std.math.maxInt(u16))));
        const unlock_index_full: u16 = @intCast(std.math.clamp(session.state.status_quest_unlock_index_full, @as(i32, 0), @as(i32, std.math.maxInt(u16))));

        if (self.status.quest_unlock_index != unlock_index) {
            self.status.quest_unlock_index = unlock_index;
            self.status_dirty = true;
        }
        if (self.status.quest_unlock_index_full != unlock_index_full) {
            self.status.quest_unlock_index_full = unlock_index_full;
            self.status_dirty = true;
        }

        for (0..formats.game_cfg.weapon_usage_count) |idx| {
            const weapon_id: game_ids.WeaponId = @enumFromInt(idx);
            const count = session.state.status_weapon_usage_counts.get(weapon_id);
            if (self.status.weapon_usage_counts[idx] != count) {
                self.status.weapon_usage_counts[idx] = count;
                self.status_dirty = true;
            }
        }
    }

    pub fn windowWidth(self: *const DesktopRuntime, fallback: i32) i32 {
        return sanitizedWindowDimension(self.config.screen_width, fallback);
    }

    pub fn windowHeight(self: *const DesktopRuntime, fallback: i32) i32 {
        return sanitizedWindowDimension(self.config.screen_height, fallback);
    }
};

fn loadOrCreateConfig(
    allocator: std.mem.Allocator,
    path: []const u8,
) DesktopRuntimeError!formats.crimson_cfg.CrimsonCfg {
    const io = std.Io.Threaded.global_single_threaded.io();
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => {
            const cfg = formats.crimson_cfg.defaultConfig();
            try writeConfig(path, cfg);
            return cfg;
        },
        else => return err,
    };
    defer allocator.free(bytes);

    return formats.crimson_cfg.decode(bytes);
}

fn writeConfig(path: []const u8, cfg: formats.crimson_cfg.CrimsonCfg) DesktopRuntimeError!void {
    const bytes = formats.crimson_cfg.encode(cfg);
    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes[0..],
    });
}

fn loadOrCreateStatus(
    allocator: std.mem.Allocator,
    path: []const u8,
) DesktopRuntimeError!formats.game_cfg.Status {
    const io = std.Io.Threaded.global_single_threaded.io();
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => {
            const status = std.mem.zeroes(formats.game_cfg.Status);
            try writeStatus(path, status);
            return status;
        },
        else => return err,
    };
    defer allocator.free(bytes);

    const parsed = try formats.game_cfg.parseFile(bytes);
    if (!parsed.checksumValid()) return error.InvalidGameCfgChecksum;
    return formats.game_cfg.parseStatusBlob(parsed.decoded[0..]);
}

fn writeStatus(path: []const u8, status: formats.game_cfg.Status) DesktopRuntimeError!void {
    const decoded = formats.game_cfg.buildStatusBlob(status);
    const bytes = try formats.game_cfg.buildFile(decoded[0..]);
    const io = std.Io.Threaded.global_single_threaded.io();
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes[0..],
    });
}

fn sanitizedWindowDimension(value: u32, fallback: i32) i32 {
    const clamped_default = @max(fallback, 1);
    if (value == 0) return clamped_default;
    return @intCast(@min(value, @as(u32, @intCast(std.math.maxInt(i32)))));
}

test "desktop runtime creates default config and status files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);

    const config_path = try std.fs.path.join(allocator, &.{ base_dir, crimson_cfg_name });
    defer allocator.free(config_path);
    const status_path = try std.fs.path.join(allocator, &.{ base_dir, game_cfg_name });
    defer allocator.free(status_path);

    const cfg = try loadOrCreateConfig(allocator, config_path);
    const status = try loadOrCreateStatus(allocator, status_path);

    try std.testing.expectEqual(@as(u32, 1024), cfg.screen_width);
    try std.testing.expectEqual(@as(u32, 768), cfg.screen_height);
    try std.testing.expectEqual(@as(u16, 0), status.quest_unlock_index);
    try std.testing.expectEqual(@as(u32, 0), status.play_time_ms);
}

test "desktop runtime records tracked quest counters" {
    var runtime: DesktopRuntime = .{
        .allocator = std.testing.allocator,
        .base_dir = &.{},
        .config_path = &.{},
        .status_path = &.{},
        .config = formats.crimson_cfg.defaultConfig(),
        .status = std.mem.zeroes(formats.game_cfg.Status),
    };

    runtime.recordQuestStart(101);
    runtime.recordQuestCompletion(101);
    runtime.recordQuestStart(510);
    runtime.recordQuestCompletion(510);

    try std.testing.expectEqual(@as(u32, 1), runtime.status.quest_play_counts[11]);
    try std.testing.expectEqual(@as(u32, 1), runtime.status.quest_play_counts[51]);
    try std.testing.expectEqual(@as(u32, 0), runtime.status.quest_play_counts[50]);
    try std.testing.expectEqual(@as(u32, 0), runtime.status.quest_play_counts[90]);
    try std.testing.expectEqual(@as(u16, 50), runtime.status.quest_unlock_index);
    try std.testing.expect(runtime.status_dirty);
}

test "desktop runtime advances hardcore quest unlock progress separately" {
    var runtime: DesktopRuntime = .{
        .allocator = std.testing.allocator,
        .base_dir = &.{},
        .config_path = &.{},
        .status_path = &.{},
        .config = formats.crimson_cfg.defaultConfig(),
        .status = std.mem.zeroes(formats.game_cfg.Status),
    };
    runtime.config.hardcore_flag = 1;
    runtime.status.quest_unlock_index = 7;

    runtime.recordQuestCompletion(501);

    try std.testing.expectEqual(@as(u16, 41), runtime.status.quest_unlock_index);
    try std.testing.expectEqual(@as(u16, 41), runtime.status.quest_unlock_index_full);
    try std.testing.expect(runtime.status_dirty);
}

test "desktop runtime status absorb mirrors session unlock and usage state" {
    var runtime: DesktopRuntime = .{
        .allocator = std.testing.allocator,
        .base_dir = &.{},
        .config_path = &.{},
        .status_path = &.{},
        .config = formats.crimson_cfg.defaultConfig(),
        .status = std.mem.zeroes(formats.game_cfg.Status),
    };

    var session = try runtime_session.DeterministicSession.init(.{
        .seed = 1,
        .game_mode = .survival,
        .player_count = 1,
        .world_size = 1024.0,
        .tick_rate = 60,
    }, .{});
    session.state.status_quest_unlock_index = 17;
    session.state.status_quest_unlock_index_full = 23;
    session.state.status_weapon_usage_counts.set(.shotgun, 9);

    runtime.absorbSessionState(&session);

    try std.testing.expectEqual(@as(u16, 17), runtime.status.quest_unlock_index);
    try std.testing.expectEqual(@as(u16, 23), runtime.status.quest_unlock_index_full);
    try std.testing.expectEqual(@as(u32, 9), runtime.status.weapon_usage_counts[@intFromEnum(game_ids.WeaponId.shotgun)]);
    try std.testing.expect(runtime.status_dirty);
}
