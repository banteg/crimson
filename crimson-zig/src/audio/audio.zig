const std = @import("std");
const rl = @import("raylib");

const formats = @import("crimson_zig").formats;
const runtime_paths = @import("crimson_zig").runtime_paths;
const music = @import("music.zig");
const sfx = @import("sfx.zig");
const sfx_map = @import("sfx_map.zig");

pub const AudioConfig = struct {
    music_enabled: bool = true,
    sfx_enabled: bool = true,
    music_volume: f32 = 1.0,
    sfx_volume: f32 = 1.0,
};

pub const AudioState = struct {
    ready: bool,
    music: music.MusicState,
    sfx: sfx.SfxState,

    pub fn deinit(self: *AudioState) void {
        defer self.* = undefined;
        if (self.ready) {
            self.sfx.deinit();
            self.music.deinit();
            rl.closeAudioDevice();
            return;
        }
        self.sfx.deinit();
        self.music.deinit();
    }

    pub fn assetsDir(self: *const AudioState) []const u8 {
        return self.music.assets_dir;
    }
};

pub const LoadRuntimeAudioError = std.mem.Allocator.Error ||
    std.Io.Dir.AccessError ||
    std.Io.Dir.ReadFileAllocError ||
    std.process.Environ.GetAllocError ||
    formats.crimson_cfg.CrimsonCfgError ||
    music.LoadMusicError ||
    sfx.LoadSfxError;

pub fn loadRuntimeAudioFromDefaultSearch(allocator: std.mem.Allocator) LoadRuntimeAudioError!?AudioState {
    const config = try loadAudioConfig(allocator);
    return loadRuntimeAudio(allocator, null, config);
}

pub fn loadRuntimeAudio(
    allocator: std.mem.Allocator,
    resolved_assets_dir: ?[]const u8,
    config: AudioConfig,
) LoadRuntimeAudioError!?AudioState {
    const owned_assets_dir = if (resolved_assets_dir) |dir|
        try allocator.dupe(u8, dir)
    else
        try resolveAudioAssetsDir(allocator);
    const assets_dir = owned_assets_dir orelse {
        if (!config.music_enabled and !config.sfx_enabled) {
            const disabled_state = try initAudioState(allocator, "", config);
            return disabled_state;
        }
        return null;
    };
    defer allocator.free(assets_dir);
    const state = try initAudioState(allocator, assets_dir, config);
    return state;
}

pub fn audioConfigFromCrimsonCfg(cfg: formats.crimson_cfg.CrimsonCfg) AudioConfig {
    return .{
        .music_enabled = cfg.music_disabled == 0,
        .sfx_enabled = cfg.sound_disabled == 0,
        .music_volume = clampVolume(cfg.music_volume),
        .sfx_volume = clampVolume(cfg.sfx_volume),
    };
}

pub fn playMusic(state: *AudioState, track_name: []const u8) void {
    state.music.playMusic(track_name);
}

pub fn stopMusic(state: *AudioState) void {
    state.music.stopMusic();
}

pub fn triggerGameTuneByRoll(state: *AudioState, roll: u32) ?[]const u8 {
    return state.music.triggerGameTuneByRoll(roll);
}

pub fn playSfx(state: *AudioState, sfx_id: sfx_map.SfxId, reflex_boost_timer: f32) void {
    state.sfx.play(sfx_id, reflex_boost_timer);
}

pub fn updateAudio(state: *AudioState, dt: f32) void {
    state.music.updateMusic(dt);
}

pub fn setMusicVolume(state: *AudioState, volume: f32) void {
    state.music.setVolume(volume);
}

pub fn setSfxVolume(state: *AudioState, volume: f32) void {
    state.sfx.setVolume(volume);
}

fn initAudioState(
    allocator: std.mem.Allocator,
    assets_dir: []const u8,
    config: AudioConfig,
) LoadRuntimeAudioError!AudioState {
    var music_state = try music.MusicState.init(allocator, false, false, config.music_volume, assets_dir);
    errdefer music_state.deinit();
    var sfx_state = sfx.SfxState.init(allocator, false, false, config.sfx_volume, sfx.default_voice_count);
    errdefer sfx_state.deinit();

    if (!config.music_enabled and !config.sfx_enabled) {
        return .{
            .ready = false,
            .music = music_state,
            .sfx = sfx_state,
        };
    }

    if (!rl.isAudioDeviceReady()) {
        rl.initAudioDevice();
    }
    const ready = rl.isAudioDeviceReady();
    if (!ready) {
        music_state.enabled = config.music_enabled;
        sfx_state.enabled = config.sfx_enabled;
        return .{
            .ready = false,
            .music = music_state,
            .sfx = sfx_state,
        };
    }

    music_state.ready = true;
    music_state.enabled = config.music_enabled;
    sfx_state.ready = true;
    sfx_state.enabled = config.sfx_enabled;

    if (config.sfx_enabled) {
        try sfx_state.loadIndex(assets_dir);
    }
    if (config.music_enabled) {
        try music_state.loadRuntimeTracks();
    }

    return .{
        .ready = true,
        .music = music_state,
        .sfx = sfx_state,
    };
}

fn resolveAudioAssetsDir(allocator: std.mem.Allocator) LoadRuntimeAudioError!?[]u8 {
    if (runtime_paths.envVarOwned(allocator, "CRIMSON_ASSETS_DIR")) |dir| {
        if (try dirHasAudioArchives(allocator, dir)) return dir;
        allocator.free(dir);
    } else |err| switch (err) {
        error.EnvironmentVariableMissing => {},
        else => return err,
    }

    const runtime_dir = try runtime_paths.defaultRuntimeDir(allocator);
    if (runtime_dir) |dir| {
        if (try dirHasAudioArchives(allocator, dir)) return dir;
        allocator.free(dir);
    }

    const candidates = [_][]const u8{
        "artifacts/assets",
        ".",
    };
    for (candidates) |candidate| {
        if (try dirHasAudioArchives(allocator, candidate)) {
            const owned = try allocator.dupe(u8, candidate);
            return owned;
        }
    }

    return null;
}

fn dirHasAudioArchives(allocator: std.mem.Allocator, dir: []const u8) LoadRuntimeAudioError!bool {
    return try runtime_paths.archiveExistsAtDir(allocator, dir, music.music_paq_name) and
        try runtime_paths.archiveExistsAtDir(allocator, dir, sfx.sfx_paq_name);
}

fn loadAudioConfig(allocator: std.mem.Allocator) LoadRuntimeAudioError!AudioConfig {
    const runtime_dir = try runtime_paths.defaultRuntimeDir(allocator);
    if (runtime_dir == null) return .{};
    defer allocator.free(runtime_dir.?);

    const cfg_path = try std.fs.path.join(allocator, &.{ runtime_dir.?, "crimson.cfg" });
    defer allocator.free(cfg_path);

    const bytes = runtimeArchiveReadConfig(allocator, cfg_path) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer allocator.free(bytes);

    const parsed = try formats.crimson_cfg.decode(bytes);
    return audioConfigFromCrimsonCfg(parsed);
}

fn runtimeArchiveReadConfig(
    allocator: std.mem.Allocator,
    path: []const u8,
) std.Io.Dir.ReadFileAllocError![]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited);
}

fn clampVolume(volume: f32) f32 {
    if (!std.math.isFinite(volume)) return 1.0;
    return std.math.clamp(volume, @as(f32, 0.0), @as(f32, 1.0));
}
