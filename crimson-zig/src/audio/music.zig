const std = @import("std");
const rl = @import("raylib");

const runtime_archive = @import("../runtime_archive.zig");

pub const music_paq_name = "music.paq";
const music_max_dt: f32 = 0.1;
const music_fade_in_per_sec: f32 = 1.0;
const music_fade_out_per_sec: f32 = 0.5;

pub const LoadMusicError = runtime_archive.OpenArchiveError || std.mem.Allocator.Error || std.fs.Dir.AccessError || rl.RaylibError;

pub const TrackPlayback = struct {
    volume: f32 = 0.0,
    muted: bool = true,
};

pub const LoadedTrack = struct {
    name: []u8,
    music: rl.Music,
    track_id: i32,
    playback: TrackPlayback = .{},

    fn deinit(self: *LoadedTrack, allocator: std.mem.Allocator) void {
        rl.stopMusicStream(self.music);
        rl.unloadMusicStream(self.music);
        allocator.free(self.name);
        self.* = undefined;
    }
};

pub const LoadTrackResult = struct {
    track_key: []const u8,
    track_id: i32,
};

pub const MusicState = struct {
    allocator: std.mem.Allocator,
    ready: bool,
    enabled: bool,
    volume: f32,
    assets_dir: []u8,
    tracks: std.ArrayList(LoadedTrack) = .empty,
    queue: std.ArrayList(usize) = .empty,
    active_track_index: ?usize = null,
    game_tune_started: bool = false,
    game_tune_track_index: ?usize = null,
    next_track_id: i32 = 0,
    archive: ?runtime_archive.Archive = null,

    pub fn init(
        allocator: std.mem.Allocator,
        ready: bool,
        enabled: bool,
        volume: f32,
        assets_dir: []const u8,
    ) !MusicState {
        return .{
            .allocator = allocator,
            .ready = ready,
            .enabled = enabled,
            .volume = clampVolume(volume),
            .assets_dir = try allocator.dupe(u8, assets_dir),
        };
    }

    pub fn deinit(self: *MusicState) void {
        for (self.tracks.items) |*track| {
            track.deinit(self.allocator);
        }
        self.tracks.deinit(self.allocator);
        self.queue.deinit(self.allocator);
        if (self.archive) |*archive| {
            archive.deinit();
        }
        self.allocator.free(self.assets_dir);
        self.* = undefined;
    }

    pub fn trackCount(self: *const MusicState) usize {
        return self.tracks.items.len;
    }

    pub fn queueCount(self: *const MusicState) usize {
        return self.queue.items.len;
    }

    pub fn activeTrackName(self: *const MusicState) ?[]const u8 {
        const idx = self.active_track_index orelse return null;
        return self.tracks.items[idx].name;
    }

    pub fn loadRuntimeTracks(self: *MusicState) LoadMusicError!void {
        if (!self.ready or !self.enabled) return;

        for (core_tracks) |track| {
            _ = try self.loadTrack(track.rel_path);
        }
        try self.loadGameTunesScript();
    }

    pub fn loadTrack(self: *MusicState, rel_path: []const u8) LoadMusicError!?LoadTrackResult {
        if (!self.ready or !self.enabled) return null;

        const track_key = try normalizeTrackKeyOwned(self.allocator, rel_path);
        errdefer self.allocator.free(track_key);

        if (self.findTrackIndex(track_key)) |idx| {
            self.allocator.free(track_key);
            const track = self.tracks.items[idx];
            return .{ .track_key = track.name, .track_id = track.track_id };
        }

        const music_stream = (try self.loadMusicStreamForPath(rel_path)) orelse {
            self.allocator.free(track_key);
            return null;
        };
        errdefer rl.unloadMusicStream(music_stream);

        rl.setMusicVolume(music_stream, self.volume);
        const loaded: LoadedTrack = .{
            .name = track_key,
            .music = music_stream,
            .track_id = self.next_track_id,
        };
        try self.tracks.append(self.allocator, loaded);
        self.next_track_id += 1;
        return .{ .track_key = loaded.name, .track_id = loaded.track_id };
    }

    pub fn queueTrack(self: *MusicState, track_key: []const u8) !void {
        if (!self.ready or !self.enabled) return;
        const idx = self.findTrackIndex(track_key) orelse return;
        try self.queue.append(self.allocator, idx);
    }

    pub fn playMusic(self: *MusicState, track_name: []const u8) void {
        if (!self.ready or !self.enabled) return;
        const target_idx = self.findTrackIndex(track_name) orelse return;

        for (self.tracks.items, 0..) |*track, idx| {
            if (idx != target_idx and !track.playback.muted) {
                track.playback.muted = true;
            }
        }

        var track = &self.tracks.items[target_idx];
        if (track.playback.volume <= 0.0) {
            track.playback.muted = false;
            track.playback.volume = self.volume;
            rl.setMusicVolume(track.music, track.playback.volume);
            rl.playMusicStream(track.music);
        }

        self.active_track_index = target_idx;
    }

    pub fn stopMusic(self: *MusicState) void {
        if (!self.ready or !self.enabled) return;
        for (self.tracks.items) |*track| {
            track.playback.muted = true;
        }
        self.active_track_index = null;
        self.game_tune_started = false;
        self.game_tune_track_index = null;
    }

    pub fn triggerGameTuneByRoll(self: *MusicState, roll: u32) ?[]const u8 {
        if (!self.ready or !self.enabled) return null;
        if (self.game_tune_started or self.queue.items.len == 0) return null;

        const queue_idx = self.queue.items[roll % self.queue.items.len];
        if (queue_idx >= self.tracks.items.len) return null;
        self.playMusic(self.tracks.items[queue_idx].name);
        self.game_tune_started = true;
        self.game_tune_track_index = queue_idx;
        return self.tracks.items[queue_idx].name;
    }

    pub fn updateMusic(self: *MusicState, dt: f32) void {
        if (!self.ready or !self.enabled) return;
        if (!(dt > 0.0)) return;

        const frame_dt = @min(dt, music_max_dt);
        if (self.volume <= 0.0) {
            for (self.tracks.items) |*track| {
                track.playback.volume = 0.0;
                track.playback.muted = true;
                rl.setMusicVolume(track.music, 0.0);
                rl.stopMusicStream(track.music);
            }
            return;
        }

        for (self.tracks.items) |*track| {
            if (rl.isMusicStreamPlaying(track.music)) {
                rl.updateMusicStream(track.music);
            }

            if (track.playback.muted) {
                track.playback.volume = @max(0.0, track.playback.volume - frame_dt * music_fade_out_per_sec);
                rl.setMusicVolume(track.music, track.playback.volume);
                if (track.playback.volume <= 0.0) {
                    rl.stopMusicStream(track.music);
                }
                continue;
            }

            track.playback.volume = @min(self.volume, track.playback.volume + frame_dt * music_fade_in_per_sec);
            rl.setMusicVolume(track.music, track.playback.volume);
            if (!rl.isMusicStreamPlaying(track.music)) {
                rl.playMusicStream(track.music);
            }
        }
    }

    pub fn setVolume(self: *MusicState, volume: f32) void {
        self.volume = clampVolume(volume);
    }

    fn loadGameTunesScript(self: *MusicState) LoadMusicError!void {
        try self.ensureArchiveLoaded();
        const archive = &(self.archive orelse return);
        const script = archive.get("music/game_tunes.txt") orelse return;

        var lines = std.mem.splitScalar(u8, script, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \t\r");
            if (line.len == 0 or std.mem.startsWith(u8, line, "//")) continue;
            const prefix = "snd_addGameTune ";
            if (!std.mem.startsWith(u8, line, prefix)) continue;

            const file_name = std.mem.trim(u8, line[prefix.len..], " \t\r");
            if (file_name.len == 0) continue;
            const rel_path = try std.fmt.allocPrint(self.allocator, "music/{s}", .{file_name});
            defer self.allocator.free(rel_path);

            const loaded = (try self.loadTrack(rel_path)) orelse continue;
            try self.queueTrack(loaded.track_key);
        }
    }

    fn loadMusicStreamForPath(self: *MusicState, rel_path: []const u8) LoadMusicError!?rl.Music {
        const normalized = try normalizeArchivePathOwned(self.allocator, rel_path);
        defer self.allocator.free(normalized);

        const full_path = try std.fs.path.join(self.allocator, &.{ self.assets_dir, normalized });
        defer self.allocator.free(full_path);

        if (std.fs.cwd().access(full_path, .{})) {
            const path_z = try self.allocator.dupeZ(u8, full_path);
            defer self.allocator.free(path_z);
            const stream = try rl.loadMusicStream(path_z);
            return stream;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }

        try self.ensureArchiveLoaded();
        const archive = &(self.archive orelse return null);
        const payload = archive.get(normalized) orelse archive.get(std.fs.path.basename(normalized)) orelse return null;
        const stream = try rl.loadMusicStreamFromMemory(".ogg", payload);
        return stream;
    }

    fn ensureArchiveLoaded(self: *MusicState) LoadMusicError!void {
        if (self.archive != null) return;
        const paq_path = try std.fs.path.join(self.allocator, &.{ self.assets_dir, music_paq_name });
        defer self.allocator.free(paq_path);
        self.archive = try runtime_archive.Archive.fromPath(self.allocator, paq_path);
    }

    fn findTrackIndex(self: *const MusicState, track_name: []const u8) ?usize {
        for (self.tracks.items, 0..) |track, idx| {
            if (std.mem.eql(u8, track.name, track_name)) return idx;
        }
        return null;
    }
};

const core_tracks = [_]struct {
    rel_path: []const u8,
}{
    .{ .rel_path = "music/intro.ogg" },
    .{ .rel_path = "music/shortie_monk.ogg" },
    .{ .rel_path = "music/crimson_theme.ogg" },
    .{ .rel_path = "music/crimsonquest.ogg" },
    .{ .rel_path = "music/gt1_ingame.ogg" },
    .{ .rel_path = "music/gt2_harppen.ogg" },
};

fn clampVolume(volume: f32) f32 {
    return std.math.clamp(volume, @as(f32, 0.0), @as(f32, 1.0));
}

fn normalizeTrackKeyOwned(allocator: std.mem.Allocator, rel_path: []const u8) ![]u8 {
    const normalized = try normalizeArchivePathOwned(allocator, rel_path);
    defer allocator.free(normalized);

    const base = std.fs.path.basename(normalized);
    const stem = if (std.ascii.endsWithIgnoreCase(base, ".ogg")) base[0 .. base.len - 4] else base;
    return allocator.dupe(u8, stem);
}

fn normalizeArchivePathOwned(allocator: std.mem.Allocator, rel_path: []const u8) ![]u8 {
    const normalized = try allocator.dupe(u8, rel_path);
    for (normalized) |*ch| {
        if (ch.* == '\\') ch.* = '/';
    }
    return normalized;
}

test "track key normalization strips suffix from basename" {
    const allocator = std.testing.allocator;
    const key = try normalizeTrackKeyOwned(allocator, "music\\gt1_ingame.ogg");
    defer allocator.free(key);
    try std.testing.expectEqualStrings("gt1_ingame", key);
}
