const std = @import("std");
const rl = @import("raylib");

const native_math = @import("crimson_zig").native_math;
const runtime_archive = @import("../runtime_archive.zig");
const sfx_map = @import("sfx_map.zig");

pub const sfx_paq_name = "sfx.paq";
pub const default_voice_count: usize = 4;
const sfx_rate_base_hz = 44100;
const sfx_rate_min_hz = 22050;

pub const LoadSfxError = runtime_archive.OpenArchiveError || std.mem.Allocator.Error || rl.RaylibError || error{
    LoadSound,
    MissingSfxEntry,
    UnsupportedSfxFormat,
};

pub const SfxSample = struct {
    entry_name: []u8,
    source: rl.Sound,
    aliases: []rl.Sound,
    next_voice: usize = 0,

    fn deinit(self: *SfxSample, allocator: std.mem.Allocator) void {
        for (self.aliases) |alias| {
            rl.stopSound(alias);
            rl.unloadSoundAlias(alias);
        }
        rl.stopSound(self.source);
        rl.unloadSound(self.source);
        allocator.free(self.aliases);
        allocator.free(self.entry_name);
        self.* = undefined;
    }

    fn setVolume(self: *SfxSample, volume: f32) void {
        rl.setSoundVolume(self.source, volume);
        for (self.aliases) |alias| {
            rl.setSoundVolume(alias, volume);
        }
    }

    fn acquireVoice(self: *SfxSample) rl.Sound {
        if (!rl.isSoundPlaying(self.source)) return self.source;
        for (self.aliases) |alias| {
            if (!rl.isSoundPlaying(alias)) return alias;
        }
        if (self.aliases.len == 0) return self.source;
        const voice = self.aliases[self.next_voice % self.aliases.len];
        self.next_voice += 1;
        return voice;
    }
};

pub const SfxState = struct {
    allocator: std.mem.Allocator,
    ready: bool,
    enabled: bool,
    volume: f32,
    voice_count: usize,
    rate_scale_hz: i32 = sfx_rate_base_hz,
    sample_indices: [sfx_map.sfx_id_count]i16 = [_]i16{-1} ** sfx_map.sfx_id_count,
    samples: std.ArrayList(SfxSample) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        ready: bool,
        enabled: bool,
        volume: f32,
        voice_count: usize,
    ) SfxState {
        return .{
            .allocator = allocator,
            .ready = ready,
            .enabled = enabled,
            .volume = clampVolume(volume),
            .voice_count = @max(@as(usize, 1), voice_count),
        };
    }

    pub fn deinit(self: *SfxState) void {
        for (self.samples.items) |*sample| {
            sample.deinit(self.allocator);
        }
        self.samples.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn uniqueSampleCount(self: *const SfxState) usize {
        return self.samples.items.len;
    }

    pub fn loadIndex(self: *SfxState, assets_dir: []const u8) LoadSfxError!void {
        if (!self.ready or !self.enabled) return;

        const paq_path = try std.fs.path.join(self.allocator, &.{ assets_dir, sfx_paq_name });
        defer self.allocator.free(paq_path);

        var archive = try runtime_archive.Archive.fromPath(self.allocator, paq_path);
        defer archive.deinit();

        for (sfx_map.native_order) |sfx_id| {
            const entry_name = sfx_map.spec(sfx_id).entry_name;
            const payload = archive.get(entry_name) orelse return error.MissingSfxEntry;
            const sample_index = self.findOrLoadSample(entry_name, payload) catch |err| {
                return err;
            };
            self.sample_indices[@intFromEnum(sfx_id)] = @intCast(sample_index);
        }
    }

    pub fn play(self: *SfxState, sfx_id: sfx_map.SfxId, reflex_boost_timer: f32) void {
        if (!self.ready or !self.enabled) return;
        const sample = self.sampleForId(sfx_id) orelse return;

        self.rate_scale_hz = nextRateScaleHz(self.rate_scale_hz, reflex_boost_timer);
        const voice = sample.acquireVoice();
        rl.setSoundPitch(voice, pitchScaleFromRateHz(self.rate_scale_hz));
        rl.playSound(voice);
    }

    pub fn playNativeId(self: *SfxState, sfx_id: i32) void {
        const resolved = sfx_map.sfxIdForNativeId(sfx_id) orelse return;
        self.play(resolved, 0.0);
    }

    pub fn setVolume(self: *SfxState, volume: f32) void {
        self.volume = clampVolume(volume);
        for (self.samples.items) |*sample| {
            sample.setVolume(self.volume);
        }
    }

    fn sampleForId(self: *SfxState, sfx_id: sfx_map.SfxId) ?*SfxSample {
        const sample_index = self.sample_indices[@intFromEnum(sfx_id)];
        if (sample_index < 0) return null;
        return &self.samples.items[@intCast(sample_index)];
    }

    fn findOrLoadSample(self: *SfxState, entry_name: []const u8, payload: []const u8) LoadSfxError!usize {
        for (self.samples.items, 0..) |sample, idx| {
            if (std.mem.eql(u8, sample.entry_name, entry_name)) return idx;
        }

        const wave = try rl.loadWaveFromMemory(try fileTypeForEntryName(entry_name), payload);
        defer rl.unloadWave(wave);

        const source = rl.loadSoundFromWave(wave);
        if (!rl.isSoundValid(source)) return error.LoadSound;

        const alias_count = self.voice_count - 1;
        const aliases = try self.allocator.alloc(rl.Sound, alias_count);
        errdefer self.allocator.free(aliases);

        for (aliases, 0..) |*alias, idx| {
            _ = idx;
            alias.* = rl.loadSoundAlias(source);
        }

        var sample: SfxSample = .{
            .entry_name = try self.allocator.dupe(u8, entry_name),
            .source = source,
            .aliases = aliases,
        };
        sample.setVolume(self.volume);
        try self.samples.append(self.allocator, sample);
        return self.samples.items.len - 1;
    }
};

fn fileTypeForEntryName(entry_name: []const u8) LoadSfxError![:0]const u8 {
    if (std.ascii.endsWithIgnoreCase(entry_name, ".ogg")) return ".ogg";
    if (std.ascii.endsWithIgnoreCase(entry_name, ".wav")) return ".wav";
    return error.UnsupportedSfxFormat;
}

fn clampVolume(volume: f32) f32 {
    return std.math.clamp(volume, @as(f32, 0.0), @as(f32, 1.0));
}

fn nextRateScaleHz(current_rate_scale_hz: i32, reflex_boost_timer: f32) i32 {
    const reflex_f32 = native_math.roundF32(reflex_boost_timer);
    if (reflex_f32 <= 0.0) return sfx_rate_base_hz;
    if (reflex_f32 <= 1.0) {
        if (reflex_f32 < 1.0) {
            const rate_expr = native_math.roundF32((native_math.roundF32(1.0) - reflex_f32 + native_math.roundF32(1.0)) * native_math.roundF32(@as(f32, sfx_rate_min_hz)));
            return @intFromFloat(std.math.round(rate_expr));
        }
        return current_rate_scale_hz;
    }
    return sfx_rate_min_hz;
}

fn pitchScaleFromRateHz(rate_scale_hz: i32) f32 {
    return native_math.roundF32(@as(f32, @floatFromInt(rate_scale_hz)) / @as(f32, sfx_rate_base_hz));
}

test "reflex boost pitch scaling mirrors python helper behavior" {
    try std.testing.expectEqual(@as(i32, 44100), nextRateScaleHz(44100, 0.0));
    try std.testing.expectEqual(@as(i32, 22050), nextRateScaleHz(44100, 1.2));
    try std.testing.expectEqual(@as(i32, 32000), nextRateScaleHz(32000, 1.0));
    try std.testing.expectEqual(@as(f32, 1.0), pitchScaleFromRateHz(44100));
}
