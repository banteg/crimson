const std = @import("std");

const cz = @import("crimson_zig");
const audio_mod = @import("audio.zig");
const sfx_map = @import("sfx_map.zig");

const game_ids = cz.game_ids;
const live_runner = cz.live_runner;
const weapon_data = cz.weapon_data;

pub const LoadState = enum {
    loaded,
    unavailable,
    disabled,
    failed,
};

pub const Bridge = struct {
    allocator: std.mem.Allocator,
    state: ?audio_mod.AudioState = null,
    load_state: LoadState = .unavailable,
    message: ?[]u8 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        config: audio_mod.AudioConfig,
        assets_dir: ?[]const u8,
    ) Bridge {
        var bridge: Bridge = .{ .allocator = allocator };
        bridge.load(config, assets_dir);
        return bridge;
    }

    pub fn deinit(self: *Bridge) void {
        if (self.state) |*state| {
            state.deinit();
            self.state = null;
        }
        if (self.message) |message| {
            self.allocator.free(message);
            self.message = null;
        }
        self.* = undefined;
    }

    pub fn load(self: *Bridge, config: audio_mod.AudioConfig, assets_dir: ?[]const u8) void {
        self.state = audio_mod.loadRuntimeAudio(self.allocator, assets_dir, config) catch |err| {
            self.load_state = .failed;
            self.replaceMessage(@errorName(err));
            return;
        };
        if (self.state == null) {
            self.load_state = .unavailable;
            return;
        }

        const state = &(self.state orelse unreachable);
        if (!state.ready and !state.music.enabled and !state.sfx.enabled) {
            self.load_state = .disabled;
            return;
        }
        if (!state.ready) {
            self.load_state = .failed;
            self.replaceMessage("AudioDeviceInit");
            return;
        }
        self.load_state = .loaded;
    }

    pub fn update(self: *Bridge, dt: f32) void {
        if (self.state) |*state| {
            audio_mod.updateAudio(state, dt);
        }
    }

    pub fn focusChanged(self: *Bridge, focused: bool) void {
        const state = if (self.state) |*state| state else return;
        if (focused) audio_mod.resumeAudio(state) else audio_mod.suspendAudio(state);
    }

    pub fn ensureIntroMusic(self: *Bridge) void {
        self.playMusic("intro");
    }

    pub fn ensureMenuTheme(self: *Bridge) void {
        self.playMusic("crimson_theme");
    }

    pub fn ensureStatisticsTheme(self: *Bridge) void {
        self.playMusic("shortie_monk");
    }

    pub fn stopGameplayMusic(self: *Bridge) void {
        if (self.state) |*state| {
            audio_mod.stopMusic(state);
        }
    }

    pub fn playUiButtonClick(self: *Bridge) void {
        self.playSfx(.ui_buttonclick, 0.0);
    }

    pub fn playUiPanelClick(self: *Bridge) void {
        self.playSfx(.ui_panelclick, 0.0);
    }

    pub fn playUiLevelUp(self: *Bridge) void {
        self.playSfx(.ui_levelup, 0.0);
    }

    pub fn playUiTypeEnter(self: *Bridge) void {
        self.playSfx(.ui_typeenter, 0.0);
    }

    pub fn playUiTypeClick(self: *Bridge, sfx_id: sfx_map.SfxId) void {
        std.debug.assert(sfx_id == .ui_typeclick_01 or sfx_id == .ui_typeclick_02);
        self.playSfx(sfx_id, 0.0);
    }

    pub fn playUiClink(self: *Bridge) void {
        self.playSfx(.ui_clink_01, 0.0);
    }

    pub fn playShockHit(self: *Bridge) void {
        self.playSfx(.shock_hit_01, 0.0);
    }

    pub fn handleFrameAudio(self: *Bridge, frame_audio: live_runner.FrameAudioEvents, reflex_boost_timer: f32) void {
        const state = &(self.state orelse return);
        if (!state.ready) return;

        for (frame_audio.hit_events[0..frame_audio.hit_event_count]) |event| {
            if (event.trigger_game_tune) {
                if (event.game_tune_roll) |roll| {
                    _ = audio_mod.triggerGameTuneByRoll(state, roll);
                }
                continue;
            }
            if (event.shock_hit) {
                audio_mod.playSfx(state, .shock_hit_01, reflex_boost_timer);
                continue;
            }
            if (event.bullet_hit_roll) |roll| {
                const sfx_id = sfx_map.bullet_hit_ids[roll % sfx_map.bullet_hit_ids.len];
                audio_mod.playSfx(state, sfx_id, reflex_boost_timer);
            }
        }

        for (frame_audio.sfx_events[0..frame_audio.sfx_event_count]) |sfx_id| {
            audio_mod.playSfx(state, sfx_id, reflex_boost_timer);
        }

        if (frame_audio.quest_play_hit_sfx) {
            audio_mod.playSfx(state, .questhit, reflex_boost_timer);
        }
        if (frame_audio.quest_play_completion_music) {
            audio_mod.playMusic(state, "crimsonquest");
        }
    }

    pub fn assetsDir(self: *const Bridge) ?[]const u8 {
        const state = self.state orelse return null;
        return state.assetsDir();
    }

    pub fn musicTrackCount(self: *const Bridge) usize {
        const state = self.state orelse return 0;
        return state.music.trackCount();
    }

    pub fn queuedGameTuneCount(self: *const Bridge) usize {
        const state = self.state orelse return 0;
        return state.music.queueCount();
    }

    pub fn sfxSampleCount(self: *const Bridge) usize {
        const state = self.state orelse return 0;
        return state.sfx.uniqueSampleCount();
    }

    fn playMusic(self: *Bridge, track_name: []const u8) void {
        if (self.state) |*state| {
            audio_mod.playMusic(state, track_name);
        }
    }

    fn playSfx(self: *Bridge, sfx_id: sfx_map.SfxId, reflex_boost_timer: f32) void {
        if (self.state) |*state| {
            audio_mod.playSfx(state, sfx_id, reflex_boost_timer);
        }
    }

    fn replaceMessage(self: *Bridge, message: []const u8) void {
        if (self.message) |existing| {
            self.allocator.free(existing);
        }
        self.message = self.allocator.dupe(u8, message) catch null;
    }
};

