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

    pub fn ensureIntroMusic(self: *Bridge) void {
        self.playMusic("intro");
    }

    pub fn ensureMenuTheme(self: *Bridge) void {
        self.playMusic("crimson_theme");
    }

    pub fn ensureMenuThemeForDemo(self: *Bridge, demo_enabled: bool) void {
        self.playMusic(if (demo_enabled) "crimsonquest" else "crimson_theme");
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

        for (frame_audio.shot_events[0..frame_audio.shot_event_count]) |shot| {
            const weapon_id = weaponIdFromInt(shot.weapon_id) orelse continue;
            if (shot.fire_bullets_active) {
                audio_mod.playSfx(state, .autorifle_fire, reflex_boost_timer);
                audio_mod.playSfx(state, .plasmaminigun_fire, reflex_boost_timer);
                continue;
            }
            const sfx_id = weaponFireSfx(weapon_id) orelse continue;
            audio_mod.playSfx(state, sfx_id, reflex_boost_timer);
        }

        for (frame_audio.reload_weapon_ids[0..frame_audio.reload_event_count]) |weapon_raw| {
            const weapon_id = weaponIdFromInt(weapon_raw) orelse continue;
            const sfx_id = weaponReloadSfx(weapon_id) orelse continue;
            audio_mod.playSfx(state, sfx_id, reflex_boost_timer);
        }

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

        if (frame_audio.perk_menu_opened) {
            audio_mod.playSfx(state, .ui_levelup, reflex_boost_timer);
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

fn weaponIdFromInt(value: i32) ?game_ids.WeaponId {
    if (value < 0 or value >= weapon_data.weapon_count_size) return null;
    return @enumFromInt(value);
}

fn weaponFireSfx(weapon_id: game_ids.WeaponId) ?sfx_map.SfxId {
    return switch (weapon_id) {
        .none => null,
        .pistol => .pistol_fire,
        .assault_rifle => .autorifle_fire,
        .shotgun => .shotgun_fire,
        .sawed_off_shotgun => .shotgun_fire,
        .submachine_gun => .hrpm_fire,
        .gauss_gun => .gauss_fire,
        .mean_minigun => .autorifle_fire,
        .flamethrower => .flamer_fire_01,
        .plasma_rifle => .shock_fire,
        .multi_plasma => .shock_fire,
        .plasma_minigun => .plasmaminigun_fire,
        .rocket_launcher => .rocket_fire,
        .seeker_rockets => .rocket_fire,
        .plasma_shotgun => .plasmashotgun_fire,
        .blow_torch => .flamer_fire_01,
        .hr_flamer => .flamer_fire_01,
        .mini_rocket_swarmers => .rocket_fire,
        .rocket_minigun => .rocketmini_fire,
        .pulse_gun => .pulse_fire,
        .jackhammer => .shotgun_fire,
        .ion_rifle => .shock_fire_alt,
        .ion_minigun => .shockminigun_fire,
        .ion_cannon => .shock_fire_alt,
        .shrinkifier_5k => .shock_fire_alt,
        .blade_gun => .shock_fire_alt,
        .spider_plasma => .bloodspill_01,
        .evil_scythe => .shock_fire_alt,
        .plasma_cannon => .shock_fire,
        .splitter_gun => .shock_fire_alt,
        .gauss_shotgun => .gauss_fire,
        .ion_shotgun => .shock_fire_alt,
        .flameburst => .flamer_fire_01,
        .raygun => .shock_fire_alt,
        .unused_34,
        .unused_35,
        .unused_36,
        .unused_37,
        .unused_38,
        .unused_39,
        .unused_40,
        .unused_46,
        .unused_47,
        .unused_48,
        .unused_49,
        => null,
        .plague_spreader_gun => .bloodspill_01,
        .bubblegun => .bloodspill_01,
        .rainbow_gun => .bloodspill_01,
        .grim_weapon => .bloodspill_01,
        .fire_bullets => .autorifle_fire,
        .transmutator => .bloodspill_01,
        .blaster_r_300 => .shock_fire,
        .lightning_rifle => .explosion_large,
        .nuke_launcher => .explosion_large,
    };
}

fn weaponReloadSfx(weapon_id: game_ids.WeaponId) ?sfx_map.SfxId {
    return switch (weapon_id) {
        .none => null,
        .pistol => .pistol_reload,
        .assault_rifle => .autorifle_reload,
        .shotgun => .shotgun_reload,
        .sawed_off_shotgun => .shotgun_reload,
        .submachine_gun => .autorifle_reload,
        .gauss_gun => .shotgun_reload,
        .mean_minigun => .autorifle_reload,
        .flamethrower => .autorifle_reload,
        .plasma_rifle => .autorifle_reload,
        .multi_plasma => .autorifle_reload,
        .plasma_minigun => .autorifle_reload,
        .rocket_launcher => .autorifle_reload_alt,
        .seeker_rockets => .autorifle_reload_alt,
        .plasma_shotgun => .shotgun_reload,
        .blow_torch => .autorifle_reload,
        .hr_flamer => .autorifle_reload,
        .mini_rocket_swarmers => .autorifle_reload_alt,
        .rocket_minigun => .autorifle_reload_alt,
        .pulse_gun => .autorifle_reload,
        .jackhammer => .shotgun_reload,
        .ion_rifle => .shock_reload,
        .ion_minigun => .shock_reload,
        .ion_cannon => .shock_reload,
        .shrinkifier_5k => .shock_reload,
        .blade_gun => .shock_reload,
        .spider_plasma => .shotgun_reload,
        .evil_scythe => .shotgun_reload,
        .plasma_cannon => .shock_reload,
        .splitter_gun => .shock_reload,
        .gauss_shotgun => .shotgun_reload,
        .ion_shotgun => .shock_reload,
        .flameburst => .shock_reload,
        .raygun => .shock_reload,
        .unused_34,
        .unused_35,
        .unused_36,
        .unused_37,
        .unused_38,
        .unused_39,
        .unused_40,
        .unused_46,
        .unused_47,
        .unused_48,
        .unused_49,
        => null,
        .plague_spreader_gun => .shotgun_reload,
        .bubblegun => .shotgun_reload,
        .rainbow_gun => .shotgun_reload,
        .grim_weapon => .shotgun_reload,
        .fire_bullets => .pistol_reload,
        .transmutator => .shotgun_reload,
        .blaster_r_300 => .shotgun_reload,
        .lightning_rifle => .shotgun_reload,
        .nuke_launcher => .shotgun_reload,
    };
}
