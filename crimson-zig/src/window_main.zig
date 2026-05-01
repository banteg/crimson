const std = @import("std");
const builtin = @import("builtin");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const persistence = cz.persistence;
const runtime_anim = cz.anim;
const weapon_data = cz.weapon_data;
const app_runtime = @import("app_runtime.zig");
const audio_mod = @import("audio/audio.zig");
const demo_trial = cz.demo_trial;
const input_codes = @import("input_codes.zig");
const local_input = cz.local_input;
const live_audio = @import("audio/live_audio.zig");
const quest_results = @import("quest_results.zig");
const runtime_paths = cz.runtime_paths;
const window_assets = @import("window_assets.zig");
const window_atlas = cz.window_atlas;
const window_boot = @import("window_boot.zig");
const window_cursor = @import("window_cursor.zig");
const window_demo_trial = @import("window_demo_trial.zig");
const window_effects = @import("window_effects.zig");
const window_ground = @import("window_ground.zig");
const window_menu = @import("window_menu.zig");
const window_menu_panels = @import("window_menu_panels.zig");
const window_misc_panels = @import("window_misc_panels.zig");
const window_options = @import("window_options.zig");
const window_pause_menu = @import("window_pause_menu.zig");
const window_perk_menu = @import("window_perk_menu.zig");
const window_projectiles = @import("window_projectiles.zig");
const window_statistics = @import("window_statistics.zig");
const window_terrain_fx = @import("window_terrain_fx.zig");
const window_ui = @import("window_ui.zig");
const window_viewport = @import("window_viewport.zig");

const bonuses_runtime = cz.bonuses;
const game_ids = cz.game_ids;
const live_runner = cz.live_runner;
const runtime_perks = cz.perks;
const runtime_session = cz.session;
const state_mod = cz.state;
const terrain_fx_mod = cz.terrain_fx;
const tutorial_runtime = cz.tutorial_runtime;
const typo_names = cz.typo_names;

const window_width = 1024;
const window_height = 768;
const ui_button_width: f32 = 280.0;
const ui_button_height: f32 = 56.0;

const bg_color = rl.Color.init(16, 12, 10, 255);
const panel_color = rl.Color.init(37, 24, 20, 255);
const panel_outline = rl.Color.init(122, 78, 58, 255);
const accent_color = rl.Color.init(218, 80, 46, 255);
const accent_dim = rl.Color.init(127, 45, 29, 255);
const text_color = rl.Color.init(245, 236, 225, 255);
const muted_text = rl.Color.init(171, 150, 132, 255);
const player_color = rl.Color.init(255, 208, 84, 255);
const dead_player_color = rl.Color.init(90, 76, 72, 255);
const creature_color = rl.Color.init(219, 62, 62, 255);
const corpse_color = rl.Color.init(108, 45, 45, 255);
const projectile_color = rl.Color.init(255, 242, 115, 255);
const secondary_projectile_color = rl.Color.init(255, 146, 58, 255);
const bonus_color = rl.Color.init(88, 183, 113, 255);
const overlay_color = rl.Color.init(8, 6, 5, 208);

const Screen = enum {
    boot,
    main_menu,
    play_game_menu,
    quests_menu,
    statistics_menu,
    mods_menu,
    other_games_menu,
    gameplay,
    pause,
    results,
    options,
    controls,
};

const ResultsReason = enum {
    dead,
    completed,
    runtime_error,
    abandoned,
};

const AssetsState = enum {
    loaded,
    unavailable,
    failed,
};

const UiButton = window_ui.UiButton;
const BootSequenceState = window_boot.State;
const MenuScreenState = window_menu.State;

const GameplayScreen = struct {
    runner: live_runner.LiveRunner,
    run_config: live_runner.LiveModeConfig,
    last_update: live_runner.FrameUpdate,
    input_interpreter: local_input.LocalInputInterpreter = .{},
    perk_ui: window_perk_menu.State = .{},
    hud_state: HudRuntimeState = .{},
    ground: ?window_ground.GroundRenderer = null,
    camera: state_mod.Vec2 = .{ .x = -1.0, .y = -1.0 },
    render_time_s: f32 = 0.0,
    tutorial_prompt_selection: usize = 0,
    pending_terrain_fx: [16]terrain_fx_mod.TerrainFxBatch = [_]terrain_fx_mod.TerrainFxBatch{.{}} ** 16,
    pending_terrain_fx_count: usize = 0,
    pause_menu: window_pause_menu.State = .{},

    fn deinit(self: *GameplayScreen) void {
        if (self.ground) |*ground| {
            ground.deinit();
            self.ground = null;
        }
        self.* = undefined;
    }

    fn queueTerrainFxBatch(self: *GameplayScreen, batch: terrain_fx_mod.TerrainFxBatch) void {
        if (batch.isEmpty()) return;
        if (self.pending_terrain_fx_count < self.pending_terrain_fx.len) {
            self.pending_terrain_fx[self.pending_terrain_fx_count] = batch;
            self.pending_terrain_fx_count += 1;
            return;
        }
        var idx: usize = 1;
        while (idx < self.pending_terrain_fx.len) : (idx += 1) {
            self.pending_terrain_fx[idx - 1] = self.pending_terrain_fx[idx];
        }
        self.pending_terrain_fx[self.pending_terrain_fx.len - 1] = batch;
    }

    fn flushPendingTerrainFx(self: *GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
        const ground = &(self.ground orelse return);
        if (!ground.renderTargetReady()) return;

        var kept: usize = 0;
        for (self.pending_terrain_fx[0..self.pending_terrain_fx_count]) |batch| {
            if (window_terrain_fx.bakeTerrainFxBatch(ground, &batch, assets)) continue;
            self.pending_terrain_fx[kept] = batch;
            kept += 1;
        }
        self.pending_terrain_fx_count = kept;
    }
};

const BonusHudSlotState = struct {
    active: bool = false,
    bonus_id: game_ids.BonusId = .unused,
    icon_id: i32 = -1,
    slide_x: f32 = -184.0,
    timer_value: f32 = 0.0,
    timer_value_alt: f32 = 0.0,
};

const HudBonusSpec = struct {
    bonus_id: game_ids.BonusId,
    icon_id: i32,
    timer_value: f32,
    timer_value_alt: f32 = 0.0,
};

const HudRuntimeState = struct {
    survival_xp_smoothed: i32 = 0,
    bonus_slots: [16]BonusHudSlotState = [_]BonusHudSlotState{.{}} ** 16,

    fn smoothXp(self: *HudRuntimeState, target_raw: i32, frame_dt_ms_raw: f32) i32 {
        const target = @max(target_raw, 0);
        if (target == 0) {
            self.survival_xp_smoothed = 0;
            return 0;
        }

        var smoothed = self.survival_xp_smoothed;
        if (smoothed == target) return smoothed;

        const frame_dt_ms = @max(frame_dt_ms_raw, 0.0);
        var step = @max(@as(i32, 1), @divTrunc(@as(i32, @intFromFloat(frame_dt_ms)), 2));
        const diff: i32 = @intCast(@abs(smoothed - target));
        if (diff > 1000) {
            step *= @max(@as(i32, 1), @divTrunc(diff, 100));
        }

        if (smoothed < target) {
            smoothed += step;
            if (smoothed > target) smoothed = target;
        } else {
            smoothed -= step;
            if (smoothed < target) smoothed = target;
        }

        self.survival_xp_smoothed = smoothed;
        return smoothed;
    }

    fn update(self: *HudRuntimeState, frame_dt: f32, session: *const runtime_session.DeterministicSession) void {
        const xp_target = if (session.playersConst().len > 0) session.playersConst()[0].experience else 0;
        _ = self.smoothXp(xp_target, @max(frame_dt, 0.0) * 1000.0);

        var desired_specs: [16]HudBonusSpec = undefined;
        var desired_count: usize = 0;
        collectHudBonusSpecs(session, desired_specs[0..], &desired_count);

        var matched = [_]bool{false} ** 16;
        for (desired_specs[0..desired_count]) |spec| {
            var existing_index: ?usize = null;
            for (self.bonus_slots, 0..) |slot, idx| {
                if (slot.active and slot.bonus_id == spec.bonus_id) {
                    existing_index = idx;
                    break;
                }
            }
            const slot_index = existing_index orelse blk: {
                for (self.bonus_slots, 0..) |slot, idx| {
                    if (!slot.active) break :blk idx;
                }
                break :blk self.bonus_slots.len - 1;
            };
            var slot = &self.bonus_slots[slot_index];
            slot.active = true;
            slot.bonus_id = spec.bonus_id;
            slot.icon_id = spec.icon_id;
            slot.timer_value = spec.timer_value;
            slot.timer_value_alt = spec.timer_value_alt;
            slot.slide_x = @min(-2.0, slot.slide_x + @max(frame_dt, 0.0) * 350.0);
            matched[slot_index] = true;
        }

        for (&self.bonus_slots, 0..) |*slot, idx| {
            if (!slot.active or matched[idx]) continue;
            slot.timer_value = 0.0;
            slot.timer_value_alt = 0.0;
            slot.slide_x -= @max(frame_dt, 0.0) * 320.0;
            var later_active = false;
            for (self.bonus_slots[idx + 1 ..]) |other| {
                if (other.active) {
                    later_active = true;
                    break;
                }
            }
            if (slot.slide_x < -184.0 and !later_active) {
                slot.* = .{};
            }
        }
    }
};

const ResultsScreen = struct {
    reason: ResultsReason,
    run_config: live_runner.LiveModeConfig,
    summary: runtime_session.SessionSummary,
    player_health_values: [state_mod.max_players]f32 = [_]f32{0.0} ** state_mod.max_players,
    player_health_count: usize = 0,
    runtime_error: ?[]const u8 = null,
    highscore: ?ResultsHighscoreState = null,
    quest_final_time: ?quest_results.QuestFinalTime = null,
};

const ResultsHighscoreState = struct {
    record: persistence.highscores.HighScoreRecord,
    rank_index: usize,
    selection: usize = 0,
    save_error: ?[]const u8 = null,
    saved: bool = false,
    input: [persistence.highscores.name_size]u8 = [_]u8{0} ** persistence.highscores.name_size,
    input_len: usize = 0,

    fn setInput(self: *ResultsHighscoreState, value: []const u8) void {
        @memset(self.input[0..], 0);
        self.input_len = @min(value.len, persistence.highscores.name_max_edit);
        @memcpy(self.input[0..self.input_len], value[0..self.input_len]);
    }

    fn inputSlice(self: *const ResultsHighscoreState) []const u8 {
        return self.input[0..self.input_len];
    }

    fn trimmedInputSlice(self: *const ResultsHighscoreState) []const u8 {
        var end = self.input_len;
        while (end > 0 and self.input[end - 1] == 0x20) : (end -= 1) {}
        return self.input[0..end];
    }

    fn promptActive(self: *const ResultsHighscoreState) bool {
        return !self.saved;
    }
};

const App = struct {
    allocator: std.mem.Allocator,
    runtime: app_runtime.DesktopRuntime,
    screen: Screen = .boot,
    boot: BootSequenceState = .{},
    menu: MenuScreenState = .{},
    results_selection: usize = 0,
    play_game_menu: window_menu_panels.PlayGameState = .{},
    quests_menu: window_menu_panels.QuestState = .{},
    statistics_menu: window_statistics.State = .{},
    mods_menu: window_misc_panels.ModsState = .{},
    other_games_menu: window_misc_panels.OtherGamesState = .{},
    gameplay: ?GameplayScreen = null,
    results: ?ResultsScreen = null,
    options: window_options.OptionsState = .{},
    controls: window_options.ControlsState = .{},
    options_back_to: Screen = .main_menu,
    controls_back_to: Screen = .options,
    runtime_assets: ?window_assets.RuntimeAssets = null,
    audio: live_audio.Bridge,
    assets_state: AssetsState = .unavailable,
    assets_message: ?[]u8 = null,
    next_seed_state: u32 = 0xC0FFEE,
    cursor_pulse_time: f32 = 0.0,
    demo_enabled: bool = false,
    demo_trial_elapsed_ms: i32 = 0,
    demo_trial_info: demo_trial.OverlayInfo = .{},
    demo_trial_ui: window_demo_trial.State = .{},
    quit_requested: bool = false,

    fn init(allocator: std.mem.Allocator, runtime: app_runtime.DesktopRuntime, demo_enabled: bool) App {
        var app: App = .{
            .allocator = allocator,
            .runtime = runtime,
            .audio = live_audio.Bridge.init(allocator, audio_mod.audioConfigFromCrimsonCfg(runtime.config), null),
            .demo_enabled = demo_enabled,
        };
        app.boot.reset();
        app.menu.reset();
        app.loadAssets();
        return app;
    }

    fn deinit(self: *App) void {
        if (self.gameplay) |*gameplay| {
            gameplay.deinit();
            self.gameplay = null;
        }
        self.statistics_menu.deinit(self.allocator);
        if (self.runtime_assets) |*runtime_assets| {
            runtime_assets.deinit();
            self.runtime_assets = null;
        }
        self.audio.deinit();
        if (self.assets_message) |message| {
            self.allocator.free(message);
            self.assets_message = null;
        }
        self.runtime.deinit();
        self.* = undefined;
    }

    fn saveAllIfDirty(self: *App) !void {
        if (self.gameplay) |*gameplay| {
            self.runtime.absorbSessionState(&gameplay.runner.session);
        }
        try self.runtime.saveAllIfDirty();
    }

    fn loadAssets(self: *App) void {
        self.runtime_assets = window_assets.loadRuntimeAssetsFromDefaultSearch(self.allocator) catch |err| {
            self.assets_state = .failed;
            self.assets_message = self.allocator.dupe(u8, @errorName(err)) catch null;
            return;
        };
        self.assets_state = if (self.runtime_assets != null) .loaded else .unavailable;
    }

    fn rootMenuFlags(self: *const App) window_menu.Flags {
        return .{
            .mods_available = self.modsAvailable(),
            .other_games_enabled = self.otherGamesEnabled(),
        };
    }

    fn modsAvailable(self: *const App) bool {
        var mods_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const mods_path = std.fmt.bufPrint(&mods_path_buf, "{s}/mods", .{self.runtime.base_dir}) catch return false;
        const io = std.Io.Threaded.global_single_threaded.io();
        var dir = std.Io.Dir.openDirAbsolute(io, mods_path, .{ .iterate = true }) catch return false;
        defer dir.close(io);

        var iter = dir.iterate();
        while (iter.next(io) catch null) |entry| {
            if (entry.kind == .file and std.ascii.endsWithIgnoreCase(entry.name, ".dll")) return true;
        }
        return false;
    }

    fn otherGamesEnabled(self: *const App) bool {
        const raw = runtime_paths.envVarOwned(self.allocator, "CRIMSON_GRIM_CONFIG_VAR_100") catch return false;
        defer self.allocator.free(raw);
        return raw.len != 0;
    }

    fn update(self: *App, frame_dt: f32) void {
        self.tickCursorPulse(frame_dt);
        switch (self.screen) {
            .boot => self.updateBoot(frame_dt),
            .main_menu => self.updateMainMenu(frame_dt),
            .play_game_menu => self.updatePlayGameMenu(frame_dt),
            .quests_menu => self.updateQuestsMenu(frame_dt),
            .statistics_menu => self.updateStatisticsMenu(frame_dt),
            .mods_menu => self.updateModsMenu(frame_dt),
            .other_games_menu => self.updateOtherGamesMenu(frame_dt),
            .gameplay => self.updateGameplay(frame_dt),
            .pause => self.updatePause(frame_dt),
            .results => self.updateResults(),
            .options => self.updateOptions(frame_dt),
            .controls => self.updateControls(frame_dt),
        }
        self.audio.update(frame_dt);
    }

    fn draw(self: *App) void {
        switch (self.screen) {
            .boot => self.drawBoot(),
            .main_menu => self.drawMainMenu(),
            .play_game_menu => self.drawPlayGameMenu(),
            .quests_menu => self.drawQuestsMenu(),
            .statistics_menu => self.drawStatisticsMenu(),
            .mods_menu => self.drawModsMenu(),
            .other_games_menu => self.drawOtherGamesMenu(),
            .gameplay => self.drawGameplay(),
            .pause => self.drawPause(),
            .results => self.drawResults(),
            .options => self.drawOptions(),
            .controls => self.drawControls(),
        }
        self.drawUiCursor();
    }

    fn setScreen(self: *App, screen: Screen) void {
        if (self.screen != screen) self.cursor_pulse_time = 0.0;
        if (self.screen != screen) {
            self.runtime.saveAllIfDirty() catch |err| {
                std.log.err("saveAllIfDirty failed during screen transition: {s}", .{@errorName(err)});
            };
        }
        self.screen = screen;
    }

    fn tickCursorPulse(self: *App, frame_dt: f32) void {
        if (self.screen == .boot) return;
        self.cursor_pulse_time += @min(@max(frame_dt, 0.0), 0.1) * 1.1;
    }

    fn drawUiCursor(self: *const App) void {
        const assets = if (self.runtime_assets) |*runtime_assets| runtime_assets else return;
        switch (self.screen) {
            .boot => {},
            .main_menu, .play_game_menu, .quests_menu, .statistics_menu, .mods_menu, .other_games_menu, .pause, .results, .options, .controls => {
                window_cursor.drawMenuCursor(assets, self.cursor_pulse_time);
            },
            .gameplay => {
                if (self.gameplay) |gameplay| {
                    if (gameplay.perk_ui.active()) {
                        window_cursor.drawMenuCursor(assets, self.cursor_pulse_time);
                    }
                }
            },
        }
    }

    fn updateBoot(self: *App, frame_dt: f32) void {
        const result = window_boot.update(&self.boot, frame_dt);
        if (result.finished) {
            self.menu.openRoot();
            self.setScreen(.main_menu);
            return;
        }
        self.audio.ensureIntroMusic();
    }

    fn updateMainMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const menu_update = window_menu.update(
            &self.menu,
            frame_dt,
            if (self.runtime_assets) |*assets| assets else null,
            self.rootMenuFlags(),
        );
        if (menu_update.play_panel_click and !self.menu.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.menu.panel_open_sfx_played = true;
        }
        if (menu_update.play_button_click) {
            self.audio.playUiButtonClick();
        }
        if (menu_update.action) |action| {
            switch (action) {
                .open_play_game => {
                    self.play_game_menu.reset();
                    self.setScreen(.play_game_menu);
                },
                .open_options => {
                    self.options.reset();
                    self.options_back_to = .main_menu;
                    self.setScreen(.options);
                },
                .open_statistics => {
                    window_statistics.openRoot(&self.statistics_menu, self.allocator);
                    self.setScreen(.statistics_menu);
                },
                .open_mods => {
                    self.mods_menu.reset(self.runtime.base_dir);
                    self.setScreen(.mods_menu);
                },
                .open_other_games => {
                    self.other_games_menu.reset();
                    self.setScreen(.other_games_menu);
                },
                .quit => self.quit_requested = true,
            }
        }
    }

    fn updatePlayGameMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const play_game_update = window_menu_panels.updatePlayGame(&self.play_game_menu, frame_dt, &self.runtime.config, self.runtime.status, if (self.runtime_assets) |*assets| assets else null, self.demo_enabled);
        if (play_game_update.config_dirty) self.runtime.config_dirty = true;
        if (play_game_update.play_panel_click and !self.play_game_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.play_game_menu.panel.panel_open_sfx_played = true;
        }
        if (play_game_update.play_button_click) self.audio.playUiButtonClick();
        if (play_game_update.action) |action| switch (action) {
            .start_survival => self.startNewRun(runConfigForLiveMode(.survival, null, &self.next_seed_state)),
            .start_rush => self.startNewRun(runConfigForLiveMode(.rush, null, &self.next_seed_state)),
            .start_typo => self.startNewRun(runConfigForLiveMode(.typo, null, &self.next_seed_state)),
            .start_tutorial => self.startNewRun(runConfigForLiveMode(.tutorial, null, &self.next_seed_state)),
            .open_quests => {
                self.quests_menu.reset();
                self.setScreen(.quests_menu);
            },
            .back_to_menu => {
                self.menu.openRoot();
                self.setScreen(.main_menu);
            },
        };
    }

    fn updateQuestsMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const quest_update = window_menu_panels.updateQuests(&self.quests_menu, frame_dt, &self.runtime.config, self.runtime.status, self.demo_enabled);
        if (quest_update.config_dirty) self.runtime.config_dirty = true;
        if (quest_update.play_panel_click and !self.quests_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.quests_menu.panel.panel_open_sfx_played = true;
        }
        if (quest_update.play_button_click) self.audio.playUiButtonClick();
        if (quest_update.back_to_play_game) {
            self.play_game_menu.reset();
            self.setScreen(.play_game_menu);
            return;
        }
        if (quest_update.start_level_key) |level_key| {
            self.startNewRun(runConfigForLiveMode(.quests, level_key, &self.next_seed_state));
        }
    }

    fn updateStatisticsMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureStatisticsTheme();
        const statistics_update = window_statistics.update(
            &self.statistics_menu,
            self.allocator,
            frame_dt,
            self.runtime.base_dir,
            &self.runtime.config,
            self.runtime.status,
            if (self.runtime_assets) |*assets| assets else null,
        );
        if (statistics_update.play_panel_click and !self.statistics_menu.hub.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.statistics_menu.hub.panel.panel_open_sfx_played = true;
        }
        if (statistics_update.play_button_click) {
            self.audio.playUiButtonClick();
        }
        switch (statistics_update.action) {
            .none => {},
            .open_play_game => {
                self.play_game_menu.reset();
                self.setScreen(.play_game_menu);
            },
            .back_to_menu => {
                self.menu.openRoot();
                self.setScreen(.main_menu);
            },
        }
    }

    fn updateGameplay(self: *App, frame_dt: f32) void {
        if (self.gameplay) |*gameplay| {
            gameplay.render_time_s += @max(frame_dt, 0.0);
            const dt_ms = @as(i32, @intFromFloat(@min(@max(frame_dt, 0.0), 0.1) * 1000.0));
            if (self.demo_enabled) {
                const current_demo_info = self.currentDemoTrialInfo(gameplay);
                const timer_tick = demo_trial.tickDemoTrialTimers(
                    true,
                    gameplay.runner.session.game_mode,
                    current_demo_info.visible,
                    self.runtime.status.game_sequence_id,
                    self.demo_trial_elapsed_ms,
                    dt_ms,
                );
                if (timer_tick.global_playtime_ms != self.runtime.status.game_sequence_id) {
                    self.runtime.status.game_sequence_id = timer_tick.global_playtime_ms;
                    self.runtime.status_dirty = true;
                }
                self.demo_trial_elapsed_ms = timer_tick.quest_grace_elapsed_ms;
                self.demo_trial_info = self.currentDemoTrialInfo(gameplay);

                if (self.demo_trial_info.visible) {
                    switch (window_demo_trial.update(&self.demo_trial_ui, dt_ms)) {
                        .none => {},
                        .maybe_later => {
                            self.closeGameplayToMenu(gameplay);
                            return;
                        },
                        .purchase => {
                            _ = openDemoPurchaseUrl(self.allocator);
                            self.quit_requested = true;
                            return;
                        },
                    }
                    return;
                }
            } else {
                self.demo_trial_info = .{};
            }

            if (!gameplay.perk_ui.active() and rl.isKeyPressed(.escape)) {
                gameplay.pause_menu.reset();
                self.setScreen(.pause);
                return;
            }

            const camera = buildWorldCamera(
                gameplay.runner.session.world_size,
                &self.runtime.config,
                gameplay.camera,
                gameplay.runner.session.state.camera_shake_offset,
            );
            if (!self.demo_enabled) {
                self.runtime.recordGameplayFrame(frame_dt);
            }
            var input = collectGameplayInput(&gameplay.input_interpreter, &gameplay.runner, camera, &self.runtime, frame_dt);
            if (gameplay.runner.session.game_mode == .tutorial and
                gameplay.runner.perkPendingCount() > 0 and
                gameplay.runner.session.state.tutorial.stage_index == 6 and
                !gameplay.perk_ui.active())
            {
                gameplay.perk_ui.menu_open = true;
                gameplay.perk_ui.selected_index = 0;
                self.audio.playUiPanelClick();
            }
            const perk_ui_update = window_perk_menu.update(
                &gameplay.perk_ui,
                frame_dt,
                if (self.runtime_assets) |*assets| assets else null,
                &self.runtime.config,
                &gameplay.runner,
                !gameplay.runner.allPlayersDead(),
            );
            input.perk_choice_index = perk_ui_update.perk_choice_index;
            input.perk_menu_active = perk_ui_update.menu_active;
            if (perk_ui_update.play_panel_click) {
                self.audio.playUiPanelClick();
            }
            if (perk_ui_update.play_button_click) {
                self.audio.playUiButtonClick();
            }
            gameplay.last_update = gameplay.runner.stepFrame(frame_dt, input) catch |err| {
                self.finishRun(gameplay, .runtime_error, @errorName(err));
                return;
            };
            gameplay.camera = updateGameplayCamera(
                gameplay.camera,
                &gameplay.runner.session,
                &self.runtime.config,
            );
            gameplay.hud_state.update(frame_dt, &gameplay.runner.session);
            self.audio.handleFrameAudio(gameplay.last_update.audio, gameplay.runner.session.state.bonuses.reflex_boost);
            gameplay.queueTerrainFxBatch(gameplay.last_update.terrain_fx);
            if (self.runtime_assets) |*runtime_assets| {
                gameplay.flushPendingTerrainFx(runtime_assets);
            }

            if (gameplay.runner.session.game_mode == .tutorial) {
                switch (updateTutorialPromptButtons(self, gameplay)) {
                    .none => {},
                    .close_to_menu => {
                        self.closeTutorialRun(gameplay);
                        return;
                    },
                    .restart => {
                        const run_config = gameplay.run_config;
                        self.closeTutorialGameplay(gameplay);
                        self.startNewRun(run_config);
                        return;
                    },
                }
            }

            if (gameplay.runner.session.game_mode == .quests and gameplay.runner.session.quest_completed) {
                self.finishRun(gameplay, .completed, null);
                return;
            }
            if (gameplay.last_update.all_players_dead) {
                self.finishRun(gameplay, .dead, null);
            }
        }
    }

    fn updatePause(self: *App, frame_dt: f32) void {
        if (self.gameplay) |*gameplay| {
            const pause_update = window_pause_menu.update(
                &gameplay.pause_menu,
                frame_dt,
                if (self.runtime_assets) |*assets| assets else null,
            );
            if (pause_update.play_panel_click and !gameplay.pause_menu.panel_open_sfx_played) {
                self.audio.playUiPanelClick();
                gameplay.pause_menu.panel_open_sfx_played = true;
            }
            if (pause_update.play_button_click) self.audio.playUiButtonClick();
            if (pause_update.action) |action| switch (action) {
                .back_to_previous => self.setScreen(.gameplay),
                .open_options => {
                    self.options.reset();
                    self.options_back_to = .pause;
                    self.setScreen(.options);
                },
                .back_to_menu => {
                    gameplay.deinit();
                    self.gameplay = null;
                    self.menu.openRoot();
                    self.setScreen(.main_menu);
                },
            };
        }
    }

    fn updateModsMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const panel_update = window_misc_panels.updateMods(&self.mods_menu, frame_dt, if (self.runtime_assets) |*assets| assets else null);
        if (panel_update.play_panel_click and !self.mods_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.mods_menu.panel.panel_open_sfx_played = true;
        }
        if (panel_update.play_button_click) self.audio.playUiButtonClick();
        if (panel_update.action == .back_to_menu) {
            self.menu.openRoot();
            self.setScreen(.main_menu);
        }
    }

    fn updateOtherGamesMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const panel_update = window_misc_panels.updateOtherGames(&self.other_games_menu, frame_dt, if (self.runtime_assets) |*assets| assets else null);
        if (panel_update.play_panel_click and !self.other_games_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.other_games_menu.panel.panel_open_sfx_played = true;
        }
        if (panel_update.play_button_click) self.audio.playUiButtonClick();
        if (panel_update.action == .back_to_menu) {
            self.menu.openRoot();
            self.setScreen(.main_menu);
        }
    }

    fn updateResults(self: *App) void {
        if (self.results) |*results| {
            if (results.highscore) |*highscore| {
                if (highscore.promptActive()) {
                    self.updateResultsHighscoreEntry(results, highscore);
                    return;
                }
            }
            const buttons = resultsButtonsFor(results);
            window_ui.updateSelectionFromPointer(&self.results_selection, buttons.items[0..buttons.len]);
            if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
                self.results_selection = if (self.results_selection == 0) buttons.len - 1 else self.results_selection - 1;
            }
            if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
                self.results_selection = (self.results_selection + 1) % buttons.len;
            }

            const activated = window_ui.buttonActivated(buttons.items[0..buttons.len], self.results_selection);
            if (!activated) return;
            self.audio.playUiButtonClick();

            switch (results.run_config.game_mode) {
                .quests => switch (results.reason) {
                    .completed => switch (self.results_selection) {
                        0 => if (nextQuestLevelKey(results.run_config.quest_level_key)) |next_level_key| {
                            var next_run = results.run_config;
                            next_run.quest_level_key = next_level_key;
                            next_run.quest_fail_retry_count = 0;
                            self.startNewRun(next_run);
                        } else {
                            self.results = null;
                            self.menu.openRoot();
                            self.setScreen(.main_menu);
                        },
                        1 => {
                            var next_run = results.run_config;
                            next_run.quest_fail_retry_count = 0;
                            self.startNewRun(next_run);
                        },
                        2 => self.openResultsHighScores(results),
                        3 => {
                            self.results = null;
                            self.menu.openRoot();
                            self.setScreen(.main_menu);
                        },
                        else => {},
                    },
                    .dead => switch (self.results_selection) {
                        0 => {
                            var next_run = results.run_config;
                            next_run.quest_fail_retry_count +%= 1;
                            self.startNewRun(next_run);
                        },
                        1 => {
                            self.results = null;
                            self.quests_menu.reset();
                            self.setScreen(.quests_menu);
                        },
                        2 => {
                            self.results = null;
                            self.menu.openRoot();
                            self.setScreen(.main_menu);
                        },
                        else => {},
                    },
                    .runtime_error, .abandoned => switch (self.results_selection) {
                        0 => self.startNewRun(results.run_config),
                        1 => {
                            self.results = null;
                            self.menu.openRoot();
                            self.setScreen(.main_menu);
                        },
                        else => {},
                    },
                },
                else => switch (self.results_selection) {
                    0 => self.startNewRun(results.run_config),
                    1 => self.openResultsHighScores(results),
                    2 => {
                        self.results = null;
                        self.menu.openRoot();
                        self.setScreen(.main_menu);
                    },
                    else => {},
                },
            }
            return;
        }
    }

    fn currentDemoTrialInfo(self: *const App, gameplay: *const GameplayScreen) demo_trial.OverlayInfo {
        return demo_trial.demoTrialOverlayInfo(
            self.demo_enabled,
            gameplay.runner.session.game_mode,
            self.runtime.status.game_sequence_id,
            self.demo_trial_elapsed_ms,
            gameplay.run_config.quest_level_key,
        );
    }

    fn closeGameplayToMenu(self: *App, gameplay: *GameplayScreen) void {
        self.audio.stopGameplayMusic();
        gameplay.deinit();
        self.gameplay = null;
        self.demo_trial_info = .{};
        self.demo_trial_ui.reset();
        self.menu.openRoot();
        self.setScreen(.main_menu);
    }

    fn openResultsHighScores(self: *App, results: *const ResultsScreen) void {
        self.runtime.config.game_mode = @intCast(@intFromEnum(results.run_config.game_mode));
        self.runtime.config_dirty = true;
        window_statistics.openHighScores(
            &self.statistics_menu,
            self.allocator,
            self.runtime.base_dir,
            self.runtime.config,
            self.runtime.status,
        );
        if (results.run_config.game_mode == .quests) {
            self.statistics_menu.high_scores.mode = .quests;
            self.statistics_menu.high_scores.quest_level_key = results.run_config.quest_level_key;
        }
        self.setScreen(.statistics_menu);
    }

    fn updateOptions(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const options_update = window_options.updateOptions(&self.options, frame_dt, &self.runtime.config, if (self.runtime_assets) |*assets| assets else null);
        if (options_update.config_dirty) self.runtime.config_dirty = true;
        if (options_update.reload_audio) self.reloadAudioConfig();
        if (options_update.play_panel_click and !self.options.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.options.panel.panel_open_sfx_played = true;
        }
        if (options_update.play_button_click) self.audio.playUiButtonClick();
        switch (options_update.action) {
            .none => {},
            .open_controls => {
                self.controls.reset();
                self.controls_back_to = .options;
                self.setScreen(.controls);
            },
            .back_to_menu => {
                self.setScreen(self.options_back_to);
            },
        }
    }

    fn updateControls(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuThemeForDemo(self.demo_enabled);
        const controls_update = window_options.updateControls(&self.controls, frame_dt, &self.runtime.config, if (self.runtime_assets) |*assets| assets else null);
        if (controls_update.config_dirty) self.runtime.config_dirty = true;
        if (controls_update.play_panel_click and !self.controls.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.controls.panel_open_sfx_played = true;
        }
        if (controls_update.play_button_click) self.audio.playUiButtonClick();
        switch (controls_update.action) {
            .none => {},
            .back_to_options => self.setScreen(self.controls_back_to),
        }
    }

    fn updateResultsHighscoreEntry(
        self: *App,
        results: *ResultsScreen,
        highscore: *ResultsHighscoreState,
    ) void {
        self.playNameInputTypeClicks(collectNameInput(highscore));

        const buttons = resultsHighscoreButtons();
        window_ui.updateSelectionFromPointer(&highscore.selection, buttons[0..]);
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            highscore.selection = if (highscore.selection == 0) buttons.len - 1 else highscore.selection - 1;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            highscore.selection = (highscore.selection + 1) % buttons.len;
        }

        if (!window_ui.buttonActivated(buttons[0..], highscore.selection)) return;
        self.audio.playUiButtonClick();

        switch (highscore.selection) {
            0 => self.saveResultsHighscore(results, highscore),
            1 => {
                highscore.saved = true;
                highscore.save_error = null;
                self.results_selection = 0;
            },
            else => {},
        }
    }

    fn saveResultsHighscore(
        self: *App,
        results: *const ResultsScreen,
        highscore: *ResultsHighscoreState,
    ) void {
        const trimmed = highscore.trimmedInputSlice();
        if (trimmed.len == 0) {
            highscore.save_error = "name required";
            self.audio.playShockHit();
            return;
        }

        highscore.record.setName(trimmed);
        formats.crimson_cfg.setPlayerNameInput(&self.runtime.config, trimmed);
        self.runtime.config_dirty = true;

        const score_path = persistence.highscores.scoresPathForMode(
            self.allocator,
            self.runtime.base_dir,
            @intFromEnum(results.run_config.game_mode),
            .{
                .hardcore = results.run_config.hardcore,
                .quest_stage_major = @divTrunc(results.run_config.quest_level_key, 100),
                .quest_stage_minor = @mod(results.run_config.quest_level_key, 100),
                .player_count = results.run_config.player_count,
            },
        ) catch |err| {
            highscore.save_error = resultsHighscorePathErrorDetail(err);
            return;
        };
        defer self.allocator.free(score_path);

        var upsert = persistence.highscores.upsertHighscoreRecord(
            self.allocator,
            score_path,
            highscore.record,
            null,
        ) catch |err| {
            highscore.save_error = resultsHighscoreSaveErrorDetail(err);
            return;
        };
        defer upsert.deinit(self.allocator);

        self.runtime.saveConfigIfDirty() catch |err| {
            highscore.save_error = resultsConfigSaveErrorDetail(err);
            return;
        };

        highscore.saved = true;
        highscore.save_error = null;
        self.results_selection = 0;
        self.audio.playUiTypeEnter();
    }

    fn playNameInputTypeClicks(self: *App, edits: NameInputEdits) void {
        if (edits.typed) self.playNameInputTypeClick();
        if (edits.backspaced) self.playNameInputTypeClick();
    }

    fn playNameInputTypeClick(self: *App) void {
        var rng = spawn_mod.Crand.init(self.next_seed_state);
        const sfx_id = uiTypeClickSfxFromRoll(rng.randTagged(rng_callers.ui_text_input_update_typeclick));
        self.next_seed_state = rng.state;
        self.audio.playUiTypeClick(sfx_id);
    }

    fn startNewRun(self: *App, run_config: live_runner.LiveModeConfig) void {
        self.audio.stopGameplayMusic();
        var configured_run = run_config;
        configured_run.player_count = @intCast(std.math.clamp(self.runtime.config.player_count, @as(u32, 1), @as(u32, 4)));
        configured_run.detail_preset = @intCast(std.math.clamp(self.runtime.config.detail_preset, @as(u32, 1), @as(u32, 5)));
        configured_run.gore_disabled = @intCast(self.runtime.config.gore_disabled);
        configured_run.hardcore = self.runtime.config.hardcore_flag != 0;
        configured_run.status_quest_unlock_index = @intCast(self.runtime.status.quest_unlock_index);
        configured_run.status_quest_unlock_index_full = @intCast(self.runtime.status.quest_unlock_index_full);
        configured_run.status_weapon_usage_counts = statusWeaponUsageCounts(self.runtime.status);
        configured_run.demo_mode_active = self.demo_enabled and (configured_run.game_mode == .quests or configured_run.game_mode == .tutorial);

        self.runtime.recordModeStart(configured_run.game_mode);
        if (configured_run.game_mode == .quests) {
            self.runtime.recordQuestStart(configured_run.quest_level_key);
        }
        var runner = live_runner.LiveRunner.init(configured_run) catch |err| {
            self.results = .{
                .reason = .runtime_error,
                .run_config = configured_run,
                .summary = zeroSessionSummary(),
                .player_health_values = [_]f32{0.0} ** state_mod.max_players,
                .player_health_count = 0,
                .runtime_error = @errorName(err),
            };
            self.results_selection = 0;
            self.setScreen(.results);
            return;
        };
        if (configured_run.game_mode == .typo) {
            loadTypoSourcesIntoState(self.allocator, self.runtime.base_dir, &runner.session.state) catch |err| {
                self.results = .{
                    .reason = .runtime_error,
                    .run_config = configured_run,
                    .summary = zeroSessionSummary(),
                    .player_health_values = [_]f32{0.0} ** state_mod.max_players,
                    .player_health_count = 0,
                    .runtime_error = @errorName(err),
                };
                self.results_selection = 0;
                self.setScreen(.results);
                return;
            };
        }
        const last_update = runner.stepFrame(0.0, .{}) catch unreachable;
        if (self.gameplay) |*gameplay| {
            gameplay.deinit();
            self.gameplay = null;
        }

        var gameplay: GameplayScreen = .{
            .runner = runner,
            .run_config = configured_run,
            .last_update = last_update,
        };
        gameplay.camera = updateGameplayCamera(
            gameplay.camera,
            &gameplay.runner.session,
            &self.runtime.config,
        );
        gameplay.hud_state.update(0.0, &gameplay.runner.session);
        gameplay.input_interpreter.setPreserveBugs(gameplay.runner.session.state.preserve_bugs);
        gameplay.input_interpreter.reset(gameplay.runner.session.playersConst());
        if (self.runtime_assets) |*runtime_assets| {
            gameplay.ground = window_ground.GroundRenderer.initForTerrainSetup(
                runtime_assets,
                gameplay.runner.terrain_setup,
                gameplay.runner.session.terrain_size,
                gameplay.runner.session.terrain_size,
                self.runtime.config.texture_scale,
            ) catch null;
        }
        gameplay.queueTerrainFxBatch(gameplay.last_update.terrain_fx);
        if (self.runtime_assets) |*runtime_assets| {
            gameplay.flushPendingTerrainFx(runtime_assets);
        }
        self.gameplay = gameplay;
        self.results = null;
        self.setScreen(.gameplay);
    }

    fn reloadAudioConfig(self: *App) void {
        self.audio.deinit();
        self.audio = live_audio.Bridge.init(
            self.allocator,
            audio_mod.audioConfigFromCrimsonCfg(self.runtime.config),
            null,
        );
    }

    fn finishRun(self: *App, gameplay: *GameplayScreen, reason: ResultsReason, runtime_error: ?[]const u8) void {
        self.audio.stopGameplayMusic();
        const runner = &gameplay.runner;
        const level_key = runner.quest_level_key;
        self.runtime.absorbSessionState(&runner.session);
        var player_health_values: [state_mod.max_players]f32 = [_]f32{0.0} ** state_mod.max_players;
        const player_health_count = collectPlayerHealthValues(&player_health_values, &runner.session);
        if (reason == .completed and runner.session.game_mode == .quests) {
            if (level_key) |resolved| self.runtime.recordQuestCompletion(resolved);
        }
        const save_error: ?[]const u8 = save_err: {
            self.runtime.saveStatusIfDirty() catch |err| break :save_err @errorName(err);
            break :save_err null;
        };
        const highscore = self.buildResultsHighscore(
            runner,
            reason,
            runtime_error orelse save_error,
            player_health_values[0..player_health_count],
        );
        self.results = .{
            .reason = reason,
            .run_config = gameplay.run_config,
            .summary = runner.summary(),
            .player_health_values = player_health_values,
            .player_health_count = player_health_count,
            .runtime_error = runtime_error orelse save_error,
            .highscore = highscore,
            .quest_final_time = if (runner.session.game_mode == .quests)
                quest_results.computeQuestFinalTime(
                    @intCast(runner.summary().elapsed_ms_sim),
                    player_health_values[0..player_health_count],
                    runner.perkPendingCount(),
                )
            else
                null,
        };
        if (highscore != null) {
            self.audio.playUiClink();
        }
        gameplay.deinit();
        self.gameplay = null;
        self.results_selection = 0;
        self.setScreen(.results);
    }

    fn closeTutorialGameplay(self: *App, gameplay: *GameplayScreen) void {
        self.audio.stopGameplayMusic();
        self.runtime.absorbSessionState(&gameplay.runner.session);
        self.runtime.saveStatusIfDirty() catch |err| {
            std.log.err("saveStatusIfDirty failed during tutorial close: {s}", .{@errorName(err)});
        };
        gameplay.deinit();
        self.gameplay = null;
        self.results = null;
    }

    fn closeTutorialRun(self: *App, gameplay: *GameplayScreen) void {
        self.closeTutorialGameplay(gameplay);
        self.menu.openRoot();
        self.setScreen(.main_menu);
    }

    fn buildResultsHighscore(
        self: *App,
        runner: *const live_runner.LiveRunner,
        reason: ResultsReason,
        runtime_error: ?[]const u8,
        player_health_values: []const f32,
    ) ?ResultsHighscoreState {
        if (runtime_error != null) return null;
        switch (reason) {
            .dead, .completed => {},
            .abandoned, .runtime_error => return null,
        }
        if (runner.session.game_mode == .quests and reason == .dead) return null;

        const player = runner.player0Const() orelse return null;
        const shot_options: persistence.highscore_record_builder.BuildRecordOptions = switch (runner.session.game_mode) {
            .typo => .{
                .shots_fired = runner.session.state.typo.typing.submit_count,
                .shots_hit = runner.session.state.typo.typing.match_count,
                .clamp_shots_hit = false,
            },
            else => .{},
        };

        const elapsed_ms = if (runner.session.game_mode == .quests)
            quest_results.computeQuestFinalTime(
                @intCast(runner.summary().elapsed_ms_sim),
                player_health_values,
                runner.perkPendingCount(),
            ).final_time_ms
        else
            @as(i32, @intCast(runner.summary().elapsed_ms_sim));

        const record = persistence.highscore_record_builder.buildHighscoreRecordForGameOver(
            runner.session.state,
            player.*,
            elapsed_ms,
            @intCast(runner.session.creatures.kill_count),
            runner.session.game_mode,
            shot_options,
        );

        const score_path = persistence.highscores.scoresPathForMode(
            self.allocator,
            self.runtime.base_dir,
            @intFromEnum(runner.session.game_mode),
            .{
                .hardcore = runner.session.state.hardcore,
                .quest_stage_major = runner.session.state.quest_stage_major,
                .quest_stage_minor = runner.session.state.quest_stage_minor,
                .player_count = runner.session.player_count,
            },
        ) catch return null;
        defer self.allocator.free(score_path);

        const table = persistence.highscores.readHighscoreTable(
            self.allocator,
            score_path,
            @intFromEnum(runner.session.game_mode),
        ) catch return null;
        defer table.deinit(self.allocator);

        const rank_index = persistence.highscores.rankIndex(table.items, record);
        if (rank_index >= persistence.highscores.table_max) return null;

        var highscore: ResultsHighscoreState = .{
            .record = record,
            .rank_index = rank_index,
        };
        highscore.setInput(formats.crimson_cfg.playerName(&self.runtime.config));
        return highscore;
    }

    fn drawBoot(self: *const App) void {
        window_boot.draw(&self.boot, if (self.runtime_assets) |*assets| assets else null);
    }

    fn drawMainMenu(self: *const App) void {
        window_menu.draw(&self.menu, if (self.runtime_assets) |*assets| assets else null, self.rootMenuFlags());
    }

    fn drawPlayGameMenu(self: *const App) void {
        window_menu_panels.drawPlayGame(
            &self.play_game_menu,
            if (self.runtime_assets) |*assets| assets else null,
            self.runtime.status,
            self.runtime.config.player_count,
            self.demo_enabled,
        );
    }

    fn drawQuestsMenu(self: *const App) void {
        window_menu_panels.drawQuests(
            &self.quests_menu,
            if (self.runtime_assets) |*assets| assets else null,
            self.runtime.config,
            self.runtime.status,
        );
    }

    fn drawStatisticsMenu(self: *const App) void {
        window_statistics.draw(
            &self.statistics_menu,
            if (self.runtime_assets) |*assets| assets else null,
            self.runtime.config,
            self.runtime.status,
        );
    }

    fn drawModsMenu(self: *const App) void {
        window_misc_panels.drawMods(&self.mods_menu, if (self.runtime_assets) |*assets| assets else null);
    }

    fn drawOtherGamesMenu(self: *const App) void {
        window_misc_panels.drawOtherGames(&self.other_games_menu, if (self.runtime_assets) |*assets| assets else null);
    }

    fn drawGameplay(self: *App) void {
        rl.clearBackground(rl.Color.init(10, 10, 12, 255));

        if (self.gameplay) |*gameplay| {
            const runner = &gameplay.runner;
            const runtime_assets: ?*const window_assets.RuntimeAssets = if (self.runtime_assets) |*loaded_assets| loaded_assets else null;
            const transform = window_viewport.viewTransform(
                runner.session.world_size,
                &self.runtime.config,
                state_mod.Vec2.add(gameplay.camera, runner.session.state.camera_shake_offset),
                .{
                    .x = @floatFromInt(rl.getScreenWidth()),
                    .y = @floatFromInt(rl.getScreenHeight()),
                },
            );
            const entity_alpha: f32 = 1.0;
            const fx_detail_0 = self.runtime.config.fx_detail_0 != 0;
            const fx_detail_1 = self.runtime.config.fx_detail_1 != 0;
            const fx_detail_2 = self.runtime.config.fx_detail_2 != 0;
            const camera = buildWorldCamera(
                runner.session.world_size,
                &self.runtime.config,
                gameplay.camera,
                runner.session.state.camera_shake_offset,
            );

            camera.begin();
            drawWorld(runner, runtime_assets, if (gameplay.ground) |*ground| ground else null);
            drawPlayers(runner, runtime_assets, gameplay.render_time_s, entity_alpha, false);
            drawCreatures(runner, runtime_assets, entity_alpha, fx_detail_0);
            drawFreezeOverlay(runner, runtime_assets, entity_alpha);
            drawPlayers(runner, runtime_assets, gameplay.render_time_s, entity_alpha, true);
            drawProjectiles(runner, runtime_assets, gameplay.render_time_s, entity_alpha, fx_detail_1);
            drawWorldEffects(runner, runtime_assets, entity_alpha, fx_detail_1, fx_detail_2);
            drawBonuses(runner, runtime_assets, gameplay.render_time_s, entity_alpha);
            camera.end();

            if (runtime_assets) |assets| {
                if (runner.session.game_mode == .typo) {
                    drawTypoNameLabels(runner, assets, transform, entity_alpha);
                }
                drawBonusHoverLabels(runner, assets, transform, entity_alpha);
                if (!gameplay.perk_ui.active()) {
                    drawDirectionArrows(runner, assets, &self.runtime.config, transform, entity_alpha);
                    drawAimEnhancements(runner, assets, transform, entity_alpha);
                }
            }

            if (gameplay.perk_ui.active()) {
                if (runtime_assets) |assets| {
                    window_perk_menu.drawMenu(&gameplay.perk_ui, assets, &self.runtime.config, runner);
                }
            } else {
                drawGameplayHud(gameplay, runtime_assets);
                if (runtime_assets) |assets| {
                    if (runner.session.game_mode == .typo) {
                        drawTypoTypingBox(gameplay, assets);
                    } else if (runner.session.game_mode == .tutorial) {
                        drawTutorialOverlay(gameplay, assets);
                    }
                    window_perk_menu.drawPrompt(&gameplay.perk_ui, assets, &self.runtime.config, runner.perkPendingCount());
                }
            }

            if (self.demo_trial_info.visible) {
                if (runtime_assets) |assets| {
                    window_demo_trial.draw(&self.demo_trial_ui, assets, self.demo_trial_info);
                }
            }
        }
    }

    fn drawPause(self: *App) void {
        self.drawGameplay();
        if (self.gameplay) |gameplay| {
            window_pause_menu.draw(&gameplay.pause_menu, if (self.runtime_assets) |*assets| assets else null);
        }
    }

    fn drawResults(self: *const App) void {
        rl.clearBackground(bg_color);
        drawBackdrop();

        if (self.results) |results| {
            if (self.runtime_assets) |*runtime_assets| {
                drawTextureFit(runtime_assets.texture(.ui_menu_panel), rl.Rectangle.init(262.0, 116.0, 756.0, 392.0), colorWithAlpha(rl.Color.white, 0.96));
                switch (results.reason) {
                    .dead => drawTextureFit(runtime_assets.texture(.ui_text_reaper), rl.Rectangle.init(464.0, 136.0, 354.0, 48.0), colorWithAlpha(rl.Color.white, 0.96)),
                    .completed => drawTextureFit(runtime_assets.texture(.ui_text_level_complete), rl.Rectangle.init(406.0, 136.0, 468.0, 48.0), colorWithAlpha(rl.Color.white, 0.96)),
                    .abandoned, .runtime_error => drawSmallTextCentered(runtime_assets, resultsTitle(results.reason), 152.0, HudTextColor.accent),
                }
                drawSmallTextCentered(runtime_assets, resultsSubtitle(results.reason), 196.0, HudTextColor.primary);
                drawSmallText(runtime_assets, "TIME", 370.0, 258.0, HudTextColor.dim);
                drawSmallText(runtime_assets, "XP", 370.0, 286.0, HudTextColor.dim);
                drawSmallText(runtime_assets, "LEVEL", 370.0, 314.0, HudTextColor.dim);
                drawSmallText(runtime_assets, "WEAPON", 370.0, 342.0, HudTextColor.dim);
                drawSmallText(runtime_assets, "HP", 370.0, 370.0, HudTextColor.dim);
                const elapsed_ms = if (results.quest_final_time) |breakdown| breakdown.final_time_ms else @as(i32, @intCast(results.summary.elapsed_ms_sim));
                drawSmallTextFmt("{d} ms", runtime_assets, .{elapsed_ms}, 510.0, 258.0, HudTextColor.primary);
                drawSmallTextFmt("{d}", runtime_assets, .{results.summary.player_experience}, 510.0, 286.0, HudTextColor.primary);
                drawSmallTextFmt("{d}", runtime_assets, .{results.summary.player_level}, 510.0, 314.0, HudTextColor.primary);
                drawSmallText(runtime_assets, weaponName(results.summary.player_weapon_id), 510.0, 342.0, HudTextColor.primary);
                const player_health = if (results.player_health_count > 0) results.player_health_values[0] else 0.0;
                drawSmallTextFmt("{d:.1}", runtime_assets, .{player_health}, 510.0, 370.0, HudTextColor.primary);
                if (results.quest_final_time) |breakdown| {
                    drawSmallText(runtime_assets, "BASE", 690.0, 258.0, HudTextColor.dim);
                    drawSmallText(runtime_assets, "LIFE BONUS", 690.0, 286.0, HudTextColor.dim);
                    drawSmallText(runtime_assets, "PERK BONUS", 690.0, 314.0, HudTextColor.dim);
                    drawSmallText(runtime_assets, "FINAL", 690.0, 342.0, HudTextColor.dim);
                    drawSmallTextFmt("{d} ms", runtime_assets, .{breakdown.base_time_ms}, 846.0, 258.0, HudTextColor.primary);
                    drawSmallTextFmt("-{d} ms", runtime_assets, .{breakdown.life_bonus_ms}, 846.0, 286.0, HudTextColor.primary);
                    drawSmallTextFmt("-{d} ms", runtime_assets, .{breakdown.unpicked_perk_bonus_ms}, 846.0, 314.0, HudTextColor.primary);
                    drawSmallTextFmt("{d} ms", runtime_assets, .{breakdown.final_time_ms}, 846.0, 342.0, HudTextColor.accent);
                }

                if (results.runtime_error) |runtime_error| {
                    drawSmallText(runtime_assets, runtime_error, 330.0, 430.0, rl.Color.orange);
                }
                if (results.highscore) |highscore| {
                    drawResultsHighscore(runtime_assets, &highscore);
                }
            }
        }

        const prompt_active = if (self.results) |results|
            if (results.highscore) |highscore| highscore.promptActive() else false
        else
            false;
        const buttons = if (prompt_active)
            ResultsButtons{ .items = .{
                resultsHighscoreButtons()[0],
                resultsHighscoreButtons()[1],
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
            }, .len = 2 }
        else if (self.results) |results|
            resultsButtonsFor(&results)
        else
            ResultsButtons{ .items = .{
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
            }, .len = 0 };
        for (buttons.items[0..buttons.len], 0..) |button, idx| {
            const mouse_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            const selected = if (prompt_active)
                if (self.results) |results|
                    if (results.highscore) |highscore| idx == highscore.selection else false
                else
                    false
            else
                idx == self.results_selection;
            window_ui.drawButton(button, selected, mouse_hovered, if (self.runtime_assets) |*assets| assets else null);
        }
    }

    fn drawOptions(self: *const App) void {
        if (self.options_back_to == .pause and self.gameplay != null) {
            @constCast(self).drawGameplay();
        }
        window_options.drawOptions(&self.options, if (self.runtime_assets) |*assets| assets else null, self.runtime.config);
    }

    fn drawControls(self: *const App) void {
        if ((self.controls_back_to == .pause or self.options_back_to == .pause) and self.gameplay != null) {
            @constCast(self).drawGameplay();
        }
        window_options.drawControls(&self.controls, if (self.runtime_assets) |*assets| assets else null, self.runtime.config);
    }
};

const WindowArgs = struct {
    demo_enabled: bool = false,
};

pub fn main(init: std.process.Init) !void {
    runtime_paths.useEnviron(init.environ_map);

    const allocator = init.gpa;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args = try parseWindowArgs(argv);
    var runtime = try app_runtime.DesktopRuntime.init(allocator);

    rl.setConfigFlags(.{
        .fullscreen_mode = runtime.config.windowed_flag == 0,
    });
    rl.initWindow(runtime.windowWidth(window_width), runtime.windowHeight(window_height), "crimson-zig");
    defer rl.closeWindow();
    rl.hideCursor();
    defer rl.showCursor();

    rl.setTargetFPS(60);

    var app = App.init(allocator, runtime, args.demo_enabled);
    defer app.deinit();

    while (!rl.windowShouldClose() and !app.quit_requested) {
        const frame_dt = rl.getFrameTime();
        input_codes.inputBeginFrame();
        app.update(frame_dt);

        rl.beginDrawing();
        defer rl.endDrawing();
        app.draw();
    }

    try app.saveAllIfDirty();
}

fn parseWindowArgs(args: []const []const u8) !WindowArgs {
    var parsed: WindowArgs = .{};
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--demo")) {
            parsed.demo_enabled = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--help")) {
            std.debug.print("usage: crimson-zig-window [--demo]\n", .{});
            std.process.exit(0);
        }
        return error.InvalidArgs;
    }
    return parsed;
}

fn openDemoPurchaseUrl(allocator: std.mem.Allocator) bool {
    _ = allocator;
    const argv: []const []const u8 = switch (builtin.os.tag) {
        .macos => &.{ "open", window_demo_trial.demo_purchase_url },
        .linux => &.{ "xdg-open", window_demo_trial.demo_purchase_url },
        .windows => &.{ "rundll32", "url.dll,FileProtocolHandler", window_demo_trial.demo_purchase_url },
        else => return false,
    };
    const io = std.Io.Threaded.global_single_threaded.io();
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    _ = child.wait(io) catch return false;
    return true;
}

fn drawBackdrop() void {
    const width = rl.getScreenWidth();
    const height = rl.getScreenHeight();
    rl.drawRectangleGradientV(0, 0, width, height, rl.Color.init(32, 18, 16, 255), bg_color);
    rl.drawCircle(width - 180, 120, 200.0, rl.Color.init(93, 31, 22, 80));
    rl.drawCircle(160, height - 80, 220.0, rl.Color.init(58, 23, 18, 90));
}

fn drawTextureFit(texture: rl.Texture2D, dest: rl.Rectangle, tint: rl.Color) void {
    const src = rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height));
    rl.drawTexturePro(texture, src, dest, rl.Vector2.zero(), 0.0, tint);
}

fn drawTextureCentered(texture: rl.Texture2D, center: rl.Vector2, width: f32, height: f32, tint: rl.Color) void {
    drawTextureFit(
        texture,
        rl.Rectangle.init(center.x - width * 0.5, center.y - height * 0.5, width, height),
        tint,
    );
}

fn drawTextureCenteredRotated(texture: rl.Texture2D, center: rl.Vector2, width: f32, height: f32, rotation_deg: f32, tint: rl.Color) void {
    const src = rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height));
    const dest = rl.Rectangle.init(center.x, center.y, width, height);
    rl.drawTexturePro(texture, src, dest, rl.Vector2.init(width * 0.5, height * 0.5), rotation_deg, tint);
}

fn drawTextureRegionCenteredRotated(
    texture: rl.Texture2D,
    src_rect: window_atlas.AtlasRect,
    center: rl.Vector2,
    width: f32,
    height: f32,
    rotation_deg: f32,
    tint: rl.Color,
) void {
    const src = rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height);
    const dest = rl.Rectangle.init(center.x, center.y, width, height);
    rl.drawTexturePro(texture, src, dest, rl.Vector2.init(width * 0.5, height * 0.5), rotation_deg, tint);
}

fn drawAtlasFrameCenteredRotated(
    texture: rl.Texture2D,
    grid: i32,
    frame: i32,
    center: rl.Vector2,
    scale: f32,
    rotation_rad: f32,
    tint: rl.Color,
) void {
    const src_rect = window_atlas.atlasRect(texture.width, texture.height, grid, frame);
    drawTextureRegionCenteredRotated(
        texture,
        src_rect,
        center,
        src_rect.width * scale,
        src_rect.height * scale,
        radiansToDegrees(rotation_rad),
        tint,
    );
}

fn radiansToDegrees(radians: f32) f32 {
    return radians * (180.0 / std.math.pi);
}

fn vecAdd(a: rl.Vector2, b: rl.Vector2) rl.Vector2 {
    return .{ .x = a.x + b.x, .y = a.y + b.y };
}

fn vecSub(a: rl.Vector2, b: rl.Vector2) rl.Vector2 {
    return .{ .x = a.x - b.x, .y = a.y - b.y };
}

fn vecScale(vec: rl.Vector2, scale: f32) rl.Vector2 {
    return .{ .x = vec.x * scale, .y = vec.y * scale };
}

fn vecLength(vec: rl.Vector2) f32 {
    return std.math.sqrt(vec.x * vec.x + vec.y * vec.y);
}

fn vecNormalizeOr(vec: rl.Vector2, fallback: rl.Vector2) rl.Vector2 {
    const len = vecLength(vec);
    if (!(len > 1e-6)) return fallback;
    return .{ .x = vec.x / len, .y = vec.y / len };
}

fn colorLerp(a: rl.Color, b: rl.Color, t_raw: f32) rl.Color {
    const t = std.math.clamp(t_raw, @as(f32, 0.0), @as(f32, 1.0));
    return .{
        .r = @intFromFloat(@as(f32, @floatFromInt(a.r)) + (@as(f32, @floatFromInt(b.r)) - @as(f32, @floatFromInt(a.r))) * t),
        .g = @intFromFloat(@as(f32, @floatFromInt(a.g)) + (@as(f32, @floatFromInt(b.g)) - @as(f32, @floatFromInt(a.g))) * t),
        .b = @intFromFloat(@as(f32, @floatFromInt(a.b)) + (@as(f32, @floatFromInt(b.b)) - @as(f32, @floatFromInt(a.b))) * t),
        .a = @intFromFloat(@as(f32, @floatFromInt(a.a)) + (@as(f32, @floatFromInt(b.a)) - @as(f32, @floatFromInt(a.a))) * t),
    };
}

fn drawTextureTiled(texture: rl.Texture2D, area: rl.Rectangle, tint: rl.Color) void {
    const tile_width = @as(f32, @floatFromInt(texture.width));
    const tile_height = @as(f32, @floatFromInt(texture.height));
    if (!(tile_width > 0.0 and tile_height > 0.0 and area.width > 0.0 and area.height > 0.0)) return;

    const max_x = area.x + area.width;
    const max_y = area.y + area.height;
    var y = area.y;
    while (y < max_y - 0.001) : (y += tile_height) {
        const draw_height = @min(tile_height, max_y - y);
        var x = area.x;
        while (x < max_x - 0.001) : (x += tile_width) {
            const draw_width = @min(tile_width, max_x - x);
            const src = rl.Rectangle.init(0.0, 0.0, draw_width, draw_height);
            const dest = rl.Rectangle.init(x, y, draw_width, draw_height);
            rl.drawTexturePro(texture, src, dest, rl.Vector2.zero(), 0.0, tint);
        }
    }
}

const ResultsButtons = struct {
    items: [4]UiButton,
    len: usize,
};

fn resultsButtonsFor(results: *const ResultsScreen) ResultsButtons {
    const center_x: f32 = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5;
    if (results.run_config.game_mode == .quests and results.reason == .completed) {
        return .{
            .items = .{
                .{ .label = "PLAY NEXT", .rect = window_ui.centeredRect(center_x, 514.0, ui_button_width, ui_button_height) },
                .{ .label = "PLAY AGAIN", .rect = window_ui.centeredRect(center_x, 586.0, ui_button_width, ui_button_height) },
                .{ .label = "HIGH SCORES", .rect = window_ui.centeredRect(center_x, 658.0, ui_button_width, ui_button_height) },
                .{ .label = "MAIN MENU", .rect = window_ui.centeredRect(center_x, 730.0, ui_button_width, ui_button_height) },
            },
            .len = 4,
        };
    }
    if (results.run_config.game_mode == .quests and results.reason == .dead) {
        return .{
            .items = .{
                .{ .label = "PLAY AGAIN", .rect = window_ui.centeredRect(center_x, 550.0, ui_button_width, ui_button_height) },
                .{ .label = "PLAY ANOTHER", .rect = window_ui.centeredRect(center_x, 622.0, ui_button_width, ui_button_height) },
                .{ .label = "MAIN MENU", .rect = window_ui.centeredRect(center_x, 694.0, ui_button_width, ui_button_height) },
                .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
            },
            .len = 3,
        };
    }
    return .{
        .items = .{
            .{ .label = "PLAY AGAIN", .rect = window_ui.centeredRect(center_x, 550.0, ui_button_width, ui_button_height) },
            .{ .label = "HIGH SCORES", .rect = window_ui.centeredRect(center_x, 622.0, ui_button_width, ui_button_height) },
            .{ .label = "MAIN MENU", .rect = window_ui.centeredRect(center_x, 694.0, ui_button_width, ui_button_height) },
            .{ .label = "", .rect = rl.Rectangle.init(0.0, 0.0, 0.0, 0.0) },
        },
        .len = 3,
    };
}

fn resultsHighscorePathErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "Unable to build high score file path.",
        else => @errorName(err),
    };
}

fn resultsHighscoreSaveErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "Unable to save high score: access denied.",
        error.OutOfMemory => "Unable to save high score: out of memory.",
        error.InvalidSize => "High score file has an invalid record size.",
        error.NoSpaceLeft => "Unable to save high score: not enough disk space.",
        else => @errorName(err),
    };
}

fn resultsConfigSaveErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "Unable to save config: access denied.",
        error.OutOfMemory => "Unable to save config: out of memory.",
        error.NoSpaceLeft => "Unable to save config: not enough disk space.",
        else => @errorName(err),
    };
}

fn resultsHighscoreButtons() [2]UiButton {
    const center_x: f32 = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5;
    return .{
        .{ .label = "SAVE SCORE", .rect = window_ui.centeredRect(center_x, 586.0, ui_button_width, ui_button_height) },
        .{ .label = "SKIP", .rect = window_ui.centeredRect(center_x, 658.0, ui_button_width, ui_button_height) },
    };
}

const NameInputEdits = struct {
    typed: bool = false,
    backspaced: bool = false,
};

fn collectNameInput(highscore: *ResultsHighscoreState) NameInputEdits {
    var edits: NameInputEdits = .{};
    while (true) {
        const codepoint = rl.getCharPressed();
        if (codepoint == 0) break;
        if (codepoint < 0x20 or codepoint > 0xFF) continue;
        if (highscore.input_len >= persistence.highscores.name_max_edit) continue;
        highscore.input[highscore.input_len] = @intCast(codepoint);
        highscore.input_len += 1;
        edits.typed = true;
    }

    if ((rl.isKeyPressed(.backspace) or rl.isKeyPressedRepeat(.backspace)) and highscore.input_len > 0) {
        highscore.input_len -= 1;
        highscore.input[highscore.input_len] = 0;
        edits.backspaced = true;
    }
    return edits;
}

fn uiTypeClickSfxFromRoll(roll: u32) state_mod.SfxId {
    return if ((roll & 1) == 0) .ui_typeclick_01 else .ui_typeclick_02;
}

fn collectTypoDictionaryWords(
    allocator: std.mem.Allocator,
    path: []const u8,
    out: *std.ArrayList([]const u8),
) !?[]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    errdefer allocator.free(bytes);

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw_line| {
        const comment_cut = std.mem.indexOfScalar(u8, raw_line, '#') orelse raw_line.len;
        const text = std.mem.trim(u8, raw_line[0..comment_cut], &std.ascii.whitespace);
        if (text.len == 0 or text.len >= typo_names.name_max_chars) continue;
        const gop = try seen.getOrPut(text);
        if (gop.found_existing) continue;
        gop.value_ptr.* = {};
        try out.append(allocator, text);
    }

    return bytes;
}

fn isTypoHighscoreNameChar(ch: u8) bool {
    return std.ascii.isAlphabetic(ch) or ch == '.';
}

fn collectTypoHighscoreNames(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    out: *std.ArrayList([]const u8),
) !void {
    const score_path = try persistence.highscores.scoresPathForMode(
        allocator,
        base_dir,
        @intFromEnum(game_ids.GameModeId.typo),
        .{},
    );
    defer allocator.free(score_path);

    const table = try persistence.highscores.readHighscoreTable(
        allocator,
        score_path,
        @intFromEnum(game_ids.GameModeId.typo),
    );
    defer table.deinit(allocator);

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    for (table.items) |record| {
        const name = record.name();
        if (name.len == 0) continue;
        var valid = true;
        for (name) |ch| {
            if (!isTypoHighscoreNameChar(ch)) {
                valid = false;
                break;
            }
        }
        if (!valid) continue;
        const gop = try seen.getOrPut(name);
        if (gop.found_existing) continue;
        gop.value_ptr.* = {};
        try out.append(allocator, name);
    }
}

fn loadTypoSourcesIntoState(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    typo: *state_mod.GameplayState,
) !void {
    var dictionary_words: std.ArrayList([]const u8) = .empty;
    defer dictionary_words.deinit(allocator);
    var highscore_names: std.ArrayList([]const u8) = .empty;
    defer highscore_names.deinit(allocator);

    const dictionary_path = try std.fs.path.join(allocator, &.{ base_dir, "typo_dictionary.txt" });
    defer allocator.free(dictionary_path);
    const dictionary_backing = try collectTypoDictionaryWords(allocator, dictionary_path, &dictionary_words);
    defer if (dictionary_backing) |bytes| allocator.free(bytes);

    try collectTypoHighscoreNames(allocator, base_dir, &highscore_names);
    typo.typo.reset(dictionary_words.items, highscore_names.items);
}

fn buildWorldCamera(
    world_size: f32,
    config: *const formats.crimson_cfg.CrimsonCfg,
    camera_pos: state_mod.Vec2,
    shake_offset: state_mod.Vec2,
) rl.Camera2D {
    const transform = window_viewport.viewTransform(
        world_size,
        config,
        state_mod.Vec2.add(camera_pos, shake_offset),
        .{
            .x = @floatFromInt(rl.getScreenWidth()),
            .y = @floatFromInt(rl.getScreenHeight()),
        },
    );
    return .{
        .offset = rl.Vector2.zero(),
        .target = rl.Vector2.init(-transform.camera.x, -transform.camera.y),
        .rotation = 0.0,
        .zoom = window_viewport.viewScaleAvg(transform.view_scale),
    };
}

fn updateGameplayCamera(
    current_camera: state_mod.Vec2,
    session: *const runtime_session.DeterministicSession,
    config: *const formats.crimson_cfg.CrimsonCfg,
) state_mod.Vec2 {
    const players = session.playersConst();
    if (players.len == 0) return current_camera;

    const screen_size = window_viewport.cameraScreenSize(
        session.world_size,
        config,
        @floatFromInt(rl.getScreenWidth()),
        @floatFromInt(rl.getScreenHeight()),
    );

    var alive_count: usize = 0;
    var focus: state_mod.Vec2 = .{};
    for (players) |player| {
        if (!(player.health > 0.0)) continue;
        focus = state_mod.Vec2.add(focus, player.pos);
        alive_count += 1;
    }

    var camera = current_camera;
    if (alive_count > 0) {
        const inv_alive = 1.0 / @as(f32, @floatFromInt(alive_count));
        focus = focus.mul(inv_alive);
        camera = state_mod.Vec2.sub(screen_size.mul(0.5), focus);
    }

    return window_viewport.clampCamera(session.world_size, camera, screen_size);
}

fn collectGameplayInput(
    interpreter: *local_input.LocalInputInterpreter,
    runner: *live_runner.LiveRunner,
    camera: rl.Camera2D,
    runtime: *const app_runtime.DesktopRuntime,
    frame_dt: f32,
) live_runner.FrameInput {
    const mouse_world = rl.getScreenToWorld2D(rl.getMousePosition(), camera);
    const player = runner.player0Const() orelse return .{};
    const screen_center: state_mod.Vec2 = .{
        .x = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5,
        .y = @as(f32, @floatFromInt(rl.getScreenHeight())) * 0.5,
    };

    var frame_input: live_runner.FrameInput = .{
        .player = interpreter.buildPlayerInput(
            input_codes.RaylibInputSampler{},
            0,
            runner.session.playersConst().len,
            player,
            &runtime.config,
            .{
                .x = rl.getMousePosition().x,
                .y = rl.getMousePosition().y,
            },
            .{
                .x = mouse_world.x,
                .y = mouse_world.y,
            },
            screen_center,
            frame_dt,
            runner.session.creatures.entries[0..],
        ),
    };

    if (runner.session.game_mode == .typo) {
        frame_input.typo_submit = rl.isKeyPressed(.enter) or rl.isKeyPressed(.kp_enter);
        frame_input.typo_backspace = rl.isKeyPressed(.backspace) or rl.isKeyPressedRepeat(.backspace);
        if (!frame_input.typo_backspace) {
            const codepoint = rl.getCharPressed();
            if (codepoint >= 0x20 and codepoint <= 0xFF and codepoint != 13 and codepoint != 8) {
                frame_input.typo_char = @intCast(codepoint);
            }
        }
    }

    return frame_input;
}

fn collectPlayerHealthValues(
    out: *[state_mod.max_players]f32,
    session: *const runtime_session.DeterministicSession,
) usize {
    var count: usize = 0;
    for (session.playersConst()) |player| {
        if (count >= out.len) break;
        out[count] = player.health;
        count += 1;
    }
    return count;
}

fn boolAxis(negative: bool, positive: bool) f32 {
    if (negative == positive) return 0.0;
    return if (positive) 1.0 else -1.0;
}

fn statusWeaponUsageCounts(status: formats.game_cfg.Status) [state_mod.weapon_count_size]u32 {
    var counts: [state_mod.weapon_count_size]u32 = [_]u32{0} ** state_mod.weapon_count_size;
    for (0..@min(counts.len, status.weapon_usage_counts.len)) |idx| {
        counts[idx] = status.weapon_usage_counts[idx];
    }
    return counts;
}

test "boolAxis returns signed unit values without overflow" {
    try std.testing.expectEqual(@as(f32, -1.0), boolAxis(true, false));
    try std.testing.expectEqual(@as(f32, 0.0), boolAxis(false, false));
    try std.testing.expectEqual(@as(f32, 0.0), boolAxis(true, true));
    try std.testing.expectEqual(@as(f32, 1.0), boolAxis(false, true));
}

test "results high score type click follows native random bit" {
    try std.testing.expectEqual(state_mod.SfxId.ui_typeclick_01, uiTypeClickSfxFromRoll(0));
    try std.testing.expectEqual(state_mod.SfxId.ui_typeclick_02, uiTypeClickSfxFromRoll(1));
    try std.testing.expectEqual(state_mod.SfxId.ui_typeclick_01, uiTypeClickSfxFromRoll(2));
}

test "results high score save errors use user-facing details" {
    try std.testing.expectEqualStrings("Unable to build high score file path.", resultsHighscorePathErrorDetail(error.OutOfMemory));
    try std.testing.expectEqualStrings("Unable to save high score: access denied.", resultsHighscoreSaveErrorDetail(error.AccessDenied));
    try std.testing.expectEqualStrings("High score file has an invalid record size.", resultsHighscoreSaveErrorDetail(error.InvalidSize));
    try std.testing.expectEqualStrings("Unable to save config: not enough disk space.", resultsConfigSaveErrorDetail(error.NoSpaceLeft));
}

fn drawWorld(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    ground: ?*const window_ground.GroundRenderer,
) void {
    const world_size = runner.session.world_size;
    const world_rect = rl.Rectangle.init(0.0, 0.0, world_size, world_size);

    if (ground) |rendered_ground| {
        rendered_ground.draw();
    } else if (runtime_assets) |assets| {
        const terrain_set = terrainTextureSet(runner.session.quest_unlock_index);
        drawTextureTiled(assets.texture(terrain_set.base), world_rect, rl.Color.white);
        drawTextureTiled(assets.texture(terrain_set.overlay), world_rect, rl.Color.init(255, 255, 255, 124));
    } else {
        rl.drawRectangleRec(world_rect, rl.Color.init(63, 56, 25, 255));
    }
}

fn drawPlayers(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    render_time_s: f32,
    entity_alpha: f32,
    alive: bool,
) void {
    for (runner.session.playersConst()) |player| {
        if (alive and player.health <= 0.0) continue;
        if (!alive and player.health > 0.0) continue;
        const center = toRlVec(player.pos);
        const radius = @max(10.0, player.size * 0.28);
        const color = colorWithAlpha(if (player.health > 0.0) player_color else dead_player_color, entity_alpha);

        if (runtime_assets) |assets| {
            const trooper_texture = assets.texture(.trooper);
            const cell = @as(f32, @floatFromInt(trooper_texture.width)) / 8.0;
            if (cell > 0.0) {
                const base_scale = player.size / cell;
                const shadow_tint = colorWithAlpha(rl.Color.black, (90.0 / 255.0) * entity_alpha);
                const elapsed_s = render_time_s;

                if (player.health > 0.0) {
                    if (runtime_perks.perkActive(&player, .radioactive)) {
                        if (window_atlas.effectRect(assets.texture(.particles).width, assets.texture(.particles).height, .aura)) |src_rect| {
                            const aura_alpha = ((std.math.sin(elapsed_s) + 1.0) * 0.1875 + 0.25);
                            if (aura_alpha > 1e-3) {
                                rl.beginBlendMode(.additive);
                                drawTextureRegionCenteredRotated(
                                    assets.texture(.particles),
                                    src_rect,
                                    center,
                                    100.0,
                                    100.0,
                                    0.0,
                                    colorWithAlpha(rl.Color.init(77, 153, 77, 255), aura_alpha * entity_alpha),
                                );
                                rl.endBlendMode();
                            }
                        }
                    }

                    const leg_frame = std.math.clamp(@as(i32, @intFromFloat(player.move_phase + 0.5)), @as(i32, 0), @as(i32, 14));
                    const torso_frame = leg_frame + 16;
                    const recoil_dir = player.aim_heading + std.math.pi / 2.0;
                    const recoil = player.muzzle_flash_alpha * 12.0;
                    const recoil_offset = state_mod.Vec2.fromAngle(recoil_dir).mul(recoil);
                    const torso_center = center;
                    const torso_draw_center = rl.Vector2.init(torso_center.x + recoil_offset.x, torso_center.y + recoil_offset.y);

                    drawAtlasFrameCenteredRotated(
                        trooper_texture,
                        8,
                        leg_frame,
                        .{ .x = center.x + 3.0 + player.size * 0.01, .y = center.y + 3.0 + player.size * 0.01 },
                        base_scale * 1.02,
                        player.heading,
                        shadow_tint,
                    );
                    drawAtlasFrameCenteredRotated(
                        trooper_texture,
                        8,
                        torso_frame,
                        .{ .x = torso_draw_center.x + 1.0 + player.size * 0.015, .y = torso_draw_center.y + 1.0 + player.size * 0.015 },
                        base_scale * 1.03,
                        player.aim_heading,
                        shadow_tint,
                    );
                    drawAtlasFrameCenteredRotated(trooper_texture, 8, leg_frame, center, base_scale, player.heading, colorWithAlpha(rl.Color.white, entity_alpha));
                    drawAtlasFrameCenteredRotated(trooper_texture, 8, torso_frame, torso_draw_center, base_scale, player.aim_heading, colorWithAlpha(rl.Color.white, entity_alpha));

                    if (player.shield_timer > 1e-3) {
                        if (window_atlas.effectRect(assets.texture(.particles).width, assets.texture(.particles).height, .shield_ring)) |src_rect| {
                            const timer = player.shield_timer;
                            var strength = ((std.math.sin(elapsed_s) + 1.0) * 0.25 + timer);
                            if (timer < 1.0) strength *= timer;
                            strength = @min(1.0, strength);
                            if (strength > 1e-3) {
                                const offset_dir = player.aim_heading - std.math.pi / 2.0;
                                const shield_center_off = state_mod.Vec2.fromAngle(offset_dir).mul(3.0);
                                const shield_center = rl.Vector2.init(center.x + shield_center_off.x, center.y + shield_center_off.y);
                                const half_1 = std.math.sin(elapsed_s * 3.0) + 17.5;
                                const size_1 = half_1 * 2.0;
                                const half_2 = std.math.sin(elapsed_s * 3.0) * 4.0 + 24.0;
                                const size_2 = half_2 * 2.0;
                                rl.beginBlendMode(.additive);
                                drawTextureRegionCenteredRotated(
                                    assets.texture(.particles),
                                    src_rect,
                                    shield_center,
                                    size_1,
                                    size_1,
                                    radiansToDegrees(elapsed_s * 2.0),
                                    colorWithAlpha(rl.Color.init(91, 180, 255, 255), strength * 0.4 * entity_alpha),
                                );
                                drawTextureRegionCenteredRotated(
                                    assets.texture(.particles),
                                    src_rect,
                                    shield_center,
                                    size_2,
                                    size_2,
                                    radiansToDegrees(elapsed_s * -2.0),
                                    colorWithAlpha(rl.Color.init(91, 180, 255, 255), strength * 0.3 * entity_alpha),
                                );
                                rl.endBlendMode();
                            }
                        }
                    }

                    if (player.muzzle_flash_alpha > 0.02) {
                        const flags = weapon_data.weapon_stats.get(player.weapon.weapon_id).flags;
                        if ((flags & 0x8) == 0) {
                            const flash_alpha = std.math.clamp(player.muzzle_flash_alpha * 0.8, @as(f32, 0.0), @as(f32, 1.0));
                            if (flash_alpha > 1e-3) {
                                const flash_size = player.size * (if ((flags & 0x4) != 0) @as(f32, 0.5) else @as(f32, 1.0));
                                const flash_heading = player.aim_heading + std.math.pi / 2.0;
                                const flash_offset = (player.muzzle_flash_alpha * 12.0) - 21.0;
                                const flash_pos_off = state_mod.Vec2.fromAngle(flash_heading).mul(flash_offset);
                                const flash_center = rl.Vector2.init(center.x + flash_pos_off.x, center.y + flash_pos_off.y);
                                rl.beginBlendMode(.additive);
                                drawTextureCenteredRotated(
                                    assets.texture(.muzzle_flash),
                                    flash_center,
                                    flash_size,
                                    flash_size,
                                    radiansToDegrees(player.aim_heading),
                                    colorWithAlpha(rl.Color.white, flash_alpha * entity_alpha),
                                );
                                rl.endBlendMode();
                            }
                        }
                    }
                    continue;
                }

                var dead_frame: i32 = 52;
                if (player.death_timer >= 0.0) {
                    dead_frame = 32 + @as(i32, @intFromFloat((16.0 - player.death_timer) * 1.25));
                    dead_frame = std.math.clamp(dead_frame, @as(i32, 32), @as(i32, 52));
                }
                drawAtlasFrameCenteredRotated(
                    trooper_texture,
                    8,
                    dead_frame,
                    .{ .x = center.x + 1.0 + player.size * 0.015, .y = center.y + 1.0 + player.size * 0.015 },
                    base_scale * 1.03,
                    player.aim_heading,
                    shadow_tint,
                );
                drawAtlasFrameCenteredRotated(trooper_texture, 8, dead_frame, center, base_scale, player.aim_heading, colorWithAlpha(dead_player_color, entity_alpha));
                continue;
            }
        } else {
            rl.drawCircleV(center, radius, color);
            rl.drawCircleLinesV(center, radius + 2.0, rl.Color.black);
            rl.drawLineEx(center, toRlVec(player.aim), 2.0, rl.Color.gold);
        }
    }
}

fn drawCreatures(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    entity_alpha: f32,
    fx_detail_0: bool,
) void {
    const monster_vision_active = if (runner.player0Const()) |player|
        runtime_perks.perkActive(player, .monster_vision)
    else
        false;

    for (runner.session.creatures.entries) |creature| {
        if (!creature.active) continue;
        const color = if (creature.hp > 0.0) creature_color else corpse_color;
        const radius = @max(6.0, creature.size * 0.24);
        if (runtime_assets) |assets| {
            if (window_atlas.creatureRenderFrame(creature)) |render_frame| {
                const texture = assets.texture(switch (render_frame.texture_kind) {
                    .alien => .alien,
                    .lizard => .lizard,
                    .spider_sp1 => .spider_sp1,
                    .spider_sp2 => .spider_sp2,
                    .trooper => .trooper,
                    .zombie => .zombie,
                });
                const cell = @as(f32, @floatFromInt(texture.width)) / 8.0;
                if (cell > 0.0) {
                    const base_scale = creature.size / cell;
                    var tint = rl.Color.white;
                    if (runner.session.state.bonuses.energizer > 0.0 and creature.max_hp < 500.0) {
                        tint = colorLerp(
                            rl.Color.white,
                            rl.Color.init(128, 128, 255, 255),
                            @min(runner.session.state.bonuses.energizer, 1.0),
                        );
                    }
                    if (creature.lifecycle_stage < 0.0) {
                        tint = colorWithAlpha(tint, @max(0.0, 1.0 + creature.lifecycle_stage * 0.1));
                    }
                    const shadow_enabled = !monster_vision_active;
                    if (shadow_enabled and fx_detail_0) {
                        const is_long = runtime_anim.creatureAnimIsLongStrip(creature.flags);
                        var shadow_alpha: f32 = 0.4;
                        if (creature.lifecycle_stage < 0.0) {
                            shadow_alpha = @max(
                                @as(f32, 0.0),
                                shadow_alpha + creature.lifecycle_stage * (if (is_long) @as(f32, 0.5) else @as(f32, 0.1)),
                            );
                        }
                        if (shadow_alpha > 1e-3) {
                            drawAtlasFrameCenteredRotated(
                                texture,
                                8,
                                render_frame.frame,
                                .{
                                    .x = creature.pos.x + creature.size * 0.035 - 0.7,
                                    .y = creature.pos.y + creature.size * 0.035 - 0.7,
                                },
                                base_scale * 1.07,
                                creature.heading - std.math.pi / 2.0,
                                colorWithAlpha(rl.Color.black, shadow_alpha),
                            );
                        }
                    }
                    drawAtlasFrameCenteredRotated(
                        texture,
                        8,
                        render_frame.frame,
                        toRlVec(creature.pos),
                        base_scale,
                        creature.heading - std.math.pi / 2.0,
                        colorWithAlpha(tint, entity_alpha),
                    );
                    continue;
                }
            }
        }
        rl.drawCircleV(toRlVec(creature.pos), radius, colorWithAlpha(color, entity_alpha));
    }
}

fn drawFreezeOverlay(runner: *const live_runner.LiveRunner, runtime_assets: ?*const window_assets.RuntimeAssets, entity_alpha: f32) void {
    const assets = runtime_assets orelse return;
    const freeze_timer = runner.session.state.bonuses.freeze;
    if (!(freeze_timer > 0.0)) return;
    const src_rect = window_atlas.effectRect(assets.texture(.particles).width, assets.texture(.particles).height, .freeze_shatter) orelse return;
    const fade: f32 = if (freeze_timer >= 1.0) 1.0 else std.math.clamp(freeze_timer, @as(f32, 0.0), @as(f32, 1.0));
    const alpha = std.math.clamp(fade * entity_alpha * 0.7, @as(f32, 0.0), @as(f32, 1.0));
    if (!(alpha > 1e-3)) return;

    rl.beginBlendMode(.alpha);
    defer rl.endBlendMode();
    for (runner.session.creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const size = creature.size;
        if (!(size > 1e-3)) continue;
        drawTextureRegionCenteredRotated(
            assets.texture(.particles),
            src_rect,
            toRlVec(creature.pos),
            size,
            size,
            radiansToDegrees(@as(f32, @floatFromInt(idx)) * 0.01 + creature.heading),
            colorWithAlpha(rl.Color.white, alpha),
        );
    }
}

fn drawProjectiles(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    render_time_s: f32,
    entity_alpha: f32,
    fx_detail_1: bool,
) void {
    for (runner.session.projectiles.entries, 0..) |projectile, proj_index| {
        if (!projectile.active) continue;
        if (runtime_assets) |assets| {
            if (window_projectiles.drawMainProjectile(projectile, proj_index, .{
                .session = &runner.session,
                .assets = assets,
                .render_time_s = render_time_s,
                .entity_alpha = entity_alpha,
                .fx_detail_1 = fx_detail_1,
            })) continue;
        }
        rl.drawCircleV(toRlVec(projectile.pos), 3.0, colorWithAlpha(projectile_color, entity_alpha));
    }
}

fn drawWorldEffects(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    entity_alpha: f32,
    fx_detail_1: bool,
    fx_detail_2: bool,
) void {
    if (runtime_assets) |assets| {
        window_effects.drawParticlePool(.{
            .session = &runner.session,
            .assets = assets,
            .entity_alpha = entity_alpha,
            .fx_detail_1 = fx_detail_1,
            .fx_detail_2 = fx_detail_2,
        });
    }
    for (runner.session.secondary_projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        if (runtime_assets) |assets| {
            if (window_projectiles.drawSecondaryProjectile(projectile, .{
                .session = &runner.session,
                .assets = assets,
                .entity_alpha = entity_alpha,
                .fx_detail_1 = fx_detail_1,
            })) continue;
        }
        rl.drawCircleV(toRlVec(projectile.pos), 6.0, colorWithAlpha(secondary_projectile_color, entity_alpha));
    }
    if (runtime_assets) |assets| {
        window_effects.drawSpriteEffectPool(.{
            .session = &runner.session,
            .assets = assets,
            .entity_alpha = entity_alpha,
            .fx_detail_1 = fx_detail_1,
            .fx_detail_2 = fx_detail_2,
        });
        window_effects.drawEffectPool(.{
            .session = &runner.session,
            .assets = assets,
            .entity_alpha = entity_alpha,
            .fx_detail_1 = fx_detail_1,
            .fx_detail_2 = fx_detail_2,
        });
    }
}

fn drawBonuses(
    runner: *const live_runner.LiveRunner,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    render_time_s: f32,
    entity_alpha: f32,
) void {
    const bonus_phase = render_time_s * 1.3;
    for (runner.session.bonuses.entries, 0..) |entry, idx| {
        if (entry.bonus_id == .unused) continue;
        if (runtime_assets) |assets| {
            const bonuses_texture = assets.texture(.bonuses);
            const bubble_src = window_atlas.bonusIconRect(bonuses_texture.width, bonuses_texture.height, 0);
            const fade = window_atlas.bonusFade(entry.time_left, entry.time_max);
            const bubble_alpha = fade * 0.9 * entity_alpha;
            const center = toRlVec(entry.pos);
            drawTextureRegionCenteredRotated(
                bonuses_texture,
                bubble_src,
                center,
                32.0,
                32.0,
                0.0,
                colorWithAlpha(rl.Color.white, bubble_alpha),
            );

            if (entry.bonus_id == .weapon) {
                const weapon_id = std.enums.fromInt(game_ids.WeaponId, entry.amount) orelse {
                    continue;
                };
                const icon_index = weapon_data.weaponIconIndex(weapon_id);
                if (icon_index >= 0) {
                    const pulse_sin = std.math.sin(bonus_phase);
                    const pulse = pulse_sin * pulse_sin * pulse_sin * pulse_sin * 0.25 + 0.75;
                    const icon_scale = fade * pulse;
                    if (icon_scale > 1e-3) {
                        const src_rect = window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index);
                        drawTextureRegionCenteredRotated(
                            assets.texture(.ui_wicons),
                            src_rect,
                            center,
                            60.0 * icon_scale,
                            30.0 * icon_scale,
                            0.0,
                            colorWithAlpha(rl.Color.white, bubble_alpha),
                        );
                    }
                }
                continue;
            }

            if (window_atlas.bonusIconId(entry)) |icon_id| {
                const idx_f: f32 = @floatFromInt(idx);
                const pulse_sin = std.math.sin(idx_f + bonus_phase);
                const pulse = pulse_sin * pulse_sin * pulse_sin * pulse_sin * 0.25 + 0.75;
                const icon_scale = fade * pulse;
                if (icon_scale > 1e-3) {
                    drawTextureRegionCenteredRotated(
                        bonuses_texture,
                        window_atlas.bonusIconRect(bonuses_texture.width, bonuses_texture.height, icon_id),
                        center,
                        32.0 * icon_scale,
                        32.0 * icon_scale,
                        radiansToDegrees(std.math.sin(idx_f - render_time_s * 3.0) * 0.2),
                        colorWithAlpha(rl.Color.white, bubble_alpha),
                    );
                }
                continue;
            }
        }
        rl.drawRectangleRec(
            .{
                .x = entry.pos.x - 8.0,
                .y = entry.pos.y - 8.0,
                .width = 16.0,
                .height = 16.0,
            },
            colorWithAlpha(bonus_color, entity_alpha),
        );
    }
}

fn drawAimEnhancements(
    runner: *const live_runner.LiveRunner,
    runtime_assets: *const window_assets.RuntimeAssets,
    transform: window_viewport.ViewTransform,
    entity_alpha: f32,
) void {
    const scale = window_viewport.viewScaleAvg(transform.view_scale);
    for (runner.session.playersConst()) |player| {
        if (player.health <= 0.0) continue;
        const aim_screen = worldToScreen(player.aim, transform);
        window_cursor.drawAimIndicators(runtime_assets, player, aim_screen, scale, entity_alpha);
    }
    for (runner.session.playersConst()) |player| {
        if (player.health <= 0.0) continue;
        const aim_screen = worldToScreen(player.aim, transform);
        window_cursor.drawAimReticle(runtime_assets, aim_screen, scale);
    }
}

fn drawDirectionArrows(
    runner: *const live_runner.LiveRunner,
    runtime_assets: *const window_assets.RuntimeAssets,
    config: *const formats.crimson_cfg.CrimsonCfg,
    transform: window_viewport.ViewTransform,
    entity_alpha: f32,
) void {
    const arrow = runtime_assets.texture(.arrow);
    const scale = window_viewport.viewScaleAvg(transform.view_scale);
    const width = @max(1.0, @as(f32, @floatFromInt(arrow.width)) * scale);
    const height = @max(1.0, @as(f32, @floatFromInt(arrow.height)) * scale);
    const src = rl.Rectangle.init(0.0, 0.0, @floatFromInt(arrow.width), @floatFromInt(arrow.height));
    const origin = rl.Vector2.init(width * 0.5, height * 0.5);

    for (runner.session.playersConst(), 0..) |player, idx| {
        if (player.health <= 0.0) continue;
        if (!formats.crimson_cfg.playerShowDirectionArrow(config, idx)) continue;
        const marker = state_mod.Vec2.add(player.pos, state_mod.Vec2.fromAngle(player.heading).mul(60.0));
        const pos = worldToScreen(marker, transform);
        const tint = directionArrowTint(runner.session.player_count, idx, entity_alpha);
        rl.drawTexturePro(
            arrow,
            src,
            rl.Rectangle.init(pos.x, pos.y, width, height),
            origin,
            radiansToDegrees(player.heading),
            tint,
        );
    }
}

fn drawBonusHoverLabels(
    runner: *const live_runner.LiveRunner,
    runtime_assets: *const window_assets.RuntimeAssets,
    transform: window_viewport.ViewTransform,
    entity_alpha: f32,
) void {
    const shadow = rl.Color.init(0, 0, 0, @intFromFloat(180.0 * entity_alpha + 0.5));
    const color = rl.Color.init(230, 230, 230, @intFromFloat(255.0 * entity_alpha + 0.5));
    const screen_w: f32 = @floatFromInt(rl.getScreenWidth());

    for (runner.session.playersConst()) |player| {
        if (player.health <= 0.0) continue;
        if (player.bonus_aim_hover_index < 0 or player.bonus_aim_hover_index >= runner.session.bonuses.entries.len) continue;
        const entry = runner.session.bonuses.entries[@intCast(player.bonus_aim_hover_index)];
        if (entry.bonus_id == .unused) continue;

        var buf: [96]u8 = undefined;
        const label = bonusHoverLabel(entry, runner.session.state.preserve_bugs, &buf) orelse continue;
        var pos = worldToScreen(player.aim, transform);
        pos.x += 16.0;
        pos.y -= 7.0;
        const text_w = measureSmallText(runtime_assets, label);
        if (pos.x + text_w > screen_w) {
            pos.x = @max(0.0, screen_w - text_w);
        }
        drawSmallText(runtime_assets, label, pos.x + 1.0, pos.y + 1.0, shadow);
        drawSmallText(runtime_assets, label, pos.x, pos.y, color);
    }
}

fn worldToScreen(pos: state_mod.Vec2, transform: window_viewport.ViewTransform) rl.Vector2 {
    return .{
        .x = (pos.x + transform.camera.x) * transform.view_scale.x,
        .y = (pos.y + transform.camera.y) * transform.view_scale.y,
    };
}

fn directionArrowTint(player_count: i32, player_index: usize, alpha: f32) rl.Color {
    if (player_count == 2) {
        return if (player_index == 0)
            rl.Color.init(204, 230, 255, @intFromFloat(153.0 * alpha + 0.5))
        else
            rl.Color.init(255, 230, 204, @intFromFloat(153.0 * alpha + 0.5));
    }
    return rl.Color.init(255, 255, 255, @intFromFloat(77.0 * alpha + 0.5));
}

fn bonusHoverLabel(
    entry: bonuses_runtime.BonusEntry,
    preserve_bugs: bool,
    buf: *[96]u8,
) ?[]const u8 {
    return switch (entry.bonus_id) {
        .weapon => blk: {
            const weapon_id = std.enums.fromInt(game_ids.WeaponId, entry.amount) orelse break :blk null;
            break :blk game_ids.weaponDisplayName(weapon_id, preserve_bugs);
        },
        .points => std.fmt.bufPrint(buf, "{s}: {d}", .{
            game_ids.bonusDisplayName(.points, preserve_bugs),
            entry.amount,
        }) catch null,
        else => game_ids.bonusDisplayName(entry.bonus_id, preserve_bugs),
    };
}

const TerrainTextureSet = struct {
    base: window_assets.TextureId,
    overlay: window_assets.TextureId,
};

fn terrainTextureSet(quest_unlock_index: i32) TerrainTextureSet {
    return if (quest_unlock_index >= 40)
        .{ .base = .ter_q4_base, .overlay = .ter_q4_overlay }
    else if (quest_unlock_index >= 30)
        .{ .base = .ter_q3_base, .overlay = .ter_q3_overlay }
    else if (quest_unlock_index >= 20)
        .{ .base = .ter_q2_base, .overlay = .ter_q2_overlay }
    else
        .{ .base = .ter_q1_base, .overlay = .ter_q1_overlay };
}

fn colorWithAlpha(color: rl.Color, alpha: f32) rl.Color {
    return rl.Color.init(
        color.r,
        color.g,
        color.b,
        @intFromFloat(std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
    );
}

fn drawResultsHighscore(
    runtime_assets: *const window_assets.RuntimeAssets,
    highscore: *const ResultsHighscoreState,
) void {
    const prompt_y = 452.0;
    if (highscore.promptActive()) {
        drawSmallTextCentered(runtime_assets, "NEW HIGH SCORE", prompt_y, HudTextColor.accent);
        drawSmallTextFmt("RANK #{d}", runtime_assets, .{highscore.rank_index + 1}, 420.0, prompt_y + 28.0, HudTextColor.primary);
        drawSmallTextCentered(runtime_assets, "ENTER YOUR NAME TO SAVE THIS RUN", prompt_y + 56.0, HudTextColor.dim);

        rl.drawRectangleRounded(
            rl.Rectangle.init(392.0, prompt_y + 86.0, 496.0, 34.0),
            0.15,
            8,
            rl.Color.init(22, 18, 16, 230),
        );
        rl.drawRectangleRoundedLinesEx(
            rl.Rectangle.init(392.0, prompt_y + 86.0, 496.0, 34.0),
            0.15,
            8,
            2.0,
            rl.Color.init(138, 101, 78, 255),
        );

        const caret_visible = @mod(@as(i32, @intFromFloat(rl.getTime() * 2.5)), 2) == 0;
        const shown_name = if (highscore.input_len == 0 and caret_visible) "_" else highscore.inputSlice();
        drawSmallText(runtime_assets, shown_name, 410.0, prompt_y + 95.0, rl.Color.white);

        if (highscore.save_error) |save_error| {
            drawSmallText(runtime_assets, save_error, 410.0, prompt_y + 126.0, rl.Color.orange);
        }
    } else {
        drawSmallTextCentered(runtime_assets, "SCORE SAVED", prompt_y, HudTextColor.accent);
        drawSmallTextFmt("RANK #{d}  NAME {s}", runtime_assets, .{ highscore.rank_index + 1, highscore.record.name() }, 330.0, prompt_y + 28.0, HudTextColor.primary);
    }
}

const HudTextColor = struct {
    const primary = rl.Color.init(220, 220, 220, 255);
    const dim = rl.Color.init(170, 170, 180, 255);
    const accent = rl.Color.init(240, 200, 80, 255);
};

const HudFlags = struct {
    show_health: bool,
    show_weapon: bool,
    show_xp: bool,
    show_time: bool,
    show_quest_hud: bool,
};

fn hudFlagsForGameMode(game_mode: game_ids.GameModeId) HudFlags {
    return switch (game_mode) {
        .quests => .{
            .show_health = true,
            .show_weapon = true,
            .show_xp = true,
            .show_time = false,
            .show_quest_hud = true,
        },
        .survival => .{
            .show_health = true,
            .show_weapon = true,
            .show_xp = true,
            .show_time = false,
            .show_quest_hud = false,
        },
        .rush => .{
            .show_health = true,
            .show_weapon = false,
            .show_xp = false,
            .show_time = true,
            .show_quest_hud = false,
        },
        .typo => .{
            .show_health = true,
            .show_weapon = false,
            .show_xp = true,
            .show_time = true,
            .show_quest_hud = false,
        },
        .tutorial => .{
            .show_health = false,
            .show_weapon = false,
            .show_xp = false,
            .show_time = false,
            .show_quest_hud = false,
        },
    };
}

fn hudBonusIconId(bonus_id: game_ids.BonusId) ?i32 {
    return switch (bonus_id) {
        .energizer => 10,
        .weapon_power_up => 7,
        .double_experience => 4,
        .reflex_boost => 5,
        .shield => 6,
        .freeze => 8,
        .speed => 9,
        .fire_bullets => 11,
        else => null,
    };
}

fn collectHudBonusSpecs(session: *const runtime_session.DeterministicSession, dest: []HudBonusSpec, count: *usize) void {
    count.* = 0;
    const state = &session.state;
    const players = session.playersConst();

    appendHudBonusSpec(dest, count, .weapon_power_up, state.bonuses.weapon_power_up, 0.0);
    appendHudBonusSpec(dest, count, .reflex_boost, state.bonuses.reflex_boost, 0.0);
    appendHudBonusSpec(dest, count, .energizer, state.bonuses.energizer, 0.0);
    appendHudBonusSpec(dest, count, .double_experience, state.bonuses.double_experience, 0.0);
    appendHudBonusSpec(dest, count, .freeze, state.bonuses.freeze, 0.0);

    const player0 = if (players.len > 0) players[0] else null;
    const player1 = if (players.len > 1) players[1] else null;
    appendHudBonusSpec(
        dest,
        count,
        .fire_bullets,
        if (player0) |player| player.fire_bullets_timer else 0.0,
        if (player1) |player| player.fire_bullets_timer else 0.0,
    );
    appendHudBonusSpec(
        dest,
        count,
        .shield,
        if (player0) |player| player.shield_timer else 0.0,
        if (player1) |player| player.shield_timer else 0.0,
    );
    appendHudBonusSpec(
        dest,
        count,
        .speed,
        if (player0) |player| player.speed_bonus_timer else 0.0,
        if (player1) |player| player.speed_bonus_timer else 0.0,
    );
}

fn appendHudBonusSpec(dest: []HudBonusSpec, count: *usize, bonus_id: game_ids.BonusId, timer_value: f32, timer_value_alt: f32) void {
    if (!(timer_value > 0.0 or timer_value_alt > 0.0)) return;
    if (count.* >= dest.len) return;
    dest[count.*] = .{
        .bonus_id = bonus_id,
        .icon_id = hudBonusIconId(bonus_id) orelse -1,
        .timer_value = @max(timer_value, 0.0),
        .timer_value_alt = @max(timer_value_alt, 0.0),
    };
    count.* += 1;
}

fn hudUiScale() f32 {
    const screen_w: f32 = @floatFromInt(rl.getScreenWidth());
    const screen_h: f32 = @floatFromInt(rl.getScreenHeight());
    const scale = @min(screen_w / 1024.0, screen_h / 768.0);
    if (scale < 0.75) return 0.75;
    if (scale > 1.5) return 1.5;
    return scale;
}

fn hs(value: f32, scale: f32) f32 {
    return value * scale;
}

fn drawProgressBar(pos: rl.Vector2, width: f32, ratio_raw: f32, fg_color: rl.Color, scale: f32) void {
    const ratio = std.math.clamp(ratio_raw, @as(f32, 0.0), @as(f32, 1.0));
    rl.drawRectangle(@intFromFloat(pos.x), @intFromFloat(pos.y), @intFromFloat(width), @intFromFloat(4.0 * scale), rl.Color.init(
        @intFromFloat(@as(f32, @floatFromInt(fg_color.r)) * 0.6),
        @intFromFloat(@as(f32, @floatFromInt(fg_color.g)) * 0.6),
        @intFromFloat(@as(f32, @floatFromInt(fg_color.b)) * 0.6),
        102,
    ));
    rl.drawRectangle(
        @intFromFloat(pos.x + 1.0 * scale),
        @intFromFloat(pos.y + 1.0 * scale),
        @intFromFloat(@max(0.0, width - 2.0 * scale) * ratio),
        @intFromFloat(2.0 * scale),
        fg_color,
    );
}

fn drawSliderRow(assets: *const window_assets.RuntimeAssets, pos: rl.Vector2, count: i32, value: i32) void {
    const rect_on = assets.texture(.ui_rect_on);
    const rect_off = assets.texture(.ui_rect_off);
    var idx: i32 = 0;
    while (idx < count) : (idx += 1) {
        const tex = if (idx < value) rect_on else rect_off;
        const tint = if (idx < value) rl.Color.white else colorWithAlpha(rl.Color.white, 0.5);
        rl.drawTexturePro(
            tex,
            rl.Rectangle.init(0.0, 0.0, @floatFromInt(tex.width), @floatFromInt(tex.height)),
            rl.Rectangle.init(pos.x + @as(f32, @floatFromInt(idx * tex.width)), pos.y, @floatFromInt(tex.width), @floatFromInt(tex.height)),
            rl.Vector2.zero(),
            0.0,
            tint,
        );
    }
}

fn questProgressRatio(session: *const runtime_session.DeterministicSession) ?f32 {
    if (session.game_mode != .quests) return null;
    if (session.quest_completed or session.quest_completion_transition_ms >= 0.0) return 1.0;
    if (session.reset_quest_spawn_entries_len == 0) return null;
    const last_trigger_ms = session.quest_spawn_entries_storage[session.reset_quest_spawn_entries_len - 1].trigger_ms;
    if (last_trigger_ms <= 0) return null;
    return std.math.clamp(session.quest_spawn_timeline_ms / @as(f32, @floatFromInt(last_trigger_ms)), @as(f32, 0.0), @as(f32, 1.0));
}

fn drawModeClock(assets: *const window_assets.RuntimeAssets, elapsed_ms: f32, x: f32, y: f32, scale: f32) void {
    drawTextureFit(assets.texture(.ui_clock_table), rl.Rectangle.init(x, y, hs(32.0, scale), hs(32.0, scale)), colorWithAlpha(rl.Color.white, 0.9));
    rl.drawTexturePro(
        assets.texture(.ui_clock_pointer),
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(assets.texture(.ui_clock_pointer).width), @floatFromInt(assets.texture(.ui_clock_pointer).height)),
        rl.Rectangle.init(x + hs(16.0, scale), y + hs(16.0, scale), hs(32.0, scale), hs(32.0, scale)),
        rl.Vector2.init(hs(16.0, scale), hs(16.0, scale)),
        elapsed_ms * 0.006,
        colorWithAlpha(rl.Color.white, 0.9),
    );
}

fn drawQuestHud(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets, scale: f32) void {
    const elapsed_ms = @as(f32, @floatFromInt(gameplay.last_update.elapsed_ms_sim));
    const slide_x = if (elapsed_ms < 1000.0) (1000.0 - elapsed_ms) * -0.128 * scale else 0.0;

    drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(slide_x - hs(90.0, scale), hs(67.0, scale), hs(182.0, scale), hs(53.0, scale)), colorWithAlpha(rl.Color.white, 0.7));
    drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(-hs(80.0, scale), hs(107.0, scale), hs(182.0, scale), hs(53.0, scale)), colorWithAlpha(rl.Color.white, 0.7));
    drawModeClock(assets, elapsed_ms, slide_x + hs(2.0, scale), hs(78.0, scale), scale);
    drawSmallTextFmt("{d}:{d:0>2}", assets, .{ @divTrunc(gameplay.last_update.elapsed_ms_sim, 60_000), @mod(@divTrunc(gameplay.last_update.elapsed_ms_sim, 1000), 60) }, slide_x + hs(32.0, scale), hs(86.0, scale), HudTextColor.primary);
    drawSmallText(assets, "Progress", hs(18.0, scale), hs(122.0, scale), HudTextColor.primary);
    if (questProgressRatio(&gameplay.runner.session)) |ratio| {
        drawProgressBar(rl.Vector2.init(hs(10.0, scale), hs(139.0, scale)), hs(70.0, scale), ratio, rl.Color.init(51, 204, 77, 204), scale);
    }
}

fn drawBonusHud(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets, scale: f32) void {
    var bonus_y: f32 = if (gameplay.runner.session.game_mode == .quests) hs(201.0, scale) else hs(121.0, scale);
    const bonuses_texture = assets.texture(.bonuses);
    for (gameplay.hud_state.bonus_slots) |slot| {
        if (!slot.active) continue;
        if (slot.slide_x < -hs(184.0, scale)) {
            bonus_y += hs(52.0, scale);
            continue;
        }
        const slide_x = slot.slide_x * scale;
        drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(slide_x, bonus_y - hs(11.0, scale), hs(182.0, scale), hs(53.0, scale)), colorWithAlpha(rl.Color.white, 0.7));
        if (slot.icon_id >= 0) {
            drawTextureRegionCenteredRotated(
                bonuses_texture,
                window_atlas.bonusIconRect(bonuses_texture.width, bonuses_texture.height, slot.icon_id),
                rl.Vector2.init(slide_x + hs(15.0, scale), bonus_y + hs(16.0, scale)),
                hs(32.0, scale),
                hs(32.0, scale),
                0.0,
                rl.Color.white,
            );
        }
        drawSmallText(assets, game_ids.bonusDisplayName(slot.bonus_id, gameplay.runner.session.state.preserve_bugs), slide_x + hs(36.0, scale), bonus_y + hs(6.0, scale), HudTextColor.primary);
        drawProgressBar(rl.Vector2.init(slide_x + hs(36.0, scale), bonus_y + hs(21.0, scale)), hs(100.0, scale), slot.timer_value * 0.05, rl.Color.init(26, 77, 153, 179), scale);
        if (slot.timer_value_alt > 0.0) {
            drawProgressBar(rl.Vector2.init(slide_x + hs(36.0, scale), bonus_y + hs(27.0, scale)), hs(100.0, scale), slot.timer_value_alt * 0.05, rl.Color.init(26, 77, 153, 179), scale);
        }
        bonus_y += hs(52.0, scale);
    }
}

fn drawWeaponAuxHud(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets, scale: f32) void {
    const players = gameplay.runner.session.playersConst();
    var bonus_bottom_y: f32 = if (gameplay.runner.session.game_mode == .quests) hs(201.0, scale) else hs(121.0, scale);
    for (gameplay.hud_state.bonus_slots) |slot| {
        if (slot.active) bonus_bottom_y += hs(52.0, scale);
    }
    for (players, 0..) |player, idx| {
        if (!(player.aux_timer > 0.0)) continue;
        const fade_raw = if (player.aux_timer > 1.0) 2.0 - player.aux_timer else player.aux_timer;
        const fade = std.math.clamp(fade_raw, @as(f32, 0.0), @as(f32, 1.0));
        if (fade <= 1e-3) continue;
        const y = bonus_bottom_y - hs(17.0, scale) + @as(f32, @floatFromInt(idx)) * hs(32.0, scale);
        drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(-hs(12.0, scale), y, hs(182.0, scale), hs(53.0, scale)), colorWithAlpha(rl.Color.white, fade * 0.8));
        const icon_index = weapon_data.weaponIconIndex(player.weapon.weapon_id);
        if (icon_index >= 0) {
            drawTextureRegionCenteredRotated(
                assets.texture(.ui_wicons),
                window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index),
                rl.Vector2.init(hs(135.0, scale), y + hs(20.0, scale)),
                hs(60.0, scale),
                hs(30.0, scale),
                0.0,
                colorWithAlpha(rl.Color.white, fade * 0.8),
            );
        }
        drawSmallText(assets, game_ids.weaponDisplayName(player.weapon.weapon_id, gameplay.runner.session.state.preserve_bugs), hs(8.0, scale), y + hs(18.0, scale), colorWithAlpha(HudTextColor.primary, fade));
    }
}

fn drawAmmoIndicators(assets: *const window_assets.RuntimeAssets, texture_id: window_assets.TextureId, ammo: f32, clip_size: i32, scale: f32) void {
    const texture = assets.texture(texture_id);
    const ammo_count = @max(0, @as(i32, @intFromFloat(ammo)));
    var bars = @max(0, clip_size);
    if (bars > 30) bars = 20;
    var idx: i32 = 0;
    while (idx < bars) : (idx += 1) {
        const alpha: f32 = if (idx < ammo_count) 0.8 else 0.24;
        drawTextureFit(
            texture,
            rl.Rectangle.init(hs(300.0, scale) + @as(f32, @floatFromInt(idx)) * hs(6.0, scale), hs(10.0, scale), hs(6.0, scale), hs(16.0, scale)),
            colorWithAlpha(rl.Color.white, alpha),
        );
    }
    if (ammo_count > bars) {
        drawSmallTextFmt("+ {d}", assets, .{ammo_count - bars}, hs(300.0, scale) + @as(f32, @floatFromInt(bars)) * hs(6.0, scale) + hs(8.0, scale), hs(11.0, scale), HudTextColor.primary);
    }
}

fn weaponIndicatorTextureId(weapon_id: game_ids.WeaponId) window_assets.TextureId {
    return switch (weapon_id) {
        .rocket_launcher, .seeker_rockets, .mini_rocket_swarmers, .rocket_minigun, .nuke_launcher => .ui_ind_rocket,
        .ion_rifle, .ion_minigun, .ion_cannon, .ion_shotgun, .lightning_rifle => .ui_ind_electric,
        .flamethrower, .blow_torch, .hr_flamer, .flameburst, .fire_bullets => .ui_ind_fire,
        else => .ui_ind_bullet,
    };
}

fn xpProgressRatio(xp: i32, level: i32) f32 {
    const safe_level = @max(level, 1);
    const prev_threshold = if (safe_level <= 1) 0 else survivalLevelThreshold(safe_level - 1);
    const next_threshold = survivalLevelThreshold(safe_level);
    if (next_threshold <= prev_threshold) return 0.0;
    return std.math.clamp(
        @as(f32, @floatFromInt(xp - prev_threshold)) / @as(f32, @floatFromInt(next_threshold - prev_threshold)),
        @as(f32, 0.0),
        @as(f32, 1.0),
    );
}

fn survivalLevelThreshold(level: i32) i32 {
    const safe_level = @max(level, 1);
    return @intFromFloat(1000.0 + std.math.pow(f32, @floatFromInt(safe_level), 1.8) * 1000.0);
}

fn drawSmallText(
    runtime_assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    x: f32,
    y: f32,
    color: rl.Color,
) void {
    const texture = runtime_assets.texture(.small_white);
    var x_pos = @floor(x);
    var y_pos = @floor(y);
    const base_x = x_pos;
    for (text) |value| {
        switch (value) {
            '\n' => {
                x_pos = base_x;
                y_pos += 16.0;
                continue;
            },
            '\r' => continue,
            else => {},
        }

        const width = runtime_assets.small_font_widths[value];
        if (width == 0) continue;
        const col = value % 16;
        const row = value / 16;
        rl.drawTexturePro(
            texture,
            rl.Rectangle.init(@as(f32, @floatFromInt(col * 16)), @as(f32, @floatFromInt(row * 16)), @floatFromInt(width), 16.0),
            rl.Rectangle.init(x_pos, y_pos, @floatFromInt(width), 16.0),
            rl.Vector2.zero(),
            0.0,
            color,
        );
        x_pos += @as(f32, @floatFromInt(width));
    }
}

fn measureSmallText(runtime_assets: *const window_assets.RuntimeAssets, text: []const u8) f32 {
    var width: f32 = 0.0;
    var best: f32 = 0.0;
    for (text) |value| {
        switch (value) {
            '\n' => {
                best = @max(best, width);
                width = 0.0;
                continue;
            },
            '\r' => continue,
            else => {},
        }
        width += @as(f32, @floatFromInt(runtime_assets.small_font_widths[value]));
    }
    return @max(best, width);
}

fn drawSmallTextFmt(
    comptime fmt: []const u8,
    runtime_assets: *const window_assets.RuntimeAssets,
    args: anytype,
    x: f32,
    y: f32,
    color: rl.Color,
) void {
    var buf: [256]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, args) catch return;
    drawSmallText(runtime_assets, text, x, y, color);
}

fn drawSmallTextCentered(
    runtime_assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    y: f32,
    color: rl.Color,
) void {
    const width = measureSmallText(runtime_assets, text);
    const x = (@as(f32, @floatFromInt(rl.getScreenWidth())) - width) * 0.5;
    drawSmallText(runtime_assets, text, x, y, color);
}

fn drawGameplayHud(gameplay: *const GameplayScreen, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const runner = &gameplay.runner;
    const update = gameplay.last_update;
    const player = runner.player0Const() orelse return;
    if (runtime_assets) |assets| {
        const flags = hudFlagsForGameMode(runner.session.game_mode);
        const elapsed_ms = @as(f32, @floatFromInt(update.elapsed_ms_sim));
        const top_alpha = 0.7;
        const scale = hudUiScale();

        drawTextureFit(
            assets.texture(.ui_game_top),
            rl.Rectangle.init(0.0, 0.0, hs(512.0, scale), hs(64.0, scale)),
            colorWithAlpha(rl.Color.white, top_alpha),
        );

        if (flags.show_health) {
            const pulse_speed: f32 = if (player.health < 30.0) 5.0 else 2.0;
            const t = elapsed_ms * 0.001;
            const pulse = std.math.pow(f32, std.math.sin(t * pulse_speed), 4) * 4.0 + 14.0;
            drawTextureCentered(
                assets.texture(.ui_life_heart),
                rl.Vector2.init(hs(27.0, scale), hs(21.0, scale)),
                pulse * 2.0 * scale,
                pulse * 2.0 * scale,
                colorWithAlpha(rl.Color.white, 0.8),
            );

            const ind_life = assets.texture(.ui_ind_life);
            const health_ratio = std.math.clamp(player.health / 100.0, @as(f32, 0.0), @as(f32, 1.0));
            drawTextureFit(ind_life, rl.Rectangle.init(hs(64.0, scale), hs(16.0, scale), hs(120.0, scale), hs(9.0, scale)), colorWithAlpha(rl.Color.white, 0.5));
            if (health_ratio > 0.0) {
                rl.drawTexturePro(
                    ind_life,
                    rl.Rectangle.init(0.0, 0.0, @as(f32, @floatFromInt(ind_life.width)) * health_ratio, @floatFromInt(ind_life.height)),
                    rl.Rectangle.init(hs(64.0, scale), hs(16.0, scale), hs(120.0, scale) * health_ratio, hs(9.0, scale)),
                    rl.Vector2.zero(),
                    0.0,
                    colorWithAlpha(rl.Color.white, 0.8),
                );
            }
        }

        if (flags.show_weapon) {
            const weapon_id = std.enums.fromInt(game_ids.WeaponId, update.player_weapon_id) orelse .pistol;
            const icon_index = weapon_data.weaponIconIndex(weapon_id);
            if (icon_index >= 0) {
                drawTextureRegionCenteredRotated(
                    assets.texture(.ui_wicons),
                    window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index),
                    rl.Vector2.init(hs(252.0, scale), hs(18.0, scale)),
                    hs(64.0, scale),
                    hs(32.0, scale),
                    0.0,
                    colorWithAlpha(rl.Color.white, 0.8),
                );
            }
            drawAmmoIndicators(assets, weaponIndicatorTextureId(weapon_id), player.weapon.ammo, player.weapon.clip_size, scale);
        }

        if (flags.show_quest_hud) {
            drawQuestHud(gameplay, assets, scale);
        }

        if (flags.show_xp) {
            const hud_y_shift: f32 = if (flags.show_quest_hud) hs(80.0, scale) else 0.0;
            drawTextureFit(
                assets.texture(.ui_ind_panel),
                rl.Rectangle.init(-hs(68.0, scale), hs(60.0, scale) + hud_y_shift, hs(182.0, scale), hs(53.0, scale)),
                colorWithAlpha(rl.Color.white, 0.9),
            );
            const xp_display = gameplay.hud_state.survival_xp_smoothed;
            drawSmallText(assets, "Xp", hs(4.0, scale), hs(78.0, scale) + hud_y_shift, HudTextColor.dim);
            drawSmallTextFmt("{d}", assets, .{xp_display}, hs(26.0, scale), hs(74.0, scale) + hud_y_shift, HudTextColor.primary);
            drawSmallTextFmt("{d}", assets, .{update.player_level}, hs(85.0, scale), hs(79.0, scale) + hud_y_shift, HudTextColor.primary);
            drawProgressBar(rl.Vector2.init(hs(26.0, scale), hs(91.0, scale) + hud_y_shift), hs(54.0, scale), xpProgressRatio(update.player_experience, update.player_level), rl.Color.init(26, 77, 153, 255), scale);
        }

        if (flags.show_time) {
            drawModeClock(assets, elapsed_ms, hs(220.0, scale), hs(2.0, scale), scale);
            drawSmallTextFmt("{d} seconds", assets, .{@divTrunc(update.elapsed_ms_sim, 1000)}, hs(255.0, scale), hs(10.0, scale), HudTextColor.primary);
        }

        drawBonusHud(gameplay, assets, scale);
        drawWeaponAuxHud(gameplay, assets, scale);
        return;
    }

    rl.drawRectangleRounded(
        .{
            .x = 22.0,
            .y = 20.0,
            .width = 380.0,
            .height = 132.0,
        },
        0.14,
        8,
        overlay_color,
    );
    drawTextFmt("hp {d:.1}  level {d}  xp {d}", .{ update.player_health, update.player_level, update.player_experience }, 36, 34, 22, text_color);
    drawTextFmt("weapon {s}  ammo {d:.1}", .{ weaponName(update.player_weapon_id), player.weapon.ammo }, 36, 62, 22, text_color);
    drawTextFmt("shots {d}  hits {d}  creatures {d}", .{ update.shots_fired, update.shots_hit, update.creature_active_count }, 36, 90, 20, muted_text);
    drawTextFmt("elapsed {d}ms  pickups {d}  pending perks {d}", .{ update.elapsed_ms_sim, update.bonus_active_count, runner.perkPendingCount() }, 36, 116, 20, muted_text);
}

fn drawTypoNameLabels(
    runner: *const live_runner.LiveRunner,
    assets: *const window_assets.RuntimeAssets,
    transform: window_viewport.ViewTransform,
    entity_alpha: f32,
) void {
    for (runner.session.creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const label = runner.session.state.typo.names.nameSlice(idx);
        if (label.len == 0) continue;

        var label_alpha = entity_alpha;
        if (creature.lifecycle_stage < 0.0) {
            label_alpha *= std.math.clamp((creature.lifecycle_stage + 10.0) * 0.1, @as(f32, 0.0), @as(f32, 1.0));
        }
        if (!(label_alpha > 1e-3)) continue;

        const screen_x = (creature.pos.x + transform.camera.x) * transform.view_scale.x;
        const screen_y = (creature.pos.y + transform.camera.y) * transform.view_scale.y;
        const text_w = measureSmallText(assets, label);
        const x = screen_x - text_w * 0.5;
        const y = screen_y - 50.0;

        rl.drawRectangleRec(
            .{
                .x = x - 4.0,
                .y = y,
                .width = text_w + 8.0,
                .height = 15.0,
            },
            colorWithAlpha(rl.Color.black, label_alpha * 0.67),
        );
        drawSmallText(assets, label, x, y, colorWithAlpha(rl.Color.white, label_alpha));
    }
}

fn drawTypoTypingBox(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
    const screen_h: f32 = @floatFromInt(rl.getScreenHeight());
    const panel_y = screen_h - 144.0;
    const text_y = screen_h - 127.0;

    drawTextureFit(
        assets.texture(.ui_ind_panel),
        rl.Rectangle.init(-1.0, panel_y, 182.0, 53.0),
        colorWithAlpha(rl.Color.white, 0.7),
    );

    const text = gameplay.runner.session.state.typo.typing.slice();
    drawSmallTextFmt(">{s}", assets, .{text}, 6.0, text_y, rl.Color.white);

    const cursor_dim = std.math.sin(gameplay.render_time_s * 4.0) > 0.0;
    const cursor_alpha: f32 = if (cursor_dim) 0.4 else 1.0;
    const cursor_x = measureSmallText(assets, text) + 14.0;
    drawSmallText(assets, "_", cursor_x, text_y, colorWithAlpha(rl.Color.white, cursor_alpha));
}

fn drawTutorialOverlay(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
    const overlay = gameplay.runner.session.state.tutorial_overlay;
    if (overlay.prompt_stage_index >= 0 and overlay.prompt_alpha > 1e-3) {
        drawTutorialPanel(
            assets,
            tutorial_runtime.promptText(overlay.prompt_stage_index),
            64.0,
            overlay.prompt_alpha,
        );
    }
    if (overlay.hint_index >= 0 and overlay.hint_alpha > 1e-3) {
        drawTutorialPanel(
            assets,
            tutorial_runtime.hintText(overlay.hint_index, gameplay.runner.session.state.tutorial.preserve_bugs),
            148.0,
            overlay.hint_alpha,
        );
    }

    drawTutorialPromptButtons(gameplay, assets);
}

fn tutorialPanelRect(
    assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    top_y: f32,
) ?rl.Rectangle {
    if (text.len == 0) return null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var max_w: f32 = 0.0;
    var line_count: usize = 0;
    while (lines.next()) |line| {
        max_w = @max(max_w, measureSmallText(assets, line));
        line_count += 1;
    }

    const line_h: f32 = 14.0;
    const pad_x: f32 = 20.0;
    const pad_y: f32 = 8.0;
    const width = max_w + pad_x * 2.0;
    const height = @as(f32, @floatFromInt(line_count)) * line_h + pad_y * 2.0;
    const left = (@as(f32, @floatFromInt(rl.getScreenWidth())) - width) * 0.5;
    return rl.Rectangle.init(left, top_y, width, height);
}

fn drawTutorialPanel(
    assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    top_y: f32,
    alpha: f32,
) void {
    if (text.len == 0 or !(alpha > 1e-3)) return;

    const rect = tutorialPanelRect(assets, text, top_y) orelse return;
    rl.drawRectangle(
        @intFromFloat(rect.x),
        @intFromFloat(rect.y),
        @intFromFloat(rect.width),
        @intFromFloat(rect.height),
        colorWithAlpha(rl.Color.black, alpha * 0.8),
    );
    rl.drawRectangleLines(
        @intFromFloat(rect.x),
        @intFromFloat(rect.y),
        @intFromFloat(rect.width),
        @intFromFloat(rect.height),
        colorWithAlpha(rl.Color.white, alpha),
    );

    const pad_x: f32 = 20.0;
    const pad_y: f32 = 8.0;
    const line_h: f32 = 14.0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var y = rect.y + pad_y;
    while (lines.next()) |line| : (y += line_h) {
        drawSmallText(assets, line, rect.x + pad_x, y, colorWithAlpha(rl.Color.white, alpha * 0.9));
    }
}

const TutorialPromptAction = enum {
    none,
    close_to_menu,
    restart,
};

fn tutorialSkipButton() UiButton {
    return window_ui.buttonAt("Skip tutorial", 10.0, @as(f32, @floatFromInt(rl.getScreenHeight())) - 50.0, true);
}

fn tutorialCompleteButtons(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) [2]UiButton {
    const text = tutorial_runtime.promptText(gameplay.runner.session.state.tutorial_overlay.prompt_stage_index);
    const rect = tutorialPanelRect(assets, text, 64.0) orelse rl.Rectangle.init(0.0, 64.0, 320.0, 40.0);
    const gap: f32 = 18.0;
    const top_y = rect.y + rect.height + 10.0;
    const play_w = window_ui.buttonWidth("Play a game", true);
    const repeat_w = window_ui.buttonWidth("Repeat tutorial", true);
    return .{
        .{
            .label = "Play a game",
            .rect = rl.Rectangle.init(rect.x + 10.0, top_y, play_w, window_ui.button_plate_height),
        },
        .{
            .label = "Repeat tutorial",
            .rect = rl.Rectangle.init(rect.x + 10.0 + play_w + gap, top_y, repeat_w, window_ui.button_plate_height),
        },
    };
}

fn updateTutorialPromptButtons(self: *App, gameplay: *GameplayScreen) TutorialPromptAction {
    const overlay = gameplay.runner.session.state.tutorial_overlay;
    const tutorial = gameplay.runner.session.state.tutorial;
    if (overlay.prompt_stage_index < 0 or overlay.prompt_alpha <= 1e-3) return .none;

    if (tutorial.stage_index == 8) {
        const assets = if (self.runtime_assets) |*runtime_assets| runtime_assets else return .none;
        const buttons = tutorialCompleteButtons(gameplay, assets);
        window_ui.updateSelectionFromPointer(&gameplay.tutorial_prompt_selection, buttons[0..]);
        if (rl.isKeyPressed(.left) or rl.isKeyPressed(.a)) {
            gameplay.tutorial_prompt_selection = if (gameplay.tutorial_prompt_selection == 0) buttons.len - 1 else gameplay.tutorial_prompt_selection - 1;
        }
        if (rl.isKeyPressed(.right) or rl.isKeyPressed(.d)) {
            gameplay.tutorial_prompt_selection = (gameplay.tutorial_prompt_selection + 1) % buttons.len;
        }
        if (!window_ui.buttonActivated(buttons[0..], gameplay.tutorial_prompt_selection)) return .none;
        self.audio.playUiButtonClick();
        return if (gameplay.tutorial_prompt_selection == 0) .close_to_menu else .restart;
    }

    const skip_alpha = std.math.clamp(@as(f32, @floatFromInt(tutorial.stage_timer_ms - 1000)) * 0.001, @as(f32, 0.0), @as(f32, 1.0));
    if (skip_alpha <= 1e-3) return .none;
    const button = tutorialSkipButton();
    gameplay.tutorial_prompt_selection = 0;
    if (!window_ui.buttonActivated(&.{button}, 0)) return .none;
    self.audio.playUiButtonClick();
    return .close_to_menu;
}

fn drawTutorialPromptButtons(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
    const overlay = gameplay.runner.session.state.tutorial_overlay;
    if (overlay.prompt_stage_index < 0 or overlay.prompt_alpha <= 1e-3) return;

    if (gameplay.runner.session.state.tutorial.stage_index == 8) {
        const buttons = tutorialCompleteButtons(gameplay, assets);
        for (buttons, 0..) |button, idx| {
            const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            window_ui.drawButton(
                button,
                idx == gameplay.tutorial_prompt_selection,
                hovered,
                assets,
            );
        }
        return;
    }

    const skip_alpha = std.math.clamp(@as(f32, @floatFromInt(gameplay.runner.session.state.tutorial.stage_timer_ms - 1000)) * 0.001, @as(f32, 0.0), @as(f32, 1.0));
    if (skip_alpha <= 1e-3) return;
    const button = tutorialSkipButton();
    const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
    window_ui.drawButton(button, false, hovered, assets);
}

fn zeroSessionSummary() runtime_session.SessionSummary {
    return .{
        .ticks_processed = 0,
        .event_index = 0,
        .elapsed_ms_sim = 0,
        .perk_menu_open_count = 0,
        .perk_pick_count = 0,
        .fire_pressed_count = 0,
        .reload_pressed_count = 0,
        .stage_spawn_count = 0,
        .wave_spawn_count = 0,
        .wave_spawn_rng_state = 0,
        .player_level = 0,
        .player_experience = 0,
        .player_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
        .perk_pending_count = 0,
        .creature_active_count = 0,
    };
}

fn nextRunSeed(seed_state: *u32) u32 {
    seed_state.* = seed_state.* *% 1664525 +% 1013904223;
    return if (seed_state.* == 0) 1 else seed_state.*;
}

fn nextQuestLevelKey(level_key: i32) ?i32 {
    const stage = @divTrunc(level_key, 100);
    const minor = @mod(level_key, 100);
    if (stage < 1 or stage > 5 or minor < 1 or minor > 10) return null;
    if (stage == 5 and minor == 10) return null;
    if (minor < 10) return stage * 100 + minor + 1;
    return (stage + 1) * 100 + 1;
}

fn runConfigForLiveMode(mode: game_ids.GameModeId, quest_level_key: ?i32, seed_state: *u32) live_runner.LiveModeConfig {
    const seed = nextRunSeed(seed_state);
    return switch (mode) {
        .rush => .{
            .seed = seed,
            .game_mode = .rush,
        },
        .quests => .{
            .seed = seed,
            .game_mode = .quests,
            .quest_level_key = quest_level_key orelse 101,
        },
        .typo => .{
            .seed = seed,
            .game_mode = .typo,
        },
        .tutorial => .{
            .seed = seed,
            .game_mode = .tutorial,
        },
        else => .{
            .seed = seed,
            .game_mode = .survival,
        },
    };
}

fn resultsTitle(reason: ResultsReason) [:0]const u8 {
    return switch (reason) {
        .dead => "Run Over",
        .completed => "Quest Complete",
        .runtime_error => "Run Interrupted",
        .abandoned => "Run Abandoned",
    };
}

fn resultsSubtitle(reason: ResultsReason) [:0]const u8 {
    return switch (reason) {
        .dead => "All players are down.",
        .completed => "Quest objectives cleared.",
        .abandoned => "Run returned to menu before completion.",
        .runtime_error => "Runtime could not complete the run.",
    };
}

fn weaponName(weapon_id_raw: i32) []const u8 {
    const weapon_id = std.enums.fromInt(game_ids.WeaponId, weapon_id_raw) orelse return "unknown";
    return @tagName(weapon_id);
}

fn toRlVec(vec: state_mod.Vec2) rl.Vector2 {
    return .{
        .x = vec.x,
        .y = vec.y,
    };
}

fn drawCenteredText(text: [:0]const u8, y: i32, font_size: i32, color: rl.Color) void {
    const width = rl.measureText(text, font_size);
    const x = @divTrunc(rl.getScreenWidth() - width, 2);
    rl.drawText(text, x, y, font_size, color);
}

fn drawCenteredTextFmt(comptime fmt: []const u8, args: anytype, y: i32, font_size: i32, color: rl.Color) void {
    var buf: [256]u8 = undefined;
    const text = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    drawCenteredText(text, y, font_size, color);
}

fn drawTextFmt(comptime fmt: []const u8, args: anytype, x: i32, y: i32, font_size: i32, color: rl.Color) void {
    var buf: [256]u8 = undefined;
    const text = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    rl.drawText(text, x, y, font_size, color);
}

fn drawTextSlice(text: []const u8, x: i32, y: i32, font_size: i32, color: rl.Color) void {
    var buf: [256]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{text}) catch return;
    rl.drawText(z, x, y, font_size, color);
}
