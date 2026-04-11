const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const persistence = cz.persistence;
const runtime_anim = cz.anim;
const weapon_data = cz.weapon_data;
const app_runtime = @import("app_runtime.zig");
const audio_mod = @import("audio/audio.zig");
const input_codes = @import("input_codes.zig");
const local_input = cz.local_input;
const live_audio = @import("audio/live_audio.zig");
const window_assets = @import("window_assets.zig");
const window_atlas = cz.window_atlas;
const window_boot = @import("window_boot.zig");
const window_ground = @import("window_ground.zig");
const window_menu = @import("window_menu.zig");
const window_menu_panels = @import("window_menu_panels.zig");
const window_projectiles = @import("window_projectiles.zig");
const window_terrain_fx = @import("window_terrain_fx.zig");
const window_ui = @import("window_ui.zig");

const bonuses_runtime = cz.bonuses;
const game_ids = cz.game_ids;
const live_runner = cz.live_runner;
const runtime_perks = cz.perks;
const runtime_session = cz.session;
const state_mod = cz.state;

const window_width = 1280;
const window_height = 720;
const ui_button_width: f32 = 280.0;
const ui_button_height: f32 = 56.0;
const world_margin: f32 = 56.0;

const bg_color = rl.Color.init(16, 12, 10, 255);
const panel_color = rl.Color.init(37, 24, 20, 255);
const panel_outline = rl.Color.init(122, 78, 58, 255);
const accent_color = rl.Color.init(218, 80, 46, 255);
const accent_dim = rl.Color.init(127, 45, 29, 255);
const text_color = rl.Color.init(245, 236, 225, 255);
const muted_text = rl.Color.init(171, 150, 132, 255);
const arena_color = rl.Color.init(33, 25, 22, 255);
const arena_grid = rl.Color.init(56, 40, 34, 255);
const border_color = rl.Color.init(171, 122, 91, 255);
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
    gameplay,
    results,
    high_scores,
    options,
    info_view,
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
    hud_state: HudRuntimeState = .{},
    ground: ?window_ground.GroundRenderer = null,
    terrain_fx: window_terrain_fx.TerrainFxTracker = .{},

    fn deinit(self: *GameplayScreen) void {
        if (self.ground) |*ground| {
            ground.deinit();
            self.ground = null;
        }
        self.* = undefined;
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
        var step = @max(@as(i32, 1), @as(i32, @intFromFloat(frame_dt_ms)) / 2);
        const diff = @abs(smoothed - target);
        if (diff > 1000) {
            step *= @divTrunc(diff, 100);
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
            if (slot.slide_x < -184.0) {
                slot.* = .{};
            }
        }
    }
};

const ResultsScreen = struct {
    reason: ResultsReason,
    run_config: live_runner.LiveModeConfig,
    summary: runtime_session.SessionSummary,
    player_health: f32,
    runtime_error: ?[]const u8 = null,
    highscore: ?ResultsHighscoreState = null,
};

const HighScoresScreen = struct {
    mode: game_ids.GameModeId = .survival,
    quest_level_key: i32 = 101,
    selection: usize = 0,
    records: []persistence.highscores.HighScoreRecord = &.{},
    records_owned: bool = false,
    load_error: ?[]const u8 = null,
    return_to_statistics: bool = false,

    fn clear(self: *HighScoresScreen, allocator: std.mem.Allocator) void {
        if (self.records_owned) {
            allocator.free(self.records);
        }
        self.records = &.{};
        self.records_owned = false;
    }

    fn deinit(self: *HighScoresScreen, allocator: std.mem.Allocator) void {
        self.clear(allocator);
        self.* = undefined;
    }
};

const OptionsScreen = struct {
    selection: usize = 0,
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
    statistics_menu: window_menu_panels.StatisticsState = .{},
    info_view: window_menu_panels.InfoViewState = .{},
    gameplay: ?GameplayScreen = null,
    results: ?ResultsScreen = null,
    high_scores: ?HighScoresScreen = null,
    options: OptionsScreen = .{},
    runtime_assets: ?window_assets.RuntimeAssets = null,
    audio: live_audio.Bridge,
    assets_state: AssetsState = .unavailable,
    assets_message: ?[]u8 = null,
    next_seed_state: u32 = 0xC0FFEE,
    quit_requested: bool = false,

    fn init(allocator: std.mem.Allocator, runtime: app_runtime.DesktopRuntime) App {
        var app: App = .{
            .allocator = allocator,
            .runtime = runtime,
            .audio = live_audio.Bridge.init(allocator, audio_mod.audioConfigFromCrimsonCfg(runtime.config), null),
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
        if (self.high_scores) |*high_scores| {
            high_scores.deinit(self.allocator);
            self.high_scores = null;
        }
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

    fn update(self: *App, frame_dt: f32) void {
        switch (self.screen) {
            .boot => self.updateBoot(frame_dt),
            .main_menu => self.updateMainMenu(frame_dt),
            .play_game_menu => self.updatePlayGameMenu(frame_dt),
            .quests_menu => self.updateQuestsMenu(frame_dt),
            .statistics_menu => self.updateStatisticsMenu(frame_dt),
            .gameplay => self.updateGameplay(frame_dt),
            .results => self.updateResults(),
            .high_scores => self.updateHighScores(),
            .options => self.updateOptions(),
            .info_view => self.updateInfoView(),
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
            .gameplay => self.drawGameplay(),
            .results => self.drawResults(),
            .high_scores => self.drawHighScores(),
            .options => self.drawOptions(),
            .info_view => self.drawInfoView(),
        }
    }

    fn updateBoot(self: *App, frame_dt: f32) void {
        const result = window_boot.update(&self.boot, frame_dt);
        if (result.finished) {
            self.menu.openRoot();
            self.screen = .main_menu;
            return;
        }
        self.audio.ensureIntroMusic();
    }

    fn updateMainMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuTheme();
        const menu_update = window_menu.update(
            &self.menu,
            frame_dt,
            if (self.runtime_assets) |*assets| assets else null,
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
                    self.screen = .play_game_menu;
                },
                .open_options => self.screen = .options,
                .open_statistics => {
                    self.statistics_menu.reset();
                    self.screen = .statistics_menu;
                },
                .quit => self.quit_requested = true,
            }
        }
    }

    fn updatePlayGameMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuTheme();
        const play_game_update = window_menu_panels.updatePlayGame(&self.play_game_menu, frame_dt, &self.runtime.config);
        if (play_game_update.config_dirty) self.runtime.config_dirty = true;
        if (play_game_update.play_panel_click and !self.play_game_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.play_game_menu.panel.panel_open_sfx_played = true;
        }
        if (play_game_update.play_button_click) self.audio.playUiButtonClick();
        if (play_game_update.action) |action| switch (action) {
            .start_survival => self.startNewRun(runConfigForLiveMode(.survival, null, &self.next_seed_state)),
            .start_rush => self.startNewRun(runConfigForLiveMode(.rush, null, &self.next_seed_state)),
            .open_quests => {
                self.quests_menu.reset();
                self.screen = .quests_menu;
            },
            .back_to_menu => {
                self.menu.openRoot();
                self.screen = .main_menu;
            },
        };
    }

    fn updateQuestsMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuTheme();
        const quest_update = window_menu_panels.updateQuests(&self.quests_menu, frame_dt, &self.runtime.config, self.runtime.status);
        if (quest_update.config_dirty) self.runtime.config_dirty = true;
        if (quest_update.play_panel_click and !self.quests_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.quests_menu.panel.panel_open_sfx_played = true;
        }
        if (quest_update.play_button_click) self.audio.playUiButtonClick();
        if (quest_update.back_to_play_game) {
            self.play_game_menu.reset();
            self.screen = .play_game_menu;
            return;
        }
        if (quest_update.start_level_key) |level_key| {
            self.startNewRun(runConfigForLiveMode(.quests, level_key, &self.next_seed_state));
        }
    }

    fn updateStatisticsMenu(self: *App, frame_dt: f32) void {
        self.audio.ensureMenuTheme();
        const statistics_update = window_menu_panels.updateStatistics(&self.statistics_menu, frame_dt);
        if (statistics_update.play_panel_click and !self.statistics_menu.panel.panel_open_sfx_played) {
            self.audio.playUiPanelClick();
            self.statistics_menu.panel.panel_open_sfx_played = true;
        }
        if (statistics_update.play_button_click) self.audio.playUiButtonClick();
        if (statistics_update.action) |action| switch (action) {
            .open_high_scores => self.openHighScores(true),
            .open_weapons => {
                self.info_view.open(.weapons);
                self.screen = .info_view;
            },
            .open_perks => {
                self.info_view.open(.perks);
                self.screen = .info_view;
            },
            .open_credits => {
                self.info_view.open(.credits);
                self.screen = .info_view;
            },
            .back_to_menu => {
                self.menu.openRoot();
                self.screen = .main_menu;
            },
        };
    }

    fn updateInfoView(self: *App) void {
        const info_update = window_menu_panels.updateInfoView(&self.info_view);
        if (info_update.back_to_statistics) {
            self.statistics_menu.reset();
            self.screen = .statistics_menu;
        }
    }

    fn updateGameplay(self: *App, frame_dt: f32) void {
        if (self.gameplay) |*gameplay| {
            if (rl.isKeyPressed(.escape)) {
                self.finishRun(gameplay, .abandoned, null);
                return;
            }

            const camera = buildWorldCamera(
                gameplay.runner.session.world_size,
                gameplay.runner.session.state.camera_shake_offset,
            );
            self.runtime.recordGameplayFrame(frame_dt);
            const input = collectGameplayInput(&gameplay.input_interpreter, &gameplay.runner, camera, &self.runtime, frame_dt);
            if (input.perk_choice_index != null) {
                self.audio.playUiButtonClick();
            }
            gameplay.last_update = gameplay.runner.stepFrame(frame_dt, input) catch |err| {
                self.finishRun(gameplay, .runtime_error, @errorName(err));
                return;
            };
            gameplay.hud_state.update(frame_dt, &gameplay.runner.session);
            self.audio.handleFrameAudio(gameplay.last_update.audio, gameplay.runner.session.state.bonuses.reflex_boost);
            if (self.runtime_assets) |*runtime_assets| {
                if (gameplay.ground) |*ground| {
                    gameplay.terrain_fx.bake(&gameplay.runner.session, ground, runtime_assets);
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

    fn updateResults(self: *App) void {
        if (self.results) |*results| {
            if (results.highscore) |*highscore| {
                if (highscore.promptActive()) {
                    self.updateResultsHighscoreEntry(results, highscore);
                    return;
                }
            }
        }

        const buttons = resultsButtons();
        window_ui.updateSelectionFromPointer(&self.results_selection, buttons[0..]);
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            self.results_selection = if (self.results_selection == 0) buttons.len - 1 else self.results_selection - 1;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            self.results_selection = (self.results_selection + 1) % buttons.len;
        }

        const activated = window_ui.buttonActivated(buttons[0..], self.results_selection);
        if (!activated) return;
        self.audio.playUiButtonClick();

        switch (self.results_selection) {
            0 => if (self.results) |results| {
                self.startNewRun(results.run_config);
            },
            1 => {
                if (self.gameplay) |*gameplay| {
                    gameplay.deinit();
                    self.gameplay = null;
                }
                self.results = null;
                self.menu.openRoot();
                self.screen = .main_menu;
            },
            else => {},
        }
    }

    fn updateHighScores(self: *App) void {
        if (self.high_scores) |*high_scores| {
            const buttons = highScoresButtons();
            window_ui.updateSelectionFromPointer(&high_scores.selection, buttons[0..]);
            if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
                high_scores.selection = if (high_scores.selection == 0) buttons.len - 1 else high_scores.selection - 1;
            }
            if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
                high_scores.selection = (high_scores.selection + 1) % buttons.len;
            }

            const activated = window_ui.buttonActivated(buttons[0..], high_scores.selection);
            if (!activated) return;
            self.audio.playUiButtonClick();

            switch (high_scores.selection) {
                0 => self.setHighScoresMode(.survival),
                1 => self.setHighScoresMode(.rush),
                2 => self.setHighScoresMode(.quests),
                3 => {
                    if (high_scores.return_to_statistics) {
                        self.statistics_menu.reset();
                        self.screen = .statistics_menu;
                    } else {
                        self.menu.openRoot();
                        self.screen = .main_menu;
                    }
                },
                else => {},
            }
        }
    }

    fn updateOptions(self: *App) void {
        const buttons = optionsButtons();
        window_ui.updateSelectionFromPointer(&self.options.selection, buttons[0..]);
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            self.options.selection = if (self.options.selection == 0) buttons.len - 1 else self.options.selection - 1;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            self.options.selection = (self.options.selection + 1) % buttons.len;
        }

        const activate = window_ui.buttonActivated(buttons[0..], self.options.selection);
        const adjust_left = rl.isKeyPressed(.left) or rl.isKeyPressed(.a);
        const adjust_right = rl.isKeyPressed(.right) or rl.isKeyPressed(.d);
        if (!(activate or adjust_left or adjust_right)) return;

        switch (self.options.selection) {
            0 => {
                var value = if (self.runtime.config.sound_disable != 0)
                    @as(i32, 0)
                else
                    @as(i32, @intFromFloat(std.math.clamp(self.runtime.config.sfx_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5));
                if (adjust_left or adjust_right) {
                    value = std.math.clamp(value + (if (adjust_left and !adjust_right) @as(i32, -1) else @as(i32, 1)), @as(i32, 0), @as(i32, 10));
                } else {
                    value = if (value == 0) 10 else 0;
                }
                self.runtime.config.sfx_volume = @as(f32, @floatFromInt(value)) * 0.1;
                self.runtime.config.sound_disable = if (value == 0) 1 else 0;
                self.runtime.config_dirty = true;
                self.reloadAudioConfig();
                self.audio.playUiButtonClick();
            },
            1 => {
                var value = if (self.runtime.config.music_disable != 0)
                    @as(i32, 0)
                else
                    @as(i32, @intFromFloat(std.math.clamp(self.runtime.config.music_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5));
                if (adjust_left or adjust_right) {
                    value = std.math.clamp(value + (if (adjust_left and !adjust_right) @as(i32, -1) else @as(i32, 1)), @as(i32, 0), @as(i32, 10));
                } else {
                    value = if (value == 0) 10 else 0;
                }
                self.runtime.config.music_volume = @as(f32, @floatFromInt(value)) * 0.1;
                self.runtime.config.music_disable = if (value == 0) 1 else 0;
                self.runtime.config_dirty = true;
                self.reloadAudioConfig();
                self.audio.playUiButtonClick();
            },
            2 => {
                const current: i32 = @intCast(std.math.clamp(self.runtime.config.detail_preset, @as(u32, 1), @as(u32, 5)));
                const delta: i32 = if (adjust_left and !activate) -1 else 1;
                self.runtime.config.detail_preset = @intCast(std.math.clamp(current + delta, @as(i32, 1), @as(i32, 5)));
                self.runtime.config_dirty = true;
                self.audio.playUiButtonClick();
            },
            3 => {
                self.runtime.config.gore_disabled = if (self.runtime.config.gore_disabled == 0) 1 else 0;
                self.runtime.config_dirty = true;
                self.audio.playUiButtonClick();
            },
            4 => {
                self.runtime.config.hardcore_flag = if (self.runtime.config.hardcore_flag == 0) 1 else 0;
                self.runtime.config_dirty = true;
                self.audio.playUiButtonClick();
            },
            5 => {
                self.audio.playUiButtonClick();
                self.menu.openRoot();
                self.screen = .main_menu;
            },
            else => {},
        }
    }

    fn updateResultsHighscoreEntry(
        self: *App,
        results: *ResultsScreen,
        highscore: *ResultsHighscoreState,
    ) void {
        collectNameInput(highscore);

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
            highscore.save_error = @errorName(err);
            return;
        };
        defer self.allocator.free(score_path);

        var upsert = persistence.highscores.upsertHighscoreRecord(
            self.allocator,
            score_path,
            highscore.record,
            null,
        ) catch |err| {
            highscore.save_error = @errorName(err);
            return;
        };
        defer upsert.deinit(self.allocator);

        self.runtime.saveConfigIfDirty() catch |err| {
            highscore.save_error = @errorName(err);
            return;
        };

        highscore.saved = true;
        highscore.save_error = null;
        self.results_selection = 0;
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

        self.runtime.recordModeStart(configured_run.game_mode);
        var runner = live_runner.LiveRunner.init(configured_run) catch |err| {
            self.results = .{
                .reason = .runtime_error,
                .run_config = configured_run,
                .summary = zeroSessionSummary(),
                .player_health = 0.0,
                .runtime_error = @errorName(err),
            };
            self.results_selection = 0;
            self.screen = .results;
            return;
        };
        const last_update = runner.stepFrame(0.0, .{}) catch unreachable;
        if (self.gameplay) |*gameplay| {
            gameplay.deinit();
            self.gameplay = null;
        }

        var gameplay: GameplayScreen = .{
            .runner = runner,
            .run_config = configured_run,
            .last_update = last_update,
            .terrain_fx = window_terrain_fx.TerrainFxTracker.init(runner.seed),
        };
        gameplay.hud_state.update(0.0, &gameplay.runner.session);
        gameplay.input_interpreter.setPreserveBugs(gameplay.runner.session.state.preserve_bugs);
        gameplay.input_interpreter.reset(gameplay.runner.session.playersConst());
        if (self.runtime_assets) |*runtime_assets| {
            gameplay.ground = window_ground.GroundRenderer.initForTerrainSetup(
                runtime_assets,
                gameplay.runner.terrain_setup,
                gameplay.runner.session.terrain_size,
                gameplay.runner.session.terrain_size,
            ) catch null;
            if (gameplay.ground) |*ground| {
                gameplay.terrain_fx.bake(&gameplay.runner.session, ground, runtime_assets);
            } else {
                gameplay.terrain_fx.capture(&gameplay.runner.session);
            }
        } else {
            gameplay.terrain_fx.capture(&gameplay.runner.session);
        }
        self.gameplay = gameplay;
        self.results = null;
        self.screen = .gameplay;
    }

    fn openHighScores(self: *App, return_to_statistics: bool) void {
        if (self.high_scores == null) {
            self.high_scores = .{};
        }
        if (self.high_scores) |*high_scores| {
            high_scores.return_to_statistics = return_to_statistics;
        }
        self.setHighScoresMode(.survival);
        self.screen = .high_scores;
    }

    fn setHighScoresMode(self: *App, mode: game_ids.GameModeId) void {
        if (self.high_scores == null) {
            self.high_scores = .{};
        }
        if (self.high_scores) |*high_scores| {
            high_scores.mode = mode;
            high_scores.load_error = null;
            high_scores.clear(self.allocator);

            const score_path = persistence.highscores.scoresPathForMode(
                self.allocator,
                self.runtime.base_dir,
                @intFromEnum(mode),
                .{
                    .hardcore = self.runtime.config.hardcore_flag != 0,
                    .quest_stage_major = @divTrunc(high_scores.quest_level_key, 100),
                    .quest_stage_minor = @mod(high_scores.quest_level_key, 100),
                    .player_count = @intCast(self.runtime.config.player_count),
                },
            ) catch |err| {
                high_scores.load_error = @errorName(err);
                return;
            };
            defer self.allocator.free(score_path);

            const records = persistence.highscores.readHighscoreTable(
                self.allocator,
                score_path,
                @intFromEnum(mode),
            ) catch |err| {
                high_scores.load_error = @errorName(err);
                return;
            };
            high_scores.records = records.items;
            high_scores.records_owned = true;
        }
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
        self.runtime.absorbSessionState(&runner.session);
        const player_health = if (runner.player0Const()) |player| player.health else 0.0;
        const save_error: ?[]const u8 = save_err: {
            self.runtime.saveStatusIfDirty() catch |err| break :save_err @errorName(err);
            break :save_err null;
        };
        const highscore = self.buildResultsHighscore(runner, reason, runtime_error orelse save_error);
        self.results = .{
            .reason = reason,
            .run_config = gameplay.run_config,
            .summary = runner.summary(),
            .player_health = player_health,
            .runtime_error = runtime_error orelse save_error,
            .highscore = highscore,
        };
        gameplay.deinit();
        self.gameplay = null;
        self.results_selection = 0;
        self.screen = .results;
    }

    fn buildResultsHighscore(
        self: *App,
        runner: *const live_runner.LiveRunner,
        reason: ResultsReason,
        runtime_error: ?[]const u8,
    ) ?ResultsHighscoreState {
        if (runtime_error != null) return null;
        switch (reason) {
            .dead, .completed => {},
            .abandoned, .runtime_error => return null,
        }

        const player = runner.player0Const() orelse return null;
        const record = persistence.highscore_record_builder.buildHighscoreRecordForGameOver(
            runner.session.state,
            player.*,
            @intCast(runner.summary().elapsed_ms_sim),
            @intCast(runner.session.creatures.kill_count),
            runner.session.game_mode,
            .{},
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
        drawStartupDiagnostics(self);
    }

    fn drawMainMenu(self: *const App) void {
        window_menu.draw(&self.menu, if (self.runtime_assets) |*assets| assets else null);
        drawStartupDiagnostics(self);
    }

    fn drawPlayGameMenu(self: *const App) void {
        window_menu_panels.drawPlayGame(
            &self.play_game_menu,
            if (self.runtime_assets) |*assets| assets else null,
            self.runtime.status,
            self.runtime.config.player_count,
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
        window_menu_panels.drawStatistics(&self.statistics_menu, if (self.runtime_assets) |*assets| assets else null);
    }

    fn drawGameplay(self: *App) void {
        rl.clearBackground(bg_color);
        drawBackdrop();

        if (self.gameplay) |*gameplay| {
            const runner = &gameplay.runner;
            const runtime_assets: ?*const window_assets.RuntimeAssets = if (self.runtime_assets) |*loaded_assets| loaded_assets else null;
            const camera = buildWorldCamera(
                runner.session.world_size,
                runner.session.state.camera_shake_offset,
            );

            camera.begin();
            drawWorld(runner, runtime_assets, if (gameplay.ground) |*ground| ground else null);
            drawPlayers(runner, runtime_assets);
            drawCreatures(runner, runtime_assets);
            drawProjectiles(runner, runtime_assets);
            drawBonuses(runner, runtime_assets);
            camera.end();

            drawGameplayHud(gameplay, runtime_assets);
            if (gameplay.last_update.paused_for_perk_pick) {
                drawPerkOverlay(gameplay, runtime_assets);
            }
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
                drawSmallTextFmt("{d} ms", runtime_assets, .{results.summary.elapsed_ms_sim}, 510.0, 258.0, HudTextColor.primary);
                drawSmallTextFmt("{d}", runtime_assets, .{results.summary.player_experience}, 510.0, 286.0, HudTextColor.primary);
                drawSmallTextFmt("{d}", runtime_assets, .{results.summary.player_level}, 510.0, 314.0, HudTextColor.primary);
                drawSmallText(runtime_assets, weaponName(results.summary.player_weapon_id), 510.0, 342.0, HudTextColor.primary);
                drawSmallTextFmt("{d:.1}", runtime_assets, .{results.player_health}, 510.0, 370.0, HudTextColor.primary);

                if (results.runtime_error) |runtime_error| {
                    drawSmallText(runtime_assets, runtime_error, 330.0, 430.0, rl.Color.orange);
                }
                if (results.highscore) |highscore| {
                    drawResultsHighscore(runtime_assets, &highscore);
                }
            } else {
                drawCenteredText(resultsTitle(results.reason), 124, 64, accent_color);
                drawCenteredText(resultsSubtitle(results.reason), 188, 22, text_color);

                drawTextFmt("elapsed_ms: {d}", .{results.summary.elapsed_ms_sim}, 460, 280, 24, text_color);
                drawTextFmt("xp: {d}", .{results.summary.player_experience}, 460, 316, 24, text_color);
                drawTextFmt("level: {d}", .{results.summary.player_level}, 460, 352, 24, text_color);
                drawTextFmt("fire inputs: {d} / reloads: {d}", .{ results.summary.fire_pressed_count, results.summary.reload_pressed_count }, 460, 388, 24, text_color);
                drawTextFmt("spawns: stage={d} wave={d}", .{ results.summary.stage_spawn_count, results.summary.wave_spawn_count }, 460, 424, 24, text_color);
                drawTextFmt("weapon_id: {d}  hp: {d:.1}", .{ results.summary.player_weapon_id, results.player_health }, 460, 460, 24, text_color);

                if (results.runtime_error) |runtime_error| {
                    drawTextSlice(runtime_error, 460, 520, 20, rl.Color.orange);
                }
                if (results.highscore) |highscore| {
                    drawResultsHighscoreFallback(&highscore);
                }
            }
        }

        const prompt_active = if (self.results) |results|
            if (results.highscore) |highscore| highscore.promptActive() else false
        else
            false;
        const buttons = if (prompt_active) resultsHighscoreButtons() else resultsButtons();
        for (buttons, 0..) |button, idx| {
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
        drawAudioStatus(&self.audio);
    }

    fn drawHighScores(self: *const App) void {
        rl.clearBackground(bg_color);
        drawBackdrop();

        if (self.runtime_assets) |*runtime_assets| {
            drawTextureFit(runtime_assets.texture(.ui_menu_panel), rl.Rectangle.init(230.0, 88.0, 820.0, 440.0), colorWithAlpha(rl.Color.white, 0.97));
            drawSmallTextCentered(runtime_assets, "HIGH SCORES", 116.0, HudTextColor.accent);
        } else {
            drawCenteredText("HIGH SCORES", 110, 46, accent_color);
        }

        if (self.high_scores) |high_scores| {
            if (self.runtime_assets) |*runtime_assets| {
                drawSmallTextCentered(
                    runtime_assets,
                    highScoreModeLabel(high_scores.mode),
                    150.0,
                    HudTextColor.primary,
                );
                drawHighScoreTable(runtime_assets, high_scores);
            } else {
                drawCenteredText(highScoreModeLabelZ(high_scores.mode), 148, 24, text_color);
                drawHighScoreTableFallback(high_scores);
            }
        }

        const buttons = highScoresButtons();
        const selected_idx = if (self.high_scores) |high_scores| high_scores.selection else 0;
        for (buttons, 0..) |button, idx| {
            const mouse_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            window_ui.drawButton(button, idx == selected_idx, mouse_hovered, if (self.runtime_assets) |*assets| assets else null);
        }
        drawAudioStatus(&self.audio);
    }

    fn drawOptions(self: *const App) void {
        rl.clearBackground(bg_color);
        drawBackdrop();

        if (self.runtime_assets) |*runtime_assets| {
            drawTextureFit(runtime_assets.texture(.ui_menu_panel), rl.Rectangle.init(240.0, 96.0, 800.0, 520.0), colorWithAlpha(rl.Color.white, 0.97));
            drawSmallTextCentered(runtime_assets, "OPTIONS", 120.0, HudTextColor.accent);
            drawSmallTextCentered(runtime_assets, "LEFT / RIGHT ADJUST. ENTER ALSO TOGGLES.", 152.0, HudTextColor.dim);
            drawOptionsTable(runtime_assets, self);
        } else {
            drawCenteredText("OPTIONS", 112, 46, accent_color);
            drawCenteredText("Left / Right adjust. Enter also toggles.", 150, 18, muted_text);
            drawOptionsTableFallback(self);
        }

        const buttons = optionsButtons();
        for (buttons, 0..) |button, idx| {
            const mouse_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            window_ui.drawButton(button, idx == self.options.selection, mouse_hovered, if (self.runtime_assets) |*assets| assets else null);
        }
        drawAudioStatus(&self.audio);
    }

    fn drawInfoView(self: *const App) void {
        window_menu_panels.drawInfoView(
            &self.info_view,
            if (self.runtime_assets) |*assets| assets else null,
            self.runtime.status,
        );
    }
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();

    var runtime = try app_runtime.DesktopRuntime.init(gpa.allocator());

    rl.setConfigFlags(.{
        .fullscreen_mode = runtime.config.windowed_flag == 0,
    });
    rl.initWindow(runtime.windowWidth(window_width), runtime.windowHeight(window_height), "crimson-zig");
    defer rl.closeWindow();

    rl.setTargetFPS(60);

    var app = App.init(gpa.allocator(), runtime);
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

fn drawBackdrop() void {
    const width = rl.getScreenWidth();
    const height = rl.getScreenHeight();
    rl.drawRectangleGradientV(0, 0, width, height, rl.Color.init(32, 18, 16, 255), bg_color);
    rl.drawCircle(width - 180, 120, 200.0, rl.Color.init(93, 31, 22, 80));
    rl.drawCircle(160, height - 80, 220.0, rl.Color.init(58, 23, 18, 90));
}

fn drawAudioStatus(audio: *const live_audio.Bridge) void {
    switch (audio.load_state) {
        .loaded => {
            const assets_dir = audio.assetsDir() orelse return;
            drawTextFmt(
                "audio: {d} music / {d} queued tunes / {d} sfx samples from {s}",
                .{ audio.musicTrackCount(), audio.queuedGameTuneCount(), audio.sfxSampleCount(), assets_dir },
                28,
                708,
                18,
                muted_text,
            );
        },
        .unavailable => drawTextSlice("audio: music.paq or sfx.paq missing; running silent", 28, 708, 18, muted_text),
        .disabled => drawTextSlice("audio: disabled by crimson.cfg", 28, 708, 18, muted_text),
        .failed => {
            drawTextSlice("audio: init failed; running silent", 28, 708, 18, muted_text);
            if (audio.message) |message| {
                drawTextSlice(message, 420, 708, 18, rl.Color.orange);
            }
        },
    }
}

fn drawStartupDiagnostics(app: *const App) void {
    switch (app.assets_state) {
        .loaded => {},
        .unavailable => drawTextSlice("assets: no crimson.paq found; using primitive fallback", 28, 688, 18, muted_text),
        .failed => {
            drawTextSlice("assets: load failed; using primitive fallback", 28, 668, 18, muted_text);
            if (app.assets_message) |message| {
                drawTextSlice(message, 28, 688, 18, rl.Color.orange);
            }
        },
    }

    switch (app.audio.load_state) {
        .loaded => {},
        .unavailable, .disabled, .failed => drawAudioStatus(&app.audio),
    }
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

fn resultsButtons() [2]UiButton {
    const center_x: f32 = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5;
    return .{
        .{ .label = "RESTART", .rect = window_ui.centeredRect(center_x, 586.0, ui_button_width, ui_button_height) },
        .{ .label = "MAIN MENU", .rect = window_ui.centeredRect(center_x, 658.0, ui_button_width, ui_button_height) },
    };
}

fn resultsHighscoreButtons() [2]UiButton {
    const center_x: f32 = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5;
    return .{
        .{ .label = "SAVE SCORE", .rect = window_ui.centeredRect(center_x, 586.0, ui_button_width, ui_button_height) },
        .{ .label = "SKIP", .rect = window_ui.centeredRect(center_x, 658.0, ui_button_width, ui_button_height) },
    };
}

fn highScoresButtons() [4]UiButton {
    const center_x: f32 = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5;
    return .{
        .{ .label = "SURVIVAL", .rect = window_ui.centeredRect(center_x, 560.0, 220.0, 48.0) },
        .{ .label = "RUSH", .rect = window_ui.centeredRect(center_x, 616.0, 220.0, 48.0) },
        .{ .label = "QUEST 1.1", .rect = window_ui.centeredRect(center_x, 672.0, 220.0, 48.0) },
        .{ .label = "BACK", .rect = window_ui.centeredRect(center_x + 262.0, 672.0, 150.0, 48.0) },
    };
}

fn optionsButtons() [6]UiButton {
    return .{
        .{ .label = "SFX", .rect = rl.Rectangle.init(304.0, 220.0, 420.0, 44.0) },
        .{ .label = "MUSIC", .rect = rl.Rectangle.init(304.0, 274.0, 420.0, 44.0) },
        .{ .label = "DETAIL", .rect = rl.Rectangle.init(304.0, 328.0, 420.0, 44.0) },
        .{ .label = "GORE", .rect = rl.Rectangle.init(304.0, 382.0, 420.0, 44.0) },
        .{ .label = "HARDCORE", .rect = rl.Rectangle.init(304.0, 436.0, 420.0, 44.0) },
        .{ .label = "BACK", .rect = rl.Rectangle.init(304.0, 522.0, 220.0, 48.0) },
    };
}

fn collectNameInput(highscore: *ResultsHighscoreState) void {
    while (true) {
        const codepoint = rl.getCharPressed();
        if (codepoint == 0) break;
        if (codepoint < 0x20 or codepoint > 0xFF) continue;
        if (highscore.input_len >= persistence.highscores.name_max_edit) continue;
        highscore.input[highscore.input_len] = @intCast(codepoint);
        highscore.input_len += 1;
    }

    if ((rl.isKeyPressed(.backspace) or rl.isKeyPressedRepeat(.backspace)) and highscore.input_len > 0) {
        highscore.input_len -= 1;
        highscore.input[highscore.input_len] = 0;
    }
}

fn buildWorldCamera(world_size: f32, shake_offset: state_mod.Vec2) rl.Camera2D {
    const screen_w: f32 = @floatFromInt(rl.getScreenWidth());
    const screen_h: f32 = @floatFromInt(rl.getScreenHeight());
    const usable_w = @max(1.0, screen_w - world_margin * 2.0);
    const usable_h = @max(1.0, screen_h - world_margin * 2.0);
    const zoom = @max(0.2, @min(usable_w / world_size, usable_h / world_size));
    return .{
        .offset = rl.Vector2.init(screen_w * 0.5, screen_h * 0.5),
        .target = rl.Vector2.init(
            world_size * 0.5 - shake_offset.x,
            world_size * 0.5 - shake_offset.y,
        ),
        .rotation = 0.0,
        .zoom = zoom,
    };
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

    if (runner.perkPendingCount() > 0) {
        if (rl.isKeyPressed(.one)) frame_input.perk_choice_index = 0;
        if (rl.isKeyPressed(.two)) frame_input.perk_choice_index = 1;
        if (rl.isKeyPressed(.three)) frame_input.perk_choice_index = 2;
        if (rl.isKeyPressed(.four)) frame_input.perk_choice_index = 3;
        if (rl.isKeyPressed(.five)) frame_input.perk_choice_index = 4;
        if (rl.isKeyPressed(.six)) frame_input.perk_choice_index = 5;
        if (rl.isKeyPressed(.seven)) frame_input.perk_choice_index = 6;
    }

    return frame_input;
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
        rl.drawRectangleRec(world_rect, rl.Color.init(16, 11, 9, 34));
    } else {
        rl.drawRectangleRec(world_rect, arena_color);

        var coord: i32 = 0;
        while (coord <= runner.session.terrain_size) : (coord += 128) {
            const line_pos: f32 = @floatFromInt(coord);
            rl.drawLineV(rl.Vector2.init(line_pos, 0.0), rl.Vector2.init(line_pos, world_size), arena_grid);
            rl.drawLineV(rl.Vector2.init(0.0, line_pos), rl.Vector2.init(world_size, line_pos), arena_grid);
        }
    }

    rl.drawRectangleLinesEx(.{
        .x = 0.0,
        .y = 0.0,
        .width = world_size,
        .height = world_size,
    }, 4.0, border_color);
}

fn drawPlayers(runner: *const live_runner.LiveRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    for (runner.session.playersConst()) |player| {
        const center = toRlVec(player.pos);
        const radius = @max(10.0, player.size * 0.28);
        const color = if (player.health > 0.0) player_color else dead_player_color;

        if (runtime_assets) |assets| {
            const trooper_texture = assets.texture(.trooper);
            const cell = @as(f32, @floatFromInt(trooper_texture.width)) / 8.0;
            if (cell > 0.0) {
                const base_scale = player.size / cell;
                const shadow_tint = colorWithAlpha(rl.Color.black, 90.0 / 255.0);
                const elapsed_s = runner.session.elapsed_ms_sim * 0.001;

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
                                    colorWithAlpha(rl.Color.init(77, 153, 77, 255), aura_alpha),
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
                    drawAtlasFrameCenteredRotated(trooper_texture, 8, leg_frame, center, base_scale, player.heading, rl.Color.white);
                    drawAtlasFrameCenteredRotated(trooper_texture, 8, torso_frame, torso_draw_center, base_scale, player.aim_heading, rl.Color.white);

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
                                    colorWithAlpha(rl.Color.init(91, 180, 255, 255), strength * 0.4),
                                );
                                drawTextureRegionCenteredRotated(
                                    assets.texture(.particles),
                                    src_rect,
                                    shield_center,
                                    size_2,
                                    size_2,
                                    radiansToDegrees(elapsed_s * -2.0),
                                    colorWithAlpha(rl.Color.init(91, 180, 255, 255), strength * 0.3),
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
                                    colorWithAlpha(rl.Color.white, flash_alpha),
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
                drawAtlasFrameCenteredRotated(trooper_texture, 8, dead_frame, center, base_scale, player.aim_heading, dead_player_color);
                continue;
            }
        } else {
            rl.drawCircleV(center, radius, color);
            rl.drawCircleLinesV(center, radius + 2.0, rl.Color.black);
            rl.drawLineEx(center, toRlVec(player.aim), 2.0, rl.Color.gold);
        }
    }
}

fn drawCreatures(runner: *const live_runner.LiveRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
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
                    if (shadow_enabled) {
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
                        tint,
                    );
                    continue;
                }
            }
        }
        rl.drawCircleV(toRlVec(creature.pos), radius, color);
    }
}

fn drawProjectiles(runner: *const live_runner.LiveRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    for (runner.session.projectiles.entries, 0..) |projectile, proj_index| {
        if (!projectile.active) continue;
        if (runtime_assets) |assets| {
            if (window_projectiles.drawMainProjectile(projectile, proj_index, .{
                .session = &runner.session,
                .assets = assets,
            })) continue;
        }
        rl.drawCircleV(toRlVec(projectile.pos), 3.0, projectile_color);
    }
    for (runner.session.secondary_projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        if (runtime_assets) |assets| {
            if (window_projectiles.drawSecondaryProjectile(projectile, .{
                .session = &runner.session,
                .assets = assets,
            })) continue;
        }
        rl.drawCircleV(toRlVec(projectile.pos), 6.0, secondary_projectile_color);
    }
}

fn drawBonuses(runner: *const live_runner.LiveRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const bonus_phase = runner.session.elapsed_ms_sim * 0.001 * 1.3;
    for (runner.session.bonuses.entries, 0..) |entry, idx| {
        if (entry.bonus_id == .unused) continue;
        if (runtime_assets) |assets| {
            const bonuses_texture = assets.texture(.bonuses);
            const bubble_src = window_atlas.bonusIconRect(bonuses_texture.width, bonuses_texture.height, 0);
            const fade = window_atlas.bonusFade(entry.time_left, entry.time_max);
            const bubble_alpha = fade * 0.9;
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
                const weapon_id = std.meta.intToEnum(game_ids.WeaponId, entry.amount) catch {
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
                        radiansToDegrees(std.math.sin(idx_f - runner.session.elapsed_ms_sim * 0.003) * 0.2),
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
            bonus_color,
        );
    }
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

fn drawResultsHighscoreFallback(highscore: *const ResultsHighscoreState) void {
    if (highscore.promptActive()) {
        drawCenteredText("NEW HIGH SCORE", 514, 24, rl.Color.gold);
        drawCenteredTextFmt("rank #{d}", .{highscore.rank_index + 1}, 546, 20, text_color);
        drawCenteredText("Enter your name to save this run.", 574, 18, muted_text);
        rl.drawRectangleRounded(.{ .x = 392.0, .y = 604.0, .width = 496.0, .height = 34.0 }, 0.15, 8, panel_color);
        rl.drawRectangleRoundedLinesEx(.{ .x = 392.0, .y = 604.0, .width = 496.0, .height = 34.0 }, 0.15, 8, 2.0, panel_outline);

        const caret_visible = @mod(@as(i32, @intFromFloat(rl.getTime() * 2.5)), 2) == 0;
        const shown_name = if (highscore.input_len == 0 and caret_visible) "_" else highscore.inputSlice();
        drawTextSlice(shown_name, 410, 612, 22, text_color);

        if (highscore.save_error) |save_error| {
            drawTextSlice(save_error, 410, 648, 18, rl.Color.orange);
        }
    } else {
        drawCenteredText("SCORE SAVED", 514, 24, rl.Color.gold);
        drawCenteredTextFmt("rank #{d}  name {s}", .{ highscore.rank_index + 1, highscore.record.name() }, 546, 18, text_color);
    }
}

fn highScoreModeLabel(mode: game_ids.GameModeId) []const u8 {
    return switch (mode) {
        .survival => "SURVIVAL",
        .rush => "RUSH",
        .quests => "QUEST 1.1",
        .typo => "TYPO",
        .tutorial => "TUTORIAL",
    };
}

fn highScoreModeLabelZ(mode: game_ids.GameModeId) [:0]const u8 {
    return switch (mode) {
        .survival => "SURVIVAL",
        .rush => "RUSH",
        .quests => "QUEST 1.1",
        .typo => "TYPO",
        .tutorial => "TUTORIAL",
    };
}

fn drawHighScoreTable(runtime_assets: *const window_assets.RuntimeAssets, high_scores: HighScoresScreen) void {
    if (high_scores.load_error) |load_error| {
        drawSmallText(runtime_assets, load_error, 280.0, 194.0, rl.Color.orange);
        return;
    }
    if (high_scores.records.len == 0) {
        drawSmallTextCentered(runtime_assets, "NO SCORES SAVED YET", 226.0, HudTextColor.dim);
        return;
    }

    rl.drawRectangle(438, 189, 322, 166, rl.Color.white);
    rl.drawRectangle(439, 190, 320, 164, rl.Color.black);
    drawSmallText(runtime_assets, "RANK", 452.0, 194.0, HudTextColor.dim);
    drawSmallText(runtime_assets, "VALUE", 492.0, 194.0, HudTextColor.dim);
    drawSmallText(runtime_assets, "PLAYER", 556.0, 194.0, HudTextColor.dim);

    const row_count = @min(high_scores.records.len, 10);
    for (high_scores.records[0..row_count], 0..) |record, idx| {
        const row_y = 208.0 + @as(f32, @floatFromInt(idx)) * 16.0;
        var value_buf: [32]u8 = undefined;
        drawSmallTextFmt("{d}", runtime_assets, .{idx + 1}, 458.0, row_y, HudTextColor.primary);
        drawSmallText(runtime_assets, formatHighScoreValue(&value_buf, record), 492.0, row_y, HudTextColor.primary);
        drawSmallText(runtime_assets, record.name(), 556.0, row_y, rl.Color.white);
    }
}

fn drawHighScoreTableFallback(high_scores: HighScoresScreen) void {
    if (high_scores.load_error) |load_error| {
        drawTextSlice(load_error, 280, 194, 20, rl.Color.orange);
        return;
    }
    if (high_scores.records.len == 0) {
        drawCenteredText("No scores saved yet.", 230, 20, muted_text);
        return;
    }

    const row_count = @min(high_scores.records.len, 10);
    for (high_scores.records[0..row_count], 0..) |record, idx| {
        var value_buf: [32]u8 = undefined;
        drawTextFmt(
            "#{d}  {s}  {s}  {s}",
            .{ idx + 1, record.name(), formatHighScoreValue(&value_buf, record), weaponName(@intFromEnum(record.mostUsedWeaponId())) },
            240,
            210 + @as(i32, @intCast(idx)) * 28,
            18,
            text_color,
        );
    }
}

fn formatHighScoreValue(buf: []u8, record: persistence.highscores.HighScoreRecord) []const u8 {
    return switch (record.gameModeId() orelse .survival) {
        .rush, .quests => std.fmt.bufPrint(buf, "{d} ms", .{record.survivalElapsedMs()}) catch "0 ms",
        else => std.fmt.bufPrint(buf, "{d} xp", .{record.scoreXp()}) catch "0 xp",
    };
}

fn drawOptionsTable(runtime_assets: *const window_assets.RuntimeAssets, app: *const App) void {
    const labels = [_][]const u8{
        "SOUND VOLUME",
        "MUSIC VOLUME",
        "GRAPHICS DETAIL",
        "VIOLENCE",
        "HARDCORE",
    };
    for (labels, 0..) |label, idx| {
        const row_y = 230.0 + @as(f32, @floatFromInt(idx)) * 54.0;
        var value_buf: [32]u8 = undefined;
        drawSmallText(runtime_assets, label, 330.0, row_y, HudTextColor.dim);
        switch (idx) {
            0, 1, 2 => {
                const slider_value: i32 = switch (idx) {
                    0 => if (app.runtime.config.sound_disable != 0) 0 else @intFromFloat(std.math.clamp(app.runtime.config.sfx_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5),
                    1 => if (app.runtime.config.music_disable != 0) 0 else @intFromFloat(std.math.clamp(app.runtime.config.music_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5),
                    else => @intCast(std.math.clamp(app.runtime.config.detail_preset, @as(u32, 1), @as(u32, 5))),
                };
                drawSliderRow(runtime_assets, rl.Vector2.init(620.0, row_y - 2.0), if (idx == 2) 5 else 10, slider_value);
                drawSmallText(runtime_assets, optionValueText(&value_buf, app, idx), 708.0, row_y, rl.Color.white);
            },
            3, 4 => {
                const checked = switch (idx) {
                    3 => app.runtime.config.gore_disabled == 0,
                    4 => app.runtime.config.hardcore_flag != 0,
                    else => false,
                };
                const texture_id: window_assets.TextureId = if (checked) .ui_check_on else .ui_check_off;
                drawTextureFit(runtime_assets.texture(texture_id), rl.Rectangle.init(620.0, row_y - 1.0, 16.0, 16.0), rl.Color.white);
                drawSmallText(runtime_assets, optionValueText(&value_buf, app, idx), 646.0, row_y, rl.Color.white);
            },
            else => {},
        }
    }
}

fn drawOptionsTableFallback(app: *const App) void {
    const labels = [_][]const u8{
        "SFX",
        "MUSIC",
        "DETAIL",
        "GORE",
        "HARDCORE",
    };
    for (labels, 0..) |label, idx| {
        var value_buf: [32]u8 = undefined;
        drawTextFmt(
            "{s}: {s}",
            .{ label, optionValueText(&value_buf, app, idx) },
            320,
            230 + @as(i32, @intCast(idx)) * 54,
            20,
            text_color,
        );
    }
}

fn optionValueText(buf: []u8, app: *const App, idx: usize) []const u8 {
    return switch (idx) {
        0 => std.fmt.bufPrint(buf, "{d}", .{if (app.runtime.config.sound_disable != 0) @as(i32, 0) else @as(i32, @intFromFloat(std.math.clamp(app.runtime.config.sfx_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5))}) catch "0",
        1 => std.fmt.bufPrint(buf, "{d}", .{if (app.runtime.config.music_disable != 0) @as(i32, 0) else @as(i32, @intFromFloat(std.math.clamp(app.runtime.config.music_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5))}) catch "0",
        2 => std.fmt.bufPrint(buf, "{d}", .{std.math.clamp(app.runtime.config.detail_preset, @as(u32, 1), @as(u32, 5))}) catch "5",
        3 => if (app.runtime.config.gore_disabled == 0) "ON" else "OFF",
        4 => if (app.runtime.config.hardcore_flag == 0) "OFF" else "ON",
        else => "",
    };
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

fn drawProgressBar(pos: rl.Vector2, width: f32, ratio_raw: f32, fg_color: rl.Color) void {
    const ratio = std.math.clamp(ratio_raw, @as(f32, 0.0), @as(f32, 1.0));
    rl.drawRectangle(@intFromFloat(pos.x), @intFromFloat(pos.y), @intFromFloat(width), 4, rl.Color.init(
        @intFromFloat(@as(f32, @floatFromInt(fg_color.r)) * 0.6),
        @intFromFloat(@as(f32, @floatFromInt(fg_color.g)) * 0.6),
        @intFromFloat(@as(f32, @floatFromInt(fg_color.b)) * 0.6),
        102,
    ));
    rl.drawRectangle(@intFromFloat(pos.x + 1.0), @intFromFloat(pos.y + 1.0), @intFromFloat((width - 2.0) * ratio), 2, fg_color);
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

fn drawModeClock(assets: *const window_assets.RuntimeAssets, elapsed_ms: f32, x: f32, y: f32) void {
    drawTextureFit(assets.texture(.ui_clock_table), rl.Rectangle.init(x, y, 32.0, 32.0), colorWithAlpha(rl.Color.white, 0.9));
    rl.drawTexturePro(
        assets.texture(.ui_clock_pointer),
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(assets.texture(.ui_clock_pointer).width), @floatFromInt(assets.texture(.ui_clock_pointer).height)),
        rl.Rectangle.init(x + 16.0, y + 16.0, 32.0, 32.0),
        rl.Vector2.init(16.0, 16.0),
        elapsed_ms * 0.006,
        colorWithAlpha(rl.Color.white, 0.9),
    );
}

fn drawQuestHud(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
    const elapsed_ms = @as(f32, @floatFromInt(gameplay.last_update.elapsed_ms_sim));
    const slide_x = if (elapsed_ms < 1000.0) (1000.0 - elapsed_ms) * -0.128 else 0.0;

    drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(slide_x - 90.0, 67.0, 182.0, 53.0), colorWithAlpha(rl.Color.white, 0.7));
    drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(-80.0, 107.0, 182.0, 53.0), colorWithAlpha(rl.Color.white, 0.7));
    drawModeClock(assets, elapsed_ms, slide_x + 2.0, 78.0);
    drawSmallTextFmt("{d}:{d:0>2}", assets, .{ @divTrunc(gameplay.last_update.elapsed_ms_sim, 60_000), @mod(@divTrunc(gameplay.last_update.elapsed_ms_sim, 1000), 60) }, slide_x + 32.0, 86.0, HudTextColor.primary);
    drawSmallText(assets, "Progress", 18.0, 122.0, HudTextColor.primary);
    if (questProgressRatio(&gameplay.runner.session)) |ratio| {
        drawProgressBar(rl.Vector2.init(10.0, 139.0), 70.0, ratio, rl.Color.init(51, 204, 77, 204));
    }
}

fn drawBonusHud(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
    var bonus_y: f32 = if (gameplay.runner.session.game_mode == .quests) 201.0 else 121.0;
    const bonuses_texture = assets.texture(.bonuses);
    for (gameplay.hud_state.bonus_slots) |slot| {
        if (!slot.active) continue;
        if (slot.slide_x < -184.0) {
            bonus_y += 52.0;
            continue;
        }
        drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(slot.slide_x, bonus_y - 11.0, 182.0, 53.0), colorWithAlpha(rl.Color.white, 0.7));
        if (slot.icon_id >= 0) {
            drawTextureRegionCenteredRotated(
                bonuses_texture,
                window_atlas.bonusIconRect(bonuses_texture.width, bonuses_texture.height, slot.icon_id),
                rl.Vector2.init(slot.slide_x + 15.0, bonus_y + 16.0),
                32.0,
                32.0,
                0.0,
                rl.Color.white,
            );
        }
        drawSmallText(assets, game_ids.bonusDisplayName(slot.bonus_id, gameplay.runner.session.state.preserve_bugs), slot.slide_x + 36.0, bonus_y + 6.0, HudTextColor.primary);
        drawProgressBar(rl.Vector2.init(slot.slide_x + 36.0, bonus_y + 21.0), 100.0, slot.timer_value * 0.05, rl.Color.init(26, 77, 153, 179));
        if (slot.timer_value_alt > 0.0) {
            drawProgressBar(rl.Vector2.init(slot.slide_x + 36.0, bonus_y + 27.0), 100.0, slot.timer_value_alt * 0.05, rl.Color.init(26, 77, 153, 179));
        }
        bonus_y += 52.0;
    }
}

fn drawWeaponAuxHud(gameplay: *const GameplayScreen, assets: *const window_assets.RuntimeAssets) void {
    const players = gameplay.runner.session.playersConst();
    var bonus_bottom_y: f32 = if (gameplay.runner.session.game_mode == .quests) 201.0 else 121.0;
    for (gameplay.hud_state.bonus_slots) |slot| {
        if (slot.active) bonus_bottom_y += 52.0;
    }
    for (players, 0..) |player, idx| {
        if (!(player.aux_timer > 0.0)) continue;
        const fade_raw = if (player.aux_timer > 1.0) 2.0 - player.aux_timer else player.aux_timer;
        const fade = std.math.clamp(fade_raw, @as(f32, 0.0), @as(f32, 1.0));
        if (fade <= 1e-3) continue;
        const y = bonus_bottom_y - 17.0 + @as(f32, @floatFromInt(idx)) * 32.0;
        drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(-12.0, y, 182.0, 53.0), colorWithAlpha(rl.Color.white, fade * 0.8));
        const icon_index = weapon_data.weaponIconIndex(player.weapon.weapon_id);
        if (icon_index >= 0) {
            drawTextureRegionCenteredRotated(
                assets.texture(.ui_wicons),
                window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index),
                rl.Vector2.init(135.0, y + 20.0),
                60.0,
                30.0,
                0.0,
                colorWithAlpha(rl.Color.white, fade * 0.8),
            );
        }
        drawSmallText(assets, game_ids.weaponDisplayName(player.weapon.weapon_id, gameplay.runner.session.state.preserve_bugs), 8.0, y + 18.0, colorWithAlpha(HudTextColor.primary, fade));
    }
}

fn drawAmmoIndicators(assets: *const window_assets.RuntimeAssets, texture_id: window_assets.TextureId, ammo: f32, clip_size: i32) void {
    const texture = assets.texture(texture_id);
    const ammo_count = @max(0, @as(i32, @intFromFloat(ammo)));
    var bars = @max(0, clip_size);
    if (bars > 30) bars = 20;
    var idx: i32 = 0;
    while (idx < bars) : (idx += 1) {
        const alpha: f32 = if (idx < ammo_count) 0.8 else 0.24;
        drawTextureFit(
            texture,
            rl.Rectangle.init(300.0 + @as(f32, @floatFromInt(idx)) * 6.0, 10.0, 6.0, 16.0),
            colorWithAlpha(rl.Color.white, alpha),
        );
    }
    if (ammo_count > bars) {
        drawSmallTextFmt("+ {d}", assets, .{ammo_count - bars}, 300.0 + @as(f32, @floatFromInt(bars)) * 6.0 + 8.0, 11.0, HudTextColor.primary);
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

        drawTextureFit(
            assets.texture(.ui_game_top),
            rl.Rectangle.init(0.0, 0.0, 512.0, 64.0),
            colorWithAlpha(rl.Color.white, top_alpha),
        );

        if (flags.show_health) {
            const pulse_speed: f32 = if (player.health < 30.0) 5.0 else 2.0;
            const t = elapsed_ms * 0.001;
            const pulse = std.math.pow(f32, std.math.sin(t * pulse_speed), 4) * 4.0 + 14.0;
            drawTextureCentered(
                assets.texture(.ui_life_heart),
                rl.Vector2.init(27.0, 21.0),
                pulse * 2.0,
                pulse * 2.0,
                colorWithAlpha(rl.Color.white, 0.8),
            );

            const ind_life = assets.texture(.ui_ind_life);
            const health_ratio = std.math.clamp(player.health / 100.0, @as(f32, 0.0), @as(f32, 1.0));
            drawTextureFit(ind_life, rl.Rectangle.init(64.0, 16.0, 120.0, 9.0), colorWithAlpha(rl.Color.white, 0.5));
            if (health_ratio > 0.0) {
                rl.drawTexturePro(
                    ind_life,
                    rl.Rectangle.init(0.0, 0.0, @as(f32, @floatFromInt(ind_life.width)) * health_ratio, @floatFromInt(ind_life.height)),
                    rl.Rectangle.init(64.0, 16.0, 120.0 * health_ratio, 9.0),
                    rl.Vector2.zero(),
                    0.0,
                    colorWithAlpha(rl.Color.white, 0.8),
                );
            }
        }

        if (flags.show_weapon) {
            const weapon_id = std.meta.intToEnum(game_ids.WeaponId, update.player_weapon_id) catch .pistol;
            const icon_index = weapon_data.weaponIconIndex(weapon_id);
            if (icon_index >= 0) {
                drawTextureRegionCenteredRotated(
                    assets.texture(.ui_wicons),
                    window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index),
                    rl.Vector2.init(252.0, 18.0),
                    64.0,
                    32.0,
                    0.0,
                    colorWithAlpha(rl.Color.white, 0.8),
                );
            }
            drawAmmoIndicators(assets, weaponIndicatorTextureId(weapon_id), player.weapon.ammo, player.weapon.clip_size);
        }

        if (flags.show_quest_hud) {
            drawQuestHud(gameplay, assets);
        }

        if (flags.show_xp) {
            const hud_y_shift: f32 = if (flags.show_quest_hud) 80.0 else 0.0;
            drawTextureFit(
                assets.texture(.ui_ind_panel),
                rl.Rectangle.init(-68.0, 60.0 + hud_y_shift, 182.0, 53.0),
                colorWithAlpha(rl.Color.white, 0.9),
            );
            const xp_display = gameplay.hud_state.survival_xp_smoothed;
            drawSmallText(assets, "Xp", 4.0, 78.0 + hud_y_shift, HudTextColor.dim);
            drawSmallTextFmt("{d}", assets, .{xp_display}, 26.0, 74.0 + hud_y_shift, HudTextColor.primary);
            drawSmallTextFmt("{d}", assets, .{update.player_level}, 85.0, 79.0 + hud_y_shift, HudTextColor.primary);
            drawProgressBar(rl.Vector2.init(26.0, 91.0 + hud_y_shift), 54.0, xpProgressRatio(update.player_experience, update.player_level), rl.Color.init(26, 77, 153, 255));
        }

        if (flags.show_time) {
            drawModeClock(assets, elapsed_ms, 220.0, 2.0);
            drawSmallTextFmt("{d} seconds", assets, .{@divTrunc(update.elapsed_ms_sim, 1000)}, 255.0, 10.0, HudTextColor.primary);
        }

        drawBonusHud(gameplay, assets);
        drawWeaponAuxHud(gameplay, assets);
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

fn drawPerkOverlay(gameplay: *GameplayScreen, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    rl.drawRectangle(0, 0, rl.getScreenWidth(), rl.getScreenHeight(), overlay_color);
    const runner = &gameplay.runner;
    if (runtime_assets) |assets| {
        drawTextureFit(assets.texture(.ui_menu_panel), rl.Rectangle.init(258.0, 140.0, 764.0, 378.0), colorWithAlpha(rl.Color.white, 0.96));
        drawTextureFit(assets.texture(.ui_text_level_up), rl.Rectangle.init(456.0, 152.0, 364.0, 40.0), colorWithAlpha(rl.Color.white, 0.96));
        drawTextureFit(assets.texture(.ui_text_pick_a_perk), rl.Rectangle.init(424.0, 190.0, 430.0, 40.0), colorWithAlpha(rl.Color.white, 0.96));

        const choices = runner.currentPerkChoices();
        for (choices, 0..) |perk_id, idx| {
            const row_y = 246.0 + @as(f32, @floatFromInt(idx)) * 19.0;
            drawSmallTextFmt("{d}.", assets, .{idx + 1}, 346.0, row_y, if (idx == 0) HudTextColor.accent else HudTextColor.primary);
            drawSmallText(assets, game_ids.perkDisplayName(perk_id, gameplay.run_config.gore_disabled, gameplay.runner.session.state.preserve_bugs), 374.0, row_y, if (idx == 0) HudTextColor.accent else HudTextColor.primary);
        }
        drawSmallText(assets, "Press 1-7 to select", 352.0, 438.0, HudTextColor.dim);
        drawSmallText(assets, "Gameplay is paused", 352.0, 456.0, HudTextColor.dim);
        return;
    }

    rl.drawRectangleRounded(
        .{
            .x = 280.0,
            .y = 170.0,
            .width = 720.0,
            .height = 320.0,
        },
        0.08,
        8,
        panel_color,
    );
    rl.drawRectangleRoundedLinesEx(
        .{
            .x = 280.0,
            .y = 170.0,
            .width = 720.0,
            .height = 320.0,
        },
        0.08,
        8,
        2.0,
        panel_outline,
    );
    drawCenteredText("Perk pick pending", 200, 30, accent_color);
    drawCenteredText("Gameplay pauses until you choose a perk.", 238, 18, text_color);

    const choices = runner.currentPerkChoices();
    for (choices, 0..) |perk_id, idx| {
        drawTextFmt("{d}. {s}", .{ idx + 1, @tagName(perk_id) }, 340, 286 + @as(i32, @intCast(idx)) * 28, 20, text_color);
    }
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
        .runtime_error => "Runtime hit an unported or invalid path.",
    };
}

fn weaponName(weapon_id_raw: i32) []const u8 {
    const weapon_id = std.meta.intToEnum(game_ids.WeaponId, weapon_id_raw) catch return "unknown";
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
