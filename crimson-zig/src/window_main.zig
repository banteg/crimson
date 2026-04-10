const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const runtime_anim = cz.anim;
const weapon_data = cz.weapon_data;
const app_runtime = @import("app_runtime.zig");
const audio_mod = @import("audio/audio.zig");
const input_codes = @import("input_codes.zig");
const live_audio = @import("audio/live_audio.zig");
const window_assets = @import("window_assets.zig");
const window_atlas = cz.window_atlas;
const window_ground = @import("window_ground.zig");
const window_projectiles = @import("window_projectiles.zig");
const window_terrain_fx = @import("window_terrain_fx.zig");

const bonuses_runtime = cz.bonuses;
const game_ids = cz.game_ids;
const live_runner = cz.live_runner;
const runtime_perks = cz.perks;
const runtime_session = cz.session;
const state_mod = cz.state;

const window_width = 1280;
const window_height = 720;
const boot_duration_seconds: f32 = 0.45;
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
    gameplay,
    results,
};

const ResultsReason = enum {
    dead,
    runtime_error,
    abandoned,
};

const AssetsState = enum {
    loaded,
    unavailable,
    failed,
};

const UiButton = struct {
    label: [:0]const u8,
    rect: rl.Rectangle,
};

const GameplayScreen = struct {
    runner: live_runner.LiveSurvivalRunner,
    last_update: live_runner.FrameUpdate,
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

const ResultsScreen = struct {
    reason: ResultsReason,
    summary: runtime_session.SessionSummary,
    player_health: f32,
    runtime_error: ?[]const u8 = null,
};

const App = struct {
    allocator: std.mem.Allocator,
    runtime: app_runtime.DesktopRuntime,
    screen: Screen = .boot,
    boot_elapsed: f32 = 0.0,
    menu_selection: usize = 0,
    results_selection: usize = 0,
    gameplay: ?GameplayScreen = null,
    results: ?ResultsScreen = null,
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
        app.loadAssets();
        return app;
    }

    fn deinit(self: *App) void {
        if (self.gameplay) |*gameplay| {
            gameplay.deinit();
            self.gameplay = null;
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
            .main_menu => self.updateMainMenu(),
            .gameplay => self.updateGameplay(frame_dt),
            .results => self.updateResults(),
        }
        self.audio.update(frame_dt);
    }

    fn draw(self: *App) void {
        switch (self.screen) {
            .boot => self.drawBoot(),
            .main_menu => self.drawMainMenu(),
            .gameplay => self.drawGameplay(),
            .results => self.drawResults(),
        }
    }

    fn updateBoot(self: *App, frame_dt: f32) void {
        self.audio.ensureIntroMusic();
        self.boot_elapsed += frame_dt;
        if (self.boot_elapsed >= boot_duration_seconds) {
            self.screen = .main_menu;
        }
    }

    fn updateMainMenu(self: *App) void {
        self.audio.ensureMenuTheme();
        const buttons = mainMenuButtons();
        updateSelectionFromPointer(&self.menu_selection, buttons[0..]);
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            self.menu_selection = if (self.menu_selection == 0) buttons.len - 1 else self.menu_selection - 1;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            self.menu_selection = (self.menu_selection + 1) % buttons.len;
        }

        const activated = buttonActivated(buttons[0..], self.menu_selection);
        if (!activated) return;
        self.audio.playUiButtonClick();

        switch (self.menu_selection) {
            0 => self.startNewRun(),
            1 => self.quit_requested = true,
            else => {},
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
            const input = collectGameplayInput(&gameplay.runner, camera, &self.runtime);
            if (input.perk_choice_index != null) {
                self.audio.playUiButtonClick();
            }
            gameplay.last_update = gameplay.runner.stepFrame(frame_dt, input) catch |err| {
                self.finishRun(gameplay, .runtime_error, @errorName(err));
                return;
            };
            self.audio.handleFrameAudio(gameplay.last_update.audio, gameplay.runner.session.state.bonuses.reflex_boost);
            if (self.runtime_assets) |*runtime_assets| {
                if (gameplay.ground) |*ground| {
                    gameplay.terrain_fx.bake(&gameplay.runner.session, ground, runtime_assets);
                }
            }

            if (gameplay.last_update.all_players_dead) {
                self.finishRun(gameplay, .dead, null);
            }
        }
    }

    fn updateResults(self: *App) void {
        const buttons = resultsButtons();
        updateSelectionFromPointer(&self.results_selection, buttons[0..]);
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            self.results_selection = if (self.results_selection == 0) buttons.len - 1 else self.results_selection - 1;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            self.results_selection = (self.results_selection + 1) % buttons.len;
        }

        const activated = buttonActivated(buttons[0..], self.results_selection);
        if (!activated) return;
        self.audio.playUiButtonClick();

        switch (self.results_selection) {
            0 => self.startNewRun(),
            1 => {
                if (self.gameplay) |*gameplay| {
                    gameplay.deinit();
                    self.gameplay = null;
                }
                self.results = null;
                self.menu_selection = 0;
                self.screen = .main_menu;
            },
            else => {},
        }
    }

    fn startNewRun(self: *App) void {
        self.audio.stopGameplayMusic();
        self.runtime.recordModeStart(.survival);
        var runner = live_runner.LiveSurvivalRunner.init(.{
            .seed = nextRunSeed(&self.next_seed_state),
            .detail_preset = @intCast(std.math.clamp(self.runtime.config.detail_preset, @as(u32, 1), @as(u32, 5))),
            .gore_disabled = @intCast(self.runtime.config.gore_disabled),
            .hardcore = self.runtime.config.hardcore_flag != 0,
            .status_quest_unlock_index = self.runtime.status.quest_unlock_index,
            .status_quest_unlock_index_full = self.runtime.status.quest_unlock_index_full,
            .status_weapon_usage_counts = statusWeaponUsageCounts(self.runtime.status),
        }) catch |err| {
            self.results = .{
                .reason = .runtime_error,
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
            .last_update = last_update,
            .terrain_fx = window_terrain_fx.TerrainFxTracker.init(runner.seed),
        };
        if (self.runtime_assets) |*runtime_assets| {
            gameplay.ground = window_ground.GroundRenderer.initForUnlockTerrain(
                runtime_assets,
                gameplay.runner.seed,
                gameplay.runner.session.quest_unlock_index,
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

    fn finishRun(self: *App, gameplay: *GameplayScreen, reason: ResultsReason, runtime_error: ?[]const u8) void {
        self.audio.stopGameplayMusic();
        const runner = &gameplay.runner;
        self.runtime.absorbSessionState(&runner.session);
        const player_health = if (runner.player0Const()) |player| player.health else 0.0;
        const save_error: ?[]const u8 = save_err: {
            self.runtime.saveStatusIfDirty() catch |err| break :save_err @errorName(err);
            break :save_err null;
        };
        self.results = .{
            .reason = reason,
            .summary = runner.summary(),
            .player_health = player_health,
            .runtime_error = runtime_error orelse save_error,
        };
        gameplay.deinit();
        self.gameplay = null;
        self.results_selection = 0;
        self.screen = .results;
    }

    fn drawBoot(self: *const App) void {
        rl.clearBackground(bgColorLerp(bootProgress(self.boot_elapsed)));
        drawBackdrop();
        if (self.runtime_assets) |*runtime_assets| {
            drawBootAssets(runtime_assets, bootProgress(self.boot_elapsed));
        }
        drawCenteredText("CRIMSON-ZIG", 144, 72, accent_color);
        drawCenteredText("Desktop survival slice booting", 232, 24, text_color);
        drawCenteredText("raylib shell + live Zig runtime + archive-backed assets", 270, 18, muted_text);
        drawAssetsStatus(self);
        drawAudioStatus(&self.audio);
    }

    fn drawMainMenu(self: *const App) void {
        rl.clearBackground(bg_color);
        drawBackdrop();
        if (self.runtime_assets) |*runtime_assets| {
            drawMenuAssets(runtime_assets);
            drawSmallTextCentered(runtime_assets, "NATIVE MENU-TO-GAMEPLAY SURVIVAL SLICE", 204.0, HudTextColor.primary);
            drawSmallTextCentered(runtime_assets, "REPLAY TOOLING IS NO LONGER THE ONLY REAL SURFACE.", 234.0, HudTextColor.dim);
        }
        if (self.runtime_assets == null) {
            drawCenteredText("CRIMSON-ZIG", 118, 68, accent_color);
            drawCenteredText("Native menu-to-gameplay survival slice", 198, 24, text_color);
            drawCenteredText("Replay tooling is no longer the only real surface.", 232, 18, muted_text);
        }
        drawAssetsStatus(self);
        drawAudioStatus(&self.audio);

        const buttons = mainMenuButtons();
        for (buttons, 0..) |button, idx| {
            const mouse_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            drawButton(button, idx == self.menu_selection, mouse_hovered, if (self.runtime_assets) |*assets| assets else null);
        }

        if (self.runtime_assets) |*runtime_assets| {
            drawSmallTextCentered(runtime_assets, "ENTER STARTS. MOUSE CLICK ALSO WORKS. ESC CLOSES THE WINDOW.", 624.0, HudTextColor.dim);
        } else {
            drawCenteredText("Enter starts. Mouse click also works. Esc closes the window.", 620, 18, muted_text);
        }
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

            drawGameplayHud(runner, gameplay.last_update, runtime_assets);
            if (gameplay.last_update.paused_for_perk_pick) {
                drawPerkOverlay(runner, runtime_assets);
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
                    .abandoned, .runtime_error => drawSmallTextCentered(runtime_assets, resultsTitle(results.reason), 152.0, HudTextColor.accent),
                }
                drawSmallTextCentered(runtime_assets, resultsSubtitle(results.reason), 196.0, HudTextColor.primary);
                drawSmallTextFmt("ELAPSED_MS {d}", runtime_assets, .{results.summary.elapsed_ms_sim}, 330.0, 258.0, HudTextColor.primary);
                drawSmallTextFmt("XP {d}", runtime_assets, .{results.summary.player_experience}, 330.0, 286.0, HudTextColor.primary);
                drawSmallTextFmt("LEVEL {d}", runtime_assets, .{results.summary.player_level}, 330.0, 314.0, HudTextColor.primary);
                drawSmallTextFmt("FIRE {d}  RELOAD {d}", runtime_assets, .{ results.summary.fire_pressed_count, results.summary.reload_pressed_count }, 330.0, 342.0, HudTextColor.primary);
                drawSmallTextFmt("SPAWNS STAGE {d}  WAVE {d}", runtime_assets, .{ results.summary.stage_spawn_count, results.summary.wave_spawn_count }, 330.0, 370.0, HudTextColor.primary);
                drawSmallTextFmt("WEAPON {s}  HP {d:.1}", runtime_assets, .{ weaponName(results.summary.player_weapon_id), results.player_health }, 330.0, 398.0, HudTextColor.primary);

                if (results.runtime_error) |runtime_error| {
                    drawSmallText(runtime_assets, runtime_error, 330.0, 438.0, rl.Color.orange);
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
            }
        }

        const buttons = resultsButtons();
        for (buttons, 0..) |button, idx| {
            const mouse_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            drawButton(button, idx == self.results_selection, mouse_hovered, if (self.runtime_assets) |*assets| assets else null);
        }
        drawAudioStatus(&self.audio);
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
        app.update(frame_dt);

        rl.beginDrawing();
        defer rl.endDrawing();
        app.draw();
    }

    try app.saveAllIfDirty();
}

fn bootProgress(boot_elapsed: f32) f32 {
    return std.math.clamp(boot_elapsed / boot_duration_seconds, @as(f32, 0.0), @as(f32, 1.0));
}

fn bgColorLerp(progress: f32) rl.Color {
    return rl.Color.init(
        @intFromFloat(8.0 + progress * 8.0),
        @intFromFloat(5.0 + progress * 7.0),
        @intFromFloat(5.0 + progress * 5.0),
        255,
    );
}

fn drawBackdrop() void {
    const width = rl.getScreenWidth();
    const height = rl.getScreenHeight();
    rl.drawRectangleGradientV(0, 0, width, height, rl.Color.init(32, 18, 16, 255), bg_color);
    rl.drawCircle(width - 180, 120, 200.0, rl.Color.init(93, 31, 22, 80));
    rl.drawCircle(160, height - 80, 220.0, rl.Color.init(58, 23, 18, 90));
}

fn drawBootAssets(runtime_assets: *const window_assets.RuntimeAssets, progress: f32) void {
    const left_rect = rl.Rectangle.init(98.0, 112.0, 320.0, 180.0);
    const right_rect = rl.Rectangle.init(862.0, 112.0, 320.0, 180.0);
    const alpha = @as(u8, @intFromFloat(64.0 + progress * 160.0));

    drawTextureFit(runtime_assets.texture(.splash_10tons), left_rect, rl.Color.init(255, 255, 255, alpha));
    drawTextureFit(runtime_assets.texture(.splash_reflexive), right_rect, rl.Color.init(255, 255, 255, alpha));
    drawTextureFit(runtime_assets.texture(.loading), rl.Rectangle.init(520.0, 330.0, 240.0, 72.0), rl.Color.init(255, 255, 255, alpha));
}

fn drawMenuAssets(runtime_assets: *const window_assets.RuntimeAssets) void {
    drawTextureFit(
        runtime_assets.texture(.backplasma),
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(rl.getScreenWidth()), @floatFromInt(rl.getScreenHeight())),
        rl.Color.init(255, 255, 255, 92),
    );
    rl.drawRectangle(0, 0, rl.getScreenWidth(), rl.getScreenHeight(), rl.Color.init(16, 11, 9, 160));
    drawTextureCentered(
        runtime_assets.texture(.ui_sign_crimson),
        rl.Vector2.init(@as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5, 120.0),
        446.0,
        110.0,
        rl.Color.init(255, 255, 255, 232),
    );
    drawTextureFit(runtime_assets.texture(.ui_menu_panel), rl.Rectangle.init(388.0, 242.0, 504.0, 252.0), rl.Color.init(255, 255, 255, 220));
    drawTextureFit(runtime_assets.texture(.logo_esrb), rl.Rectangle.init(42.0, 44.0, 112.0, 150.0), rl.Color.init(255, 255, 255, 190));
}

fn drawAssetsStatus(app: *const App) void {
    switch (app.assets_state) {
        .loaded => {
            const runtime_assets = &(app.runtime_assets orelse return);
            drawTextFmt(
                "assets: {d} textures / {d} archive entries from {s}",
                .{ runtime_assets.textureCount(), runtime_assets.archive_entry_count, runtime_assets.assets_dir },
                28,
                688,
                18,
                muted_text,
            );
        },
        .unavailable => drawTextSlice("assets: no crimson.paq found; using primitive fallback", 28, 688, 18, muted_text),
        .failed => {
            drawTextSlice("assets: load failed; using primitive fallback", 28, 668, 18, muted_text);
            if (app.assets_message) |message| {
                drawTextSlice(message, 28, 688, 18, rl.Color.orange);
            }
        },
    }
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

fn mainMenuButtons() [2]UiButton {
    const center_x: f32 = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5;
    return .{
        .{ .label = "START SURVIVAL", .rect = centeredRect(center_x, 300.0, ui_button_width, ui_button_height) },
        .{ .label = "QUIT", .rect = centeredRect(center_x, 372.0, ui_button_width, ui_button_height) },
    };
}

fn resultsButtons() [2]UiButton {
    const center_x: f32 = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5;
    return .{
        .{ .label = "RESTART", .rect = centeredRect(center_x, 586.0, ui_button_width, ui_button_height) },
        .{ .label = "MAIN MENU", .rect = centeredRect(center_x, 658.0, ui_button_width, ui_button_height) },
    };
}

fn centeredRect(center_x: f32, top_y: f32, width: f32, height: f32) rl.Rectangle {
    return .{
        .x = center_x - width * 0.5,
        .y = top_y,
        .width = width,
        .height = height,
    };
}

fn updateSelectionFromPointer(selection: *usize, buttons: []const UiButton) void {
    const mouse = rl.getMousePosition();
    for (buttons, 0..) |button, idx| {
        if (rl.checkCollisionPointRec(mouse, button.rect)) {
            selection.* = idx;
            return;
        }
    }
}

fn buttonActivated(buttons: []const UiButton, selection: usize) bool {
    if (rl.isKeyPressed(.enter) or rl.isKeyPressed(.space)) return true;

    if (!rl.isMouseButtonPressed(.left)) return false;
    const mouse = rl.getMousePosition();
    for (buttons, 0..) |button, idx| {
        if (idx == selection and rl.checkCollisionPointRec(mouse, button.rect)) {
            return true;
        }
    }
    return false;
}

fn drawButton(
    button: UiButton,
    selected: bool,
    hovered: bool,
    runtime_assets: ?*const window_assets.RuntimeAssets,
) void {
    if (runtime_assets) |assets| {
        const scale = button.rect.height / 32.0;
        const texture = if (button.rect.width > 120.0) assets.texture(.ui_button_md) else assets.texture(.ui_button_sm);
        const glow_alpha: f32 = if (selected or hovered) 0.92 else 0.72;
        if (selected or hovered) {
            rl.drawRectangleRounded(
                .{
                    .x = button.rect.x + 12.0 * scale,
                    .y = button.rect.y + 5.0 * scale,
                    .width = button.rect.width - 24.0 * scale,
                    .height = button.rect.height - 10.0 * scale,
                },
                0.18,
                8,
                rl.Color.init(128, 128, 178, @intFromFloat(glow_alpha * 120.0)),
            );
        }
        const plate_alpha: f32 = if (selected or hovered) 255.0 else 230.0;
        rl.drawTexturePro(
            texture,
            rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)),
            button.rect,
            rl.Vector2.zero(),
            0.0,
            rl.Color.init(255, 255, 255, @intFromFloat(plate_alpha)),
        );

        const label_width = measureSmallText(assets, button.label);
        drawSmallText(
            assets,
            button.label,
            button.rect.x + (button.rect.width - label_width) * 0.5 + 1.0,
            button.rect.y + 10.0,
            colorWithAlpha(rl.Color.white, if (selected or hovered) 1.0 else 0.7),
        );
        return;
    }

    const fill = if (selected or hovered) accent_color else panel_color;
    const outline = if (selected or hovered) rl.Color.gold else panel_outline;
    rl.drawRectangleRounded(button.rect, 0.2, 8, fill);
    rl.drawRectangleRoundedLinesEx(button.rect, 0.2, 8, 2.0, outline);

    const label_width = rl.measureText(button.label, 24);
    const label_x = @as(i32, @intFromFloat(button.rect.x + (button.rect.width - @as(f32, @floatFromInt(label_width))) * 0.5));
    const label_y = @as(i32, @intFromFloat(button.rect.y + (button.rect.height - 24.0) * 0.5));
    rl.drawText(button.label, label_x, label_y, 24, text_color);
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
    runner: *live_runner.LiveSurvivalRunner,
    camera: rl.Camera2D,
    runtime: *const app_runtime.DesktopRuntime,
) live_runner.FrameInput {
    const binds = runtime.primaryBindBlock();
    const move_up_pressed = inputCodeIsDownWithAlt(binds.move_forward, 0xC8);
    const move_down_pressed = inputCodeIsDownWithAlt(binds.move_backward, 0xD0);
    const move_left_pressed = inputCodeIsDownWithAlt(binds.turn_left, 0xCB);
    const move_right_pressed = inputCodeIsDownWithAlt(binds.turn_right, 0xCD);
    const mouse_world = rl.getScreenToWorld2D(rl.getMousePosition(), camera);

    var frame_input: live_runner.FrameInput = .{
        .player = .{
            .move_x = boolAxis(move_left_pressed, move_right_pressed),
            .move_y = boolAxis(move_up_pressed, move_down_pressed),
            .aim_x = mouse_world.x,
            .aim_y = mouse_world.y,
            .flags = .{
                .fire_down = input_codes.inputCodeIsDown(binds.fire),
                .fire_pressed = input_codes.inputCodeIsPressed(binds.fire),
                .reload_pressed = input_codes.inputCodeIsPressed(@intCast(runtime.config.keybind_reload)),
                .move_mode = @intCast(runtime.config.player_mode_flag_p1),
                .aim_scheme = 0,
                .move_forward_pressed = move_up_pressed,
                .move_backward_pressed = move_down_pressed,
                .turn_left_pressed = move_left_pressed,
                .turn_right_pressed = move_right_pressed,
            },
        },
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
    return @floatFromInt(@intFromBool(positive) - @intFromBool(negative));
}

fn inputCodeIsDownWithAlt(primary_code: i32, alt_code: i32) bool {
    return input_codes.inputCodeIsDown(primary_code) or input_codes.inputCodeIsDown(alt_code);
}

fn statusWeaponUsageCounts(status: formats.game_cfg.Status) [state_mod.weapon_count_size]u32 {
    var counts: [state_mod.weapon_count_size]u32 = [_]u32{0} ** state_mod.weapon_count_size;
    for (0..@min(counts.len, status.weapon_usage_counts.len)) |idx| {
        counts[idx] = status.weapon_usage_counts[idx];
    }
    return counts;
}

fn drawWorld(
    runner: *const live_runner.LiveSurvivalRunner,
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

fn drawPlayers(runner: *const live_runner.LiveSurvivalRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
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

fn drawCreatures(runner: *const live_runner.LiveSurvivalRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
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

fn drawProjectiles(runner: *const live_runner.LiveSurvivalRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
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

fn drawBonuses(runner: *const live_runner.LiveSurvivalRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
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

const HudTextColor = struct {
    const primary = rl.Color.init(220, 220, 220, 255);
    const dim = rl.Color.init(170, 170, 180, 255);
    const accent = rl.Color.init(240, 200, 80, 255);
};

fn drawAmmoIndicators(assets: *const window_assets.RuntimeAssets, texture_id: window_assets.TextureId, ammo: f32) void {
    const texture = assets.texture(texture_id);
    const count = @max(0, @min(30, @as(i32, @intFromFloat(ammo + 0.999))));
    var idx: i32 = 0;
    while (idx < count) : (idx += 1) {
        const alpha: f32 = if (idx < 20) 0.8 else 0.45;
        drawTextureFit(
            texture,
            rl.Rectangle.init(300.0 + @as(f32, @floatFromInt(idx)) * 6.0, 10.0, 6.0, 16.0),
            colorWithAlpha(rl.Color.white, alpha),
        );
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

fn drawGameplayHud(
    runner: *live_runner.LiveSurvivalRunner,
    update: live_runner.FrameUpdate,
    runtime_assets: ?*const window_assets.RuntimeAssets,
) void {
    const player = runner.player0Const() orelse return;
    if (runtime_assets) |assets| {
        drawTextureFit(
            assets.texture(.ui_game_top),
            rl.Rectangle.init(0.0, 0.0, 512.0, 64.0),
            colorWithAlpha(rl.Color.white, 0.9),
        );
        drawTextureCentered(assets.texture(.ui_life_heart), rl.Vector2.init(27.0, 21.0), 32.0, 32.0, colorWithAlpha(rl.Color.white, 0.9));

        rl.drawRectangleRounded(
            .{
                .x = 64.0,
                .y = 16.0,
                .width = 120.0,
                .height = 9.0,
            },
            0.22,
            4,
            rl.Color.init(72, 20, 20, 128),
        );
        rl.drawRectangleRounded(
            .{
                .x = 64.0,
                .y = 16.0,
                .width = 120.0 * std.math.clamp(player.health / 100.0, @as(f32, 0.0), @as(f32, 1.0)),
                .height = 9.0,
            },
            0.22,
            4,
            rl.Color.init(208, 58, 58, 220),
        );

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
                colorWithAlpha(rl.Color.white, 0.9),
            );
        }

        drawAmmoIndicators(assets, weaponIndicatorTextureId(weapon_id), player.weapon.ammo);
        drawTextureFit(assets.texture(.ui_ind_panel), rl.Rectangle.init(0.0, 60.0, 182.0, 53.0), colorWithAlpha(rl.Color.white, 0.9));

        drawSmallTextFmt("HP {d:.0}", assets, .{player.health}, 30.0, 38.0, HudTextColor.primary);
        drawSmallTextFmt("XP", assets, .{}, 6.0, 78.0, HudTextColor.dim);
        drawSmallTextFmt("{d}", assets, .{update.player_experience}, 26.0, 74.0, HudTextColor.primary);
        drawSmallTextFmt("LV {d}", assets, .{update.player_level}, 86.0, 79.0, HudTextColor.accent);

        rl.drawRectangle(26, 91, 54, 4, rl.Color.init(16, 26, 54, 140));
        rl.drawRectangle(27, 92, @intFromFloat(52.0 * xpProgressRatio(update.player_experience, update.player_level)), 2, rl.Color.init(26, 77, 153, 255));
        drawSmallTextFmt("{d}ms", assets, .{update.elapsed_ms_sim}, 92.0, 74.0, HudTextColor.dim);
        drawSmallTextFmt("{d}/{d}", assets, .{ @as(i32, @intFromFloat(player.weapon.ammo)), weapon_data.weapon_stats.get(weapon_id).clip_size }, 308.0, 28.0, HudTextColor.primary);
        drawSmallTextFmt("shots {d} hits {d}", assets, .{ update.shots_fired, update.shots_hit }, 24.0, @floatFromInt(rl.getScreenHeight() - 34), HudTextColor.dim);
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

    drawTextSlice("WASD move  mouse aim/fire  R reload  Esc end run", 24, rl.getScreenHeight() - 34, 18, muted_text);
}

fn drawPerkOverlay(runner: *live_runner.LiveSurvivalRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    rl.drawRectangle(0, 0, rl.getScreenWidth(), rl.getScreenHeight(), overlay_color);
    if (runtime_assets) |assets| {
        drawTextureFit(assets.texture(.ui_menu_panel), rl.Rectangle.init(262.0, 152.0, 756.0, 360.0), colorWithAlpha(rl.Color.white, 0.96));
        drawTextureFit(assets.texture(.ui_text_pick_a_perk), rl.Rectangle.init(432.0, 176.0, 410.0, 40.0), colorWithAlpha(rl.Color.white, 0.96));

        const choices = runner.currentPerkChoices();
        for (choices, 0..) |perk_id, idx| {
            const row_y = 240.0 + @as(f32, @floatFromInt(idx)) * 28.0;
            rl.drawTexturePro(
                assets.texture(.ui_menu_item),
                rl.Rectangle.init(0.0, 0.0, @floatFromInt(assets.texture(.ui_menu_item).width), @floatFromInt(assets.texture(.ui_menu_item).height)),
                rl.Rectangle.init(332.0, row_y - 6.0, 612.0, 32.0),
                rl.Vector2.zero(),
                0.0,
                colorWithAlpha(rl.Color.white, if (idx == 0) 0.95 else 0.72),
            );
            drawSmallTextFmt("{d}. {s}", assets, .{ idx + 1, @tagName(perk_id) }, 360.0, row_y, if (idx == 0) HudTextColor.accent else HudTextColor.primary);
        }
        drawSmallText(assets, "Press 1-7 to select. Gameplay is paused.", 334.0, 458.0, HudTextColor.dim);
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

fn resultsTitle(reason: ResultsReason) [:0]const u8 {
    return switch (reason) {
        .dead => "Run Over",
        .runtime_error => "Run Interrupted",
        .abandoned => "Run Abandoned",
    };
}

fn resultsSubtitle(reason: ResultsReason) [:0]const u8 {
    return switch (reason) {
        .dead => "All players are down.",
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
