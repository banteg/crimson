const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const runtime_anim = cz.anim;
const weapon_data = cz.weapon_data;
const window_assets = @import("window_assets.zig");
const window_atlas = cz.window_atlas;
const window_ground = @import("window_ground.zig");
const window_projectiles = @import("window_projectiles.zig");

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
    screen: Screen = .boot,
    boot_elapsed: f32 = 0.0,
    menu_selection: usize = 0,
    results_selection: usize = 0,
    gameplay: ?GameplayScreen = null,
    results: ?ResultsScreen = null,
    runtime_assets: ?window_assets.RuntimeAssets = null,
    assets_state: AssetsState = .unavailable,
    assets_message: ?[]u8 = null,
    next_seed_state: u32 = 0xC0FFEE,
    quit_requested: bool = false,

    fn init(allocator: std.mem.Allocator) App {
        var app: App = .{
            .allocator = allocator,
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
        if (self.assets_message) |message| {
            self.allocator.free(message);
            self.assets_message = null;
        }
        self.* = undefined;
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
        self.boot_elapsed += frame_dt;
        if (self.boot_elapsed >= boot_duration_seconds) {
            self.screen = .main_menu;
        }
    }

    fn updateMainMenu(self: *App) void {
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
            const input = collectGameplayInput(&gameplay.runner, camera);
            gameplay.last_update = gameplay.runner.stepFrame(frame_dt, input) catch |err| {
                self.finishRun(gameplay, .runtime_error, @errorName(err));
                return;
            };

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
        var runner = live_runner.LiveSurvivalRunner.init(.{
            .seed = nextRunSeed(&self.next_seed_state),
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
        };
        if (self.runtime_assets) |*runtime_assets| {
            gameplay.ground = window_ground.GroundRenderer.initForUnlockTerrain(
                runtime_assets,
                gameplay.runner.seed,
                gameplay.runner.session.quest_unlock_index,
                gameplay.runner.session.terrain_size,
                gameplay.runner.session.terrain_size,
            ) catch null;
        }
        self.gameplay = gameplay;
        self.results = null;
        self.screen = .gameplay;
    }

    fn finishRun(self: *App, gameplay: *GameplayScreen, reason: ResultsReason, runtime_error: ?[]const u8) void {
        const runner = &gameplay.runner;
        const player_health = if (runner.player0Const()) |player| player.health else 0.0;
        self.results = .{
            .reason = reason,
            .summary = runner.summary(),
            .player_health = player_health,
            .runtime_error = runtime_error,
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
    }

    fn drawMainMenu(self: *const App) void {
        rl.clearBackground(bg_color);
        drawBackdrop();
        if (self.runtime_assets) |*runtime_assets| {
            drawMenuAssets(runtime_assets);
        }

        drawCenteredText("CRIMSON-ZIG", 118, 68, accent_color);
        drawCenteredText("Native menu-to-gameplay survival slice", 198, 24, text_color);
        drawCenteredText("Replay tooling is no longer the only real surface.", 232, 18, muted_text);
        drawAssetsStatus(self);

        const buttons = mainMenuButtons();
        for (buttons, 0..) |button, idx| {
            const mouse_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            drawButton(button, idx == self.menu_selection, mouse_hovered);
        }

        drawCenteredText("Enter starts. Mouse click also works. Esc closes the window.", 620, 18, muted_text);
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

            drawGameplayHud(runner, gameplay.last_update);
            if (gameplay.last_update.paused_for_perk_pick) {
                drawPerkOverlay(runner);
            }
        }
    }

    fn drawResults(self: *const App) void {
        rl.clearBackground(bg_color);
        drawBackdrop();

        if (self.results) |results| {
            drawCenteredText(resultsTitle(results.reason), 124, 64, accent_color);
            switch (results.reason) {
                .dead => drawCenteredText("All players are down.", 188, 22, text_color),
                .abandoned => drawCenteredText("Run returned to menu before completion.", 188, 22, text_color),
                .runtime_error => drawCenteredText("Runtime hit an unported or invalid path.", 188, 22, text_color),
            }

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

        const buttons = resultsButtons();
        for (buttons, 0..) |button, idx| {
            const mouse_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            drawButton(button, idx == self.results_selection, mouse_hovered);
        }
    }
};

pub fn main() !void {
    rl.initWindow(window_width, window_height, "crimson-zig");
    defer rl.closeWindow();

    rl.setTargetFPS(60);

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();

    var app = App.init(gpa.allocator());
    defer app.deinit();

    while (!rl.windowShouldClose() and !app.quit_requested) {
        const frame_dt = rl.getFrameTime();
        app.update(frame_dt);

        rl.beginDrawing();
        defer rl.endDrawing();
        app.draw();
    }
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
        runtime_assets.texture(.cl_logo),
        rl.Vector2.init(@as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5, 120.0),
        380.0,
        120.0,
        rl.Color.init(255, 255, 255, 232),
    );
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

fn drawButton(button: UiButton, selected: bool, hovered: bool) void {
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

fn collectGameplayInput(runner: *live_runner.LiveSurvivalRunner, camera: rl.Camera2D) live_runner.FrameInput {
    const move_x = axisFromKeys(.a, .d);
    const move_y = axisFromKeys(.w, .s);
    const mouse_world = rl.getScreenToWorld2D(rl.getMousePosition(), camera);

    var frame_input: live_runner.FrameInput = .{
        .player = .{
            .move_x = move_x,
            .move_y = move_y,
            .aim_x = mouse_world.x,
            .aim_y = mouse_world.y,
            .flags = .{
                .fire_down = rl.isMouseButtonDown(.left) or rl.isKeyDown(.space),
                .fire_pressed = rl.isMouseButtonPressed(.left) or rl.isKeyPressed(.space),
                .reload_pressed = rl.isKeyPressed(.r),
                .move_mode = 3,
                .aim_scheme = 0,
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

fn axisFromKeys(negative: rl.KeyboardKey, positive: rl.KeyboardKey) f32 {
    var value: f32 = 0.0;
    if (rl.isKeyDown(negative)) value -= 1.0;
    if (rl.isKeyDown(positive)) value += 1.0;
    return value;
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

fn drawGameplayHud(runner: *live_runner.LiveSurvivalRunner, update: live_runner.FrameUpdate) void {
    const player = runner.player0Const() orelse return;
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

fn drawPerkOverlay(runner: *live_runner.LiveSurvivalRunner) void {
    rl.drawRectangle(0, 0, rl.getScreenWidth(), rl.getScreenHeight(), overlay_color);
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
