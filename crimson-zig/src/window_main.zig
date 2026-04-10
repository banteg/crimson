const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const window_assets = @import("window_assets.zig");

const bonuses_runtime = cz.bonuses;
const game_ids = cz.game_ids;
const live_runner = cz.live_runner;
const secondary_projectiles_runtime = cz.secondary_projectiles;
const runtime_session = cz.session;
const spawn_runtime = cz.spawn;
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
                self.finishRun(&gameplay.runner, .abandoned, null);
                return;
            }

            const camera = buildWorldCamera(
                gameplay.runner.session.world_size,
                gameplay.runner.session.state.camera_shake_offset,
            );
            const input = collectGameplayInput(&gameplay.runner, camera);
            gameplay.last_update = gameplay.runner.stepFrame(frame_dt, input) catch |err| {
                self.finishRun(&gameplay.runner, .runtime_error, @errorName(err));
                return;
            };

            if (gameplay.last_update.all_players_dead) {
                self.finishRun(&gameplay.runner, .dead, null);
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
                self.gameplay = null;
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
        self.gameplay = .{
            .runner = runner,
            .last_update = last_update,
        };
        self.results = null;
        self.screen = .gameplay;
    }

    fn finishRun(self: *App, runner: *const live_runner.LiveSurvivalRunner, reason: ResultsReason, runtime_error: ?[]const u8) void {
        const player_health = if (runner.player0Const()) |player| player.health else 0.0;
        self.results = .{
            .reason = reason,
            .summary = runner.summary(),
            .player_health = player_health,
            .runtime_error = runtime_error,
        };
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
            drawWorld(runner, runtime_assets);
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

fn drawWorld(runner: *const live_runner.LiveSurvivalRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const world_size = runner.session.world_size;
    const world_rect = rl.Rectangle.init(0.0, 0.0, world_size, world_size);

    if (runtime_assets) |assets| {
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
            const base_tint = if (player.health > 0.0) rl.Color.white else dead_player_color;
            drawTextureCenteredRotated(
                assets.texture(.trooper),
                center,
                player.size * 1.2,
                player.size * 1.2,
                headingToDegrees(player.aim_heading),
                base_tint,
            );

            if (player.health > 0.0 and player.muzzle_flash_alpha > 0.02) {
                drawTextureCenteredRotated(
                    assets.texture(.muzzle_flash),
                    toRlVec(player.aim),
                    player.size * 0.72,
                    player.size * 0.72,
                    headingToDegrees(player.aim_heading),
                    colorWithAlpha(rl.Color.white, std.math.clamp(player.muzzle_flash_alpha, @as(f32, 0.0), @as(f32, 1.0))),
                );
            }
        } else {
            rl.drawCircleV(center, radius, color);
            rl.drawCircleLinesV(center, radius + 2.0, rl.Color.black);
        }

        rl.drawLineEx(center, toRlVec(player.aim), 2.0, rl.Color.gold);
    }
}

fn drawCreatures(runner: *const live_runner.LiveSurvivalRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    for (runner.session.creatures.entries) |creature| {
        if (!creature.active) continue;
        const color = if (creature.hp > 0.0) creature_color else corpse_color;
        const radius = @max(6.0, creature.size * 0.24);
        if (runtime_assets) |assets| {
            if (creatureTextureId(creature)) |texture_id| {
                drawTextureCenteredRotated(
                    assets.texture(texture_id),
                    toRlVec(creature.pos),
                    creature.size * 1.14,
                    creature.size * 1.14,
                    headingToDegrees(creature.heading),
                    if (creature.hp > 0.0) rl.Color.white else corpse_color,
                );
                continue;
            }
        }
        rl.drawCircleV(toRlVec(creature.pos), radius, color);
    }
}

fn drawProjectiles(runner: *const live_runner.LiveSurvivalRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    for (runner.session.projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        if (runtime_assets) |assets| {
            const projectile_texture = projectileTextureId(projectile.type_id) orelse {
                rl.drawCircleV(toRlVec(projectile.pos), 3.0, projectile_color);
                continue;
            };
            const sprite_size = projectileSpriteSize(projectile.type_id);
            drawTextureCenteredRotated(
                assets.texture(projectile_texture),
                toRlVec(projectile.pos),
                sprite_size,
                sprite_size,
                headingToDegrees(projectile.angle),
                rl.Color.white,
            );
            continue;
        }
        rl.drawCircleV(toRlVec(projectile.pos), 3.0, projectile_color);
    }
    for (runner.session.secondary_projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        if (runtime_assets) |assets| {
            if (secondaryProjectileTextureId(projectile.type_id)) |texture_id| {
                const sprite_size = secondaryProjectileSpriteSize(projectile);
                drawTextureCenteredRotated(
                    assets.texture(texture_id),
                    toRlVec(projectile.pos),
                    sprite_size,
                    sprite_size,
                    headingToDegrees(projectile.angle),
                    colorWithAlpha(rl.Color.white, secondaryProjectileAlpha(projectile)),
                );
                continue;
            }
        }
        rl.drawCircleV(toRlVec(projectile.pos), 6.0, secondary_projectile_color);
    }
}

fn drawBonuses(runner: *const live_runner.LiveSurvivalRunner, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    for (runner.session.bonuses.entries) |entry| {
        if (entry.bonus_id == .unused) continue;
        if (runtime_assets) |assets| {
            if (bonusTextureId(entry)) |texture_id| {
                const alpha = bonusAlpha(entry);
                drawTextureCenteredRotated(
                    assets.texture(texture_id),
                    toRlVec(entry.pos),
                    26.0,
                    26.0,
                    0.0,
                    colorWithAlpha(rl.Color.white, alpha),
                );
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

fn creatureTextureId(creature: cz.creatures.CreatureState) ?window_assets.TextureId {
    const creature_type = std.meta.intToEnum(spawn_runtime.CreatureTypeId, creature.type_id) catch return null;
    return switch (creature_type) {
        .alien => .alien,
        .lizard => .lizard,
        .spider_sp1 => .spider_sp1,
        .spider_sp2 => .spider_sp2,
        .trooper => .trooper,
        .zombie => .zombie,
    };
}

fn projectileTextureId(projectile_type_raw: i32) ?window_assets.TextureId {
    const projectile_type = std.meta.intToEnum(game_ids.ProjectileTypeId, projectile_type_raw) catch return null;
    return switch (projectile_type) {
        .pistol,
        .assault_rifle,
        .shotgun,
        .submachine_gun,
        => .bullet_i,
        .gauss_gun,
        .plasma_rifle,
        .plasma_minigun,
        .pulse_gun,
        .ion_rifle,
        .ion_minigun,
        .ion_cannon,
        .shrinkifier,
        .blade_gun,
        .spider_plasma,
        .plasma_cannon,
        .splitter_gun,
        .plague_spreader,
        .rainbow_gun,
        .fire_bullets,
        => .bullet_trail,
    };
}

fn projectileSpriteSize(projectile_type_raw: i32) f32 {
    const projectile_type = std.meta.intToEnum(game_ids.ProjectileTypeId, projectile_type_raw) catch return 10.0;
    return switch (projectile_type) {
        .ion_cannon,
        .plasma_cannon,
        => 26.0,
        .ion_rifle,
        .ion_minigun,
        .plasma_rifle,
        .plasma_minigun,
        .pulse_gun,
        => 18.0,
        .gauss_gun,
        .blade_gun,
        => 16.0,
        else => 12.0,
    };
}

fn secondaryProjectileTextureId(projectile_type: secondary_projectiles_runtime.SecondaryProjectileTypeId) ?window_assets.TextureId {
    return switch (projectile_type) {
        .rocket, .homing_rocket, .rocket_minigun => .arrow,
        .detonation => .muzzle_flash,
        .none => null,
    };
}

fn secondaryProjectileSpriteSize(projectile: secondary_projectiles_runtime.SecondaryProjectile) f32 {
    return switch (projectile.type_id) {
        .rocket => 26.0,
        .homing_rocket => 30.0,
        .rocket_minigun => 22.0,
        .detonation => 96.0 * projectile.detonation_scale * @max(0.35, projectile.detonation_t),
        .none => 18.0,
    };
}

fn secondaryProjectileAlpha(projectile: secondary_projectiles_runtime.SecondaryProjectile) f32 {
    return switch (projectile.type_id) {
        .detonation => std.math.clamp(1.0 - projectile.detonation_t * 0.5, @as(f32, 0.15), @as(f32, 1.0)),
        else => 1.0,
    };
}

fn bonusTextureId(entry: bonuses_runtime.BonusEntry) ?window_assets.TextureId {
    return switch (entry.bonus_id) {
        .unused => null,
        .points, .energizer, .double_experience => .ui_arrow,
        .weapon, .weapon_power_up => .ui_ind_bullet,
        .nuke => .ui_ind_rocket,
        .shock_chain => .ui_ind_electric,
        .fireblast, .fire_bullets => .ui_ind_fire,
        .reflex_boost => .ui_icon_aim,
        .shield, .medikit => .ui_ind_life,
        .freeze => .ui_ind_panel,
        .speed => .arrow,
    };
}

fn bonusAlpha(entry: bonuses_runtime.BonusEntry) f32 {
    if (entry.picked) return 0.42;
    if (!(entry.time_max > 0.0)) return 1.0;
    return std.math.clamp(entry.time_left / entry.time_max, @as(f32, 0.28), @as(f32, 1.0));
}

fn colorWithAlpha(color: rl.Color, alpha: f32) rl.Color {
    return rl.Color.init(
        color.r,
        color.g,
        color.b,
        @intFromFloat(std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
    );
}

fn headingToDegrees(heading: f32) f32 {
    return heading * (180.0 / std.math.pi);
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
