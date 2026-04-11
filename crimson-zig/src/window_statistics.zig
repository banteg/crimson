const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const persistence = cz.persistence;
const game_ids = cz.game_ids;
const runtime_bonuses = cz.bonuses;
const runtime_perks = cz.perks;
const state_mod = cz.state;
const weapon_data = cz.weapon_data;
const window_atlas = cz.window_atlas;

const window_assets = @import("window_assets.zig");
const window_menu = @import("window_menu.zig");
const window_ui = @import("window_ui.zig");
const window_statistics_data = @import("window_statistics_data.zig");

const panel_color = rl.Color.init(37, 24, 20, 255);
const text_color = rl.Color.init(245, 236, 225, 255);
const muted_text = rl.Color.init(171, 150, 132, 255);
const accent_color = rl.Color.init(218, 80, 46, 255);
const value_color = rl.Color.init(70, 180, 240, 255);
const gold_color = rl.Color.init(255, 228, 170, 255);

const panel_timeline_max_ms: i32 = 300;

const left_panel_rect = rl.Rectangle.init(164.0, 156.0, 424.0, 402.0);
const right_panel_rect = rl.Rectangle.init(678.0, 174.0, 424.0, 276.0);
const stats_panel_rect = rl.Rectangle.init(390.0, 168.0, 510.0, 378.0);
const credits_panel_rect = rl.Rectangle.init(360.0, 168.0, 510.0, 378.0);

const HubAction = enum {
    high_scores,
    weapons,
    perks,
    credits,
    back,
};

const View = enum {
    hub,
    high_scores,
    weapons,
    perks,
    credits,
};

const DropdownKind = enum {
    none,
    player_count,
    game_mode,
    date_mode,
    score_list,
};

const PanelState = struct {
    selection: usize = 0,
    timeline_ms: i32 = 0,
    panel_open_sfx_played: bool = false,

    fn reset(self: *PanelState) void {
        self.* = .{};
    }

    fn advance(self: *PanelState, frame_dt: f32) i32 {
        const dt_ms = @as(i32, @intFromFloat(@min(frame_dt, 0.1) * 1000.0));
        if (dt_ms > 0) {
            self.timeline_ms = @min(panel_timeline_max_ms, self.timeline_ms + dt_ms);
        }
        return dt_ms;
    }
};

const HubState = struct {
    panel: PanelState = .{},

    fn reset(self: *HubState) void {
        self.* = .{};
    }
};

const HighScoresScreen = struct {
    mode: game_ids.GameModeId = .survival,
    quest_level_key: i32 = 101,
    button_selection: usize = 0,
    dropdown_open: DropdownKind = .none,
    records: []persistence.highscores.HighScoreRecord = &.{},
    records_owned: bool = false,
    load_error: ?[]const u8 = null,

    fn reset(self: *HighScoresScreen, allocator: std.mem.Allocator) void {
        self.clear(allocator);
        self.* = .{};
    }

    fn clear(self: *HighScoresScreen, allocator: std.mem.Allocator) void {
        if (self.records_owned) allocator.free(self.records);
        self.records = &.{};
        self.records_owned = false;
        self.load_error = null;
    }
};

const WeaponsScreen = struct {
    selection: usize = 0,
    scroll: usize = 0,

    fn reset(self: *WeaponsScreen) void {
        self.* = .{};
    }
};

const PerksScreen = struct {
    selection: usize = 0,
    scroll: usize = 0,

    fn reset(self: *PerksScreen) void {
        self.* = .{};
    }
};

const CreditsScreen = struct {
    scroll: usize = 0,

    fn reset(self: *CreditsScreen) void {
        self.* = .{};
    }
};

pub const Action = enum {
    none,
    back_to_menu,
    open_play_game,
};

pub const UpdateResult = struct {
    action: Action = .none,
    config_dirty: bool = false,
    play_panel_click: bool = false,
    play_button_click: bool = false,
};

pub const State = struct {
    view: View = .hub,
    hub: HubState = .{},
    high_scores: HighScoresScreen = .{},
    weapons: WeaponsScreen = .{},
    perks: PerksScreen = .{},
    credits: CreditsScreen = .{},

    pub fn reset(self: *State, allocator: std.mem.Allocator) void {
        self.high_scores.clear(allocator);
        self.* = .{};
    }

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        self.high_scores.clear(allocator);
        self.* = undefined;
    }
};

pub fn openRoot(state: *State, allocator: std.mem.Allocator) void {
    state.reset(allocator);
}

pub fn openHighScores(
    state: *State,
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) void {
    state.view = .high_scores;
    state.high_scores.clear(allocator);
    state.high_scores.mode = highScoreModeFromConfig(config, status);
    state.high_scores.quest_level_key = questLevelKeyFromConfig(config);
    loadHighScores(&state.high_scores, allocator, base_dir, config, status);
}

pub fn update(
    state: *State,
    allocator: std.mem.Allocator,
    frame_dt: f32,
    base_dir: []const u8,
    config: *formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) UpdateResult {
    return switch (state.view) {
        .hub => updateHub(state, allocator, frame_dt, base_dir, config, status),
        .high_scores => updateHighScores(state, allocator, frame_dt, base_dir, config, status),
        .weapons => updateWeapons(state, frame_dt, config.*, status),
        .perks => updatePerks(state, frame_dt, status),
        .credits => updateCredits(state, frame_dt),
    };
}

pub fn draw(
    state: *const State,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) void {
    switch (state.view) {
        .hub => drawHub(&state.hub, runtime_assets, status),
        .high_scores => drawHighScores(&state.high_scores, runtime_assets, config, status),
        .weapons => drawWeapons(&state.weapons, runtime_assets, config, status),
        .perks => drawPerks(&state.perks, runtime_assets, config, status),
        .credits => drawCredits(&state.credits, runtime_assets),
    }
}

fn updateHub(
    state: *State,
    allocator: std.mem.Allocator,
    frame_dt: f32,
    base_dir: []const u8,
    config: *formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) UpdateResult {
    const dt_ms = state.hub.panel.advance(frame_dt);
    const buttons = hubButtons();
    window_ui.updateSelectionFromPointer(&state.hub.panel.selection, buttons[0..]);

    if (rl.isKeyPressed(.escape)) {
        return .{ .action = .back_to_menu, .play_button_click = true };
    }
    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        state.hub.panel.selection = if (state.hub.panel.selection == 0) buttons.len - 1 else state.hub.panel.selection - 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.hub.panel.selection = (state.hub.panel.selection + 1) % buttons.len;
    }
    if (!window_ui.buttonActivated(buttons[0..], state.hub.panel.selection)) {
        return .{
            .play_panel_click = dt_ms > 0 and state.hub.panel.timeline_ms >= panel_timeline_max_ms and !state.hub.panel.panel_open_sfx_played,
        };
    }

    const action: HubAction = switch (state.hub.panel.selection) {
        0 => .high_scores,
        1 => .weapons,
        2 => .perks,
        3 => .credits,
        4 => .back,
        else => .back,
    };
    switch (action) {
        .high_scores => openHighScores(state, allocator, base_dir, config.*, status),
        .weapons => {
            state.view = .weapons;
            state.weapons.reset();
        },
        .perks => {
            state.view = .perks;
            state.perks.reset();
        },
        .credits => {
            state.view = .credits;
            state.credits.reset();
        },
        .back => return .{ .action = .back_to_menu, .play_button_click = true },
    }
    return .{ .play_button_click = true };
}

fn updateHighScores(
    state: *State,
    allocator: std.mem.Allocator,
    frame_dt: f32,
    base_dir: []const u8,
    config: *formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) UpdateResult {
    _ = state.hub.panel.advance(frame_dt);
    const hs = &state.high_scores;
    const buttons = highScoreButtons();
    window_ui.updateSelectionFromPointer(&hs.button_selection, buttons[0..]);

    if (rl.isKeyPressed(.escape)) {
        hs.dropdown_open = .none;
        state.view = .hub;
        state.hub.reset();
        return .{ .play_button_click = true };
    }

    if (hs.dropdown_open == .none) {
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            hs.button_selection = if (hs.button_selection == 0) buttons.len - 1 else hs.button_selection - 1;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            hs.button_selection = (hs.button_selection + 1) % buttons.len;
        }
    }

    if (updateHighScoreQuestArrows(hs, config, status)) {
        loadHighScores(hs, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }

    if (updateHighScoreWidgets(hs, allocator, base_dir, config, status)) |widget_result| {
        return widget_result;
    }

    if (!window_ui.buttonActivated(buttons[0..], hs.button_selection)) return .{};

    return switch (hs.button_selection) {
        0 => blk: {
            loadHighScores(hs, allocator, base_dir, config.*, status);
            break :blk .{ .play_button_click = true };
        },
        1 => .{ .action = .open_play_game, .play_button_click = true },
        2 => blk: {
            hs.dropdown_open = .none;
            state.view = .hub;
            state.hub.reset();
            break :blk .{ .play_button_click = true };
        },
        else => .{},
    };
}

fn updateWeapons(state: *State, frame_dt: f32, config: formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status) UpdateResult {
    _ = state.hub.panel.advance(frame_dt);
    var weapon_ids: [state_mod.weapon_count_size]game_ids.WeaponId = undefined;
    const total = buildWeaponList(&weapon_ids, config, status);
    const screen = &state.weapons;

    if (total == 0) {
        screen.selection = 0;
        screen.scroll = 0;
    } else if (screen.selection >= total) {
        screen.selection = total - 1;
    }

    if (rl.isKeyPressed(.escape) or backButtonActivated(backOnlyButton()[0])) {
        state.view = .hub;
        state.hub.reset();
        return .{ .play_button_click = true };
    }

    const mouse = rl.getMousePosition();
    if (rl.getMouseWheelMove() != 0 and rectContains(weaponListRect(), mouse)) {
        const max_scroll = if (total > 10) total - 10 else 0;
        if (rl.getMouseWheelMove() > 0) {
            if (screen.scroll > 0) screen.scroll -= 1;
        } else if (screen.scroll < max_scroll) {
            screen.scroll += 1;
        }
    }

    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        if (screen.selection > 0) screen.selection -= 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        if (screen.selection + 1 < total) screen.selection += 1;
    }
    if (total > 10) {
        if (screen.selection < screen.scroll) screen.scroll = screen.selection;
        if (screen.selection >= screen.scroll + 10) screen.scroll = screen.selection - 9;
    }
    if (hoveredListRow(weaponListRect(), total, screen.scroll)) |row| {
        screen.selection = row;
    }

    return .{};
}

fn updatePerks(state: *State, frame_dt: f32, status: formats.game_cfg.Status) UpdateResult {
    _ = state.hub.panel.advance(frame_dt);
    var perk_ids: [state_mod.perk_count_size]game_ids.PerkId = undefined;
    const total = buildPerkList(&perk_ids, status);
    const screen = &state.perks;

    if (total == 0) {
        screen.selection = 0;
        screen.scroll = 0;
    } else if (screen.selection >= total) {
        screen.selection = total - 1;
    }

    if (rl.isKeyPressed(.escape) or backButtonActivated(backOnlyButton()[0])) {
        state.view = .hub;
        state.hub.reset();
        return .{ .play_button_click = true };
    }

    const mouse = rl.getMousePosition();
    if (rl.getMouseWheelMove() != 0 and rectContains(perkListRect(), mouse)) {
        const max_scroll = if (total > 10) total - 10 else 0;
        if (rl.getMouseWheelMove() > 0) {
            if (screen.scroll > 0) screen.scroll -= 1;
        } else if (screen.scroll < max_scroll) {
            screen.scroll += 1;
        }
    }

    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        if (screen.selection > 0) screen.selection -= 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        if (screen.selection + 1 < total) screen.selection += 1;
    }
    if (total > 10) {
        if (screen.selection < screen.scroll) screen.scroll = screen.selection;
        if (screen.selection >= screen.scroll + 10) screen.scroll = screen.selection - 9;
    }
    if (hoveredListRow(perkListRect(), total, screen.scroll)) |row| {
        screen.selection = row;
    }

    return .{};
}

fn updateCredits(state: *State, frame_dt: f32) UpdateResult {
    _ = state.hub.panel.advance(frame_dt);
    const max_scroll = if (window_statistics_data.credits_lines.len > 20) window_statistics_data.credits_lines.len - 20 else 0;
    if (rl.isKeyPressed(.escape) or backButtonActivated(backOnlyButton()[0])) {
        state.view = .hub;
        state.hub.reset();
        return .{ .play_button_click = true };
    }
    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        if (state.credits.scroll > 0) state.credits.scroll -= 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.credits.scroll = @min(state.credits.scroll + 1, max_scroll);
    }
    if (rl.getMouseWheelMove() > 0 and state.credits.scroll > 0) state.credits.scroll -= 1;
    if (rl.getMouseWheelMove() < 0 and state.credits.scroll < max_scroll) state.credits.scroll += 1;
    return .{};
}

fn drawHub(state: *const HubState, runtime_assets: ?*const window_assets.RuntimeAssets, status: formats.game_cfg.Status) void {
    if (runtime_assets) |assets| {
        drawPanelShellNoTitle(state.panel.timeline_ms, assets, stats_panel_rect);
        drawAtlasTitle(assets, stats_panel_rect, 290.0, 52.0, window_menu.label_row_statistics);
        var playtime_buf: [64]u8 = undefined;
        window_ui.drawSmallText(assets, formatPlaytimeText(&playtime_buf, status.game_sequence_id), stats_panel_rect.x + 204.0, stats_panel_rect.y + 334.0, muted_text);
        const buttons = hubButtons();
        for (buttons, 0..) |button, idx| {
            const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            window_ui.drawButton(button, idx == state.panel.selection, hovered, assets);
        }
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawHighScores(
    state: *const HighScoresScreen,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) void {
    if (runtime_assets) |assets| {
        drawSplitPanelShell(assets, window_menu.label_row_statistics);
        drawHighScoreMainPanel(state, assets, config, status);
        drawHighScoreRightPanel(state, assets, config, status);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawWeapons(
    state: *const WeaponsScreen,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) void {
    if (runtime_assets) |assets| {
        drawSplitPanelShell(assets, window_menu.label_row_statistics);
        drawWeaponsPanels(state, assets, config, status);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawPerks(
    state: *const PerksScreen,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) void {
    if (runtime_assets) |assets| {
        drawSplitPanelShell(assets, window_menu.label_row_statistics);
        drawPerksPanels(state, assets, status, config.gore_disabled, config.hardcore_flag != 0, config.game_mode == @intFromEnum(game_ids.GameModeId.tutorial));
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawCredits(state: *const CreditsScreen, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    if (runtime_assets) |assets| {
        drawPanelShellNoTitle(300, assets, credits_panel_rect);
        drawAtlasTitle(assets, credits_panel_rect, 202.0, 46.0, window_menu.label_row_statistics);
        var y: f32 = credits_panel_rect.y + 60.0;
        const start = state.scroll;
        const end = @min(start + 16, window_statistics_data.credits_lines.len);
        for (window_statistics_data.credits_lines[start..end]) |line| {
            const color = if (line.heading) gold_color else text_color;
            const line_width = window_ui.measureSmallText(assets, line.text);
            const x = credits_panel_rect.x + 198.0 + 140.0 - line_width * 0.5;
            window_ui.drawSmallText(assets, line.text, x, y, color);
            y += 16.0;
        }
        const back = backOnlyButton()[0];
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
        window_ui.drawButton(back, false, hovered, assets);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawHighScoreMainPanel(
    state: *const HighScoresScreen,
    assets: *const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) void {
    const title = highScoreTitle(state.mode);
    window_ui.drawSmallText(assets, title, left_panel_rect.x + 158.0, left_panel_rect.y + 42.0, text_color);
    drawUnderline(left_panel_rect.x + 158.0, left_panel_rect.y + 56.0, window_ui.measureSmallText(assets, title));

    if (state.mode == .quests) {
        var quest_buf: [96]u8 = undefined;
        const quest_label = std.fmt.bufPrint(&quest_buf, "{d}.{d}: {s}", .{
            @divTrunc(state.quest_level_key, 100),
            @mod(state.quest_level_key, 100),
            if (config.hardcore_flag != 0) "Hardcore quest" else "Quest",
        }) catch "Quest";
        window_ui.drawSmallText(assets, quest_label, left_panel_rect.x + 126.0, left_panel_rect.y + 64.0, if (config.hardcore_flag != 0) rl.Color.init(250, 70, 60, 180) else value_color);
        drawQuestArrows(assets, state.quest_level_key, config.hardcore_flag != 0, status);
    }

    window_ui.drawSmallText(assets, "Rank", left_panel_rect.x + 102.0, left_panel_rect.y + 84.0, text_color);
    window_ui.drawSmallText(assets, "Score", left_panel_rect.x + 138.0, left_panel_rect.y + 84.0, text_color);
    window_ui.drawSmallText(assets, "Player", left_panel_rect.x + 194.0, left_panel_rect.y + 84.0, text_color);

    const frame = scoreFrameRect();
    rl.drawRectangle(@intFromFloat(frame.x), @intFromFloat(frame.y), @intFromFloat(frame.width), @intFromFloat(frame.height), rl.Color.white);
    rl.drawRectangle(@intFromFloat(frame.x + 1.0), @intFromFloat(frame.y + 1.0), @intFromFloat(frame.width - 2.0), @intFromFloat(frame.height - 2.0), rl.Color.black);

    if (state.load_error) |load_error| {
        window_ui.drawSmallText(assets, load_error, frame.x + 8.0, frame.y + 8.0, rl.Color.orange);
    } else if (state.records.len == 0) {
        window_ui.drawSmallText(assets, "No scores yet.", frame.x + 8.0, frame.y + 8.0, muted_text);
    } else {
        const hovered_rank = hoveredHighScoreRank();
        const row_count = @min(state.records.len, 10);
        for (state.records[0..row_count], 0..) |record, idx| {
            const row_y = frame.y + 8.0 + @as(f32, @floatFromInt(idx)) * 16.0;
            const color = if (hovered_rank != null and hovered_rank.? == idx) text_color else muted_text;
            var value_buf: [32]u8 = undefined;
            window_ui.drawSmallTextFmt("{d}", assets, .{idx + 1}, frame.x + 6.0, row_y, color);
            window_ui.drawSmallText(assets, formatHighScoreValue(&value_buf, record), frame.x + 36.0, row_y, color);
            window_ui.drawSmallText(assets, clippedRecordName(record), frame.x + 94.0, row_y, color);
        }
    }

    const buttons = highScoreButtons();
    for (buttons, 0..) |button, idx| {
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
        window_ui.drawButton(button, idx == state.button_selection, hovered, assets);
    }
}

fn drawHighScoreRightPanel(
    state: *const HighScoresScreen,
    assets: *const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) void {
    if (hoveredHighScoreRank()) |rank| {
        if (rank < state.records.len) {
            drawHighScoreLocalDetails(assets, state.records[rank], rank);
            return;
        }
    }

    const check_tex = if (config.hardcore_flag != 0) assets.texture(.ui_check_on) else assets.texture(.ui_check_off);
    window_ui.drawTextureFit(check_tex, rl.Rectangle.init(right_panel_rect.x + 44.0, right_panel_rect.y + 44.0, @floatFromInt(check_tex.width), @floatFromInt(check_tex.height)), rl.Color.white);
    window_ui.drawSmallText(assets, "Hardcore", right_panel_rect.x + 66.0, right_panel_rect.y + 45.0, text_color);
    window_ui.drawSmallText(assets, "Number of players", right_panel_rect.x + 46.0, right_panel_rect.y + 64.0, text_color);
    window_ui.drawSmallText(assets, "Game mode", right_panel_rect.x + 174.0, right_panel_rect.y + 64.0, text_color);
    window_ui.drawSmallText(assets, "Show scores:", right_panel_rect.x + 44.0, right_panel_rect.y + 106.0, text_color);
    window_ui.drawSmallText(assets, "Selected score list:", right_panel_rect.x + 44.0, right_panel_rect.y + 150.0, text_color);

    drawDropdown(
        assets,
        playerCountWidgetRect(),
        playerCountLabels()[0..],
        @as(usize, @intCast(std.math.clamp(config.player_count, @as(u32, 1), @as(u32, 4)))) - 1,
        state.dropdown_open == .player_count,
    );

    var mode_labels_buf: [4][]const u8 = undefined;
    const mode_labels = highScoreModeLabels(&mode_labels_buf, status);
    drawDropdown(
        assets,
        gameModeWidgetRect(),
        mode_labels,
        highScoreModeLabelIndex(state.mode, status),
        state.dropdown_open == .game_mode,
    );

    drawDropdown(
        assets,
        dateModeWidgetRect(),
        scoreDateModeLabels()[0..],
        @min(config.highscore_date_mode, 3),
        state.dropdown_open == .date_mode,
    );

    var saved_names: [formats.crimson_cfg.saved_name_slot_count][]const u8 = undefined;
    for (0..saved_names.len) |idx| saved_names[idx] = formats.crimson_cfg.savedNameLabel(&config, idx);
    drawDropdown(
        assets,
        scoreListWidgetRect(),
        saved_names[0..],
        formats.crimson_cfg.selectedSavedNameSlot(&config),
        state.dropdown_open == .score_list,
    );
}

fn drawWeaponsPanels(
    state: *const WeaponsScreen,
    assets: *const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) void {
    const title = "Unlocked Weapons Database";
    window_ui.drawSmallText(assets, title, left_panel_rect.x + 150.0, left_panel_rect.y + 50.0, text_color);
    drawUnderline(left_panel_rect.x + 150.0, left_panel_rect.y + 64.0, window_ui.measureSmallText(assets, title));

    var weapon_ids: [state_mod.weapon_count_size]game_ids.WeaponId = undefined;
    const total = buildWeaponList(&weapon_ids, config, status);
    window_ui.drawSmallTextFmt("{d} weapons in database", assets, .{total}, left_panel_rect.x + 102.0, left_panel_rect.y + 80.0, muted_text);
    window_ui.drawSmallText(assets, "Weapon", left_panel_rect.x + 102.0, left_panel_rect.y + 108.0, text_color);
    drawListFrame(weaponListRect());

    const start = @min(state.scroll, if (total > 10) total - 10 else 0);
    const end = @min(start + 10, total);
    for (weapon_ids[start..end], 0..) |weapon_id, row| {
        const list_index = start + row;
        const color = if (list_index == state.selection) text_color else muted_text;
        window_ui.drawSmallText(assets, game_ids.weaponDisplayName(weapon_id, false), weaponListRect().x + 6.0, weaponListRect().y + 6.0 + @as(f32, @floatFromInt(row)) * 16.0, color);
    }

    const back = backOnlyButton()[0];
    const back_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
    window_ui.drawButton(back, false, back_hovered, assets);

    if (total == 0) return;
    const weapon_id = weapon_ids[@min(state.selection, total - 1)];
    const detail_x = right_panel_rect.x + 46.0;
    window_ui.drawSmallTextFmt("weapon #{d}", assets, .{@intFromEnum(weapon_id)}, detail_x + 146.0, right_panel_rect.y + 32.0, muted_text);
    const name = game_ids.weaponDisplayName(weapon_id, false);
    window_ui.drawSmallText(assets, name, detail_x, right_panel_rect.y + 50.0, text_color);
    const icon_index = weapon_data.weaponIconIndex(weapon_id);
    if (icon_index >= 0) {
        const src_rect = window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index);
        rl.drawTexturePro(
            assets.texture(.ui_wicons),
            rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height),
            rl.Rectangle.init(detail_x + 20.0, right_panel_rect.y + 82.0, 64.0, 32.0),
            rl.Vector2.zero(),
            0.0,
            rl.Color.white,
        );
    }
    const stats_entry = weapon_data.weapon_stats.get(weapon_id);
    const ammo_class = @intFromEnum(weapon_data.projectileTypeIdFromWeaponId(weapon_id) orelse game_ids.ProjectileTypeId.pistol);
    var fire_rate_buf: [64]u8 = undefined;
    const fire_rate_text = if (ammo_class == 1)
        "Fire rate: n/a"
    else
        std.fmt.bufPrint(&fire_rate_buf, "Fire rate: {d} rpm", .{@as(i32, @intFromFloat(60.0 / stats_entry.shot_cooldown))}) catch "Fire rate: ?";
    window_ui.drawSmallText(assets, fire_rate_text, detail_x + 16.0, right_panel_rect.y + 128.0, text_color);
    var reload_buf: [64]u8 = undefined;
    const reload_text = std.fmt.bufPrint(&reload_buf, "Reload time: {d:.1} secs", .{stats_entry.reload_time}) catch "Reload time: ?";
    window_ui.drawSmallText(assets, reload_text, detail_x + 16.0, right_panel_rect.y + 146.0, text_color);
    window_ui.drawSmallTextFmt("Clip size: {d}", assets, .{stats_entry.clip_size}, detail_x + 16.0, right_panel_rect.y + 164.0, text_color);
}

fn drawPerksPanels(
    state: *const PerksScreen,
    assets: *const window_assets.RuntimeAssets,
    status: formats.game_cfg.Status,
    violence_disabled: u8,
    hardcore: bool,
    preserve_bugs: bool,
) void {
    _ = hardcore;
    const title = "Unlocked Perks Database";
    window_ui.drawSmallText(assets, title, left_panel_rect.x + 162.0, left_panel_rect.y + 50.0, text_color);
    drawUnderline(left_panel_rect.x + 162.0, left_panel_rect.y + 64.0, window_ui.measureSmallText(assets, title));

    var perk_ids: [state_mod.perk_count_size]game_ids.PerkId = undefined;
    const total = buildPerkList(&perk_ids, status);
    window_ui.drawSmallTextFmt("{d} perks in database", assets, .{total}, left_panel_rect.x + 102.0, left_panel_rect.y + 78.0, muted_text);
    window_ui.drawSmallText(assets, "Perks", left_panel_rect.x + 102.0, left_panel_rect.y + 106.0, text_color);
    drawListFrame(perkListRect());

    const start = @min(state.scroll, if (total > 10) total - 10 else 0);
    const end = @min(start + 10, total);
    for (perk_ids[start..end], 0..) |perk_id, row| {
        const list_index = start + row;
        const color = if (list_index == state.selection) text_color else muted_text;
        window_ui.drawSmallText(
            assets,
            game_ids.perkDisplayName(perk_id, violence_disabled, preserve_bugs),
            perkListRect().x + 6.0,
            perkListRect().y + 6.0 + @as(f32, @floatFromInt(row)) * 16.0,
            color,
        );
    }

    const back = backOnlyButton()[0];
    const back_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
    window_ui.drawButton(back, false, back_hovered, assets);

    if (total == 0) return;
    const perk_id = perk_ids[@min(state.selection, total - 1)];
    const detail_x = right_panel_rect.x + 40.0;
    window_ui.drawSmallTextFmt("perk #{d}", assets, .{@intFromEnum(perk_id)}, detail_x + 154.0, right_panel_rect.y + 32.0, muted_text);
    const name = game_ids.perkDisplayName(perk_id, violence_disabled, preserve_bugs);
    window_ui.drawSmallText(assets, name, detail_x + 30.0, right_panel_rect.y + 50.0, text_color);
    drawUnderline(detail_x + 30.0, right_panel_rect.y + 64.0, window_ui.measureSmallText(assets, name));

    var y = right_panel_rect.y + 92.0;
    if (window_statistics_data.perkPrerequisite(perk_id)) |prereq| {
        var req_buf: [128]u8 = undefined;
        const req_text = std.fmt.bufPrint(&req_buf, "Requires: {s}", .{game_ids.perkDisplayName(prereq, violence_disabled, preserve_bugs)}) catch "Requires: ?";
        window_ui.drawSmallText(assets, req_text, detail_x, y, rl.Color.init(255, 204, 204, 220));
        y += 18.0;
    }
    drawWrappedSmallText(assets, window_statistics_data.perkDescription(perk_id), detail_x, y, 256.0, muted_text);
}

fn drawSplitPanelShell(assets: *const window_assets.RuntimeAssets, label_row: i32) void {
    window_menu.drawMenuBackdrop(assets);
    window_menu.drawSign(panel_timeline_max_ms, assets);
    window_ui.drawTextureFit(assets.texture(.ui_menu_panel), left_panel_rect, window_ui.colorWithAlpha(rl.Color.white, 0.96));
    window_ui.drawTextureFit(assets.texture(.ui_menu_panel), right_panel_rect, window_ui.colorWithAlpha(rl.Color.white, 0.96));
    window_menu.drawAtlasLabelCentered(assets, label_row, 146.0, window_ui.colorWithAlpha(rl.Color.white, 0.96));
}

fn drawPanelShell(timeline_ms: i32, assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle, label_row: i32) void {
    window_menu.drawMenuBackdrop(assets);
    window_menu.drawSign(timeline_ms, assets);
    window_ui.drawTextureFit(assets.texture(.ui_menu_panel), rect, window_ui.colorWithAlpha(rl.Color.white, 0.96));
    window_menu.drawAtlasLabelCentered(assets, label_row, rect.y + 42.0, window_ui.colorWithAlpha(rl.Color.white, 0.96));
}

fn drawPanelShellNoTitle(timeline_ms: i32, assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle) void {
    window_menu.drawMenuBackdrop(assets);
    window_menu.drawSign(timeline_ms, assets);
    window_ui.drawTextureFit(assets.texture(.ui_menu_panel), rect, window_ui.colorWithAlpha(rl.Color.white, 0.96));
}

fn drawAtlasTitle(assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle, rel_x: f32, rel_y: f32, row: i32) void {
    const texture = assets.texture(.ui_item_texts);
    rl.drawTexturePro(
        texture,
        rl.Rectangle.init(0.0, @as(f32, @floatFromInt(row)) * 32.0, 128.0, 32.0),
        rl.Rectangle.init(rect.x + rel_x, rect.y + rel_y, 128.0, 32.0),
        rl.Vector2.zero(),
        0.0,
        rl.Color.white,
    );
}

fn hubButtons() [5]window_ui.UiButton {
    return .{
        .{ .label = "High scores", .rect = window_ui.centeredRect(stats_panel_rect.x + 270.0, stats_panel_rect.y + 104.0, 240.0, 44.0) },
        .{ .label = "Weapons", .rect = window_ui.centeredRect(stats_panel_rect.x + 270.0, stats_panel_rect.y + 138.0, 240.0, 44.0) },
        .{ .label = "Perks", .rect = window_ui.centeredRect(stats_panel_rect.x + 270.0, stats_panel_rect.y + 172.0, 240.0, 44.0) },
        .{ .label = "Credits", .rect = window_ui.centeredRect(stats_panel_rect.x + 270.0, stats_panel_rect.y + 206.0, 240.0, 44.0) },
        .{ .label = "Back", .rect = window_ui.centeredRect(stats_panel_rect.x + 394.0, stats_panel_rect.y + 290.0, 180.0, 44.0) },
    };
}

fn highScoreButtons() [3]window_ui.UiButton {
    return .{
        .{ .label = "Update scores", .rect = window_ui.centeredRect(left_panel_rect.x + 212.0, left_panel_rect.y + 268.0, 240.0, 44.0) },
        .{ .label = "Play a game", .rect = window_ui.centeredRect(left_panel_rect.x + 212.0, left_panel_rect.y + 322.0, 240.0, 44.0) },
        .{ .label = "Back", .rect = window_ui.centeredRect(left_panel_rect.x + 340.0, left_panel_rect.y + 355.0, 150.0, 44.0) },
    };
}

fn backOnlyButton() [1]window_ui.UiButton {
    return .{
        .{ .label = "Back", .rect = window_ui.centeredRect(credits_panel_rect.x + 298.0, credits_panel_rect.y + 310.0, 180.0, 44.0) },
    };
}

fn scoreFrameRect() rl.Rectangle {
    return rl.Rectangle.init(left_panel_rect.x + 100.0, left_panel_rect.y + 101.0, 250.0, 164.0);
}

fn weaponListRect() rl.Rectangle {
    return rl.Rectangle.init(left_panel_rect.x + 102.0, left_panel_rect.y + 128.0, 250.0, 164.0);
}

fn perkListRect() rl.Rectangle {
    return rl.Rectangle.init(left_panel_rect.x + 102.0, left_panel_rect.y + 126.0, 250.0, 164.0);
}

fn drawListFrame(rect: rl.Rectangle) void {
    rl.drawRectangle(@intFromFloat(rect.x), @intFromFloat(rect.y), @intFromFloat(rect.width), @intFromFloat(rect.height), rl.Color.white);
    rl.drawRectangle(@intFromFloat(rect.x + 1.0), @intFromFloat(rect.y + 1.0), @intFromFloat(rect.width - 2.0), @intFromFloat(rect.height - 2.0), rl.Color.black);
}

fn drawUnderline(x: f32, y: f32, width: f32) void {
    rl.drawRectangle(@intFromFloat(x), @intFromFloat(y), @intFromFloat(width), 1, rl.Color.init(255, 255, 255, 180));
}

fn playerCountLabels() [4][]const u8 {
    return .{ "1 player", "2 players", "3 players", "4 players" };
}

fn scoreDateModeLabels() [4][]const u8 {
    return .{ "Best of all time", "Best of month", "Best of week", "Best of day" };
}

fn drawDropdown(
    assets: *const window_assets.RuntimeAssets,
    rect: rl.Rectangle,
    items: []const []const u8,
    selected_index_raw: usize,
    is_open: bool,
) void {
    const selected_index = @min(selected_index_raw, if (items.len == 0) @as(usize, 0) else items.len - 1);
    const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), rect);
    const texture = if (is_open or hovered) assets.texture(.ui_drop_on) else assets.texture(.ui_drop_off);

    rl.drawRectangleRec(rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(rect.x + 1.0), @intFromFloat(rect.y + 1.0), @intFromFloat(rect.width - 2.0), @intFromFloat(rect.height - 2.0), rl.Color.black);
    if (items.len != 0) {
        window_ui.drawSmallText(assets, items[selected_index], rect.x + 4.0, rect.y + 1.0, if (hovered or is_open) text_color else muted_text);
    }
    rl.drawTexturePro(
        texture,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)),
        rl.Rectangle.init(rect.x + rect.width - 17.0, rect.y, 16.0, 16.0),
        rl.Vector2.zero(),
        0.0,
        rl.Color.white,
    );

    if (!is_open or items.len == 0) return;
    const list_rect = rl.Rectangle.init(rect.x, rect.y, rect.width, 16.0 * @as(f32, @floatFromInt(items.len + 1)));
    rl.drawRectangleRec(list_rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(list_rect.x + 1.0), @intFromFloat(list_rect.y + 1.0), @intFromFloat(list_rect.width - 2.0), @intFromFloat(list_rect.height - 2.0), rl.Color.black);
    for (items, 0..) |item, idx| {
        const row_rect = rl.Rectangle.init(rect.x, rect.y + 17.0 + @as(f32, @floatFromInt(idx)) * 16.0, rect.width, 16.0);
        const row_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), row_rect);
        window_ui.drawSmallText(assets, item, row_rect.x + 4.0, row_rect.y + 1.0, if (row_hovered or idx == selected_index) text_color else muted_text);
    }
}

fn playerCountWidgetRect() rl.Rectangle {
    return rl.Rectangle.init(right_panel_rect.x + 46.0, right_panel_rect.y + 78.0, 102.0, 16.0);
}

fn gameModeWidgetRect() rl.Rectangle {
    return rl.Rectangle.init(right_panel_rect.x + 174.0, right_panel_rect.y + 78.0, 118.0, 16.0);
}

fn dateModeWidgetRect() rl.Rectangle {
    return rl.Rectangle.init(right_panel_rect.x + 44.0, right_panel_rect.y + 120.0, 150.0, 16.0);
}

fn scoreListWidgetRect() rl.Rectangle {
    return rl.Rectangle.init(right_panel_rect.x + 44.0, right_panel_rect.y + 164.0, 174.0, 16.0);
}

fn hoveredHighScoreRank() ?usize {
    const mouse = rl.getMousePosition();
    const frame = scoreFrameRect();
    if (!rectContains(frame, mouse)) return null;
    const row = @as(usize, @intFromFloat((mouse.y - (frame.y + 8.0)) / 16.0));
    if (row >= 10) return null;
    return row;
}

fn hoveredListRow(rect: rl.Rectangle, total: usize, scroll: usize) ?usize {
    const mouse = rl.getMousePosition();
    if (!rectContains(rect, mouse)) return null;
    const row = @as(usize, @intFromFloat((mouse.y - (rect.y + 6.0)) / 16.0));
    if (row >= 10 or scroll + row >= total) return null;
    return scroll + row;
}

fn drawHighScoreLocalDetails(assets: *const window_assets.RuntimeAssets, record: persistence.highscores.HighScoreRecord, rank: usize) void {
    const detail_x = right_panel_rect.x + 78.0;
    window_ui.drawSmallText(assets, clippedRecordName(record), detail_x, right_panel_rect.y + 44.0, text_color);
    window_ui.drawSmallText(assets, "Local score", detail_x, right_panel_rect.y + 58.0, muted_text);
    var date_buf: [64]u8 = undefined;
    if (formatRecordDateBuf(&date_buf, record)) |date| {
        window_ui.drawSmallText(assets, date, detail_x + 115.0, right_panel_rect.y + 72.0, muted_text);
    }
    window_ui.drawSmallText(assets, "Score", detail_x + 27.0, right_panel_rect.y + 90.0, muted_text);
    window_ui.drawSmallText(assets, "Game time", detail_x + 114.0, right_panel_rect.y + 90.0, muted_text);
    window_ui.drawSmallTextFmt("{d}", assets, .{record.scoreXp()}, detail_x + 27.0, right_panel_rect.y + 105.0, text_color);
    var time_buf: [32]u8 = undefined;
    window_ui.drawSmallText(assets, formatElapsedMmSsBuf(&time_buf, record.survivalElapsedMs()), detail_x + 148.0, right_panel_rect.y + 109.0, text_color);
    var rank_buf: [32]u8 = undefined;
    var ordinal_buf: [16]u8 = undefined;
    const rank_text = std.fmt.bufPrint(&rank_buf, "Rank: {s}", .{ordinalBuf(&ordinal_buf, rank + 1)}) catch "Rank: ?";
    window_ui.drawSmallText(assets, rank_text, detail_x + 16.0, right_panel_rect.y + 120.0, muted_text);
    const icon_index = weapon_data.weaponIconIndex(record.mostUsedWeaponId());
    if (icon_index >= 0) {
        const src_rect = window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index);
        rl.drawTexturePro(
            assets.texture(.ui_wicons),
            rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height),
            rl.Rectangle.init(detail_x + 12.0, right_panel_rect.y + 146.0, 64.0, 32.0),
            rl.Vector2.zero(),
            0.0,
            rl.Color.white,
        );
    }
    window_ui.drawSmallTextFmt("Frags: {d}", assets, .{record.creatureKillCount()}, detail_x + 122.0, right_panel_rect.y + 147.0, muted_text);
    const shots_fired = record.shotsFired();
    const hit_pct: u32 = if (shots_fired == 0) 0 else @intCast(@divTrunc(record.shotsHit() * 100, shots_fired));
    window_ui.drawSmallTextFmt("Hit %: {d}%", assets, .{hit_pct}, detail_x + 122.0, right_panel_rect.y + 161.0, muted_text);
    window_ui.drawSmallText(assets, game_ids.weaponDisplayName(record.mostUsedWeaponId(), false), detail_x + 12.0, right_panel_rect.y + 178.0, text_color);
}

fn updateHighScoreWidgets(
    state: *HighScoresScreen,
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    config: *formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) ?UpdateResult {
    const mouse = rl.getMousePosition();
    const click = rl.isMouseButtonPressed(.left);

    const hardcore_rect = rl.Rectangle.init(right_panel_rect.x + 44.0, right_panel_rect.y + 44.0, 120.0, 16.0);
    if (click and state.dropdown_open == .none and rectContains(hardcore_rect, mouse)) {
        config.hardcore_flag = if (config.hardcore_flag == 0) 1 else 0;
        loadHighScores(state, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }

    if (updateDropdownSelection(&state.dropdown_open, .player_count, playerCountWidgetRect(), playerCountLabels()[0..], click, mouse)) |selected| {
        config.player_count = @intCast(selected + 1);
        loadHighScores(state, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }
    var mode_labels_buf: [4][]const u8 = undefined;
    const mode_labels = highScoreModeLabels(&mode_labels_buf, status);
    if (updateDropdownSelection(&state.dropdown_open, .game_mode, gameModeWidgetRect(), mode_labels, click, mouse)) |selected| {
        const mode = highScoreModeFromIndex(selected, status);
        state.mode = mode;
        config.game_mode = @intCast(@intFromEnum(mode));
        if (mode == .typo) config.player_count = 1;
        if (mode == .quests and state.quest_level_key <= 0) state.quest_level_key = 101;
        loadHighScores(state, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }
    if (updateDropdownSelection(&state.dropdown_open, .date_mode, dateModeWidgetRect(), scoreDateModeLabels()[0..], click, mouse)) |selected| {
        config.highscore_date_mode = @intCast(selected);
        loadHighScores(state, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }
    var saved_names: [formats.crimson_cfg.saved_name_slot_count][]const u8 = undefined;
    for (0..saved_names.len) |idx| saved_names[idx] = formats.crimson_cfg.savedNameLabel(config, idx);
    if (updateDropdownSelection(&state.dropdown_open, .score_list, scoreListWidgetRect(), saved_names[0..], click, mouse)) |selected| {
        formats.crimson_cfg.setSelectedSavedNameSlot(config, selected);
        return .{ .config_dirty = true, .play_button_click = true };
    }
    return null;
}

fn updateDropdownSelection(
    open: *DropdownKind,
    kind: DropdownKind,
    rect: rl.Rectangle,
    items: []const []const u8,
    click: bool,
    mouse: rl.Vector2,
) ?usize {
    if (!click) return null;
    if (open.* == .none) {
        if (rectContains(rect, mouse)) {
            open.* = kind;
        }
        return null;
    }
    if (open.* != kind) {
        if (!rectContains(rect, mouse)) open.* = .none;
        return null;
    }

    const list_rect = rl.Rectangle.init(rect.x, rect.y, rect.width, 16.0 * @as(f32, @floatFromInt(items.len + 1)));
    if (!rectContains(list_rect, mouse)) {
        open.* = .none;
        return null;
    }
    if (mouse.y < rect.y + 16.0) {
        open.* = .none;
        return null;
    }
    const row = @as(usize, @intFromFloat((mouse.y - (rect.y + 17.0)) / 16.0));
    open.* = .none;
    if (row < items.len) return row;
    return null;
}

fn updateHighScoreQuestArrows(
    state: *HighScoresScreen,
    config: *formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) bool {
    if (state.mode != .quests) return false;
    const click = rl.isMouseButtonPressed(.left);
    if (!click) return false;

    const unlock = if (config.hardcore_flag != 0) status.quest_unlock_index_full else status.quest_unlock_index;
    const max_index = std.math.clamp(unlock, @as(i32, 0), @as(i32, 49));
    const current_index = questLevelKeyToIndex(state.quest_level_key);
    const mouse = rl.getMousePosition();
    if (current_index > 0 and rectContains(questPrevArrowRect(), mouse)) {
        state.quest_level_key = questIndexToLevelKey(current_index - 1);
        return true;
    }
    if (current_index < max_index and rectContains(questNextArrowRect(), mouse)) {
        state.quest_level_key = questIndexToLevelKey(current_index + 1);
        return true;
    }
    return false;
}

fn drawQuestArrows(
    assets: *const window_assets.RuntimeAssets,
    quest_level_key: i32,
    hardcore: bool,
    status: formats.game_cfg.Status,
) void {
    const arrow = assets.texture(.ui_arrow);
    const unlock = if (hardcore) status.quest_unlock_index_full else status.quest_unlock_index;
    const max_index = std.math.clamp(unlock, @as(i32, 0), @as(i32, 49));
    const current_index = questLevelKeyToIndex(quest_level_key);
    const tint = rl.Color.init(255, 255, 255, 130);
    if (current_index > 0) {
        rl.drawTexturePro(
            arrow,
            rl.Rectangle.init(0.0, 0.0, @floatFromInt(arrow.width), @floatFromInt(arrow.height)),
            questPrevArrowRect(),
            rl.Vector2.zero(),
            0.0,
            tint,
        );
    }
    if (current_index < max_index) {
        rl.drawTexturePro(
            arrow,
            rl.Rectangle.init(0.0, 0.0, -@as(f32, @floatFromInt(arrow.width)), @floatFromInt(arrow.height)),
            questNextArrowRect(),
            rl.Vector2.zero(),
            0.0,
            tint,
        );
    }
}

fn questPrevArrowRect() rl.Rectangle {
    return rl.Rectangle.init(left_panel_rect.x + 96.0, left_panel_rect.y + 62.0, 32.0, 16.0);
}

fn questNextArrowRect() rl.Rectangle {
    return rl.Rectangle.init(left_panel_rect.x + 352.0, left_panel_rect.y + 62.0, 32.0, 16.0);
}

fn highScoreTitle(mode: game_ids.GameModeId) []const u8 {
    return switch (mode) {
        .quests => "High scores - Quests",
        .rush => "High scores - Rush",
        .survival => "High scores - Survival",
        .typo => "High scores - Typ'o'Shooter",
        .tutorial => "High scores - Tutorial",
    };
}

fn highScoreModeFromConfig(config: formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status) game_ids.GameModeId {
    const mode = std.meta.intToEnum(game_ids.GameModeId, @as(i32, @intCast(config.game_mode))) catch .survival;
    if (mode == .typo and status.quest_unlock_index < 40) return .survival;
    return switch (mode) {
        .survival, .rush, .quests, .typo => mode,
        .tutorial => .survival,
    };
}

fn highScoreModeLabels(buf: *[4][]const u8, status: formats.game_cfg.Status) []const []const u8 {
    buf.* = .{ "Quests", "Rush", "Survival", "Typ'o'Shooter" };
    return if (status.quest_unlock_index >= 40) buf[0..4] else buf[0..3];
}

fn highScoreModeFromIndex(index: usize, status: formats.game_cfg.Status) game_ids.GameModeId {
    return switch (@min(index, if (status.quest_unlock_index >= 40) @as(usize, 3) else @as(usize, 2))) {
        0 => .quests,
        1 => .rush,
        2 => .survival,
        3 => .typo,
        else => .survival,
    };
}

fn highScoreModeLabelIndex(mode: game_ids.GameModeId, status: formats.game_cfg.Status) usize {
    return switch (mode) {
        .quests => 0,
        .rush => 1,
        .survival => 2,
        .typo => if (status.quest_unlock_index >= 40) 3 else 2,
        .tutorial => 2,
    };
}

fn loadHighScores(
    state: *HighScoresScreen,
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) void {
    _ = status;
    state.clear(allocator);
    state.load_error = null;

    const score_path = persistence.highscores.scoresPathForMode(
        allocator,
        base_dir,
        @intFromEnum(state.mode),
        .{
            .hardcore = config.hardcore_flag != 0,
            .quest_stage_major = @divTrunc(state.quest_level_key, 100),
            .quest_stage_minor = @mod(state.quest_level_key, 100),
            .player_count = @intCast(config.player_count),
        },
    ) catch |err| {
        state.load_error = @errorName(err);
        return;
    };
    defer allocator.free(score_path);

    const records = persistence.highscores.readHighscoreTable(
        allocator,
        score_path,
        @intFromEnum(state.mode),
    ) catch |err| {
        state.load_error = @errorName(err);
        return;
    };

    var filtered: std.ArrayList(persistence.highscores.HighScoreRecord) = .empty;
    defer filtered.deinit(allocator);
    for (records.items) |record| {
        if (!passesDateFilter(record, config.highscore_date_mode)) continue;
        filtered.append(allocator, record) catch {
            state.load_error = "OutOfMemory";
            records.deinit(allocator);
            return;
        };
    }
    records.deinit(allocator);

    state.records = filtered.toOwnedSlice(allocator) catch {
        state.load_error = "OutOfMemory";
        return;
    };
    state.records_owned = true;
}

fn passesDateFilter(record: persistence.highscores.HighScoreRecord, date_mode_raw: u8) bool {
    const mode = @min(date_mode_raw, 3);
    if (mode == 0) return true;
    const stamp = currentDateStampUtc();
    const day = record.data[0x40];
    const checksum = record.data[0x41];
    const month = record.data[0x42];
    const year = 2000 + @as(i32, record.data[0x43]);
    if (day == 0 or month == 0) return false;
    return switch (mode) {
        1 => month == stamp.month and year == stamp.year,
        2 => checksum == @as(u8, @intCast(persistence.highscores.highscoreDateChecksum(stamp.year, stamp.month, stamp.day) & 0xFF)) and year == stamp.year,
        3 => day == stamp.day and month == stamp.month and year == stamp.year,
        else => true,
    };
}

fn currentDateStampUtc() persistence.highscores.DateStamp {
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(std.time.timestamp(), 0)) };
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return .{
        .year = year_day.year,
        .month = @intCast(@intFromEnum(month_day.month) + 1),
        .day = @intCast(month_day.day_index + 1),
    };
}

fn buildWeaponList(
    dest: *[state_mod.weapon_count_size]game_ids.WeaponId,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
) usize {
    const available = runtime_bonuses.buildWeaponAvailabilityForStatus(
        highScoreModeFromConfig(config, status),
        false,
        status.quest_unlock_index,
        status.quest_unlock_index_full,
    );
    var count: usize = 0;
    var weapon_id_raw: i32 = 1;
    while (weapon_id_raw < state_mod.weapon_count_size) : (weapon_id_raw += 1) {
        const weapon_id: game_ids.WeaponId = @enumFromInt(weapon_id_raw);
        const include = available.get(weapon_id) or weapon_id == .pistol or status.weapon_usage_counts[@intCast(weapon_id_raw)] != 0;
        if (!include) continue;
        dest[count] = weapon_id;
        count += 1;
    }
    return count;
}

fn buildPerkList(dest: *[state_mod.perk_count_size]game_ids.PerkId, status: formats.game_cfg.Status) usize {
    const available = runtime_perks.buildPerkAvailabilityForUnlockIndex(status.quest_unlock_index);
    var count: usize = 0;
    var perk_id_raw: i32 = 1;
    while (perk_id_raw < state_mod.perk_count_size) : (perk_id_raw += 1) {
        const perk_id: game_ids.PerkId = @enumFromInt(perk_id_raw);
        if (!available.get(perk_id)) continue;
        dest[count] = perk_id;
        count += 1;
    }
    return count;
}

fn clippedRecordName(record: persistence.highscores.HighScoreRecord) []const u8 {
    const name = record.name();
    return if (name.len > 16) name[0..16] else name;
}

fn formatHighScoreValue(buf: []u8, record: persistence.highscores.HighScoreRecord) []const u8 {
    return switch (record.gameModeId() orelse .survival) {
        .rush, .quests => std.fmt.bufPrint(buf, "{d}", .{@divTrunc(record.survivalElapsedMs(), 1000)}) catch "0",
        else => std.fmt.bufPrint(buf, "{d}", .{record.scoreXp()}) catch "0",
    };
}

fn formatPlaytimeText(buf: []u8, game_sequence_ms: u32) []const u8 {
    const total_minutes = @divTrunc(@divTrunc(game_sequence_ms, 1000), 60);
    const hours = @divTrunc(total_minutes, 60);
    const minutes = @mod(total_minutes, 60);
    const hour_label = if (hours == 1) "hour" else "hours";
    const minute_label = if (minutes == 1) "minute" else "minutes";
    return std.fmt.bufPrint(buf, "played for {d} {s} {d} {s}", .{ hours, hour_label, minutes, minute_label }) catch "played for 0 hours 0 minutes";
}

fn formatElapsedMmSsBuf(buf: []u8, elapsed_ms: u32) []const u8 {
    const total_seconds = @divTrunc(elapsed_ms, 1000);
    const minutes = @divTrunc(total_seconds, 60);
    const seconds = @mod(total_seconds, 60);
    return std.fmt.bufPrint(buf, "{d}:{d:0>2}", .{ minutes, seconds }) catch "0:00";
}

fn formatRecordDateBuf(buf: []u8, record: persistence.highscores.HighScoreRecord) ?[]const u8 {
    const day = record.data[0x40];
    const month = record.data[0x42];
    if (day == 0 or month == 0 or month > 12) return null;
    const year = 2000 + @as(i32, record.data[0x43]);
    return std.fmt.bufPrint(buf, "{d}. {s} {d}", .{ day, monthNames()[month - 1], year }) catch null;
}

fn monthNames() [12][]const u8 {
    return .{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
}

fn ordinalBuf(buf: []u8, rank: usize) []const u8 {
    const suffix = switch (rank % 10) {
        1 => if (rank % 100 == 11) "th" else "st",
        2 => if (rank % 100 == 12) "th" else "nd",
        3 => if (rank % 100 == 13) "th" else "rd",
        else => "th",
    };
    return std.fmt.bufPrint(buf, "{d}{s}", .{ rank, suffix }) catch "?";
}

fn questLevelKeyFromConfig(config: formats.crimson_cfg.CrimsonCfg) i32 {
    _ = config;
    return 101;
}

fn questLevelKeyToIndex(level_key: i32) i32 {
    const major = @divTrunc(level_key, 100);
    const minor = @mod(level_key, 100);
    return (major - 1) * 10 + (minor - 1);
}

fn questIndexToLevelKey(index: i32) i32 {
    const safe_index = std.math.clamp(index, @as(i32, 0), @as(i32, 49));
    return (@divTrunc(safe_index, 10) + 1) * 100 + @mod(safe_index, 10) + 1;
}

fn drawWrappedSmallText(
    assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    x: f32,
    y: f32,
    wrap_width: f32,
    color: rl.Color,
) void {
    var line_buf: [256]u8 = undefined;
    var line_len: usize = 0;
    var draw_y = y;
    var words = std.mem.tokenizeScalar(u8, text, ' ');
    while (words.next()) |word| {
        var candidate_buf: [256]u8 = undefined;
        const candidate = if (line_len == 0)
            std.fmt.bufPrint(&candidate_buf, "{s}", .{word}) catch word
        else
            std.fmt.bufPrint(&candidate_buf, "{s} {s}", .{ line_buf[0..line_len], word }) catch line_buf[0..line_len];
        const candidate_len = candidate.len;
        if (candidate_len > 0 and window_ui.measureSmallText(assets, candidate[0..candidate_len]) > wrap_width and line_len > 0) {
            window_ui.drawSmallText(assets, line_buf[0..line_len], x, draw_y, color);
            draw_y += 16.0;
            @memset(line_buf[0..], 0);
            line_len = @min(word.len, line_buf.len);
            @memcpy(line_buf[0..line_len], word[0..line_len]);
            continue;
        }
        line_len = @min(candidate_len, line_buf.len);
        @memcpy(line_buf[0..line_len], candidate[0..line_len]);
    }
    if (line_len > 0) {
        window_ui.drawSmallText(assets, line_buf[0..line_len], x, draw_y, color);
    }
}

fn rectContains(rect: rl.Rectangle, point: rl.Vector2) bool {
    return rl.checkCollisionPointRec(point, rect);
}

fn backButtonActivated(button: window_ui.UiButton) bool {
    return rl.isMouseButtonPressed(.left) and rectContains(button.rect, rl.getMousePosition());
}

test "high score date filter matches current month and day semantics" {
    var record = persistence.highscores.HighScoreRecord.blank();
    const stamp = currentDateStampUtc();
    record.data[0x40] = stamp.day;
    record.data[0x42] = stamp.month;
    record.data[0x43] = @intCast(@mod(stamp.year - 2000, 256));
    record.data[0x41] = @intCast(persistence.highscores.highscoreDateChecksum(stamp.year, stamp.month, stamp.day) & 0xFF);
    try std.testing.expect(passesDateFilter(record, 1));
    try std.testing.expect(passesDateFilter(record, 2));
    try std.testing.expect(passesDateFilter(record, 3));
}
