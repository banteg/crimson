const builtin = @import("builtin");
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
const window_menu_panels = @import("window_menu_panels.zig");
const window_ui = @import("window_ui.zig");
const window_statistics_data = @import("window_statistics_data.zig");

const panel_color = rl.Color.init(37, 24, 20, 255);
const text_color = rl.Color.init(245, 236, 225, 255);
const muted_text = rl.Color.init(171, 150, 132, 255);
const accent_color = rl.Color.init(218, 80, 46, 255);
const value_color = rl.Color.init(70, 180, 240, 255);
const gold_color = rl.Color.init(255, 228, 170, 255);

const panel_timeline_max_ms: i32 = 300;
const credits_table_size: usize = 0x100;
const credits_flag_heading: u8 = 0x1;
const credits_flag_clicked: u8 = 0x4;

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
    scroll: usize = 0,
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
    hovered: ?usize = null,

    fn reset(self: *PerksScreen) void {
        self.* = .{};
    }
};

const CreditsScreen = struct {
    scroll_time_s: f32 = 0.0,
    line_start_index: i32 = 0,
    line_end_index: i32 = 0,
    line_max_index: i32 = 0,
    secret_line_base_index: usize = 0x54,
    secret_unlock: bool = false,
    lines: [credits_table_size]CreditLineState = [_]CreditLineState{.{}} ** credits_table_size,

    fn reset(self: *CreditsScreen) void {
        self.* = .{};
        buildCreditsLines(self);
    }
};

const CreditLineState = struct {
    text: []const u8 = "",
    flags: u8 = 0,

    fn heading(self: CreditLineState) bool {
        return (self.flags & credits_flag_heading) != 0;
    }

    fn clicked(self: CreditLineState) bool {
        return (self.flags & credits_flag_clicked) != 0;
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

pub const OpenHighScoresOptions = struct {
    quest_level_key: ?i32 = null,
};

pub fn openHighScores(
    state: *State,
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
    options: OpenHighScoresOptions,
) void {
    state.view = .high_scores;
    state.high_scores.clear(allocator);
    state.high_scores.mode = highScoreModeFromConfig(config, status);
    state.high_scores.quest_level_key = if (state.high_scores.mode == .quests)
        options.quest_level_key orelse questLevelKeyFromConfig(config)
    else
        questLevelKeyFromConfig(config);
    loadHighScores(&state.high_scores, allocator, base_dir, config, status);
}

pub fn update(
    state: *State,
    allocator: std.mem.Allocator,
    frame_dt: f32,
    base_dir: []const u8,
    config: *formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
    runtime_assets: ?*const window_assets.RuntimeAssets,
) UpdateResult {
    return switch (state.view) {
        .hub => updateHub(state, allocator, frame_dt, base_dir, config, status),
        .high_scores => updateHighScores(state, allocator, frame_dt, base_dir, config, status),
        .weapons => updateWeapons(state, frame_dt, config.*, status),
        .perks => updatePerks(state, frame_dt, status),
        .credits => updateCredits(state, frame_dt, runtime_assets),
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
        .high_scores => drawHighScores(&state.high_scores, runtime_assets, config, status, state.hub.panel.timeline_ms),
        .weapons => drawWeapons(&state.weapons, runtime_assets, config, status, state.hub.panel.timeline_ms),
        .perks => drawPerks(&state.perks, runtime_assets, config, status, state.hub.panel.timeline_ms),
        .credits => drawCredits(&state.credits, runtime_assets, state.hub.panel.timeline_ms),
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
    const panel_rect = animatedCenterPanelRect(stats_panel_rect, state.hub.panel.timeline_ms);
    const buttons = hubButtons(panel_rect);
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
        .high_scores => openHighScores(state, allocator, base_dir, config.*, status, .{}),
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
    const left_rect = animatedLeftPanelRect(left_panel_rect, state.hub.panel.timeline_ms);
    const right_rect = animatedRightPanelRect(right_panel_rect, state.hub.panel.timeline_ms);
    const hs = &state.high_scores;
    const buttons = highScoreButtons(left_rect);
    window_ui.updateSelectionFromPointer(&hs.button_selection, buttons[0..]);
    const rows: usize = 10;
    const max_scroll = if (hs.records.len > rows) hs.records.len - rows else 0;

    if (rl.isKeyPressed(.escape)) {
        hs.dropdown_open = .none;
        state.view = .hub;
        state.hub.reset();
        return .{ .play_button_click = true };
    }

    if (hs.dropdown_open == .none) {
        const wheel = @as(i32, @intFromFloat(rl.getMouseWheelMove()));
        if (wheel != 0) {
            hs.scroll = @intCast(std.math.clamp(@as(i32, @intCast(hs.scroll)) - wheel, 0, @as(i32, @intCast(max_scroll))));
        }
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            hs.button_selection = if (hs.button_selection == 0) buttons.len - 1 else hs.button_selection - 1;
            hs.scroll = hs.scroll -| 1;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            hs.button_selection = (hs.button_selection + 1) % buttons.len;
            hs.scroll = @min(hs.scroll + 1, max_scroll);
        }
        if (rl.isKeyPressed(.page_up)) {
            hs.scroll = hs.scroll -| rows;
        }
        if (rl.isKeyPressed(.page_down)) {
            hs.scroll = @min(hs.scroll + rows, max_scroll);
        }
        if (rl.isKeyPressed(.home)) {
            hs.scroll = 0;
        }
        if (rl.isKeyPressed(.end)) {
            hs.scroll = max_scroll;
        }
    }

    if (updateHighScoreQuestArrows(hs, config, status, left_rect)) {
        loadHighScores(hs, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }

    if (updateHighScoreWidgets(hs, allocator, base_dir, config, status, right_rect)) |widget_result| {
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
    const left_rect = animatedLeftPanelRect(left_panel_rect, state.hub.panel.timeline_ms);
    var weapon_ids: [state_mod.weapon_count_size]game_ids.WeaponId = undefined;
    const total = buildWeaponList(&weapon_ids, config, status);
    const screen = &state.weapons;

    if (total == 0) {
        screen.selection = 0;
        screen.scroll = 0;
    } else if (screen.selection >= total) {
        screen.selection = total - 1;
    }

    if (rl.isKeyPressed(.escape) or backButtonActivated(weaponBackButton(left_rect)[0])) {
        state.view = .hub;
        state.hub.reset();
        return .{ .play_button_click = true };
    }

    const mouse = rl.getMousePosition();
    if (rl.getMouseWheelMove() != 0 and rectContains(weaponListRect(left_rect), mouse)) {
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
    if (hoveredListRow(weaponListRect(left_rect), total, screen.scroll)) |row| {
        screen.selection = row;
    }

    return .{};
}

fn updatePerks(state: *State, frame_dt: f32, status: formats.game_cfg.Status) UpdateResult {
    _ = state.hub.panel.advance(frame_dt);
    const left_rect = animatedLeftPanelRect(left_panel_rect, state.hub.panel.timeline_ms);
    var perk_ids: [state_mod.perk_count_size]game_ids.PerkId = undefined;
    const total = buildPerkList(&perk_ids, status);
    const screen = &state.perks;
    screen.hovered = null;

    if (total == 0) {
        screen.selection = 0;
        screen.scroll = 0;
        screen.hovered = null;
    } else if (screen.selection >= total) {
        screen.selection = total - 1;
    }

    if (rl.isKeyPressed(.escape) or backButtonActivated(perkBackButton(left_rect)[0])) {
        state.view = .hub;
        state.hub.reset();
        return .{ .play_button_click = true };
    }

    const mouse = rl.getMousePosition();
    if (rl.getMouseWheelMove() != 0 and rectContains(perkListRect(left_rect), mouse)) {
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
    if (hoveredListRow(perkListRect(left_rect), total, screen.scroll)) |row| {
        screen.hovered = row;
        if (rl.isMouseButtonPressed(.left)) {
            screen.selection = row;
        }
    }

    return .{};
}

fn updateCredits(state: *State, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets) UpdateResult {
    _ = state.hub.panel.advance(frame_dt);
    const panel_rect = animatedCenterPanelRect(credits_panel_rect, state.hub.panel.timeline_ms);
    if (rl.isKeyPressed(.escape) or backButtonActivated(backOnlyButton(panel_rect)[0])) {
        state.view = .hub;
        state.hub.reset();
        return .{ .play_button_click = true };
    }
    const dt_clamped = @min(frame_dt, 0.1);
    state.credits.scroll_time_s += dt_clamped;
    updateCreditsWindow(&state.credits);
    if (runtime_assets) |assets| {
        updateCreditsLineClicks(&state.credits, assets, panel_rect, rl.getMousePosition(), rl.isMouseButtonPressed(.left));
        updateCreditsSecretUnlock(&state.credits);
    }
    return .{};
}

fn drawHub(state: *const HubState, runtime_assets: ?*const window_assets.RuntimeAssets, status: formats.game_cfg.Status) void {
    if (runtime_assets) |assets| {
        const panel_rect = animatedCenterPanelRect(stats_panel_rect, state.panel.timeline_ms);
        drawPanelShellNoTitle(state.panel.timeline_ms, assets, stats_panel_rect);
        drawAtlasTitle(assets, panel_rect, 290.0, 52.0, window_menu.label_row_statistics);
        var playtime_buf: [64]u8 = undefined;
        window_ui.drawSmallText(assets, formatPlaytimeText(&playtime_buf, status.game_sequence_id), panel_rect.x + 204.0, panel_rect.y + 334.0, muted_text);
        const buttons = hubButtons(panel_rect);
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
    timeline_ms: i32,
) void {
    if (runtime_assets) |assets| {
        const left_rect = animatedLeftPanelRect(left_panel_rect, timeline_ms);
        const right_rect = animatedRightPanelRect(right_panel_rect, timeline_ms);
        drawSplitPanelShell(assets, timeline_ms);
        drawHighScoreMainPanel(state, assets, config, status, left_rect);
        drawHighScoreRightPanel(state, assets, config, status, left_rect, right_rect);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawWeapons(
    state: *const WeaponsScreen,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
    timeline_ms: i32,
) void {
    if (runtime_assets) |assets| {
        const left_rect = animatedLeftPanelRect(left_panel_rect, timeline_ms);
        const right_rect = animatedRightPanelRect(right_panel_rect, timeline_ms);
        drawSplitPanelShell(assets, timeline_ms);
        drawWeaponsPanels(state, assets, config, status, left_rect, right_rect);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawPerks(
    state: *const PerksScreen,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
    timeline_ms: i32,
) void {
    if (runtime_assets) |assets| {
        const left_rect = animatedLeftPanelRect(left_panel_rect, timeline_ms);
        const right_rect = animatedRightPanelRect(right_panel_rect, timeline_ms);
        drawSplitPanelShell(assets, timeline_ms);
        drawPerksPanels(state, assets, status, config.gore_disabled, config.hardcore_flag != 0, config.game_mode == @intFromEnum(game_ids.GameModeId.tutorial), left_rect, right_rect);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawCredits(state: *const CreditsScreen, runtime_assets: ?*const window_assets.RuntimeAssets, timeline_ms: i32) void {
    if (runtime_assets) |assets| {
        const panel_rect = animatedCenterPanelRect(credits_panel_rect, timeline_ms);
        drawPanelShellNoTitle(timeline_ms, assets, credits_panel_rect);
        window_ui.drawSmallText(assets, "credits", panel_rect.x + 202.0, panel_rect.y + 46.0, text_color);
        const visible_count = state.line_end_index - state.line_start_index;
        if (visible_count > 0) {
            const base_y = panel_rect.y + 60.0;
            const frac_px = creditsScrollFractionPx(state.scroll_time_s);
            const center_x = panel_rect.x + 198.0 + 140.0;
            var row: i32 = 0;
            while (row < visible_count) : (row += 1) {
                const index = state.line_start_index + row;
                if (index < 0 or index >= credits_table_size) continue;
                const line = state.lines[@intCast(index)];
                const y = base_y + @as(f32, @floatFromInt(row)) * 16.0 - frac_px;
                const alpha = creditsLineAlpha(y, base_y, visible_count);
                if (alpha <= 0.0) continue;
                const color = creditsLineColor(line, alpha);
                const line_width = window_ui.measureSmallText(assets, line.text);
                const x = center_x - line_width * 0.5;
                window_ui.drawSmallText(assets, line.text, x, y, color);
            }
        }
        const back = backOnlyButton(panel_rect)[0];
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
    left_rect: rl.Rectangle,
) void {
    const title = highScoreTitle(state.mode);
    const title_x: f32 = if (state.mode == .survival) 266.0 else 269.0;
    window_ui.drawSmallText(assets, title, left_rect.x + title_x, left_rect.y + 41.0, text_color);
    drawUnderline(left_rect.x + title_x, left_rect.y + 55.0, window_ui.measureSmallText(assets, title));

    if (state.mode == .quests) {
        var quest_buf: [96]u8 = undefined;
        const quest_title = questTitleForLevelKey(state.quest_level_key);
        const quest_label = std.fmt.bufPrint(&quest_buf, "{d}.{d}: {s}", .{
            @divTrunc(state.quest_level_key, 100),
            @mod(state.quest_level_key, 100),
            quest_title,
        }) catch "Quest";
        window_ui.drawSmallText(assets, quest_label, left_rect.x + 236.0, left_rect.y + 63.0, if (config.hardcore_flag != 0) rl.Color.init(250, 70, 60, 180) else value_color);
        drawQuestArrows(assets, state.quest_level_key, config.hardcore_flag != 0, status, left_rect);
    }

    window_ui.drawSmallText(assets, "Rank", left_rect.x + 211.0, left_rect.y + 84.0, text_color);
    window_ui.drawSmallText(assets, "Score", left_rect.x + 246.0, left_rect.y + 84.0, text_color);
    window_ui.drawSmallText(assets, "Player", left_rect.x + 302.0, left_rect.y + 84.0, text_color);

    const frame = scoreFrameRect(left_rect);
    rl.drawRectangle(@intFromFloat(frame.x), @intFromFloat(frame.y), @intFromFloat(frame.width), @intFromFloat(frame.height), rl.Color.white);
    rl.drawRectangle(@intFromFloat(frame.x + 1.0), @intFromFloat(frame.y + 1.0), @intFromFloat(frame.width - 2.0), @intFromFloat(frame.height - 2.0), rl.Color.black);

    if (state.load_error) |load_error| {
        window_ui.drawSmallText(assets, load_error, frame.x + 8.0, frame.y + 8.0, rl.Color.orange);
    } else if (state.records.len == 0) {
        window_ui.drawSmallText(assets, "No scores yet.", left_rect.x + 211.0, frame.y + 8.0, muted_text);
    } else {
        const hovered_rank = hoveredHighScoreRank(state, left_rect);
        const start = @min(state.scroll, if (state.records.len > 10) state.records.len - 10 else 0);
        const end = @min(start + 10, state.records.len);
        for (state.records[start..end], 0..) |record, row| {
            const idx = start + row;
            const color = if (hovered_rank != null and hovered_rank.? == idx) text_color else muted_text;
            var value_buf: [32]u8 = undefined;
            const y = frame.y + 8.0 + @as(f32, @floatFromInt(row)) * 16.0;
            window_ui.drawSmallTextFmt("{d}", assets, .{idx + 1}, left_rect.x + 216.0, y, color);
            window_ui.drawSmallText(assets, formatHighScoreValue(&value_buf, record), left_rect.x + 246.0, y, color);
            window_ui.drawSmallText(assets, clippedRecordName(record), left_rect.x + 304.0, y, color);
        }
    }

    const buttons = highScoreButtons(left_rect);
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
    left_rect: rl.Rectangle,
    right_rect: rl.Rectangle,
) void {
    if (hoveredHighScoreRank(state, left_rect)) |rank| {
        if (rank < state.records.len) {
            drawHighScoreLocalDetails(assets, state.records[rank], rank, right_rect);
            return;
        }
    }

    const check_tex = if (config.score_load_gate != 0) assets.texture(.ui_check_on) else assets.texture(.ui_check_off);
    window_ui.drawTextureFit(check_tex, rl.Rectangle.init(right_rect.x + 44.0, right_rect.y + 44.0, @floatFromInt(check_tex.width), @floatFromInt(check_tex.height)), rl.Color.white);
    window_ui.drawSmallText(assets, "Show internet scores", right_rect.x + 66.0, right_rect.y + 45.0, text_color);
    window_ui.drawSmallText(assets, "Number of players", right_rect.x + 46.0, right_rect.y + 64.0, text_color);
    window_ui.drawSmallText(assets, "Game mode", right_rect.x + 174.0, right_rect.y + 64.0, text_color);
    window_ui.drawSmallText(assets, "Show scores:", right_rect.x + 44.0, right_rect.y + 106.0, text_color);
    window_ui.drawSmallText(assets, "Selected score list:", right_rect.x + 44.0, right_rect.y + 150.0, text_color);

    var mode_labels_buf: [4][]const u8 = undefined;
    const mode_labels = highScoreModeLabels(&mode_labels_buf, status);
    var saved_names: [formats.crimson_cfg.saved_name_slot_count][]const u8 = undefined;
    for (0..saved_names.len) |idx| saved_names[idx] = formats.crimson_cfg.savedNameLabel(&config, idx);
    const dropdowns = [_]struct {
        kind: DropdownKind,
        rect: rl.Rectangle,
        items: []const []const u8,
        selected: usize,
    }{
        .{
            .kind = .player_count,
            .rect = playerCountWidgetRect(right_rect),
            .items = playerCountLabels()[0..],
            .selected = @as(usize, @intCast(std.math.clamp(config.player_count, @as(u32, 1), @as(u32, 4)))) - 1,
        },
        .{
            .kind = .game_mode,
            .rect = gameModeWidgetRect(right_rect),
            .items = mode_labels,
            .selected = highScoreModeLabelIndex(state.mode, status),
        },
        .{
            .kind = .date_mode,
            .rect = dateModeWidgetRect(right_rect),
            .items = scoreDateModeLabels()[0..],
            .selected = @min(config.highscore_date_mode, 3),
        },
        .{
            .kind = .score_list,
            .rect = scoreListWidgetRect(right_rect),
            .items = saved_names[0..],
            .selected = formats.crimson_cfg.selectedSavedNameSlot(&config),
        },
    };
    for (dropdowns) |dropdown| {
        if (state.dropdown_open == dropdown.kind) continue;
        drawDropdown(assets, dropdown.rect, dropdown.items, dropdown.selected, false);
    }
    for (dropdowns) |dropdown| {
        if (state.dropdown_open != dropdown.kind) continue;
        drawDropdown(assets, dropdown.rect, dropdown.items, dropdown.selected, true);
    }
}

fn drawWeaponsPanels(
    state: *const WeaponsScreen,
    assets: *const window_assets.RuntimeAssets,
    config: formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
    left_rect: rl.Rectangle,
    right_rect: rl.Rectangle,
) void {
    const title = "Unlocked Weapons Database";
    window_ui.drawSmallText(assets, title, left_rect.x + 251.0, left_rect.y + 50.0, text_color);
    drawUnderline(left_rect.x + 251.0, left_rect.y + 63.0, window_ui.measureSmallText(assets, title));

    var weapon_ids: [state_mod.weapon_count_size]game_ids.WeaponId = undefined;
    const total = buildWeaponList(&weapon_ids, config, status);
    const weapon_label = if (total == 1) "weapon" else "weapons";
    window_ui.drawSmallTextFmt("{d} {s} in database", assets, .{ total, weapon_label }, left_rect.x + 210.0, left_rect.y + 80.0, muted_text);
    window_ui.drawSmallText(assets, "Weapon", left_rect.x + 210.0, left_rect.y + 108.0, text_color);
    drawListFrame(weaponListRect(left_rect));

    const start = @min(state.scroll, if (total > 10) total - 10 else 0);
    const end = @min(start + 10, total);
    for (weapon_ids[start..end], 0..) |weapon_id, row| {
        const list_index = start + row;
        const color = if (list_index == state.selection) text_color else muted_text;
        window_ui.drawSmallText(assets, game_ids.weaponDisplayName(weapon_id, false), left_rect.x + 218.0, left_rect.y + 130.0 + @as(f32, @floatFromInt(row)) * 16.0, color);
    }

    const back = weaponBackButton(left_rect)[0];
    const back_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
    window_ui.drawButton(back, false, back_hovered, assets);

    if (total == 0) return;
    const weapon_id = weapon_ids[@min(state.selection, total - 1)];
    const detail_x = right_rect.x;
    window_ui.drawSmallTextFmt("weapon #{d}", assets, .{@intFromEnum(weapon_id)}, detail_x + 240.0, right_rect.y + 32.0, muted_text);
    const name = game_ids.weaponDisplayName(weapon_id, false);
    window_ui.drawSmallText(assets, name, detail_x + 50.0, right_rect.y + 50.0, text_color);
    const icon_index = weapon_data.weaponIconIndex(weapon_id);
    if (icon_index >= 0) {
        const src_rect = window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index);
        rl.drawTexturePro(
            assets.texture(.ui_wicons),
            rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height),
            rl.Rectangle.init(detail_x + 82.0, right_rect.y + 82.0, 64.0, 32.0),
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
    window_ui.drawSmallText(assets, fire_rate_text, detail_x + 66.0, right_rect.y + 128.0, text_color);
    var reload_buf: [64]u8 = undefined;
    const reload_text = std.fmt.bufPrint(&reload_buf, "Reload time: {d:.1} secs", .{stats_entry.reload_time}) catch "Reload time: ?";
    window_ui.drawSmallText(assets, reload_text, detail_x + 66.0, right_rect.y + 146.0, text_color);
    window_ui.drawSmallTextFmt("Clip size: {d}", assets, .{stats_entry.clip_size}, detail_x + 66.0, right_rect.y + 164.0, text_color);
}

fn drawPerksPanels(
    state: *const PerksScreen,
    assets: *const window_assets.RuntimeAssets,
    status: formats.game_cfg.Status,
    violence_disabled: u8,
    hardcore: bool,
    preserve_bugs: bool,
    left_rect: rl.Rectangle,
    right_rect: rl.Rectangle,
) void {
    _ = hardcore;
    const title = "Unlocked Perks Database";
    window_ui.drawSmallText(assets, title, left_rect.x + 261.0, left_rect.y + 50.0, text_color);
    drawUnderline(left_rect.x + 261.0, left_rect.y + 63.0, window_ui.measureSmallText(assets, title));

    var perk_ids: [state_mod.perk_count_size]game_ids.PerkId = undefined;
    const total = buildPerkList(&perk_ids, status);
    const perk_label = if (total == 1) "perk" else "perks";
    window_ui.drawSmallTextFmt("{d} {s} in database", assets, .{ total, perk_label }, left_rect.x + 210.0, left_rect.y + 78.0, muted_text);
    window_ui.drawSmallText(assets, "Perks", left_rect.x + 210.0, left_rect.y + 106.0, text_color);
    drawListFrame(perkListRect(left_rect));

    const start = @min(state.scroll, if (total > 10) total - 10 else 0);
    const end = @min(start + 10, total);
    for (perk_ids[start..end], 0..) |perk_id, row| {
        const list_index = start + row;
        const alpha: f32 = if (state.hovered != null and state.hovered.? == list_index) 1.0 else if (list_index == state.selection) 0.9 else 0.7;
        window_ui.drawSmallText(
            assets,
            game_ids.perkDisplayName(perk_id, violence_disabled, preserve_bugs),
            left_rect.x + 218.0,
            left_rect.y + 128.0 + @as(f32, @floatFromInt(row)) * 16.0,
            rl.Color.init(255, 255, 255, @intFromFloat(255.0 * alpha)),
        );
    }
    if (total > 10) drawPerkScrollbar(total, start, left_rect);

    const back = perkBackButton(left_rect)[0];
    const back_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
    window_ui.drawButton(back, false, back_hovered, assets);

    if (total == 0) return;
    const detail_index = @min(state.hovered orelse state.selection, total - 1);
    const perk_id = perk_ids[detail_index];
    const detail_x = right_rect.x + 34.0;
    window_ui.drawSmallTextFmt("perk #{d}", assets, .{@intFromEnum(perk_id)}, detail_x + 190.0, right_rect.y + 32.0, muted_text);
    const name = game_ids.perkDisplayName(perk_id, violence_disabled, preserve_bugs);
    const name_width = window_ui.measureSmallText(assets, name);
    const name_x = detail_x + 128.0 - name_width * 0.5;
    window_ui.drawSmallText(assets, name, name_x, right_rect.y + 50.0, text_color);
    drawUnderline(name_x, right_rect.y + 63.0, name_width);

    var y = right_rect.y + 72.0;
    if (window_statistics_data.perkPrerequisite(perk_id)) |prereq| {
        var req_buf: [128]u8 = undefined;
        const req_text = std.fmt.bufPrint(&req_buf, "Requires: {s}", .{game_ids.perkDisplayName(prereq, violence_disabled, preserve_bugs)}) catch "Requires: ?";
        window_ui.drawSmallText(assets, req_text, detail_x + 16.0, y, rl.Color.init(255, 204, 204, 220));
        y += 18.0;
    }
    drawWrappedSmallText(assets, window_statistics_data.perkDescription(perk_id), detail_x + 16.0, y, 256.0, muted_text);
}

fn animatedCenterPanelRect(rect: rl.Rectangle, timeline_ms: i32) rl.Rectangle {
    const anim = window_menu.uiElementAnim(1, panel_timeline_max_ms, 0, rect.width, timeline_ms);
    return rl.Rectangle.init(rect.x + anim.offset_x, rect.y, rect.width, rect.height);
}

fn animatedLeftPanelRect(rect: rl.Rectangle, timeline_ms: i32) rl.Rectangle {
    const anim = window_menu.uiElementAnim(1, panel_timeline_max_ms, 0, rect.width, timeline_ms);
    return rl.Rectangle.init(rect.x + anim.offset_x, rect.y, rect.width, rect.height);
}

fn animatedRightPanelRect(rect: rl.Rectangle, timeline_ms: i32) rl.Rectangle {
    const anim = window_menu.uiElementAnim(2, panel_timeline_max_ms, 0, rect.width, timeline_ms);
    return rl.Rectangle.init(rect.x - anim.offset_x, rect.y, rect.width, rect.height);
}

fn drawSplitPanelShell(assets: *const window_assets.RuntimeAssets, timeline_ms: i32) void {
    window_menu.drawMenuBackdrop(assets);
    window_menu.drawSign(timeline_ms, assets);
    window_ui.drawClassicMenuPanel(assets.texture(.ui_menu_panel), animatedLeftPanelRect(left_panel_rect, timeline_ms), rl.Color.white, false);
    window_ui.drawClassicMenuPanel(assets.texture(.ui_menu_panel), animatedRightPanelRect(right_panel_rect, timeline_ms), rl.Color.white, true);
}

fn drawPanelShell(timeline_ms: i32, assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle, label_row: i32) void {
    window_menu.drawMenuBackdrop(assets);
    window_menu.drawSign(timeline_ms, assets);
    const panel_rect = animatedCenterPanelRect(rect, timeline_ms);
    window_ui.drawClassicMenuPanel(assets.texture(.ui_menu_panel), panel_rect, rl.Color.white, false);
    window_menu.drawAtlasLabelCentered(assets, label_row, panel_rect.y + 42.0, rl.Color.white);
}

fn drawPanelShellNoTitle(timeline_ms: i32, assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle) void {
    window_menu.drawMenuBackdrop(assets);
    window_menu.drawSign(timeline_ms, assets);
    window_ui.drawClassicMenuPanel(assets.texture(.ui_menu_panel), animatedCenterPanelRect(rect, timeline_ms), rl.Color.white, false);
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

fn hubButtons(panel_rect: rl.Rectangle) [5]window_ui.UiButton {
    return .{
        window_ui.buttonAt("High scores", panel_rect.x + 270.0, panel_rect.y + 104.0, true),
        window_ui.buttonAt("Weapons", panel_rect.x + 270.0, panel_rect.y + 138.0, true),
        window_ui.buttonAt("Perks", panel_rect.x + 270.0, panel_rect.y + 172.0, true),
        window_ui.buttonAt("Credits", panel_rect.x + 270.0, panel_rect.y + 206.0, true),
        window_ui.buttonAt("Back", panel_rect.x + 394.0, panel_rect.y + 290.0, false),
    };
}

fn highScoreButtons(left_rect: rl.Rectangle) [3]window_ui.UiButton {
    return .{
        window_ui.buttonAt("Update scores", left_rect.x + 234.0, left_rect.y + 268.0, true),
        window_ui.buttonAt("Play a game", left_rect.x + 234.0, left_rect.y + 301.0, true),
        window_ui.buttonAt("Back", left_rect.x + 400.0, left_rect.y + 301.0, false),
    };
}

fn backOnlyButton(panel_rect: rl.Rectangle) [1]window_ui.UiButton {
    return .{
        window_ui.buttonAt("Back", panel_rect.x + 298.0, panel_rect.y + 310.0, false),
    };
}

fn weaponBackButton(left_rect: rl.Rectangle) [1]window_ui.UiButton {
    return .{
        window_ui.buttonAt("Back", left_rect.x + 368.0, left_rect.y + 313.0, false),
    };
}

fn perkBackButton(left_rect: rl.Rectangle) [1]window_ui.UiButton {
    return .{
        window_ui.buttonAt("Back", left_rect.x + 356.0, left_rect.y + 315.0, false),
    };
}

fn scoreFrameRect(left_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(left_rect.x + 210.0, left_rect.y + 101.0, 250.0, 164.0);
}

fn weaponListRect(left_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(left_rect.x + 212.0, left_rect.y + 128.0, 250.0, 164.0);
}

fn perkListRect(left_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(left_rect.x + 212.0, left_rect.y + 126.0, 250.0, 164.0);
}

fn drawListFrame(rect: rl.Rectangle) void {
    rl.drawRectangle(@intFromFloat(rect.x), @intFromFloat(rect.y), @intFromFloat(rect.width), @intFromFloat(rect.height), rl.Color.white);
    rl.drawRectangle(@intFromFloat(rect.x + 1.0), @intFromFloat(rect.y + 1.0), @intFromFloat(rect.width - 2.0), @intFromFloat(rect.height - 2.0), rl.Color.black);
}

fn drawPerkScrollbar(total: usize, start: usize, left_rect: rl.Rectangle) void {
    const track_x = left_rect.x + 452.0;
    const track_y = left_rect.y + 126.0;
    const track_h = 164.0;
    const scroll_span = @max(total, 10) - 10;
    const thumb_h = @min((10.0 / @as(f32, @floatFromInt(total))) * track_h, track_h - 3.0);
    const thumb_top = track_y + 1.0 + ((track_h - 3.0 - thumb_h) / @as(f32, @floatFromInt(@max(scroll_span, 1)))) * @as(f32, @floatFromInt(start));
    rl.drawRectangle(@intFromFloat(track_x), @intFromFloat(track_y), 1, @intFromFloat(track_h), rl.Color.white);
    rl.drawRectangle(@intFromFloat(track_x + 1.0), @intFromFloat(thumb_top), 8, @intFromFloat(thumb_h + 1.0), rl.Color.init(255, 255, 255, 204));
    rl.drawRectangle(@intFromFloat(track_x + 2.0), @intFromFloat(thumb_top + 1.0), 6, @intFromFloat(@max(1.0, thumb_h - 1.0)), rl.Color.init(51, 204, 255, 51));
}

fn drawUnderline(x: f32, y: f32, width: f32) void {
    rl.drawRectangle(@intFromFloat(x), @intFromFloat(y), @intFromFloat(width), 1, rl.Color.init(255, 255, 255, 180));
}

fn creditsScrollFractionPx(scroll_time_s: f32) f32 {
    var frac = scroll_time_s * 16.0;
    while (frac > 16.0) frac -= 16.0;
    return frac;
}

fn updateCreditsWindow(screen: *CreditsScreen) void {
    if ((screen.line_max_index + 2) < screen.line_start_index) {
        screen.scroll_time_s = 0.0;
        screen.line_start_index = 0;
    }
    const whole_scroll: i32 = @intFromFloat(screen.scroll_time_s);
    screen.line_start_index = whole_scroll - 15;
    screen.line_end_index = whole_scroll + 1;
    if (screen.line_max_index < screen.line_end_index) screen.line_end_index = screen.line_max_index;
}

fn creditsLineColor(line: CreditLineState, alpha: f32) rl.Color {
    const rgb = if (line.clicked())
        if (line.heading()) [_]u8{ 230, 255, 230 } else [_]u8{ 102, 179, 179 }
    else if (line.heading())
        [_]u8{ 255, 255, 255 }
    else
        [_]u8{ 102, 128, 178 };
    return rl.Color.init(rgb[0], rgb[1], rgb[2], @intFromFloat(std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0)) * 255.0));
}

fn creditsLineAlpha(y: f32, base_y: f32, visible_count: i32) f32 {
    const fade_px: f32 = 24.0;
    const top = base_y + 8.0;
    var alpha: f32 = 1.0;
    if (y < top) {
        alpha = 1.0 - ((top - y) / fade_px);
    } else {
        const bottom = base_y + @as(f32, @floatFromInt(visible_count - 1)) * 16.0 - fade_px;
        if (y > bottom) alpha = ((bottom - y) / fade_px) + 1.0;
    }
    return std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0));
}

const credits_secret_lines = [_][]const u8{
    "Inside Dead Let Mighty Blood",
    "Do Firepower See Mark Of",
    "The Sacrifice Old Center",
    "Yourself Ground First For",
    "Triangle Cube Last Not Flee",
    "0001001110000010101110011",
    "0101001011100010010101100",
    "011111001000111",
    "(4 bits for index) <- OOOPS I meant FIVE!",
    "(4 bits for index)",
};

fn buildCreditsLines(screen: *CreditsScreen) void {
    for (&screen.lines) |*line| line.* = .{};
    screen.line_max_index = 0;
    screen.secret_line_base_index = 0x54;
    screen.secret_unlock = false;

    const setLine = struct {
        fn apply(screen_: *CreditsScreen, index: usize, text: []const u8, flags: u8) void {
            screen_.lines[index] = .{ .text = text, .flags = flags };
            screen_.line_max_index = @intCast(index);
        }
    }.apply;

    setLine(screen, 0x00, "2026 Remake:", credits_flag_heading);
    setLine(screen, 0x01, "banteg", 0);
    setLine(screen, 0x02, "", 0);
    setLine(screen, 0x03, "Crimsonland", credits_flag_heading);
    setLine(screen, 0x04, "Game Design:", credits_flag_heading);
    setLine(screen, 0x05, "Tero Alatalo", 0);
    setLine(screen, 0x06, "", 0);
    setLine(screen, 0x07, "Programming:", credits_flag_heading);
    setLine(screen, 0x08, "Tero Alatalo", 0);
    setLine(screen, 0x09, "", 0);
    setLine(screen, 0x0A, "Producer:", credits_flag_heading);
    setLine(screen, 0x0B, "Zach Young", 0);
    setLine(screen, 0x0C, "", 0);
    setLine(screen, 0x0D, "2D Art:", credits_flag_heading);
    setLine(screen, 0x0E, "Tero Alatalo", 0);
    setLine(screen, 0x0F, "", 0);
    setLine(screen, 0x10, "3D Modelling:", credits_flag_heading);
    setLine(screen, 0x11, "Tero Alatalo", 0);
    setLine(screen, 0x12, "Timo Palonen", 0);
    setLine(screen, 0x13, "", 0);
    setLine(screen, 0x14, "Music:", credits_flag_heading);
    setLine(screen, 0x15, "Valtteri Pihlajam", 0);
    setLine(screen, 0x16, "Ville Eriksson", 0);
    setLine(screen, 0x17, "", 0);
    setLine(screen, 0x18, "Sound Effects:", credits_flag_heading);
    setLine(screen, 0x19, "Ion Hardie", 0);
    setLine(screen, 0x1A, "Tero Alatalo", 0);
    setLine(screen, 0x1B, "Valtteri Pihlajam", 0);
    setLine(screen, 0x1C, "Ville Eriksson", 0);
    setLine(screen, 0x1D, "", 0);
    setLine(screen, 0x1E, "Manual:", credits_flag_heading);
    setLine(screen, 0x1F, "Miikka Kulmala", 0);
    setLine(screen, 0x20, "Zach Young", 0);
    setLine(screen, 0x21, "", 0);
    setLine(screen, 0x22, "Special thanks to:", credits_flag_heading);
    setLine(screen, 0x23, "Petri J", 0);
    setLine(screen, 0x24, "Peter Hajba / Remedy", 0);
    setLine(screen, 0x25, "", 0);
    setLine(screen, 0x26, "Play testers:", credits_flag_heading);
    setLine(screen, 0x27, "Avraham Petrosyan", 0);
    setLine(screen, 0x28, "Bryce Baker", 0);
    setLine(screen, 0x29, "Dan Ruskin", 0);
    setLine(screen, 0x2A, "Dirk Bunk", 0);
    setLine(screen, 0x2B, "Eric Dallaire", 0);
    setLine(screen, 0x2C, "Erik Van Pelt", 0);
    setLine(screen, 0x2D, "Ernie Ramirez", 0);
    setLine(screen, 0x2E, "Ion Hardie", 0);
    setLine(screen, 0x2F, "James C. Smith", 0);
    setLine(screen, 0x30, "Jarkko Forsbacka", 0);
    setLine(screen, 0x31, "Jeff McAteer", 0);
    setLine(screen, 0x32, "Juha Alatalo", 0);
    setLine(screen, 0x33, "Kalle Hahl", 0);
    setLine(screen, 0x34, "Lars Brubaker", 0);
    setLine(screen, 0x35, "Lee Cooper", 0);
    setLine(screen, 0x36, "Markus Lassila", 0);
    setLine(screen, 0x37, "Matti Alanen", 0);
    setLine(screen, 0x38, "Miikka Kulmala", 0);
    setLine(screen, 0x39, "Mika Alatalo", 0);
    setLine(screen, 0x3A, "Mike Colonnese", 0);
    setLine(screen, 0x3B, "Simon Hallam", 0);
    setLine(screen, 0x3C, "Toni Nurminen", 0);
    setLine(screen, 0x3D, "Valtteri Pihlajam", 0);
    setLine(screen, 0x3E, "Ville Eriksson", 0);
    setLine(screen, 0x3F, "Ville M", 0);
    setLine(screen, 0x40, "Zach Young", 0);
    setLine(screen, 0x41, "", 0);
    setLine(screen, 0x42, "", 0);
    setLine(screen, 0x43, "", 0);
    setLine(screen, 0x44, "2003 (c) 10tons entertainment", 0);
    setLine(screen, 0x45, "10tons logo by", 0);
    setLine(screen, 0x46, "Pasi Heinonen", 0);
    setLine(screen, 0x47, "", 0);
    setLine(screen, 0x48, "", 0);
    setLine(screen, 0x49, "", 0);
    setLine(screen, 0x4A, "Uses Vorbis Audio Decompression", 0);
    setLine(screen, 0x4B, "2003 (c) Xiph.Org Foundation", 0);
    setLine(screen, 0x4C, "(see vorbis.txt)", 0);
    var index: usize = 0x4D;
    while (index < 0x54) : (index += 1) setLine(screen, index, "", 0);
    setLine(screen, 0x54, "", 0);
    setLine(screen, 0x55, "", 0);
    setLine(screen, 0x56, "", 0);
    setLine(screen, 0x57, "You can stop watching now.", 0);
    index = 0x58;
    while (index < 0x77) : (index += 1) setLine(screen, index, "", 0);
    setLine(screen, 0x77, "Click the ones with the round ones!", 0);
    setLine(screen, 0x78, "(and be patient!)", 0);
    index = 0x79;
    while (index < 0x7E) : (index += 1) setLine(screen, index, "", 0);
}

fn updateCreditsLineClicks(screen: *CreditsScreen, assets: *const window_assets.RuntimeAssets, panel_rect: rl.Rectangle, mouse: rl.Vector2, click: bool) void {
    if (!click) return;
    const visible_count = screen.line_end_index - screen.line_start_index;
    if (visible_count <= 0) return;

    const base_y = panel_rect.y + 60.0;
    const frac_px = creditsScrollFractionPx(screen.scroll_time_s);
    const center_x = panel_rect.x + 198.0 + 140.0;
    var row: i32 = 0;
    while (row < visible_count) : (row += 1) {
        const index = screen.line_start_index + row;
        if (index < 0 or index >= credits_table_size) continue;
        const line = screen.lines[@intCast(index)];
        const text_w = window_ui.measureSmallText(assets, line.text);
        const x = center_x - text_w * 0.5;
        const y = base_y + @as(f32, @floatFromInt(row)) * 16.0 - frac_px;
        if (!(mouse.x >= x and mouse.x <= x + text_w and mouse.y >= y and mouse.y <= y + 16.0)) continue;
        if (std.mem.indexOfScalar(u8, line.text, 'o') != null) {
            screen.lines[@intCast(index)].flags |= credits_flag_clicked;
        } else {
            _ = creditsLineClearFlag(screen, index);
        }
        return;
    }
}

fn creditsLineClearFlag(screen: *CreditsScreen, start_index: i32) bool {
    var index = start_index;
    while (index >= 0) : (index -= 1) {
        const slot: usize = @intCast(index);
        if ((screen.lines[slot].flags & credits_flag_clicked) != 0) {
            screen.lines[slot].flags &= ~credits_flag_clicked;
            return true;
        }
    }
    return false;
}

fn updateCreditsSecretUnlock(screen: *CreditsScreen) void {
    if (screen.secret_unlock or !creditsAllRoundLinesFlagged(screen)) return;
    screen.secret_unlock = true;
    for (credits_secret_lines, 0..) |text, offset| {
        const index = screen.secret_line_base_index + offset;
        screen.lines[index].text = text;
        screen.lines[index].flags |= credits_flag_clicked;
    }
}

fn creditsAllRoundLinesFlagged(screen: *const CreditsScreen) bool {
    var index: usize = 0;
    while (index < credits_table_size) : (index += 1) {
        const line = screen.lines[index];
        if (line.text.len != 0 and std.mem.indexOfScalar(u8, line.text, 'o') != null and (line.flags & credits_flag_clicked) == 0) return false;
    }
    return true;
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
    const active = is_open or hovered;
    const texture = if (active) assets.texture(.ui_drop_on) else assets.texture(.ui_drop_off);

    rl.drawRectangleRec(rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(rect.x + 1.0), @intFromFloat(rect.y + 1.0), @intFromFloat(rect.width - 2.0), @intFromFloat(rect.height - 2.0), rl.Color.black);
    if (active) {
        rl.drawRectangle(@intFromFloat(rect.x), @intFromFloat(rect.y + 15.0), @intFromFloat(rect.width), 1, rl.Color.init(255, 255, 255, 128));
    }
    if (items.len != 0) {
        window_ui.drawSmallText(assets, items[selected_index], rect.x + 4.0, rect.y + 1.0, rl.Color.init(255, 255, 255, if (active) 242 else 191));
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
        const alpha: u8 = if (row_hovered) 242 else if (idx == selected_index) 245 else 153;
        window_ui.drawSmallText(assets, item, row_rect.x + 4.0, row_rect.y + 1.0, rl.Color.init(255, 255, 255, alpha));
    }
}

fn playerCountWidgetRect(right_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(right_rect.x + 46.0, right_rect.y + 78.0, 102.0, 16.0);
}

fn gameModeWidgetRect(right_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(right_rect.x + 174.0, right_rect.y + 78.0, 95.0, 16.0);
}

fn dateModeWidgetRect(right_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(right_rect.x + 44.0, right_rect.y + 120.0, 134.0, 16.0);
}

fn scoreListWidgetRect(right_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(right_rect.x + 44.0, right_rect.y + 164.0, 174.0, 16.0);
}

fn hoveredHighScoreRank(state: *const HighScoresScreen, left_rect: rl.Rectangle) ?usize {
    const mouse = rl.getMousePosition();
    const frame = scoreFrameRect(left_rect);
    if (!rectContains(frame, mouse)) return null;
    const row = @as(usize, @intFromFloat((mouse.y - (frame.y + 8.0)) / 16.0));
    if (row >= 10) return null;
    const start = @min(state.scroll, if (state.records.len > 10) state.records.len - 10 else 0);
    const rank = start + row;
    if (rank >= state.records.len) return null;
    return rank;
}

fn hoveredListRow(rect: rl.Rectangle, total: usize, scroll: usize) ?usize {
    const mouse = rl.getMousePosition();
    if (!rectContains(rect, mouse)) return null;
    const row = @as(usize, @intFromFloat((mouse.y - (rect.y + 6.0)) / 16.0));
    if (row >= 10 or scroll + row >= total) return null;
    return scroll + row;
}

fn drawHighScoreLocalDetails(assets: *const window_assets.RuntimeAssets, record: persistence.highscores.HighScoreRecord, rank: usize, right_rect: rl.Rectangle) void {
    const detail_x = right_rect.x + 78.0;
    const mode = record.gameModeId() orelse .survival;
    const local_text = rl.Color.init(229, 229, 229, 204);
    const value_text = rl.Color.init(229, 229, 255, 255);
    const lower_text = rl.Color.init(229, 229, 229, 178);
    const separator = rl.Color.init(149, 175, 198, 178);

    window_ui.drawSmallText(assets, clippedRecordName(record), detail_x, right_rect.y + 44.0, local_text);
    window_ui.drawSmallText(assets, "Local score", detail_x, right_rect.y + 58.0, local_text);
    rl.drawLine(@intFromFloat(right_rect.x + 78.0), @intFromFloat(right_rect.y + 57.0), @intFromFloat(right_rect.x + 117.0), @intFromFloat(right_rect.y + 57.0), separator);
    var date_buf: [64]u8 = undefined;
    if (formatRecordDateBuf(&date_buf, record)) |date| {
        const date_w = window_ui.measureSmallText(assets, date);
        window_ui.drawSmallText(assets, date, right_rect.x + 230.0 - date_w * 0.5, right_rect.y + 72.0, local_text);
    }
    rl.drawLine(@intFromFloat(right_rect.x + 74.0), @intFromFloat(right_rect.y + 72.0), @intFromFloat(right_rect.x + 266.0), @intFromFloat(right_rect.y + 72.0), separator);
    window_ui.drawSmallText(assets, "Score", detail_x + 27.0, right_rect.y + 90.0, local_text);
    const time_label = if (mode == .quests) "Experience" else "Game time";
    window_ui.drawSmallText(assets, time_label, detail_x + 114.0, right_rect.y + 90.0, local_text);
    rl.drawLine(@intFromFloat(right_rect.x + 170.0), @intFromFloat(right_rect.y + 90.0), @intFromFloat(right_rect.x + 170.0), @intFromFloat(right_rect.y + 138.0), separator);

    switch (mode) {
        .rush, .quests => {
            var score_buf: [32]u8 = undefined;
            const score_text = std.fmt.bufPrint(&score_buf, "{d:.2} secs", .{@as(f32, @floatFromInt(record.survivalElapsedMs())) * 0.001}) catch "0.00 secs";
            const label_center_x = detail_x + 27.0 + window_ui.measureSmallText(assets, "Score") * 0.5;
            const score_w = window_ui.measureSmallText(assets, score_text);
            window_ui.drawSmallText(assets, score_text, label_center_x - score_w * 0.5, right_rect.y + 105.0, value_text);
            window_ui.drawSmallTextFmt("{d}", assets, .{record.scoreXp()}, detail_x + 148.0, right_rect.y + 109.0, local_text);
        },
        .survival, .typo, .tutorial => {
            window_ui.drawSmallTextFmt("{d}", assets, .{record.scoreXp()}, detail_x + 27.0, right_rect.y + 105.0, value_text);
            drawClockGauge(assets, record.survivalElapsedMs(), right_rect.x + 194.0, right_rect.y + 103.0);
            var time_buf: [32]u8 = undefined;
            window_ui.drawSmallText(assets, formatElapsedMmSsBuf(&time_buf, record.survivalElapsedMs()), detail_x + 148.0, right_rect.y + 109.0, local_text);
        },
    }
    var rank_buf: [32]u8 = undefined;
    var ordinal_buf: [16]u8 = undefined;
    const rank_text = std.fmt.bufPrint(&rank_buf, "Rank: {s}", .{ordinalBuf(&ordinal_buf, rank + 1)}) catch "Rank: ?";
    window_ui.drawSmallText(assets, rank_text, detail_x + 16.0, right_rect.y + 120.0, local_text);
    const icon_index = weapon_data.weaponIconIndex(record.mostUsedWeaponId());
    rl.drawLine(@intFromFloat(right_rect.x + 74.0), @intFromFloat(right_rect.y + 142.0), @intFromFloat(right_rect.x + 266.0), @intFromFloat(right_rect.y + 142.0), separator);
    if (icon_index >= 0) {
        const src_rect = window_atlas.weaponIconRect(assets.texture(.ui_wicons).width, assets.texture(.ui_wicons).height, icon_index);
        rl.drawTexturePro(
            assets.texture(.ui_wicons),
            rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height),
            rl.Rectangle.init(detail_x + 12.0, right_rect.y + 146.0, 64.0, 32.0),
            rl.Vector2.zero(),
            0.0,
            rl.Color.white,
        );
    }
    window_ui.drawSmallTextFmt("Frags: {d}", assets, .{record.creatureKillCount()}, detail_x + 122.0, right_rect.y + 147.0, lower_text);
    const shots_fired = record.shotsFired();
    const hit_pct: u32 = if (shots_fired == 0) 0 else @intCast(@divTrunc(record.shotsHit() * 100, shots_fired));
    window_ui.drawSmallTextFmt("Hit %: {d}%", assets, .{hit_pct}, detail_x + 122.0, right_rect.y + 161.0, lower_text);
    const weapon_name = game_ids.weaponDisplayName(record.mostUsedWeaponId(), false);
    const weapon_name_x = right_rect.x + 90.0 + @max(@as(f32, 0.0), 32.0 - window_ui.measureSmallText(assets, weapon_name) * 0.5);
    window_ui.drawSmallText(assets, weapon_name, weapon_name_x, right_rect.y + 178.0, lower_text);
    rl.drawLine(@intFromFloat(right_rect.x + 74.0), @intFromFloat(right_rect.y + 194.0), @intFromFloat(right_rect.x + 266.0), @intFromFloat(right_rect.y + 194.0), separator);
}

fn drawClockGauge(assets: *const window_assets.RuntimeAssets, elapsed_ms: u32, x: f32, y: f32) void {
    const table = assets.texture(.ui_clock_table);
    const pointer = assets.texture(.ui_clock_pointer);
    rl.drawTexturePro(
        table,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(table.width), @floatFromInt(table.height)),
        rl.Rectangle.init(x, y, 32.0, 32.0),
        rl.Vector2.zero(),
        0.0,
        rl.Color.white,
    );
    const seconds = @divTrunc(elapsed_ms, 1000);
    rl.drawTexturePro(
        pointer,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(pointer.width), @floatFromInt(pointer.height)),
        rl.Rectangle.init(x + 16.0, y + 16.0, 32.0, 32.0),
        rl.Vector2.init(16.0, 16.0),
        @as(f32, @floatFromInt(seconds)) * 6.0,
        rl.Color.white,
    );
}

fn updateHighScoreWidgets(
    state: *HighScoresScreen,
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    config: *formats.crimson_cfg.CrimsonCfg,
    status: formats.game_cfg.Status,
    right_rect: rl.Rectangle,
) ?UpdateResult {
    const mouse = rl.getMousePosition();
    const click = rl.isMouseButtonPressed(.left);

    const internet_rect = rl.Rectangle.init(right_rect.x + 44.0, right_rect.y + 44.0, 180.0, 16.0);
    if (click and state.dropdown_open == .none and rectContains(internet_rect, mouse)) {
        config.score_load_gate = if (config.score_load_gate == 0) 1 else 0;
        loadHighScores(state, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }

    if (updateDropdownSelection(&state.dropdown_open, .player_count, playerCountWidgetRect(right_rect), playerCountLabels()[0..], click, mouse)) |selected| {
        config.player_count = @intCast(selected + 1);
        loadHighScores(state, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }
    var mode_labels_buf: [4][]const u8 = undefined;
    const mode_labels = highScoreModeLabels(&mode_labels_buf, status);
    if (updateDropdownSelection(&state.dropdown_open, .game_mode, gameModeWidgetRect(right_rect), mode_labels, click, mouse)) |selected| {
        const mode = highScoreModeFromIndex(selected, status);
        state.mode = mode;
        config.game_mode = @intCast(@intFromEnum(mode));
        if (mode == .typo) config.player_count = 1;
        if (mode == .quests and state.quest_level_key <= 0) state.quest_level_key = 101;
        loadHighScores(state, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }
    if (updateDropdownSelection(&state.dropdown_open, .date_mode, dateModeWidgetRect(right_rect), scoreDateModeLabels()[0..], click, mouse)) |selected| {
        config.highscore_date_mode = @intCast(selected);
        loadHighScores(state, allocator, base_dir, config.*, status);
        return .{ .config_dirty = true, .play_button_click = true };
    }
    var saved_names: [formats.crimson_cfg.saved_name_slot_count][]const u8 = undefined;
    for (0..saved_names.len) |idx| saved_names[idx] = formats.crimson_cfg.savedNameLabel(config, idx);
    if (updateDropdownSelection(&state.dropdown_open, .score_list, scoreListWidgetRect(right_rect), saved_names[0..], click, mouse)) |selected| {
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
    left_rect: rl.Rectangle,
) bool {
    if (state.mode != .quests) return false;
    const click = rl.isMouseButtonPressed(.left);
    if (!click) return false;

    const unlock = if (config.hardcore_flag != 0) status.quest_unlock_index_full else status.quest_unlock_index;
    const max_index = std.math.clamp(unlock, @as(i32, 0), @as(i32, 49));
    const current_index = questLevelKeyToIndex(state.quest_level_key);
    const mouse = rl.getMousePosition();
    if (current_index > 0 and rectContains(questPrevArrowRect(left_rect), mouse)) {
        state.quest_level_key = questIndexToLevelKey(current_index - 1);
        return true;
    }
    if (current_index < max_index and rectContains(questNextArrowRect(left_rect), mouse)) {
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
    left_rect: rl.Rectangle,
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
            questPrevArrowRect(left_rect),
            rl.Vector2.zero(),
            0.0,
            tint,
        );
    }
    if (current_index < max_index) {
        rl.drawTexturePro(
            arrow,
            rl.Rectangle.init(0.0, 0.0, -@as(f32, @floatFromInt(arrow.width)), @floatFromInt(arrow.height)),
            questNextArrowRect(left_rect),
            rl.Vector2.zero(),
            0.0,
            tint,
        );
    }
}

fn questPrevArrowRect(left_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(left_rect.x + 96.0, left_rect.y + 62.0, 32.0, 16.0);
}

fn questNextArrowRect(left_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(left_rect.x + 352.0, left_rect.y + 62.0, 32.0, 16.0);
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
    const mode = std.enums.fromInt(game_ids.GameModeId, @as(i32, @intCast(config.game_mode))) orelse .survival;
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
        state.load_error = highScorePathErrorDetail(err);
        return;
    };
    defer allocator.free(score_path);

    const records = persistence.highscores.readHighscoreTable(
        allocator,
        score_path,
        @intFromEnum(state.mode),
    ) catch |err| {
        state.load_error = highScoreReadErrorDetail(err);
        return;
    };

    var filtered: std.ArrayList(persistence.highscores.HighScoreRecord) = .empty;
    defer filtered.deinit(allocator);
    for (records.items) |record| {
        if (!passesDateFilter(record, config.highscore_date_mode)) continue;
        filtered.append(allocator, record) catch {
            state.load_error = highScoreAllocationErrorDetail(error.OutOfMemory);
            records.deinit(allocator);
            return;
        };
    }
    records.deinit(allocator);

    state.records = filtered.toOwnedSlice(allocator) catch {
        state.load_error = highScoreAllocationErrorDetail(error.OutOfMemory);
        return;
    };
    state.records_owned = true;
    state.scroll = @min(state.scroll, if (state.records.len > 10) state.records.len - 10 else 0);
}

fn highScorePathErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "Unable to build high score file path.",
        else => @errorName(err),
    };
}

fn highScoreReadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "Unable to read high score file: access denied.",
        error.OutOfMemory => "Unable to load high scores: out of memory.",
        error.InvalidSize => "High score file has an invalid record size.",
        else => @errorName(err),
    };
}

fn highScoreAllocationErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "Unable to load high scores: out of memory.",
        else => @errorName(err),
    };
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
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = currentEpochSeconds() };
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return .{
        .year = year_day.year,
        .month = @intCast(@intFromEnum(month_day.month) + 1),
        .day = @intCast(month_day.day_index + 1),
    };
}

fn currentEpochSeconds() u64 {
    if (builtin.os.tag == .freestanding) return 0;
    const io = std.Io.Threaded.global_single_threaded.io();
    const timestamp = std.Io.Timestamp.now(io, .real);
    return @intCast(@max(timestamp.toSeconds(), 0));
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

fn questTitleForLevelKey(level_key: i32) []const u8 {
    const index = questLevelKeyToIndex(level_key);
    if (index < 0 or index >= window_menu_panels.quest_titles.len) return "???";
    return window_menu_panels.quest_titles[@intCast(index)];
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

test "high score load errors use user-facing details" {
    try std.testing.expectEqualStrings(
        "Unable to build high score file path.",
        highScorePathErrorDetail(error.OutOfMemory),
    );
    try std.testing.expectEqualStrings(
        "Unable to read high score file: access denied.",
        highScoreReadErrorDetail(error.AccessDenied),
    );
    try std.testing.expectEqualStrings(
        "Unable to load high scores: out of memory.",
        highScoreAllocationErrorDetail(error.OutOfMemory),
    );
    try std.testing.expectEqualStrings(
        "FileBusy",
        highScoreReadErrorDetail(error.FileBusy),
    );
}

test "openHighScores loads requested quest level before reading records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);

    var quest_101 = persistence.highscores.HighScoreRecord.blank();
    quest_101.setName("Quest101");
    quest_101.setGameModeId(.quests);
    quest_101.setSurvivalElapsedMs(1000);
    const path_101 = try persistence.highscores.scoresPathForMode(
        allocator,
        base_dir,
        @intFromEnum(game_ids.GameModeId.quests),
        .{ .quest_stage_major = 1, .quest_stage_minor = 1 },
    );
    defer allocator.free(path_101);
    try persistence.highscores.writeHighscoreRecords(allocator, path_101, &.{quest_101}, null);

    var quest_203 = persistence.highscores.HighScoreRecord.blank();
    quest_203.setName("Quest203");
    quest_203.setGameModeId(.quests);
    quest_203.setSurvivalElapsedMs(2000);
    const path_203 = try persistence.highscores.scoresPathForMode(
        allocator,
        base_dir,
        @intFromEnum(game_ids.GameModeId.quests),
        .{ .quest_stage_major = 2, .quest_stage_minor = 3 },
    );
    defer allocator.free(path_203);
    try persistence.highscores.writeHighscoreRecords(allocator, path_203, &.{quest_203}, null);

    var state: State = .{};
    defer state.high_scores.clear(allocator);
    var config = formats.crimson_cfg.defaultConfig();
    config.game_mode = @intFromEnum(game_ids.GameModeId.quests);
    config.player_count = 1;
    const status = std.mem.zeroes(formats.game_cfg.Status);

    openHighScores(&state, allocator, base_dir, config, status, .{ .quest_level_key = 203 });

    try std.testing.expectEqual(View.high_scores, state.view);
    try std.testing.expectEqual(game_ids.GameModeId.quests, state.high_scores.mode);
    try std.testing.expectEqual(@as(i32, 203), state.high_scores.quest_level_key);
    try std.testing.expectEqual(@as(usize, 1), state.high_scores.records.len);
    try std.testing.expectEqualStrings("Quest203", state.high_scores.records[0].name());
}
