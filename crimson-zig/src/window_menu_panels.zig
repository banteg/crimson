const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const game_ids = cz.game_ids;
const quest_status = @import("quest_status.zig");

const window_assets = @import("window_assets.zig");
const window_menu = @import("window_menu.zig");
const window_ui = @import("window_ui.zig");

const panel_color = rl.Color.init(37, 24, 20, 255);
const panel_outline = rl.Color.init(122, 78, 58, 255);
const text_color = rl.Color.init(245, 236, 225, 255);
const muted_text = rl.Color.init(171, 150, 132, 255);
const accent_color = rl.Color.init(218, 80, 46, 255);

const player_count_labels = [_][:0]const u8{
    "1 player",
    "2 players",
    "3 players",
    "4 players",
};

pub const quest_titles = [_][]const u8{
    "Land Hostile",          "Minor Alien Breach",       "Target Practice",    "Frontline Assault", "Alien Dens",
    "The Random Factor",     "Spider Wave Syndrome",     "Alien Squads",       "Nesting Grounds",   "8-legged Terror",
    "Everred Pastures",      "Spider Spawns",            "Arachnoid Farm",     "Two Fronts",        "Sweep Stakes",
    "Evil Zombies At Large", "Survival Of The Fastest",  "Land Of Lizards",    "Ghost Patrols",     "Spideroids",
    "The Blighting",         "Lizard Kings",             "The Killing",        "Hidden Evil",       "Surrounded By Reptiles",
    "The Lizquidation",      "Spiders Inc.",             "Lizard Raze",        "Deja vu",           "Zombie Masters",
    "Major Alien Breach",    "Zombie Time",              "Lizard Zombie Pact", "The Collaboration", "The Massacre",
    "The Unblitzkrieg",      "Gauntlet",                 "Syntax Terror",      "The Annihilation",  "The End of All",
    "The Beating",           "The Spanking Of The Dead", "The Fortress",       "The Gang Wars",     "Knee-deep in the Dead",
    "Cross Fire",            "Army of Three",            "Monster Blues",      "Nagolipoli",        "The Gathering",
};

pub const PlayGameAction = enum {
    start_survival,
    start_rush,
    start_typo,
    start_tutorial,
    open_quests,
    back_to_menu,
};

const PanelState = struct {
    selection: usize = 0,
    timeline_ms: i32 = 0,
    panel_open_sfx_played: bool = false,

    fn reset(self: *PanelState) void {
        self.* = .{};
    }
};

pub const PlayGameState = struct {
    panel: PanelState = .{},
    player_list_open: bool = false,
    player_count_selection: usize = 0,
    closing: bool = false,
    close_action: ?PlayGameAction = null,
    tooltip_ms: [6]i32 = [_]i32{0} ** 6,
    back_hover_amount: i32 = 0,

    pub fn reset(self: *PlayGameState) void {
        self.* = .{};
    }
};

pub const PlayGameResult = struct {
    action: ?PlayGameAction = null,
    play_panel_click: bool = false,
    play_button_click: bool = false,
    config_dirty: bool = false,
};

const PlayGameModeKey = enum {
    tutorial,
    quests,
    rush,
    survival,
    typo,
};

const PlayGameEntry = struct {
    key: PlayGameModeKey,
    label: [:0]const u8,
    tooltip: []const u8,
    action: PlayGameAction,
    game_mode: ?game_ids.GameModeId = null,
    show_count: bool = false,
};

const PlayGameLayout = struct {
    panel_rect: rl.Rectangle,
    base_pos: rl.Vector2,
    drop_pos: rl.Vector2,
    title_pos: rl.Vector2,
    y_start: f32,
    y_step: f32,
    count_x: f32,
    tooltip_pos: rl.Vector2,
};

const QuestLayout = struct {
    panel_rect: rl.Rectangle,
    title_pos: rl.Vector2,
    icons_start_pos: rl.Vector2,
    list_pos: rl.Vector2,
    back_pos: rl.Vector2,
};

const quest_title_w: f32 = 64.0;
const quest_title_h: f32 = 32.0;
const quest_stage_icon_size: f32 = 32.0;
const quest_stage_icon_step: f32 = 36.0;
const quest_stage_icon_scale_unselected: f32 = 0.8;
const quest_list_row_step: f32 = 20.0;
const quest_list_name_x_offset: f32 = 32.0;
const quest_list_hover_left_pad: f32 = 10.0;
const quest_list_hover_right_pad: f32 = 210.0;
const quest_list_hover_top_pad: f32 = 2.0;
const quest_list_hover_bottom_pad: f32 = 18.0;
const quest_hardcore_unlock_index: u32 = 40;
const demo_quest_unlock_limit: u16 = 10;

pub fn updatePlayGame(state: *PlayGameState, frame_dt: f32, config: *formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status, runtime_assets: ?*const window_assets.RuntimeAssets, demo_enabled: bool) PlayGameResult {
    const dt_ms = frameDeltaMs(frame_dt);
    if (state.closing) {
        if (dt_ms > 0) state.panel.timeline_ms -= dt_ms;
        if (state.panel.timeline_ms < 0) {
            const action = state.close_action;
            state.closing = false;
            state.close_action = null;
            if (action) |resolved| return .{ .action = resolved };
        }
        return .{};
    }
    if (dt_ms > 0) state.panel.timeline_ms = @min(panel_timeline_max_ms, state.panel.timeline_ms + dt_ms);
    const player_count = @as(usize, @intCast(std.math.clamp(config.player_count, @as(u32, 1), @as(u32, 4))));
    if (state.player_count_selection >= player_count_labels.len) state.player_count_selection = player_count - 1;

    if (rl.isKeyPressed(.escape)) {
        state.player_list_open = false;
        beginClosePlayGame(state, .back_to_menu);
        return .{ .play_button_click = true };
    }

    if (state.player_list_open) {
        return updatePlayGamePlayerList(state, config, status, dt_ms, state.panel.timeline_ms, demo_enabled);
    }

    const entries = playGameEntries(config, status, demo_enabled);
    const layout = playGameLayout(config, status, state.panel.timeline_ms, demo_enabled);
    const hovered = hoveredPlayGameEntry(entries[0..], layout);
    updatePlayGameTooltipTimers(state, entries[0..], hovered, dt_ms);
    const back_hovered = if (runtime_assets) |assets|
        state.panel.timeline_ms >= panel_timeline_max_ms and rl.checkCollisionPointRec(rl.getMousePosition(), window_menu.panelBackHitRect(assets, state.panel.timeline_ms))
    else
        false;
    if (back_hovered) {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount + dt_ms * 6, 0, 1000);
    } else {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount - dt_ms * 2, 0, 1000);
    }

    const selector = playerCountHeaderRect(layout);
    if (rl.checkCollisionPointRec(rl.getMousePosition(), selector) and rl.isMouseButtonPressed(.left)) {
        state.player_list_open = true;
        state.player_count_selection = player_count - 1;
        return .{ .play_button_click = true };
    }

    if (back_hovered and rl.isMouseButtonPressed(.left)) {
        beginClosePlayGame(state, .back_to_menu);
        return .{ .play_button_click = true };
    }

    if (hovered) |hovered_idx| {
        const entry = entries[hovered_idx];
        if (rl.isMouseButtonPressed(.left)) {
            beginClosePlayGame(state, entry.action);
            return .{
                .play_button_click = true,
                .config_dirty = if (entry.game_mode) |mode| setConfigGameMode(config, mode) else false,
            };
        }
    }

    return .{
        .play_panel_click = dt_ms > 0 and state.panel.timeline_ms >= panel_timeline_max_ms and !state.panel.panel_open_sfx_played,
    };
}

fn updatePlayGamePlayerList(state: *PlayGameState, config: *formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status, dt_ms: i32, timeline_ms: i32, demo_enabled: bool) PlayGameResult {
    _ = dt_ms;
    const layout = playGameLayout(config, status, timeline_ms, demo_enabled);
    if (rl.isKeyPressed(.escape)) {
        state.player_list_open = false;
        return .{};
    }
    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        state.player_count_selection = if (state.player_count_selection == 0) player_count_labels.len - 1 else state.player_count_selection - 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.player_count_selection = (state.player_count_selection + 1) % player_count_labels.len;
    }

    const mouse = rl.getMousePosition();
    for (0..player_count_labels.len) |idx| {
        if (rl.checkCollisionPointRec(mouse, playerCountRowRect(layout, idx)) and rl.isMouseButtonPressed(.left)) {
            config.player_count = @intCast(idx + 1);
            state.player_list_open = false;
            return .{ .play_button_click = true, .config_dirty = true };
        }
    }

    if (window_ui.confirmPressed()) {
        config.player_count = @intCast(state.player_count_selection + 1);
        state.player_list_open = false;
        return .{ .play_button_click = true, .config_dirty = true };
    }

    if (rl.isMouseButtonPressed(.left) and !rl.checkCollisionPointRec(mouse, playerCountListRect(layout))) {
        state.player_list_open = false;
    }

    return .{};
}

pub fn drawPlayGame(state: *const PlayGameState, runtime_assets: ?*const window_assets.RuntimeAssets, status: formats.game_cfg.Status, player_count_raw: u32, demo_enabled: bool, debug_enabled: bool) void {
    if (runtime_assets) |assets| {
        drawMenuPanelShellNoTitle(state.panel.timeline_ms, assets, playGameLayoutFromPlayerCount(player_count_raw, status, state.panel.timeline_ms, demo_enabled).panel_rect);
        drawPlayGameContent(state, assets, status, player_count_raw, demo_enabled, debug_enabled);
        window_menu.drawPanelBackEntry(assets, state.panel.timeline_ms, state.back_hover_amount);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawPlayGameContent(state: *const PlayGameState, runtime_assets: *const window_assets.RuntimeAssets, status: formats.game_cfg.Status, player_count_raw: u32, demo_enabled: bool, debug_enabled: bool) void {
    const clamped_player_count = std.math.clamp(player_count_raw, @as(u32, 1), @as(u32, 4));
    const layout = playGameLayoutFromPlayerCount(clamped_player_count, status, state.panel.timeline_ms, demo_enabled);
    const entries = playGameEntriesFromPlayerCount(clamped_player_count, status, demo_enabled);
    const show_counts = debugCountOverlayVisible(debug_enabled, rl.isKeyDown(.f1));

    drawAtlasLabelAt(runtime_assets, layout.title_pos.x, layout.title_pos.y, window_menu.label_row_play_game, rl.Color.white);

    if (show_counts) {
        window_ui.drawSmallText(runtime_assets, "times played:", layout.base_pos.x + 132.0, layout.base_pos.y + 16.0, text_color);
    }

    var y = layout.base_pos.y + layout.y_start;
    for (entries) |entry| {
        const button = playGameButton(entry.label, layout.base_pos.x, y);
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
        window_ui.drawButton(button, false, hovered, runtime_assets);
        if (show_counts and entry.show_count) {
            window_ui.drawSmallTextFmt("{d}", runtime_assets, .{playGameCount(entry.key, status)}, layout.count_x, y + 8.0, if (hovered) text_color else muted_text);
        }
        y += layout.y_step;
    }

    drawPlayerCountWidget(state, runtime_assets, layout, player_count_raw);
    drawPlayGameTooltips(state, runtime_assets, entries[0..], layout);
}

fn playGameEntries(config: *const formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status, demo_enabled: bool) []const PlayGameEntry {
    return playGameEntriesFromPlayerCount(config.player_count, status, demo_enabled);
}

fn playGameEntriesFromPlayerCount(player_count_raw: u32, status: formats.game_cfg.Status, demo_enabled: bool) []const PlayGameEntry {
    const player_count = std.math.clamp(player_count_raw, @as(u32, 1), @as(u32, 4));
    const main_total = questTotalPlayed(status) +% status.mode_play_rush +% status.mode_play_survival;
    const quest_unlock_index = visibleQuestUnlockIndex(status, demo_enabled);
    const has_typo = !demo_enabled and player_count == 1 and quest_unlock_index >= quest_hardcore_unlock_index;
    const tutorial_first = player_count == 1 and main_total == 0;
    if (player_count != 1) return play_game_entries_multi[0..];
    if (has_typo and tutorial_first) return play_game_entries_single_typo_tutorial_first[0..];
    if (has_typo) return play_game_entries_single_typo[0..];
    if (tutorial_first) return play_game_entries_single_tutorial_first[0..];
    return play_game_entries_single[0..];
}

fn playGameLayout(config: *const formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status, timeline_ms: i32, demo_enabled: bool) PlayGameLayout {
    return playGameLayoutFromPlayerCount(config.player_count, status, timeline_ms, demo_enabled);
}

fn playGameLayoutFromPlayerCount(player_count_raw: u32, status: formats.game_cfg.Status, timeline_ms: i32, demo_enabled: bool) PlayGameLayout {
    const entries = playGameEntriesFromPlayerCount(player_count_raw, status, demo_enabled);
    const player_count = std.math.clamp(player_count_raw, @as(u32, 1), @as(u32, 4));
    const tight_spacing = player_count == 1 and visibleQuestUnlockIndex(status, demo_enabled) >= quest_hardcore_unlock_index;
    const y_step: f32 = if (tight_spacing) 28.0 else 32.0;
    const y_start: f32 = if (entries.len >= 6) 36.0 else if (tight_spacing) 42.0 else 48.0;
    const panel_height: f32 = if (entries.len >= 5) 322.0 else 278.0;
    const panel_rect = animatedPanelRect(.{ .x = 352.0, .y = 150.0, .width = 510.0, .height = panel_height }, timeline_ms);
    const base_pos = rl.Vector2.init(panel_rect.x + 266.0, panel_rect.y + 50.0);
    const drop_pos = rl.Vector2.init(base_pos.x + 80.0, base_pos.y + 1.0);
    const y_end = y_start + y_step * @as(f32, @floatFromInt(entries.len));
    return .{
        .panel_rect = panel_rect,
        .base_pos = base_pos,
        .drop_pos = drop_pos,
        .title_pos = .{ .x = base_pos.x - 64.0, .y = base_pos.y - 8.0 },
        .y_start = y_start,
        .y_step = y_step,
        .count_x = base_pos.x + 158.0,
        .tooltip_pos = .{ .x = base_pos.x - 55.0, .y = base_pos.y + y_end + 16.0 },
    };
}

fn playGameButton(label: [:0]const u8, center_x: f32, top_y: f32) window_ui.UiButton {
    return window_ui.buttonAt(label, center_x, top_y, false);
}

fn hoveredPlayGameEntry(entries: []const PlayGameEntry, layout: PlayGameLayout) ?usize {
    const mouse = rl.getMousePosition();
    var y = layout.base_pos.y + layout.y_start;
    for (entries, 0..) |entry, idx| {
        const button = playGameButton(entry.label, layout.base_pos.x, y);
        if (rl.checkCollisionPointRec(mouse, button.rect)) return idx;
        y += layout.y_step;
    }
    return null;
}

fn playGameCount(key: PlayGameModeKey, status: formats.game_cfg.Status) u32 {
    return switch (key) {
        .quests => questTotalPlayed(status),
        .rush => status.mode_play_rush,
        .survival => status.mode_play_survival,
        .typo => status.mode_play_typo,
        .tutorial => status.mode_play_other,
    };
}

fn beginClosePlayGame(state: *PlayGameState, action: PlayGameAction) void {
    if (state.closing) return;
    state.closing = true;
    state.close_action = action;
    state.player_list_open = false;
}

fn tooltipIndexForKey(key: PlayGameModeKey) usize {
    return switch (key) {
        .tutorial => 0,
        .quests => 1,
        .rush => 2,
        .survival => 3,
        .typo => 4,
    };
}

fn updatePlayGameTooltipTimers(state: *PlayGameState, entries: []const PlayGameEntry, hovered: ?usize, dt_ms: i32) void {
    for (entries, 0..) |entry, idx| {
        const tooltip_idx = tooltipIndexForKey(entry.key);
        if (hovered != null and hovered.? == idx) {
            state.tooltip_ms[tooltip_idx] = @min(1000, state.tooltip_ms[tooltip_idx] + dt_ms * 6);
        } else {
            state.tooltip_ms[tooltip_idx] = @max(0, state.tooltip_ms[tooltip_idx] - dt_ms * 2);
        }
    }
}

fn drawPlayGameTooltips(state: *const PlayGameState, runtime_assets: *const window_assets.RuntimeAssets, entries: []const PlayGameEntry, layout: PlayGameLayout) void {
    for (entries) |entry| {
        const tooltip_idx = tooltipIndexForKey(entry.key);
        const ms = state.tooltip_ms[tooltip_idx];
        if (ms <= 0) continue;
        const alpha = @as(u8, @intFromFloat(@min(@as(f32, 1.0), @as(f32, @floatFromInt(ms)) * 0.0009) * 255.0));
        const offset = playGameTooltipOffset(entry.key);
        var lines = std.mem.splitScalar(u8, entry.tooltip, '\n');
        var y = layout.tooltip_pos.y + offset.y;
        while (lines.next()) |line| {
            window_ui.drawSmallText(runtime_assets, line, layout.tooltip_pos.x + offset.x, y, rl.Color.init(255, 255, 255, alpha));
            y += 14.0;
        }
    }
}

fn playGameTooltipOffset(key: PlayGameModeKey) rl.Vector2 {
    return switch (key) {
        .quests => .{ .x = -8.0, .y = 0.0 },
        .rush => .{ .x = 32.0, .y = 0.0 },
        .survival => .{ .x = 20.0, .y = 0.0 },
        .typo => .{ .x = 0.0, .y = -12.0 },
        .tutorial => .{ .x = 38.0, .y = 0.0 },
    };
}

const play_game_entries_multi = [_]PlayGameEntry{
    .{ .key = .quests, .label = " Quests ", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "  Rush  ", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "Survival", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
};

const play_game_entries_single_tutorial_first = [_]PlayGameEntry{
    .{ .key = .tutorial, .label = "Tutorial", .tooltip = "Learn how to play Crimsonland.", .action = .start_tutorial, .game_mode = .tutorial },
    .{ .key = .quests, .label = " Quests ", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "  Rush  ", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "Survival", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
};

const play_game_entries_single = [_]PlayGameEntry{
    .{ .key = .quests, .label = " Quests ", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "  Rush  ", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "Survival", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
    .{ .key = .tutorial, .label = "Tutorial", .tooltip = "Learn how to play Crimsonland.", .action = .start_tutorial, .game_mode = .tutorial },
};

const play_game_entries_single_typo_tutorial_first = [_]PlayGameEntry{
    .{ .key = .tutorial, .label = "Tutorial", .tooltip = "Learn how to play Crimsonland.", .action = .start_tutorial, .game_mode = .tutorial },
    .{ .key = .quests, .label = " Quests ", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "  Rush  ", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "Survival", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
    .{ .key = .typo, .label = "Typ'o'Shooter", .tooltip = "Use your typing skills as the weapon to lay\nthem down.", .action = .start_typo, .game_mode = .typo, .show_count = true },
};

const play_game_entries_single_typo = [_]PlayGameEntry{
    .{ .key = .quests, .label = " Quests ", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "  Rush  ", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "Survival", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
    .{ .key = .typo, .label = "Typ'o'Shooter", .tooltip = "Use your typing skills as the weapon to lay\nthem down.", .action = .start_typo, .game_mode = .typo, .show_count = true },
    .{ .key = .tutorial, .label = "Tutorial", .tooltip = "Learn how to play Crimsonland.", .action = .start_tutorial, .game_mode = .tutorial },
};

test "demo play game layout caps visible quest unlock progress" {
    var status = std.mem.zeroes(formats.game_cfg.Status);
    status.quest_unlock_index = 49;

    const demo_entries = playGameEntriesFromPlayerCount(1, status, true);
    for (demo_entries) |entry| {
        try std.testing.expect(entry.key != .typo);
    }

    const demo_layout = playGameLayoutFromPlayerCount(1, status, panel_timeline_max_ms, true);
    try std.testing.expectEqual(@as(f32, 32.0), demo_layout.y_step);
    try std.testing.expectEqual(@as(f32, 48.0), demo_layout.y_start);

    const full_entries = playGameEntriesFromPlayerCount(1, status, false);
    try std.testing.expect(full_entries.len >= 1);
    var full_has_typo = false;
    for (full_entries) |entry| {
        full_has_typo = full_has_typo or entry.key == .typo;
    }
    try std.testing.expect(full_has_typo);
}

fn drawPlayerCountWidget(state: *const PlayGameState, runtime_assets: *const window_assets.RuntimeAssets, layout: PlayGameLayout, player_count_raw: u32) void {
    const rect = playerCountHeaderRect(layout);
    const selected_index = @as(usize, @intCast(std.math.clamp(player_count_raw, @as(u32, 1), @as(u32, 4)))) - 1;
    const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), rect);
    const active = state.player_list_open or hovered;
    const texture = if (active) runtime_assets.texture(.ui_drop_on) else runtime_assets.texture(.ui_drop_off);

    rl.drawRectangleRec(rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(rect.x + 1.0), @intFromFloat(rect.y + 1.0), @intFromFloat(rect.width - 2.0), @intFromFloat(rect.height - 2.0), rl.Color.black);
    if (active) {
        rl.drawRectangle(@intFromFloat(rect.x), @intFromFloat(rect.y + 15.0), @intFromFloat(rect.width), 1, rl.Color.init(255, 255, 255, 128));
    }
    window_ui.drawSmallText(runtime_assets, player_count_labels[selected_index], rect.x + 4.0, rect.y + 1.0, rl.Color.init(255, 255, 255, if (active) 242 else 191));
    rl.drawTexturePro(
        texture,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)),
        rl.Rectangle.init(rect.x + rect.width - 17.0, rect.y, 16.0, 16.0),
        rl.Vector2.zero(),
        0.0,
        rl.Color.white,
    );

    if (!state.player_list_open) return;

    const list_rect = playerCountListRect(layout);
    rl.drawRectangleRec(list_rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(list_rect.x + 1.0), @intFromFloat(list_rect.y + 1.0), @intFromFloat(list_rect.width - 2.0), @intFromFloat(list_rect.height - 2.0), rl.Color.black);
    for (player_count_labels, 0..) |label, idx| {
        const row_rect = playerCountRowRect(layout, idx);
        const row_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), row_rect);
        const alpha: u8 = if (row_hovered) 242 else if (idx == state.player_count_selection) 245 else 153;
        window_ui.drawSmallText(runtime_assets, label, row_rect.x + 4.0, row_rect.y + 1.0, rl.Color.init(255, 255, 255, alpha));
    }
}

fn questTotalPlayed(status: formats.game_cfg.Status) u32 {
    var total: u32 = 0;
    var idx: usize = 11;
    while (idx <= 50 and idx < status.quest_play_counts.len) : (idx += 1) {
        total +%= status.quest_play_counts[idx];
    }
    return total;
}

pub const QuestState = struct {
    panel: PanelState = .{},
    stage: i32 = 1,
    closing: bool = false,
    closing_level_key: ?i32 = null,
    closing_back: bool = false,

    pub fn reset(self: *QuestState) void {
        self.* = .{};
    }

    pub fn resetToLevelKey(self: *QuestState, level_key: i32) void {
        self.reset();
        self.stage = std.math.clamp(@divTrunc(level_key, 100), @as(i32, 1), @as(i32, 5));
    }
};

pub const QuestResult = struct {
    start_level_key: ?i32 = null,
    back_to_play_game: bool = false,
    play_panel_click: bool = false,
    play_button_click: bool = false,
    config_dirty: bool = false,
    status_dirty: bool = false,
};

fn questResultWithDirty(result: QuestResult, config_dirty: bool, status_dirty: bool) QuestResult {
    var merged = result;
    merged.config_dirty = merged.config_dirty or config_dirty;
    merged.status_dirty = merged.status_dirty or status_dirty;
    return merged;
}

test "quest menu reset can preserve selected quest stage" {
    var state: QuestState = .{ .stage = 1 };

    state.resetToLevelKey(407);
    try std.testing.expectEqual(@as(i32, 4), state.stage);

    state.resetToLevelKey(999);
    try std.testing.expectEqual(@as(i32, 5), state.stage);

    state.resetToLevelKey(-1);
    try std.testing.expectEqual(@as(i32, 1), state.stage);
}

pub fn updateQuests(state: *QuestState, frame_dt: f32, config: *formats.crimson_cfg.CrimsonCfg, status: *formats.game_cfg.Status, demo_enabled: bool, debug_enabled: bool) QuestResult {
    const dt_ms = frameDeltaMs(frame_dt);
    var config_dirty = false;
    var status_dirty = false;
    if (state.closing) {
        if (dt_ms > 0) state.panel.timeline_ms -= dt_ms;
        if (state.panel.timeline_ms < 0) {
            if (state.closing_back) {
                state.closing = false;
                state.closing_back = false;
                return .{ .back_to_play_game = true };
            }
            if (state.closing_level_key) |level_key| {
                state.closing = false;
                state.closing_level_key = null;
                return .{ .start_level_key = level_key };
            }
        }
        return .{};
    }
    if (dt_ms > 0) state.panel.timeline_ms = @min(panel_timeline_max_ms, state.panel.timeline_ms + dt_ms);
    if (demo_enabled and config.hardcore_flag != 0) {
        config.hardcore_flag = 0;
        config_dirty = true;
    }
    if (debug_enabled and rl.isKeyPressed(.f5)) {
        status_dirty = unlockAllQuestsForDebug(status);
    }
    if (rl.isKeyPressed(.escape)) {
        beginCloseQuestBack(state);
        return questResultWithDirty(.{ .play_button_click = true }, config_dirty, status_dirty);
    }

    if (rl.isKeyPressed(.left)) state.stage = @max(1, state.stage - 1);
    if (rl.isKeyPressed(.right)) state.stage = @min(5, state.stage + 1);
    const layout = questLayout(state.panel.timeline_ms);
    const hovered_stage = hoveredQuestStage(layout);
    if (hovered_stage) |stage| {
        if (rl.isMouseButtonPressed(.left)) {
            state.stage = stage;
            return questResultWithDirty(.{ .play_button_click = true }, config_dirty, status_dirty);
        }
    }

    if (questDigitRowPressed()) |row| {
        return questResultWithDirty(tryStartQuest(state, config, status.*, demo_enabled, state.stage, row), config_dirty, status_dirty);
    }

    const hovered_row = hoveredQuestRow(layout, hardcoreUnlocked(status.*, demo_enabled));

    if (hardcoreUnlocked(status.*, demo_enabled)) {
        const hardcore_rect = hardcoreCheckRect(layout);
        if (rl.checkCollisionPointRec(rl.getMousePosition(), hardcore_rect) and rl.isMouseButtonPressed(.left)) {
            config.hardcore_flag = if (config.hardcore_flag == 0) 1 else 0;
            if (demo_enabled) config.hardcore_flag = 0;
            return questResultWithDirty(.{ .play_button_click = true, .config_dirty = true }, config_dirty, status_dirty);
        }
    }

    if (hovered_row) |row| {
        if (rl.isMouseButtonPressed(.left) or window_ui.confirmPressed()) {
            return questResultWithDirty(tryStartQuest(state, config, status.*, demo_enabled, state.stage, row), config_dirty, status_dirty);
        }
    }

    if (questBackButtonActivated(layout)) {
        beginCloseQuestBack(state);
        return questResultWithDirty(.{ .play_button_click = true }, config_dirty, status_dirty);
    }

    return .{
        .play_panel_click = dt_ms > 0 and state.panel.timeline_ms >= panel_timeline_max_ms and !state.panel.panel_open_sfx_played,
        .config_dirty = config_dirty,
        .status_dirty = status_dirty,
    };
}

pub fn drawQuests(state: *const QuestState, runtime_assets: ?*const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status, demo_enabled: bool, debug_enabled: bool) void {
    if (runtime_assets) |assets| {
        drawMenuPanelShellNoTitle(state.panel.timeline_ms, assets, questLayout(state.panel.timeline_ms).panel_rect);
        drawQuestContent(state, assets, config, status, demo_enabled, debug_enabled);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawQuestContent(state: *const QuestState, runtime_assets: *const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status, demo_enabled: bool, debug_enabled: bool) void {
    const layout = questLayout(state.panel.timeline_ms);
    const title_tex = runtime_assets.texture(.ui_text_quest);
    const hovered_stage = hoveredQuestStage(layout);
    const hovered_row = hoveredQuestRow(layout, hardcoreUnlocked(status, demo_enabled));
    const show_counts = debugCountOverlayVisible(debug_enabled, rl.isKeyDown(.f1));
    rl.drawTexturePro(
        title_tex,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(title_tex.width), @floatFromInt(title_tex.height)),
        rl.Rectangle.init(layout.title_pos.x, layout.title_pos.y, quest_title_w, quest_title_h),
        rl.Vector2.zero(),
        0.0,
        rl.Color.init(179, 179, 179, 179),
    );

    const stage_textures = [_]window_assets.TextureId{ .ui_num1, .ui_num2, .ui_num3, .ui_num4, .ui_num5 };
    for (stage_textures, 0..) |texture_id, idx| {
        const stage = @as(i32, @intCast(idx + 1));
        const icon_scale = if (stage == state.stage) @as(f32, 1.0) else quest_stage_icon_scale_unselected;
        const tint = if (stage == state.stage) rl.Color.white else if (hovered_stage != null and hovered_stage.? == stage) rl.Color.init(255, 255, 255, 204) else rl.Color.init(179, 179, 179, 179);
        const x = layout.icons_start_pos.x + @as(f32, @floatFromInt(stage - 1)) * quest_stage_icon_step;
        window_ui.drawTextureFit(runtime_assets.texture(texture_id), rl.Rectangle.init(x, layout.icons_start_pos.y, quest_stage_icon_size * icon_scale, quest_stage_icon_size * icon_scale), tint);
    }

    if (hardcoreUnlocked(status, demo_enabled)) {
        const check_tex = if (config.hardcore_flag != 0) runtime_assets.texture(.ui_check_on) else runtime_assets.texture(.ui_check_off);
        const rect = hardcoreCheckRect(layout);
        window_ui.drawTextureFit(check_tex, rl.Rectangle.init(rect.x, rect.y, @floatFromInt(check_tex.width), @floatFromInt(check_tex.height)), rl.Color.white);
        window_ui.drawSmallText(runtime_assets, "Hardcore", rect.x + @as(f32, @floatFromInt(check_tex.width)) + 6.0, rect.y + 1.0, questRowColor(config.hardcore_flag != 0, false));
    }

    var y = questRowsY0(layout, hardcoreUnlocked(status, demo_enabled));
    for (0..10) |row| {
        const level_minor = @as(i32, @intCast(row + 1));
        const unlocked = questUnlocked(status, config.hardcore_flag != 0, demo_enabled, state.stage, level_minor);
        const hovered = hovered_row != null and hovered_row.? == row;
        const color = questRowColor(config.hardcore_flag != 0, hovered);
        window_ui.drawSmallTextFmt("{d}.{d}", runtime_assets, .{ state.stage, level_minor }, layout.list_pos.x, y, color);
        const title = if (unlocked) questTitle(state.stage, level_minor) else "???";
        window_ui.drawSmallText(runtime_assets, title, layout.list_pos.x + quest_list_name_x_offset, y, color);
        if (unlocked) {
            const title_w = window_ui.measureSmallText(runtime_assets, title);
            rl.drawLine(
                @intFromFloat(layout.list_pos.x),
                @intFromFloat(y + 13.0),
                @intFromFloat(layout.list_pos.x + title_w + quest_list_name_x_offset),
                @intFromFloat(y + 13.0),
                color,
            );
            if (show_counts) {
                const counts = questCounts(status, state.stage, row);
                var counts_buf: [32]u8 = undefined;
                const counts_text = std.fmt.bufPrint(&counts_buf, "({d}/{d})", .{ counts.completed, counts.games }) catch "";
                window_ui.drawSmallText(runtime_assets, counts_text, layout.list_pos.x + quest_list_name_x_offset + title_w + 12.0, y, color);
            }
        }
        y += quest_list_row_step;
    }

    if (show_counts) {
        window_ui.drawSmallText(runtime_assets, "(completed/games)", layout.list_pos.x + 96.0, questRowsY0(layout, hardcoreUnlocked(status, demo_enabled)) + quest_list_row_step * 10.0 - 2.0, questRowColor(config.hardcore_flag != 0, false));
    }

    const back = questBackButton(layout);
    const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
    window_ui.drawButton(back, false, hovered, runtime_assets);
}

fn questUnlocked(status: formats.game_cfg.Status, hardcore: bool, demo_enabled: bool, stage: i32, minor: i32) bool {
    const global_index = (stage - 1) * 10 + (minor - 1);
    const unlock = if (!demo_enabled and hardcore)
        status.quest_unlock_index_full
    else
        visibleQuestUnlockIndex(status, demo_enabled);
    return @as(i32, unlock) >= global_index;
}

fn hardcoreUnlocked(status: formats.game_cfg.Status, demo_enabled: bool) bool {
    return visibleQuestUnlockIndex(status, demo_enabled) >= quest_hardcore_unlock_index;
}

fn visibleQuestUnlockIndex(status: formats.game_cfg.Status, demo_enabled: bool) u16 {
    if (demo_enabled) return @min(status.quest_unlock_index, demo_quest_unlock_limit);
    return status.quest_unlock_index;
}

fn unlockAllQuestsForDebug(status: *formats.game_cfg.Status) bool {
    const unlock: u16 = 49;
    var dirty = false;
    if (status.quest_unlock_index < unlock) {
        status.quest_unlock_index = unlock;
        dirty = true;
    }
    if (status.quest_unlock_index_full < unlock) {
        status.quest_unlock_index_full = unlock;
        dirty = true;
    }
    return dirty;
}

test "demo quest menu caps visible unlock progress to native demo limit" {
    var status = std.mem.zeroes(formats.game_cfg.Status);
    status.quest_unlock_index = 49;
    status.quest_unlock_index_full = 49;

    try std.testing.expect(questUnlocked(status, false, true, 1, 10));
    try std.testing.expect(questUnlocked(status, false, true, 2, 1));
    try std.testing.expect(!questUnlocked(status, false, true, 2, 2));
    try std.testing.expect(!questUnlocked(status, true, true, 2, 2));
    try std.testing.expect(!hardcoreUnlocked(status, true));

    try std.testing.expect(questUnlocked(status, false, false, 5, 10));
    try std.testing.expect(hardcoreUnlocked(status, false));
}

test "debug quest unlock raises both normal and hardcore progress" {
    var status = std.mem.zeroes(formats.game_cfg.Status);
    status.quest_unlock_index = 3;
    status.quest_unlock_index_full = 12;

    try std.testing.expect(unlockAllQuestsForDebug(&status));
    try std.testing.expectEqual(@as(u16, 49), status.quest_unlock_index);
    try std.testing.expectEqual(@as(u16, 49), status.quest_unlock_index_full);

    try std.testing.expect(!unlockAllQuestsForDebug(&status));
    try std.testing.expectEqual(@as(u16, 49), status.quest_unlock_index);
    try std.testing.expectEqual(@as(u16, 49), status.quest_unlock_index_full);
}

test "quest result dirty flags merge with action results" {
    const merged = questResultWithDirty(.{ .play_button_click = true }, true, true);
    try std.testing.expect(merged.play_button_click);
    try std.testing.expect(merged.config_dirty);
    try std.testing.expect(merged.status_dirty);
}

fn questTitle(stage: i32, minor: i32) []const u8 {
    const index = (stage - 1) * 10 + (minor - 1);
    return quest_titles[@intCast(std.math.clamp(index, @as(i32, 0), @as(i32, @intCast(quest_titles.len - 1))))];
}

fn hoveredQuestStage(layout: QuestLayout) ?i32 {
    const mouse = rl.getMousePosition();
    for (1..6) |stage| {
        const x = layout.icons_start_pos.x + @as(f32, @floatFromInt(stage - 1)) * quest_stage_icon_step;
        if (rl.checkCollisionPointRec(mouse, rl.Rectangle.init(x, layout.title_pos.y, quest_stage_icon_size, quest_stage_icon_size))) return @intCast(stage);
    }
    return null;
}

fn hoveredQuestRow(layout: QuestLayout, show_hardcore_toggle: bool) ?usize {
    const mouse = rl.getMousePosition();
    var y: f32 = questRowsY0(layout, show_hardcore_toggle);
    for (0..10) |row| {
        const rect = rl.Rectangle.init(
            layout.list_pos.x - quest_list_hover_left_pad,
            y - quest_list_hover_top_pad,
            quest_list_hover_left_pad + quest_list_hover_right_pad,
            quest_list_hover_bottom_pad - quest_list_hover_top_pad,
        );
        if (rl.checkCollisionPointRec(mouse, rect)) return row;
        y += quest_list_row_step;
    }
    return null;
}

fn hardcoreCheckRect(layout: QuestLayout) rl.Rectangle {
    return rl.Rectangle.init(layout.list_pos.x + 132.0, layout.list_pos.y - 12.0, 120.0, 16.0);
}

fn beginCloseQuestBack(state: *QuestState) void {
    if (state.closing) return;
    state.closing = true;
    state.closing_back = true;
}

fn beginCloseQuestStart(state: *QuestState, level_key: i32) void {
    if (state.closing) return;
    state.closing = true;
    state.closing_level_key = level_key;
}

fn tryStartQuest(state: *QuestState, config: *formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status, demo_enabled: bool, stage: i32, row: usize) QuestResult {
    const minor = @as(i32, @intCast(row + 1));
    if (!questUnlocked(status, config.hardcore_flag != 0, demo_enabled, stage, minor)) return .{};
    const level_key = stage * 100 + minor;
    config.game_mode = @intFromEnum(game_ids.GameModeId.quests);
    beginCloseQuestStart(state, level_key);
    return .{ .play_button_click = true, .config_dirty = true };
}

fn questDigitRowPressed() ?usize {
    if (rl.isKeyPressed(.one)) return 0;
    if (rl.isKeyPressed(.two)) return 1;
    if (rl.isKeyPressed(.three)) return 2;
    if (rl.isKeyPressed(.four)) return 3;
    if (rl.isKeyPressed(.five)) return 4;
    if (rl.isKeyPressed(.six)) return 5;
    if (rl.isKeyPressed(.seven)) return 6;
    if (rl.isKeyPressed(.eight)) return 7;
    if (rl.isKeyPressed(.nine)) return 8;
    if (rl.isKeyPressed(.zero)) return 9;
    return null;
}

fn questLayout(timeline_ms: i32) QuestLayout {
    const panel_rect = animatedPanelRect(.{ .x = 390.0, .y = 168.0, .width = 510.0, .height = 378.0 }, timeline_ms);
    return .{
        .panel_rect = panel_rect,
        .title_pos = .{ .x = panel_rect.x + 219.0, .y = 212.0 },
        .icons_start_pos = .{ .x = panel_rect.x + 299.0, .y = 215.0 },
        .list_pos = .{ .x = panel_rect.x + 251.0, .y = 262.0 },
        .back_pos = .{ .x = panel_rect.x + 389.0, .y = 474.0 },
    };
}

fn questRowsY0(layout: QuestLayout, show_hardcore_toggle: bool) f32 {
    return layout.list_pos.y + if (show_hardcore_toggle) @as(f32, 10.0) else @as(f32, 0.0);
}

fn questBackButton(layout: QuestLayout) window_ui.UiButton {
    return window_ui.buttonAt("Back", layout.back_pos.x, layout.back_pos.y, false);
}

fn questBackButtonActivated(layout: QuestLayout) bool {
    const back = questBackButton(layout);
    return rl.isMouseButtonPressed(.left) and rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
}

fn questRowColor(hardcore: bool, hovered: bool) rl.Color {
    if (hardcore) {
        return if (hovered) rl.Color.init(250, 70, 60, 255) else rl.Color.init(250, 70, 60, 153);
    }
    return if (hovered) rl.Color.init(70, 180, 240, 255) else rl.Color.init(70, 180, 240, 153);
}

const QuestCountPair = struct {
    completed: u32,
    games: u32,
};

fn questCounts(status: formats.game_cfg.Status, stage: i32, row: usize) QuestCountPair {
    const minor = @as(i32, @intCast(row)) + 1;
    const level_key = stage * 100 + minor;
    const games_idx = quest_status.trackedQuestGamesCounterIndex(level_key);
    const completed_idx = quest_status.trackedQuestCompletedCounterIndex(level_key);
    return .{
        .completed = if (completed_idx) |idx| status.quest_play_counts[idx] else stage5CompletedCount(status, stage, minor),
        .games = if (games_idx) |idx| status.quest_play_counts[idx] else stage5GamesCount(status, stage, minor),
    };
}

fn debugCountOverlayVisible(debug_enabled: bool, f1_down: bool) bool {
    return debug_enabled and f1_down;
}

fn stage5GamesCount(status: formats.game_cfg.Status, stage: i32, minor: i32) u32 {
    if (stage != 5) return 0;
    const global_index = quest_status.questGlobalIndex(stage, minor) orelse return 0;
    const idx = global_index + quest_status.quest_status_games_offset;
    if (idx < 0 or idx >= formats.game_cfg.quest_play_count) return 0;
    return status.quest_play_counts[@intCast(idx)];
}

fn stage5CompletedCount(status: formats.game_cfg.Status, stage: i32, minor: i32) u32 {
    if (stage != 5) return 0;
    const global_index = quest_status.questGlobalIndex(stage, minor) orelse return 0;
    const tail_slot = global_index - quest_status.quest_status_tracked_count;
    return switch (tail_slot) {
        0 => status.mode_play_survival,
        1 => status.mode_play_rush,
        2 => status.mode_play_typo,
        3 => status.mode_play_other,
        4 => status.play_time_ms,
        5...8 => statusReservedSeedWordsU32(status, @intCast(tail_slot - 5)),
        else => 0,
    };
}

fn statusReservedSeedWordsU32(status: formats.game_cfg.Status, slot: usize) u32 {
    const off = slot * 4;
    if (off + 4 > status.reserved_seed_words.len) return 0;
    return std.mem.readInt(u32, status.reserved_seed_words[off..][0..4], .little);
}

test "quest counts read tracked stage four counters" {
    var status = std.mem.zeroes(formats.game_cfg.Status);
    status.quest_play_counts[50] = 12;
    status.quest_play_counts[90] = 34;

    const counts = questCounts(status, 4, 9);

    try std.testing.expectEqual(@as(u32, 34), counts.completed);
    try std.testing.expectEqual(@as(u32, 12), counts.games);
}

test "quest counts mirror native stage five overflow fields" {
    var status = std.mem.zeroes(formats.game_cfg.Status);
    status.quest_play_counts[51] = 123;
    status.quest_play_counts[52] = 222;
    status.quest_play_counts[55] = 456;
    status.quest_play_counts[56] = 789;
    status.quest_play_counts[60] = 999;
    status.mode_play_survival = 111;
    status.mode_play_rush = 222;
    status.mode_play_typo = 333;
    status.mode_play_other = 444;
    status.play_time_ms = 0x01020304;
    status.reserved_seed_words = [_]u8{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    };

    const row0 = questCounts(status, 5, 0);
    try std.testing.expectEqual(@as(u32, 111), row0.completed);
    try std.testing.expectEqual(@as(u32, 123), row0.games);

    const row1 = questCounts(status, 5, 1);
    try std.testing.expectEqual(@as(u32, 222), row1.completed);
    try std.testing.expectEqual(@as(u32, 222), row1.games);

    const row4 = questCounts(status, 5, 4);
    try std.testing.expectEqual(@as(u32, 0x01020304), row4.completed);
    try std.testing.expectEqual(@as(u32, 456), row4.games);

    const row5 = questCounts(status, 5, 5);
    try std.testing.expectEqual(@as(u32, 0x03020100), row5.completed);
    try std.testing.expectEqual(@as(u32, 789), row5.games);

    const row9 = questCounts(status, 5, 9);
    try std.testing.expectEqual(@as(u32, 0), row9.completed);
    try std.testing.expectEqual(@as(u32, 999), row9.games);
}

test "debug count overlays require debug flag and F1" {
    try std.testing.expect(!debugCountOverlayVisible(false, false));
    try std.testing.expect(!debugCountOverlayVisible(false, true));
    try std.testing.expect(!debugCountOverlayVisible(true, false));
    try std.testing.expect(debugCountOverlayVisible(true, true));
}

fn frameDeltaMs(frame_dt: f32) i32 {
    return @intFromFloat(@min(frame_dt, 0.1) * 1000.0);
}

fn panelAdvance(panel: *PanelState, frame_dt: f32) i32 {
    const dt_ms = frameDeltaMs(frame_dt);
    if (dt_ms > 0) {
        panel.timeline_ms = @min(panel_timeline_max_ms, panel.timeline_ms + dt_ms);
    }
    return dt_ms;
}

const panel_timeline_max_ms: i32 = 300;

fn drawMenuPanelShell(timeline_ms: i32, runtime_assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle, title_row_or_texture: anytype) void {
    window_menu.drawMenuBackdrop(runtime_assets);
    window_menu.drawSign(timeline_ms, runtime_assets);

    const panel_rect = animatedPanelRect(rect, timeline_ms);
    window_ui.drawClassicMenuPanel(runtime_assets.texture(.ui_menu_panel), panel_rect, rl.Color.white, false);

    const T = @TypeOf(title_row_or_texture);
    if (T == i32) {
        drawAtlasLabelAt(runtime_assets, panel_rect.x + (panel_rect.width - 128.0) * 0.5, panel_rect.y + 42.0, title_row_or_texture, rl.Color.white);
    } else {
        drawTextureLabel(runtime_assets, title_row_or_texture, panel_rect.x + rect.width * 0.5 - 64.0, panel_rect.y + 34.0, 128.0, 32.0, rl.Color.white);
    }
}

fn drawMenuPanelShellNoTitle(timeline_ms: i32, runtime_assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle) void {
    window_menu.drawMenuBackdrop(runtime_assets);
    window_menu.drawSign(timeline_ms, runtime_assets);

    const panel_rect = animatedPanelRect(rect, timeline_ms);
    window_ui.drawClassicMenuPanel(runtime_assets.texture(.ui_menu_panel), panel_rect, rl.Color.white, false);
}

fn drawTextureLabel(runtime_assets: *const window_assets.RuntimeAssets, texture_id: window_assets.TextureId, x: f32, y: f32, w: f32, h: f32, tint: rl.Color) void {
    window_ui.drawTextureFit(runtime_assets.texture(texture_id), rl.Rectangle.init(x, y, w, h), tint);
}

fn drawAtlasLabelAt(runtime_assets: *const window_assets.RuntimeAssets, x: f32, y: f32, row: i32, tint: rl.Color) void {
    const texture = runtime_assets.texture(.ui_item_texts);
    rl.drawTexturePro(
        texture,
        rl.Rectangle.init(0.0, @as(f32, @floatFromInt(row)) * 32.0, 128.0, 32.0),
        rl.Rectangle.init(x, y, 128.0, 32.0),
        rl.Vector2.zero(),
        0.0,
        tint,
    );
}

fn playGameButtons() [4]window_ui.UiButton {
    const center_x = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5;
    return .{
        .{ .label = "QUESTS", .rect = window_ui.centeredRect(center_x - 44.0, 276.0, 210.0, 48.0) },
        .{ .label = "RUSH", .rect = window_ui.centeredRect(center_x - 44.0, 332.0, 210.0, 48.0) },
        .{ .label = "SURVIVAL", .rect = window_ui.centeredRect(center_x - 44.0, 388.0, 210.0, 48.0) },
        .{ .label = "BACK", .rect = window_ui.centeredRect(center_x, 454.0, 180.0, 44.0) },
    };
}

fn playerCountHeaderRect(layout: PlayGameLayout) rl.Rectangle {
    return rl.Rectangle.init(layout.drop_pos.x, layout.drop_pos.y, 102.0, 16.0);
}

fn playerCountListRect(layout: PlayGameLayout) rl.Rectangle {
    return rl.Rectangle.init(layout.drop_pos.x, layout.drop_pos.y, 102.0, 88.0);
}

fn playerCountRowRect(layout: PlayGameLayout, idx: usize) rl.Rectangle {
    return rl.Rectangle.init(layout.drop_pos.x, layout.drop_pos.y + 17.0 + @as(f32, @floatFromInt(idx)) * 16.0, 102.0, 16.0);
}

fn animatedPanelRect(rect: rl.Rectangle, timeline_ms: i32) rl.Rectangle {
    const anim = window_menu.uiElementAnim(1, panel_timeline_max_ms, 0, rect.width, timeline_ms);
    return rl.Rectangle.init(rect.x + anim.offset_x, rect.y, rect.width, rect.height);
}

fn setConfigGameMode(config: *formats.crimson_cfg.CrimsonCfg, mode: game_ids.GameModeId) bool {
    const mode_value: u32 = @intCast(@intFromEnum(mode));
    if (config.game_mode == mode_value) return false;
    config.game_mode = mode_value;
    return true;
}
