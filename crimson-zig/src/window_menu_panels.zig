const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const game_ids = cz.game_ids;

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

const quest_titles = [_][]const u8{
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

const credits_lines = [_][]const u8{
    "2026 Remake:",
    "banteg",
    "",
    "Crimsonland",
    "Game Design:",
    "Tero Alatalo",
    "",
    "Programming:",
    "Tero Alatalo",
    "",
    "Producer:",
    "Zach Young",
    "",
    "2D Art:",
    "Tero Alatalo",
    "",
    "3D Modelling:",
    "Tero Alatalo",
    "Timo Palonen",
    "",
    "Music:",
    "Valtteri Pihlajam",
    "Ville Eriksson",
    "",
    "Sound Effects:",
    "Ion Hardie",
    "Tero Alatalo",
    "Valtteri Pihlajam",
    "Ville Eriksson",
    "",
    "Manual:",
    "Miikka Kulmala",
    "Zach Young",
    "",
    "Special thanks to:",
    "Petri J",
    "Peter Hajba / Remedy",
    "",
    "Play testers:",
    "Avraham Petrosyan",
    "Bryce Baker",
    "Dan Ruskin",
    "Dirk Bunk",
    "Eric Dallaire",
    "Erik Van Pelt",
    "Ernie Ramirez",
    "Ion Hardie",
    "James C. Smith",
    "Jarkko Forsbacka",
    "Jeff McAteer",
    "Juha Alatalo",
    "Kalle Hahl",
    "Lars Brubaker",
    "Lee Cooper",
    "Markus Lassila",
    "Matti Alanen",
    "Miikka Kulmala",
    "Mika Alatalo",
    "Mike Colonnese",
    "Simon Hallam",
    "Toni Nurminen",
    "Valtteri Pihlajam",
    "Ville Eriksson",
    "Ville M",
    "Zach Young",
    "",
    "2003 (c) 10tons entertainment",
    "10tons logo by Pasi Heinonen",
    "",
    "Uses Vorbis Audio Decompression",
    "2003 (c) Xiph.Org Foundation",
    "(see vorbis.txt)",
};

pub const PlayGameAction = enum {
    start_survival,
    start_rush,
    start_typo,
    start_tutorial,
    open_quests,
    back_to_menu,
};

pub const StatisticsAction = enum {
    open_high_scores,
    open_weapons,
    open_perks,
    open_credits,
    back_to_menu,
};

pub const InfoKind = enum {
    weapons,
    perks,
    credits,
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
    selection: usize = 0,

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
    content_x: f32,
    content_y: f32,
    drop_x: f32,
    y_start: f32,
    y_step: f32,
    count_x: f32,
    tooltip_y: f32,
};

pub fn updatePlayGame(state: *PlayGameState, frame_dt: f32, config: *formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status) PlayGameResult {
    const dt_ms = panelAdvance(&state.panel, frame_dt);
    const player_count = @as(usize, @intCast(std.math.clamp(config.player_count, @as(u32, 1), @as(u32, 4))));
    if (state.player_count_selection >= player_count_labels.len) state.player_count_selection = player_count - 1;

    if (rl.isKeyPressed(.escape)) {
        state.player_list_open = false;
        return .{ .action = .back_to_menu, .play_button_click = true };
    }

    if (state.player_list_open) {
        return updatePlayGamePlayerList(state, config, dt_ms);
    }

    const entries = playGameEntries(config, status);
    const button_count = entries.len + 1;
    if (state.selection >= button_count) state.selection = button_count - 1;

    const layout = playGameLayout(config, status);
    if (hoveredPlayGameEntry(entries[0..], layout)) |hovered| {
        state.selection = hovered;
    } else if (rl.checkCollisionPointRec(rl.getMousePosition(), backOnlyButton()[0].rect)) {
        state.selection = entries.len;
    }
    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        state.selection = if (state.selection == 0) button_count - 1 else state.selection - 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.selection = (state.selection + 1) % button_count;
    }

    const selector = playerCountHeaderRect();
    if (rl.checkCollisionPointRec(rl.getMousePosition(), selector) and rl.isMouseButtonPressed(.left)) {
        state.player_list_open = true;
        state.player_count_selection = player_count - 1;
        return .{ .play_button_click = true };
    }
    if ((rl.isKeyPressed(.left) or rl.isKeyPressed(.right)) and state.selection == entries.len) {
        state.player_list_open = true;
        state.player_count_selection = player_count - 1;
        return .{ .play_button_click = true };
    }

    if (!playGameActivated(entries[0..], layout, state.selection)) {
        return .{
            .play_panel_click = dt_ms > 0 and state.panel.timeline_ms >= panel_timeline_max_ms and !state.panel.panel_open_sfx_played,
        };
    }

    if (state.selection == entries.len) {
        return .{ .action = .back_to_menu, .play_button_click = true };
    }

    const entry = entries[state.selection];
    return .{
        .action = entry.action,
        .play_button_click = true,
        .config_dirty = if (entry.game_mode) |mode| setConfigGameMode(config, mode) else false,
    };
}

fn updatePlayGamePlayerList(state: *PlayGameState, config: *formats.crimson_cfg.CrimsonCfg, dt_ms: i32) PlayGameResult {
    _ = dt_ms;
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
        if (rl.checkCollisionPointRec(mouse, playerCountRowRect(idx)) and rl.isMouseButtonPressed(.left)) {
            config.player_count = @intCast(idx + 1);
            state.player_list_open = false;
            return .{ .play_button_click = true, .config_dirty = true };
        }
    }

    if (rl.isKeyPressed(.enter) or rl.isKeyPressed(.space)) {
        config.player_count = @intCast(state.player_count_selection + 1);
        state.player_list_open = false;
        return .{ .play_button_click = true, .config_dirty = true };
    }

    if (rl.isMouseButtonPressed(.left) and !rl.checkCollisionPointRec(mouse, playerCountListRect())) {
        state.player_list_open = false;
    }

    return .{};
}

pub fn drawPlayGame(state: *const PlayGameState, runtime_assets: ?*const window_assets.RuntimeAssets, status: formats.game_cfg.Status, player_count_raw: u32) void {
    if (runtime_assets) |assets| {
        drawMenuPanelShell(state.panel.timeline_ms, assets, playGameLayoutFromPlayerCount(player_count_raw, status).panel_rect, window_menu.label_row_play_game);
        drawPlayGameContent(state, assets, status, player_count_raw);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawPlayGameContent(state: *const PlayGameState, runtime_assets: *const window_assets.RuntimeAssets, status: formats.game_cfg.Status, player_count_raw: u32) void {
    const clamped_player_count = std.math.clamp(player_count_raw, @as(u32, 1), @as(u32, 4));
    const layout = playGameLayoutFromPlayerCount(clamped_player_count, status);
    const entries = playGameEntriesFromPlayerCount(clamped_player_count, status);

    window_ui.drawSmallText(runtime_assets, "PLAYER COUNT", layout.drop_x, layout.content_y - 14.0, muted_text);
    drawPlayerCountWidget(state, runtime_assets, player_count_raw);

    var y = layout.content_y + layout.y_start;
    for (entries, 0..) |entry, idx| {
        const button = playGameButton(entry.label, layout.content_x, y);
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
        const selected = idx == state.selection and !state.player_list_open;
        window_ui.drawButton(button, selected, hovered, runtime_assets);
        if (entry.show_count) {
            window_ui.drawSmallTextFmt("{d}", runtime_assets, .{playGameCount(entry.key, status)}, layout.count_x, y + 8.0, if (selected or hovered) text_color else muted_text);
        }
        y += layout.y_step;
    }

    const back = backOnlyButton()[0];
    const back_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
    window_ui.drawButton(back, state.selection == entries.len and !state.player_list_open, back_hovered, runtime_assets);

    const tooltip_entry = tooltipEntry(entries, state.selection, layout);
    if (tooltip_entry) |entry| {
        drawTooltip(runtime_assets, entry.tooltip, layout.content_x, layout.tooltip_y);
    }
}

fn playGameEntries(config: *const formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status) []const PlayGameEntry {
    return playGameEntriesFromPlayerCount(config.player_count, status);
}

fn playGameEntriesFromPlayerCount(player_count_raw: u32, status: formats.game_cfg.Status) []const PlayGameEntry {
    const player_count = std.math.clamp(player_count_raw, @as(u32, 1), @as(u32, 4));
    const main_total = questTotalPlayed(status) + status.mode_play_rush + status.mode_play_survival;
    const has_typo = player_count == 1 and status.quest_unlock_index >= 40;
    const tutorial_first = player_count == 1 and main_total == 0;
    if (player_count != 1) return play_game_entries_multi[0..];
    if (has_typo and tutorial_first) return play_game_entries_single_typo_tutorial_first[0..];
    if (has_typo) return play_game_entries_single_typo[0..];
    if (tutorial_first) return play_game_entries_single_tutorial_first[0..];
    return play_game_entries_single[0..];
}

fn playGameLayout(config: *const formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status) PlayGameLayout {
    return playGameLayoutFromPlayerCount(config.player_count, status);
}

fn playGameLayoutFromPlayerCount(player_count_raw: u32, status: formats.game_cfg.Status) PlayGameLayout {
    const entries = playGameEntriesFromPlayerCount(player_count_raw, status);
    const player_count = std.math.clamp(player_count_raw, @as(u32, 1), @as(u32, 4));
    const tight_spacing = player_count == 1 and status.quest_unlock_index >= 40;
    const y_step: f32 = if (tight_spacing) 28.0 else 32.0;
    const y_start: f32 = if (tight_spacing) 42.0 else 48.0;
    const panel_height = 206.0 + y_start + y_step * @as(f32, @floatFromInt(entries.len));
    return .{
        .panel_rect = .{ .x = 352.0, .y = 150.0, .width = 510.0, .height = panel_height },
        .content_x = 470.0,
        .content_y = 206.0,
        .drop_x = 522.0,
        .y_start = y_start,
        .y_step = y_step,
        .count_x = 744.0,
        .tooltip_y = 230.0 + y_start + y_step * @as(f32, @floatFromInt(entries.len)),
    };
}

fn playGameButton(label: [:0]const u8, center_x: f32, top_y: f32) window_ui.UiButton {
    return .{ .label = label, .rect = window_ui.centeredRect(center_x, top_y, 220.0, 44.0) };
}

fn hoveredPlayGameEntry(entries: []const PlayGameEntry, layout: PlayGameLayout) ?usize {
    const mouse = rl.getMousePosition();
    var y = layout.content_y + layout.y_start;
    for (entries, 0..) |entry, idx| {
        const button = playGameButton(entry.label, layout.content_x, y);
        if (rl.checkCollisionPointRec(mouse, button.rect)) return idx;
        y += layout.y_step;
    }
    return null;
}

fn playGameActivated(entries: []const PlayGameEntry, layout: PlayGameLayout, selection: usize) bool {
    if (rl.isKeyPressed(.enter) or rl.isKeyPressed(.space)) return true;
    if (!rl.isMouseButtonPressed(.left)) return false;
    if (selection == entries.len) return rl.checkCollisionPointRec(rl.getMousePosition(), backOnlyButton()[0].rect);

    var y = layout.content_y + layout.y_start;
    for (entries, 0..) |entry, idx| {
        _ = entry;
        const button = playGameButton(entries[idx].label, layout.content_x, y);
        if (idx == selection and rl.checkCollisionPointRec(rl.getMousePosition(), button.rect)) return true;
        y += layout.y_step;
    }
    return false;
}

fn tooltipEntry(entries: []const PlayGameEntry, selection: usize, layout: PlayGameLayout) ?PlayGameEntry {
    if (hoveredPlayGameEntry(entries, layout)) |hovered| return entries[hovered];
    if (selection < entries.len) return entries[selection];
    return null;
}

fn drawTooltip(runtime_assets: *const window_assets.RuntimeAssets, text: []const u8, x: f32, y: f32) void {
    window_ui.drawSmallText(runtime_assets, text, x - 40.0, y, rl.Color.init(185, 185, 196, 255));
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

const play_game_entries_multi = [_]PlayGameEntry{
    .{ .key = .quests, .label = "QUESTS", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "RUSH", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "SURVIVAL", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
};

const play_game_entries_single_tutorial_first = [_]PlayGameEntry{
    .{ .key = .tutorial, .label = "TUTORIAL", .tooltip = "Learn how to play Crimsonland.", .action = .start_tutorial, .game_mode = .tutorial },
    .{ .key = .quests, .label = "QUESTS", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "RUSH", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "SURVIVAL", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
};

const play_game_entries_single = [_]PlayGameEntry{
    .{ .key = .quests, .label = "QUESTS", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "RUSH", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "SURVIVAL", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
    .{ .key = .tutorial, .label = "TUTORIAL", .tooltip = "Learn how to play Crimsonland.", .action = .start_tutorial, .game_mode = .tutorial },
};

const play_game_entries_single_typo_tutorial_first = [_]PlayGameEntry{
    .{ .key = .tutorial, .label = "TUTORIAL", .tooltip = "Learn how to play Crimsonland.", .action = .start_tutorial, .game_mode = .tutorial },
    .{ .key = .quests, .label = "QUESTS", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "RUSH", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "SURVIVAL", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
    .{ .key = .typo, .label = "TYP'O'SHOOTER", .tooltip = "Use your typing skills as the weapon to lay\nthem down.", .action = .start_typo, .game_mode = .typo, .show_count = true },
};

const play_game_entries_single_typo = [_]PlayGameEntry{
    .{ .key = .quests, .label = "QUESTS", .tooltip = "Unlock new weapons and perks in Quest mode.", .action = .open_quests, .show_count = true },
    .{ .key = .rush, .label = "RUSH", .tooltip = "Face a rush of aliens in Rush mode.", .action = .start_rush, .game_mode = .rush, .show_count = true },
    .{ .key = .survival, .label = "SURVIVAL", .tooltip = "Gain perks and weapons and fight back.", .action = .start_survival, .game_mode = .survival, .show_count = true },
    .{ .key = .typo, .label = "TYP'O'SHOOTER", .tooltip = "Use your typing skills as the weapon to lay\nthem down.", .action = .start_typo, .game_mode = .typo, .show_count = true },
    .{ .key = .tutorial, .label = "TUTORIAL", .tooltip = "Learn how to play Crimsonland.", .action = .start_tutorial, .game_mode = .tutorial },
};

fn drawPlayerCountWidget(state: *const PlayGameState, runtime_assets: *const window_assets.RuntimeAssets, player_count_raw: u32) void {
    const rect = playerCountHeaderRect();
    const selected_index = @as(usize, @intCast(std.math.clamp(player_count_raw, @as(u32, 1), @as(u32, 4)))) - 1;
    const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), rect);
    const texture = if (state.player_list_open or hovered) runtime_assets.texture(.ui_drop_on) else runtime_assets.texture(.ui_drop_off);

    rl.drawRectangleRec(rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(rect.x + 1.0), @intFromFloat(rect.y + 1.0), @intFromFloat(rect.width - 2.0), @intFromFloat(rect.height - 2.0), rl.Color.black);
    window_ui.drawSmallText(runtime_assets, player_count_labels[selected_index], rect.x + 4.0, rect.y + 1.0, if (hovered or state.player_list_open) text_color else muted_text);
    rl.drawTexturePro(
        texture,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)),
        rl.Rectangle.init(rect.x + rect.width - 17.0, rect.y, 16.0, 16.0),
        rl.Vector2.zero(),
        0.0,
        rl.Color.white,
    );

    if (!state.player_list_open) return;

    const list_rect = playerCountListRect();
    rl.drawRectangleRec(list_rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(list_rect.x + 1.0), @intFromFloat(list_rect.y + 1.0), @intFromFloat(list_rect.width - 2.0), @intFromFloat(list_rect.height - 2.0), rl.Color.black);
    for (player_count_labels, 0..) |label, idx| {
        const row_rect = playerCountRowRect(idx);
        const row_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), row_rect);
        window_ui.drawSmallText(runtime_assets, label, row_rect.x + 4.0, row_rect.y + 1.0, if (row_hovered or idx == state.player_count_selection) text_color else muted_text);
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
    row_selection: usize = 0,

    pub fn reset(self: *QuestState) void {
        self.* = .{};
    }
};

pub const QuestResult = struct {
    start_level_key: ?i32 = null,
    back_to_play_game: bool = false,
    play_panel_click: bool = false,
    play_button_click: bool = false,
    config_dirty: bool = false,
};

pub fn updateQuests(state: *QuestState, frame_dt: f32, config: *formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status) QuestResult {
    const dt_ms = panelAdvance(&state.panel, frame_dt);
    if (rl.isKeyPressed(.escape)) return .{ .back_to_play_game = true, .play_button_click = true };

    if (rl.isKeyPressed(.left)) state.stage = @max(1, state.stage - 1);
    if (rl.isKeyPressed(.right)) state.stage = @min(5, state.stage + 1);
    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        state.row_selection = if (state.row_selection == 0) 9 else state.row_selection - 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.row_selection = (state.row_selection + 1) % 10;
    }

    const hovered_stage = hoveredQuestStage();
    if (hovered_stage) |stage| {
        state.stage = stage;
        if (rl.isMouseButtonPressed(.left)) return .{ .play_button_click = true };
    }

    const hovered_row = hoveredQuestRow(hardcoreUnlocked(status));
    if (hovered_row) |row| {
        state.row_selection = row;
    }

    if (hardcoreUnlocked(status)) {
        const hardcore_rect = hardcoreCheckRect();
        if (rl.checkCollisionPointRec(rl.getMousePosition(), hardcore_rect) and rl.isMouseButtonPressed(.left)) {
            config.hardcore_flag = if (config.hardcore_flag == 0) 1 else 0;
            return .{ .play_button_click = true, .config_dirty = true };
        }
    }

    if (rl.isKeyPressed(.enter) or rl.isKeyPressed(.space) or (hovered_row != null and rl.isMouseButtonPressed(.left))) {
        if (questUnlocked(status, config.hardcore_flag != 0, state.stage, @intCast(state.row_selection + 1))) {
            const level_key = state.stage * 100 + @as(i32, @intCast(state.row_selection + 1));
            config.game_mode = @intFromEnum(game_ids.GameModeId.quests);
            return .{ .start_level_key = level_key, .play_button_click = true, .config_dirty = true };
        }
    }

    if (backButtonActivated()) {
        return .{ .back_to_play_game = true, .play_button_click = true };
    }

    return .{
        .play_panel_click = dt_ms > 0 and state.panel.timeline_ms >= panel_timeline_max_ms and !state.panel.panel_open_sfx_played,
    };
}

pub fn drawQuests(state: *const QuestState, runtime_assets: ?*const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status) void {
    if (runtime_assets) |assets| {
        drawMenuPanelShell(state.panel.timeline_ms, assets, .{ .x = 320.0, .y = 132.0, .width = 620.0, .height = 430.0 }, window_assets.TextureId.ui_text_quest);
        drawQuestContent(state, assets, config, status);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawQuestContent(state: *const QuestState, runtime_assets: *const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg, status: formats.game_cfg.Status) void {
    const base_x: f32 = 390.0;
    const base_y: f32 = 182.0;
    drawTextureLabel(runtime_assets, .ui_text_quest, 480.0, 166.0, 128.0, 32.0, rl.Color.init(179, 179, 179, 179));

    const stage_textures = [_]window_assets.TextureId{ .ui_num1, .ui_num2, .ui_num3, .ui_num4, .ui_num5 };
    for (stage_textures, 0..) |texture_id, idx| {
        const stage = @as(i32, @intCast(idx + 1));
        const rect = questStageRect(stage);
        const tint = if (stage == state.stage) rl.Color.white else if (hoveredQuestStage() != null and hoveredQuestStage().? == stage) rl.Color.init(255, 255, 255, 204) else rl.Color.init(179, 179, 179, 179);
        window_ui.drawTextureFit(runtime_assets.texture(texture_id), rect, tint);
    }

    if (hardcoreUnlocked(status)) {
        const check_tex = if (config.hardcore_flag != 0) runtime_assets.texture(.ui_check_on) else runtime_assets.texture(.ui_check_off);
        const rect = hardcoreCheckRect();
        window_ui.drawTextureFit(check_tex, rl.Rectangle.init(rect.x, rect.y, @floatFromInt(check_tex.width), @floatFromInt(check_tex.height)), rl.Color.white);
        window_ui.drawSmallText(runtime_assets, "Hardcore", rect.x + @as(f32, @floatFromInt(check_tex.width)) + 6.0, rect.y + 1.0, muted_text);
    }

    var y = base_y + (if (hardcoreUnlocked(status)) @as(f32, 26.0) else @as(f32, 0.0));
    const hovered_row = hoveredQuestRow(hardcoreUnlocked(status));
    for (0..10) |row| {
        const level_minor = @as(i32, @intCast(row + 1));
        const unlocked = questUnlocked(status, config.hardcore_flag != 0, state.stage, level_minor);
        const hovered = hovered_row != null and hovered_row.? == row;
        const color = if (hovered or row == state.row_selection) rl.Color.init(70, 180, 240, 255) else rl.Color.init(70, 180, 240, 153);
        window_ui.drawSmallTextFmt("{d}.{d}", runtime_assets, .{ state.stage, level_minor }, base_x, y, color);
        const title = if (unlocked) questTitle(state.stage, level_minor) else "???";
        window_ui.drawSmallText(runtime_assets, title, base_x + 52.0, y, color);
        y += 18.0;
    }

    const back = backOnlyButton()[0];
    const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
    window_ui.drawButton(back, false, hovered, runtime_assets);
}

fn questUnlocked(status: formats.game_cfg.Status, hardcore: bool, stage: i32, minor: i32) bool {
    const global_index = (stage - 1) * 10 + (minor - 1);
    const unlock = if (hardcore) status.quest_unlock_index_full else status.quest_unlock_index;
    return @as(i32, unlock) >= global_index;
}

fn hardcoreUnlocked(status: formats.game_cfg.Status) bool {
    return status.quest_unlock_index >= 49;
}

fn questTitle(stage: i32, minor: i32) []const u8 {
    const index = (stage - 1) * 10 + (minor - 1);
    return quest_titles[@intCast(std.math.clamp(index, @as(i32, 0), @as(i32, @intCast(quest_titles.len - 1))))];
}

fn questStageRect(stage: i32) rl.Rectangle {
    return rl.Rectangle.init(554.0 + @as(f32, @floatFromInt(stage - 1)) * 40.0, 170.0, 32.0, 32.0);
}

fn hoveredQuestStage() ?i32 {
    const mouse = rl.getMousePosition();
    for (1..6) |stage| {
        if (rl.checkCollisionPointRec(mouse, questStageRect(@intCast(stage)))) return @intCast(stage);
    }
    return null;
}

fn hoveredQuestRow(show_hardcore_toggle: bool) ?usize {
    const mouse = rl.getMousePosition();
    var y: f32 = 182.0 + if (show_hardcore_toggle) @as(f32, 26.0) else @as(f32, 0.0);
    for (0..10) |row| {
        const rect = rl.Rectangle.init(382.0, y - 3.0, 340.0, 16.0);
        if (rl.checkCollisionPointRec(mouse, rect)) return row;
        y += 18.0;
    }
    return null;
}

fn hardcoreCheckRect() rl.Rectangle {
    return rl.Rectangle.init(390.0, 182.0, 90.0, 16.0);
}

pub const StatisticsState = struct {
    panel: PanelState = .{},

    pub fn reset(self: *StatisticsState) void {
        self.* = .{};
    }
};

pub const StatisticsResult = struct {
    action: ?StatisticsAction = null,
    play_panel_click: bool = false,
    play_button_click: bool = false,
};

pub fn updateStatistics(state: *StatisticsState, frame_dt: f32) StatisticsResult {
    const dt_ms = panelAdvance(&state.panel, frame_dt);
    const buttons = statisticsButtons();
    window_ui.updateSelectionFromPointer(&state.panel.selection, buttons[0..]);
    if (rl.isKeyPressed(.escape)) return .{ .action = .back_to_menu, .play_button_click = true };
    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        state.panel.selection = if (state.panel.selection == 0) buttons.len - 1 else state.panel.selection - 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.panel.selection = (state.panel.selection + 1) % buttons.len;
    }
    if (!window_ui.buttonActivated(buttons[0..], state.panel.selection)) {
        return .{
            .play_panel_click = dt_ms > 0 and state.panel.timeline_ms >= panel_timeline_max_ms and !state.panel.panel_open_sfx_played,
        };
    }
    return .{
        .play_button_click = true,
        .action = switch (state.panel.selection) {
            0 => .open_high_scores,
            1 => .open_weapons,
            2 => .open_perks,
            3 => .open_credits,
            4 => .back_to_menu,
            else => null,
        },
    };
}

pub fn drawStatistics(state: *const StatisticsState, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    if (runtime_assets) |assets| {
        drawMenuPanelShell(state.panel.timeline_ms, assets, .{ .x = 390.0, .y = 168.0, .width = 500.0, .height = 360.0 }, window_menu.label_row_statistics);
        const buttons = statisticsButtons();
        for (buttons, 0..) |button, idx| {
            const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
            window_ui.drawButton(button, idx == state.panel.selection, hovered, assets);
        }
        return;
    }
    rl.clearBackground(panel_color);
}

pub const InfoViewState = struct {
    kind: InfoKind = .weapons,
    scroll: usize = 0,

    pub fn open(self: *InfoViewState, kind: InfoKind) void {
        self.* = .{ .kind = kind };
    }
};

pub const InfoResult = struct {
    back_to_statistics: bool = false,
};

pub fn updateInfoView(state: *InfoViewState) InfoResult {
    const max_scroll = infoMaxScroll(state.kind);
    if (rl.isKeyPressed(.escape) or backButtonActivated()) {
        return .{ .back_to_statistics = true };
    }
    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        if (state.scroll > 0) state.scroll -= 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.scroll = @min(state.scroll + 1, max_scroll);
    }
    return .{};
}

pub fn drawInfoView(state: *const InfoViewState, runtime_assets: ?*const window_assets.RuntimeAssets, status: formats.game_cfg.Status) void {
    if (runtime_assets) |assets| {
        drawMenuPanelShell(300, assets, .{ .x = 250.0, .y = 118.0, .width = 780.0, .height = 500.0 }, infoLabelRow(state.kind));
        drawInfoContents(state, assets, status);
        return;
    }
    rl.clearBackground(panel_color);
}

fn drawInfoContents(state: *const InfoViewState, runtime_assets: *const window_assets.RuntimeAssets, status: formats.game_cfg.Status) void {
    const lines = infoLines(state.kind, status);
    const start = state.scroll;
    const end = @min(start + 20, lines.len);
    var y: f32 = 178.0;
    for (lines[start..end]) |line| {
        window_ui.drawSmallText(runtime_assets, line, 300.0, y, text_color);
        y += 16.0;
    }
    const back = backOnlyButton()[0];
    const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
    window_ui.drawButton(back, false, hovered, runtime_assets);
}

fn infoLines(kind: InfoKind, status: formats.game_cfg.Status) []const []const u8 {
    _ = status;
    return switch (kind) {
        .credits => credits_lines[0..],
        .weapons => weapon_lines[0..],
        .perks => perk_lines[0..],
    };
}

fn infoMaxScroll(kind: InfoKind) usize {
    const total = switch (kind) {
        .credits => credits_lines.len,
        .weapons => weapon_lines.len,
        .perks => perk_lines.len,
    };
    return if (total > 20) total - 20 else 0;
}

fn infoLabelRow(kind: InfoKind) i32 {
    return switch (kind) {
        .credits => window_menu.label_row_statistics,
        .weapons => window_menu.label_row_statistics,
        .perks => window_menu.label_row_statistics,
    };
}

fn panelAdvance(panel: *PanelState, frame_dt: f32) i32 {
    const dt_ms = @as(i32, @intFromFloat(@min(frame_dt, 0.1) * 1000.0));
    if (dt_ms > 0) {
        panel.timeline_ms = @min(panel_timeline_max_ms, panel.timeline_ms + dt_ms);
    }
    return dt_ms;
}

const panel_timeline_max_ms: i32 = 300;

fn drawMenuPanelShell(timeline_ms: i32, runtime_assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle, title_row_or_texture: anytype) void {
    window_menu.drawMenuBackdrop(runtime_assets);
    window_menu.drawSign(timeline_ms, runtime_assets);

    const anim = window_menu.uiElementAnim(1, panel_timeline_max_ms, 0, rect.width, timeline_ms);
    const panel_rect = rl.Rectangle.init(rect.x + anim.offset_x, rect.y, rect.width, rect.height);
    window_ui.drawTextureFit(runtime_assets.texture(.ui_menu_panel), panel_rect, window_ui.colorWithAlpha(rl.Color.white, 0.96));

    const T = @TypeOf(title_row_or_texture);
    if (T == i32) {
        window_menu.drawAtlasLabelCentered(runtime_assets, title_row_or_texture, rect.y + 42.0, window_ui.colorWithAlpha(rl.Color.white, 0.96));
    } else {
        drawTextureLabel(runtime_assets, title_row_or_texture, rect.x + rect.width * 0.5 - 64.0, rect.y + 34.0, 128.0, 32.0, window_ui.colorWithAlpha(rl.Color.white, 0.96));
    }
}

fn drawTextureLabel(runtime_assets: *const window_assets.RuntimeAssets, texture_id: window_assets.TextureId, x: f32, y: f32, w: f32, h: f32, tint: rl.Color) void {
    window_ui.drawTextureFit(runtime_assets.texture(texture_id), rl.Rectangle.init(x, y, w, h), tint);
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

fn playerCountHeaderRect() rl.Rectangle {
    return rl.Rectangle.init(492.0, 258.0, 124.0, 16.0);
}

fn playerCountListRect() rl.Rectangle {
    return rl.Rectangle.init(492.0, 258.0, 124.0, 80.0);
}

fn playerCountRowRect(idx: usize) rl.Rectangle {
    return rl.Rectangle.init(492.0, 275.0 + @as(f32, @floatFromInt(idx)) * 16.0, 124.0, 16.0);
}

fn statisticsButtons() [5]window_ui.UiButton {
    const center_x = @as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5;
    return .{
        .{ .label = "HIGH SCORES", .rect = window_ui.centeredRect(center_x, 250.0, 240.0, 44.0) },
        .{ .label = "WEAPONS", .rect = window_ui.centeredRect(center_x, 304.0, 240.0, 44.0) },
        .{ .label = "PERKS", .rect = window_ui.centeredRect(center_x, 358.0, 240.0, 44.0) },
        .{ .label = "CREDITS", .rect = window_ui.centeredRect(center_x, 412.0, 240.0, 44.0) },
        .{ .label = "BACK", .rect = window_ui.centeredRect(center_x, 478.0, 180.0, 44.0) },
    };
}

fn backOnlyButton() [1]window_ui.UiButton {
    return .{
        .{ .label = "BACK", .rect = window_ui.centeredRect(@as(f32, @floatFromInt(rl.getScreenWidth())) * 0.5, 562.0, 180.0, 44.0) },
    };
}

fn setConfigGameMode(config: *formats.crimson_cfg.CrimsonCfg, mode: game_ids.GameModeId) bool {
    const mode_value: u32 = @intCast(@intFromEnum(mode));
    if (config.game_mode == mode_value) return false;
    config.game_mode = mode_value;
    return true;
}

fn backButtonActivated() bool {
    const back = backOnlyButton()[0];
    return rl.isMouseButtonPressed(.left) and rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
}

const weapon_lines = buildWeaponLines();
const perk_lines = buildPerkLines();

fn buildWeaponLines() [53][]const u8 {
    var lines: [53][]const u8 = undefined;
    var idx: usize = 0;
    inline for (std.meta.fields(game_ids.WeaponId)) |field| {
        const weapon_id: game_ids.WeaponId = @enumFromInt(field.value);
        if (weapon_id == .none) continue;
        lines[idx] = game_ids.weaponDisplayName(weapon_id, false);
        idx += 1;
    }
    return lines;
}

fn buildPerkLines() [58][]const u8 {
    var lines: [58][]const u8 = undefined;
    inline for (std.meta.fields(game_ids.PerkId), 0..) |field, idx| {
        const perk_id: game_ids.PerkId = @enumFromInt(field.value);
        lines[idx] = game_ids.perkDisplayName(perk_id, 0, false);
    }
    return lines;
}
