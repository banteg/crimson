const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const game_ids = cz.game_ids;
const persistence = cz.persistence;
const ui_formatting = cz.ui_formatting;
const weapon_data = cz.weapon_data;
const window_atlas = cz.window_atlas;
const window_assets = @import("window_assets.zig");
const window_ui = @import("window_ui.zig");

const HighScoreRecord = persistence.highscores.HighScoreRecord;

/// The native `game_state_id` values the card branches on.
pub const GameState = enum(i32) {
    game_over = 0x07,
    quest_results = 0x08,
    quest_failed = 0x0C,
    highscores = 0x0E,

    fn results(self: GameState) bool {
        return switch (self) {
            .game_over, .quest_results, .quest_failed => true,
            .highscores => false,
        };
    }
};

/// Native `ui_stats_hover_weapon` / `ui_stats_hover_time` / `ui_stats_hover_hit_ratio` globals.
const StatsHover = struct {
    weapon: f32 = 0.0,
    time: f32 = 0.0,
    hit_ratio: f32 = 0.0,
};

var hover: StatsHover = .{};

// `render_tint_color` as initialized by `render_tint_color_global_init`.
const render_tint_r: f32 = 0.58431375;
const render_tint_g: f32 = 0.686274529;
const render_tint_b: f32 = 0.776470602;

/// `grim_set_color`: clamp alpha, then truncate each channel to a byte.
fn grimColor(r: f32, g: f32, b: f32, a: f32) rl.Color {
    return rl.Color.init(
        @intFromFloat(r * 255.0),
        @intFromFloat(g * 255.0),
        @intFromFloat(b * 255.0),
        @intFromFloat(std.math.clamp(a, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
    );
}

// Native divides the int text width by 2 with C integer division.
fn halfWidth(assets: *const window_assets.RuntimeAssets, text: []const u8) f32 {
    const width: i32 = @intFromFloat(window_ui.measureSmallText(assets, text));
    return @floatFromInt(@divTrunc(width, 2));
}

fn divider(x: f32, y: f32, width: f32, height: f32, color: rl.Color) void {
    // `grim_draw_rect_outline` with a 1px side is one filled quad.
    rl.drawRectangleRec(rl.Rectangle.init(x - 16.0, y, width, height), color);
}

fn inside(mouse: rl.Vector2, x0: f32, y0: f32, x1: f32, y1: f32) bool {
    return x0 < mouse.x and mouse.x < x1 and y0 < mouse.y and mouse.y < y1;
}

fn hoverStep(value: *f32, hovered: bool, step: f32) void {
    value.* += if (hovered) step else -step;
}

pub fn uiDrawClockGauge(assets: *const window_assets.RuntimeAssets, x: f32, y: f32, time_ms: i32, alpha: f32) void {
    const tint = grimColor(1.0, 1.0, 1.0, alpha);
    window_ui.drawTextureFit(assets.texture(.ui_clock_table), rl.Rectangle.init(x, y, 32.0, 32.0), tint);
    // The pointer quad rotates about its center by whole seconds * 6 degrees.
    const pointer = assets.texture(.ui_clock_pointer);
    rl.drawTexturePro(
        pointer,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(pointer.width), @floatFromInt(pointer.height)),
        rl.Rectangle.init(x + 16.0, y + 16.0, 32.0, 32.0),
        rl.Vector2.init(16.0, 16.0),
        @as(f32, @floatFromInt(@divTrunc(time_ms, 1000))) * 6.0,
        tint,
    );
}

pub fn hitPercent(record: *const HighScoreRecord) u64 {
    // Native divides by zero shots into INT_MIN; the port shows 0%.
    const shots_fired = record.shotsFired();
    if (shots_fired == 0) return 0;
    return @divTrunc(@as(u64, record.shotsHit()) * 100, @as(u64, shots_fired));
}

/// The weapon row is hidden while results show the name entry (phase 0) and once quest results show their buttons (phase 2).
fn weaponRowHidden(game_state: GameState, ui_phase: i32) bool {
    return (ui_phase == 2 and game_state == .quest_results) or (game_state.results() and ui_phase == 0);
}

/// `ui_text_input_render`: the high-score card shared by game over, quest results/failed and the high-score screen.
pub fn uiTextInputRender(
    assets: *const window_assets.RuntimeAssets,
    xy: rl.Vector2,
    record: *const HighScoreRecord,
    alpha: f32,
    rank: i32,
    game_state: GameState,
    ui_phase: i32,
    mouse: rl.Vector2,
    dt: f32,
    preserve_bugs: bool,
) void {
    const divider_color = grimColor(render_tint_r, render_tint_g, render_tint_b, alpha * 0.7);
    const label_color = grimColor(0.9, 0.9, 0.9, alpha * 0.8);
    const tooltip_color = grimColor(0.9, 0.9, 0.9, alpha * 0.7);
    const hover_step = dt + dt;
    const results = game_state.results();
    var x = xy.x + 4.0;
    var y = xy.y;

    if (!results) {
        const name = record.name();
        window_ui.drawSmallText(assets, name, x, y, grimColor(1.0, 1.0, 1.0, alpha));
        rl.drawRectangleRec(rl.Rectangle.init(x, y + 13.0, @trunc(window_ui.measureSmallText(assets, name)), 1.0), divider_color);
        if (record.flags() & 2 != 0) {
            window_ui.drawSmallText(assets, "Internet score of local origin", x, y + 14.0, grimColor(0.8, 0.8, 0.8, alpha * 0.8));
            window_ui.drawSmallTextFmt("uni#{d}", assets, .{record.uniNum()}, x + 94.0, y - 12.0, grimColor(0.5, 0.5, 0.5, alpha * 0.5));
        } else if (record.flags() & 1 != 0) {
            window_ui.drawSmallText(assets, "Score from the Internet", x, y + 14.0, grimColor(0.7, 1.0, 0.7, alpha * 0.8));
        } else {
            window_ui.drawSmallText(assets, "Local score", x, y + 14.0, grimColor(0.8, 0.8, 0.8, alpha * 0.8));
        }

        y += 15.0;
        var date_buf: [32]u8 = undefined;
        const date = ui_formatting.formatHighscoreDateLabel(&date_buf, record.day(), record.month(), @as(i32, record.yearOffset()) + 2000);
        window_ui.drawSmallText(assets, date, x + 192.0 - 32.0 - 8.0 - halfWidth(assets, date), y + 13.0, label_color);
        x = xy.x + 16.0;
        y += 13.0;
        divider(x, y, 192.0, 1.0, divider_color);
        y += 4.0 + 14.0;
    }

    window_ui.drawSmallText(assets, "Score", x + 32.0 - halfWidth(assets, "Score"), y, label_color);
    var score_buf: [32]u8 = undefined;
    const score_text = switch (record.gameModeId() orelse .survival) {
        .rush, .quests => std.fmt.bufPrint(&score_buf, "{d:.2} secs", .{@as(f64, @floatFromInt(record.survivalElapsedMs())) * 0.001}) catch "",
        .survival, .typo, .tutorial => std.fmt.bufPrint(&score_buf, "{d}", .{record.scoreXp()}) catch "",
    };
    window_ui.drawSmallText(assets, score_text, x + 32.0 - halfWidth(assets, score_text), y + 15.0, grimColor(0.9, 0.9, 1.0, alpha));
    if (game_state != .quest_failed) {
        var ordinal_buf: [16]u8 = undefined;
        var rank_buf: [32]u8 = undefined;
        const rank_text = std.fmt.bufPrint(&rank_buf, "Rank: {s}", .{ui_formatting.formatOrdinal(&ordinal_buf, rank)}) catch "";
        window_ui.drawSmallText(assets, rank_text, x + 32.0 - halfWidth(assets, rank_text), y + 30.0, label_color);
    }

    x += 96.0;
    // The vertical divider leaves its color current for the next label.
    divider(x, y, 1.0, 48.0, divider_color);
    if (record.gameModeId() == .quests) {
        window_ui.drawSmallText(assets, "Experience", x, y, divider_color);
        var xp_buf: [16]u8 = undefined;
        const xp_text = std.fmt.bufPrint(&xp_buf, "{d}", .{record.scoreXp()}) catch "";
        window_ui.drawSmallText(assets, xp_text, x + 32.0 - halfWidth(assets, xp_text), y + 15.0, label_color);
        hover.time -= hover_step;
    } else {
        window_ui.drawSmallText(assets, "Game time", x + 6.0, y, divider_color);
        uiDrawClockGauge(assets, @trunc(x + 8.0), @trunc(y + 13.0), record.survivalElapsedMs(), alpha);
        hoverStep(&hover.time, inside(mouse, x + 8.0, y + 16.0, x + 72.0, y + 45.0), hover_step);
        var time_buf: [16]u8 = undefined;
        window_ui.drawSmallText(assets, ui_formatting.formatTimeMmSs(&time_buf, record.survivalElapsedMs()), x + 40.0, y + 19.0, label_color);
    }

    x -= 96.0;
    y += 52.0;
    if (!weaponRowHidden(game_state, ui_phase)) {
        divider(x, y, 192.0, 1.0, divider_color);
        y += 4.0;
        const weapon_id = record.mostUsedWeaponId();
        const wicons = assets.texture(.ui_wicons);
        const icon = window_atlas.weaponIconRect(wicons.width, wicons.height, weapon_data.weaponIconIndex(weapon_id));
        rl.drawTexturePro(
            wicons,
            rl.Rectangle.init(icon.x, icon.y, icon.width, icon.height),
            rl.Rectangle.init(@trunc(x), @trunc(y), 64.0, 32.0),
            rl.Vector2.zero(),
            0.0,
            grimColor(1.0, 1.0, 1.0, alpha),
        );
        hoverStep(&hover.weapon, inside(mouse, x, y, x + 64.0, y + 32.0), hover_step);

        const weapon_name = game_ids.weaponDisplayName(weapon_id, preserve_bugs);
        const name_x = @max(0.0, 32.0 - halfWidth(assets, weapon_name));
        window_ui.drawSmallText(assets, weapon_name, x + name_x, y + 32.0, tooltip_color);
        window_ui.drawSmallTextFmt("Frags: {d}", assets, .{record.creatureKillCount()}, x + 110.0, y + 1.0, tooltip_color);
        window_ui.drawSmallTextFmt("Hit %: {d}%", assets, .{hitPercent(record)}, x + 110.0, y + 15.0, tooltip_color);
        hoverStep(&hover.hit_ratio, inside(mouse, x + 110.0, y + 15.0, x + 174.0, y + 32.0), hover_step);
        y += 48.0;
    } else {
        hover.hit_ratio = 0.0;
    }

    divider(x, y, 192.0, 1.0, divider_color);
    y += 4.0;
    hover.weapon = std.math.clamp(hover.weapon, 0.0, 1.0);
    hover.time = std.math.clamp(hover.time, 0.0, 1.0);
    hover.hit_ratio = std.math.clamp(hover.hit_ratio, 0.0, 1.0);

    if (results) {
        const tooltips = [_]struct { value: f32, dx: f32, text: []const u8 }{
            .{ .value = hover.weapon, .dx = -20.0, .text = "Most used weapon during the game" },
            .{ .value = hover.time, .dx = 12.0, .text = "The time the game lasted" },
            .{ .value = hover.hit_ratio, .dx = -22.0, .text = "The % of shot bullets hit the target" },
        };
        for (tooltips) |tooltip| {
            if (tooltip.value > 0.5) {
                window_ui.drawSmallText(assets, tooltip.text, x + tooltip.dx, y, grimColor(0.9, 0.9, 0.9, (tooltip.value - 0.5) * alpha * 2.0));
            }
        }
    }
}

test "results hide the weapon row during name entry and quest results once their buttons show" {
    try std.testing.expect(weaponRowHidden(.game_over, 0));
    try std.testing.expect(!weaponRowHidden(.game_over, 1));
    try std.testing.expect(!weaponRowHidden(.quest_results, 1));
    try std.testing.expect(weaponRowHidden(.quest_results, 2));
    try std.testing.expect(weaponRowHidden(.quest_failed, 0));
    try std.testing.expect(!weaponRowHidden(.highscores, 0));
}

test "hit percent truncates with wide math and shows 0 without shots" {
    var record = HighScoreRecord.blank();
    try std.testing.expectEqual(@as(u64, 0), hitPercent(&record));
    record.setShotsFired(3);
    record.setShotsHit(2);
    try std.testing.expectEqual(@as(u64, 66), hitPercent(&record));
    record.setShotsFired(1);
    record.setShotsHit(std.math.maxInt(u32));
    try std.testing.expectEqual(@as(u64, 429496729500), hitPercent(&record));
}
