const std = @import("std");
const rl = @import("raylib");

const window_assets = @import("window_assets.zig");
const window_menu = @import("window_menu.zig");
const window_ui = @import("window_ui.zig");

const menu_label_width: f32 = 122.0;
const menu_label_height: f32 = 28.0;
const menu_label_row_height: f32 = 32.0;
const menu_label_offset_x: f32 = 271.0;
const menu_label_offset_y: f32 = -37.0;
const menu_label_base_x: f32 = -60.0;
const menu_label_base_y: f32 = 210.0;
const menu_label_step: f32 = 60.0;
const menu_item_offset_x: f32 = -71.0;
const menu_item_offset_y: f32 = -59.0;

pub const Action = enum {
    open_options,
    back_to_menu,
    back_to_previous,
};

pub const State = struct {
    selection: usize = 0,
    timeline_ms: i32 = 0,
    focus_timer_ms: i32 = 0,
    hovered_index: ?usize = null,
    panel_open_sfx_played: bool = false,
    closing: bool = false,
    close_action: ?Action = null,
    hover_amounts: [3]i32 = [_]i32{0} ** 3,

    pub fn reset(self: *State) void {
        self.* = .{};
    }
};

pub const UpdateResult = struct {
    action: ?Action = null,
    play_panel_click: bool = false,
    play_button_click: bool = false,
};

const Entry = struct {
    slot: usize,
    row: i32,
};

const entries = [_]Entry{
    .{ .slot = 0, .row = window_menu.label_row_options },
    .{ .slot = 1, .row = window_menu.label_row_quit },
    .{ .slot = 2, .row = window_menu.label_row_back },
};

const TimelineUpdate = struct {
    action: ?Action = null,
    play_panel_click: bool = false,
};

pub fn update(state: *State, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets) UpdateResult {
    const dt_ms = @as(i32, @intFromFloat(@min(frame_dt, 0.1) * 1000.0));

    const timeline_update = advanceTimeline(state, dt_ms);
    if (timeline_update.action) |action| {
        updateHoverAmounts(state, dt_ms);
        return .{ .action = action };
    }
    if (state.closing) {
        updateHoverAmounts(state, dt_ms);
        return .{};
    }

    if (runtime_assets == null) {
        updateHoverAmounts(state, dt_ms);
        return .{};
    }

    state.hovered_index = hoveredIndex(runtime_assets);
    if (state.hovered_index) |hovered_index| {
        if (entryEnabled(hovered_index, state.timeline_ms)) {
            state.selection = hovered_index;
            state.focus_timer_ms = 1000;
        }
    }

    if (!activateSelection(state)) {
        if (rl.isKeyPressed(.tab) or rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            state.selection = previousEnabledSelection(state.selection, state.timeline_ms);
            state.focus_timer_ms = 1000;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            state.selection = nextEnabledSelection(state.selection, state.timeline_ms);
            state.focus_timer_ms = 1000;
        }
        if (rl.isKeyPressed(.escape)) {
            updateHoverAmounts(state, dt_ms);
            beginClose(state, .back_to_previous);
            return .{ .play_button_click = true };
        }
        updateHoverAmounts(state, dt_ms);
        return .{
            .play_panel_click = timeline_update.play_panel_click,
        };
    }

    const action: Action = switch (state.selection) {
        0 => .open_options,
        1 => .back_to_menu,
        2 => .back_to_previous,
        else => unreachable,
    };
    beginClose(state, action);
    updateHoverAmounts(state, dt_ms);
    return .{
        .play_button_click = true,
        .play_panel_click = timeline_update.play_panel_click,
    };
}

pub fn draw(state: *const State, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const assets = runtime_assets orelse return;
    rl.drawRectangle(0, 0, rl.getScreenWidth(), rl.getScreenHeight(), rl.Color.init(0, 0, 0, 140));
    window_menu.drawSign(state.timeline_ms, assets);
    for (entries, 0..) |entry, idx| {
        drawEntry(state, assets, entry, idx, idx == state.selection);
    }
}

fn drawEntry(state: *const State, assets: *const window_assets.RuntimeAssets, entry: Entry, idx: usize, selected: bool) void {
    const item = assets.texture(.ui_menu_item);
    const labels = assets.texture(.ui_item_texts);
    const scale_info = menuItemScale(entry.slot);
    const pos_x = menuSlotPosX(entry.slot);
    const pos_y = menu_label_base_y + @as(f32, @floatFromInt(entry.slot)) * menu_label_step + window_menu.menuWidescreenYShift(@floatFromInt(rl.getScreenWidth()));
    const anim = window_menu.uiElementAnim(entry.slot + 2, menuSlotStartMs(entry.slot), menuSlotEndMs(entry.slot), @as(f32, @floatFromInt(item.width)) * scale_info.scale, state.timeline_ms);
    const dst = rl.Rectangle.init(pos_x, pos_y, @as(f32, @floatFromInt(item.width)) * scale_info.scale, @as(f32, @floatFromInt(item.height)) * scale_info.scale);
    const origin = rl.Vector2.init(-(menu_item_offset_x * scale_info.scale), -(menu_item_offset_y * scale_info.scale - scale_info.local_y_shift));
    const rotation_deg = radiansToDegrees(anim.angle_rad);

    rl.drawTexturePro(
        item,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(item.width), @floatFromInt(item.height)),
        dst,
        origin,
        rotation_deg,
        rl.Color.white,
    );

    const hover_counter = if (selected and state.focus_timer_ms > 0) state.focus_timer_ms else state.hover_amounts[idx];
    const label_alpha = if (entryEnabled(idx, state.timeline_ms)) mainMenuLabelAlpha(hover_counter) else @as(u8, 100);
    const tint = rl.Color.init(255, 255, 255, label_alpha);
    const src = rl.Rectangle.init(0.0, @as(f32, @floatFromInt(entry.row)) * menu_label_row_height, menu_label_width, menu_label_row_height);
    const label_dst = rl.Rectangle.init(pos_x, pos_y, menu_label_width * scale_info.scale, menu_label_height * scale_info.scale);
    const label_origin = rl.Vector2.init(-(menu_label_offset_x * scale_info.scale), -(menu_label_offset_y * scale_info.scale - scale_info.local_y_shift));
    rl.drawTexturePro(labels, src, label_dst, label_origin, rotation_deg, tint);
    if (entryEnabled(idx, state.timeline_ms)) {
        rl.beginBlendMode(.additive);
        rl.drawTexturePro(labels, src, label_dst, label_origin, rotation_deg, tint);
        rl.endBlendMode();
    }
}

fn hoveredIndex(runtime_assets: ?*const window_assets.RuntimeAssets) ?usize {
    const mouse = rl.getMousePosition();
    const assets = runtime_assets orelse return null;
    const item = assets.texture(.ui_menu_item);
    for (entries, 0..) |entry, idx| {
        if (rl.checkCollisionPointRec(mouse, buttonRect(entry.slot, item))) return idx;
    }
    return null;
}

fn activateSelection(state: *State) bool {
    if (!entryEnabled(state.selection, state.timeline_ms)) return false;
    if (window_ui.confirmPressed()) return true;
    if (!rl.isMouseButtonPressed(.left)) return false;
    const hovered = state.hovered_index orelse return false;
    return hovered == state.selection;
}

fn beginClose(state: *State, action: Action) void {
    if (state.closing) return;
    state.closing = true;
    state.close_action = action;
}

fn advanceTimeline(state: *State, dt_ms: i32) TimelineUpdate {
    if (dt_ms <= 0) return .{};
    if (state.closing) {
        state.timeline_ms -= dt_ms;
        state.focus_timer_ms = @max(0, state.focus_timer_ms - dt_ms);
        if (state.timeline_ms < 0) {
            const action = state.close_action orelse return .{};
            state.closing = false;
            state.close_action = null;
            return .{ .action = action };
        }
        return .{};
    }
    const previous_timeline = state.timeline_ms;
    state.timeline_ms = @min(timelineMaxMs(), state.timeline_ms + dt_ms);
    state.focus_timer_ms = @max(0, state.focus_timer_ms - dt_ms);
    return .{
        .play_panel_click = previous_timeline < timelineMaxMs() and state.timeline_ms >= timelineMaxMs() and !state.panel_open_sfx_played,
    };
}

fn buttonRect(slot: usize, item_texture: rl.Texture2D) rl.Rectangle {
    const scale = menuItemScale(slot);
    const width = @as(f32, @floatFromInt(item_texture.width)) * scale.scale;
    const height = @as(f32, @floatFromInt(item_texture.height)) * scale.scale;
    const x = menuSlotPosX(slot) + menu_item_offset_x * scale.scale;
    const y = menu_label_base_y + @as(f32, @floatFromInt(slot)) * menu_label_step + window_menu.menuWidescreenYShift(@floatFromInt(rl.getScreenWidth())) + menu_item_offset_y * scale.scale - scale.local_y_shift;
    return rl.Rectangle.init(x, y, width, height);
}

fn entryEnabled(slot: usize, timeline_ms: i32) bool {
    return timeline_ms >= menuSlotStartMs(slot);
}

fn previousEnabledSelection(selection: usize, timeline_ms: i32) usize {
    var idx = selection;
    var attempts: usize = 0;
    while (attempts < entries.len) : (attempts += 1) {
        idx = if (idx == 0) entries.len - 1 else idx - 1;
        if (entryEnabled(idx, timeline_ms)) return idx;
    }
    return selection;
}

fn nextEnabledSelection(selection: usize, timeline_ms: i32) usize {
    var idx = selection;
    var attempts: usize = 0;
    while (attempts < entries.len) : (attempts += 1) {
        idx = (idx + 1) % entries.len;
        if (entryEnabled(idx, timeline_ms)) return idx;
    }
    return selection;
}

fn updateHoverAmounts(state: *State, dt_ms: i32) void {
    for (0..entries.len) |idx| {
        const hovered = state.hovered_index != null and state.hovered_index.? == idx;
        if (hovered) {
            state.hover_amounts[idx] = std.math.clamp(state.hover_amounts[idx] + dt_ms * 6, 0, 1000);
        } else {
            state.hover_amounts[idx] = std.math.clamp(state.hover_amounts[idx] - dt_ms * 2, 0, 1000);
        }
    }
}

fn timelineMaxMs() i32 {
    var max_ms: i32 = 300;
    for (entries) |entry| {
        max_ms = @max(max_ms, menuSlotStartMs(entry.slot));
    }
    return max_ms;
}

fn menuSlotPosX(slot: usize) f32 {
    return menu_label_base_x - @as(f32, @floatFromInt(slot)) * 20.0;
}

fn menuSlotStartMs(slot: usize) i32 {
    return @intCast((slot + 2) * 100 + 300);
}

fn menuSlotEndMs(slot: usize) i32 {
    return @intCast((slot + 2) * 100);
}

fn mainMenuLabelAlpha(counter_value: i32) u8 {
    return @intCast(100 + @divTrunc(counter_value * 155, 1000));
}

fn menuItemScale(slot: usize) struct { scale: f32, local_y_shift: f32 } {
    if (rl.getScreenWidth() < 641) {
        return .{ .scale = 0.9, .local_y_shift = @as(f32, @floatFromInt(slot)) * 11.0 };
    }
    return .{ .scale = 1.0, .local_y_shift = 0.0 };
}

fn radiansToDegrees(radians: f32) f32 {
    return radians * (180.0 / std.math.pi);
}

test "pause menu close timeline gates action dispatch" {
    var state: State = .{};
    state.timeline_ms = timelineMaxMs();
    beginClose(&state, .back_to_menu);

    try std.testing.expect(state.closing);
    try std.testing.expectEqual(@as(?Action, null), advanceTimeline(&state, 100).action);
    try std.testing.expectEqual(timelineMaxMs() - 100, state.timeline_ms);
    try std.testing.expectEqual(@as(?Action, null), advanceTimeline(&state, 499).action);
    try std.testing.expect(state.closing);

    const update_result = advanceTimeline(&state, 1);
    try std.testing.expectEqual(Action.back_to_menu, update_result.action.?);
    try std.testing.expect(!state.closing);
    try std.testing.expectEqual(@as(?Action, null), state.close_action);
}

test "pause menu open timeline emits panel click once when fully open" {
    var state: State = .{};
    var update_result = advanceTimeline(&state, timelineMaxMs() - 1);
    try std.testing.expect(!update_result.play_panel_click);

    update_result = advanceTimeline(&state, 1);
    try std.testing.expect(update_result.play_panel_click);

    state.panel_open_sfx_played = true;
    update_result = advanceTimeline(&state, 1);
    try std.testing.expect(!update_result.play_panel_click);
}
