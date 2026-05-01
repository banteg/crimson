const std = @import("std");
const rl = @import("raylib");

const window_assets = @import("window_assets.zig");
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
const menu_sign_width: f32 = 571.44;
const menu_sign_height: f32 = 141.36;
const menu_sign_offset_x: f32 = -576.44;
const menu_sign_offset_y: f32 = -61.0;
const menu_sign_pos_y: f32 = 70.0;
const menu_sign_pos_y_small: f32 = 60.0;
const menu_sign_pos_x_pad: f32 = 4.0;
const menu_scale_small_threshold: i32 = 640;
const menu_scale_large_min: i32 = 801;
const menu_scale_large_max: i32 = 1024;
const menu_scale_small: f32 = 0.8;
const menu_scale_large: f32 = 1.2;
const menu_scale_shift: f32 = 10.0;

pub const label_row_play_game: i32 = 1;
pub const label_row_options: i32 = 2;
pub const label_row_statistics: i32 = 3;
pub const label_row_mods: i32 = 4;
pub const label_row_other_games: i32 = 5;
pub const label_row_quit: i32 = 6;
pub const label_row_back: i32 = 7;
pub const panel_back_pos_x: f32 = -55.0;
pub const panel_back_pos_y: f32 = 430.0;

pub const Action = enum {
    open_play_game,
    open_options,
    open_statistics,
    open_mods,
    open_other_games,
    quit,
};

pub const Flags = struct {
    mods_available: bool = false,
    other_games_enabled: bool = false,
};

pub const State = struct {
    selection: usize = 0,
    timeline_ms: i32 = 0,
    focus_timer_ms: i32 = 0,
    hovered_index: ?usize = null,
    panel_open_sfx_played: bool = false,
    idle_ms: i32 = 0,
    last_mouse_pos: rl.Vector2 = .{ .x = 0.0, .y = 0.0 },
    hover_amounts: [6]i32 = [_]i32{0} ** 6,

    pub fn reset(self: *State) void {
        self.* = .{
            .last_mouse_pos = rl.getMousePosition(),
        };
    }

    pub fn openRoot(self: *State) void {
        self.reset();
    }
};

pub const UpdateResult = struct {
    action: ?Action = null,
    play_panel_click: bool = false,
    play_button_click: bool = false,
};

const RootEntry = struct {
    slot: usize,
    row: i32,
};

const RootEntries = struct {
    items: [6]RootEntry = undefined,
    len: usize = 0,

    fn slice(self: *const RootEntries) []const RootEntry {
        return self.items[0..self.len];
    }
};

pub fn update(state: *State, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets, flags: Flags) UpdateResult {
    const dt_ms = @as(i32, @intFromFloat(@min(frame_dt, 0.1) * 1000.0));
    const root_entries = rootEntries(flags);
    if (root_entries.len == 0) return .{};
    if (state.selection >= root_entries.len) state.selection = root_entries.len - 1;
    if (dt_ms > 0) {
        const mouse = rl.getMousePosition();
        const mouse_moved = mouse.x != state.last_mouse_pos.x or mouse.y != state.last_mouse_pos.y;
        if (mouse_moved) state.last_mouse_pos = mouse;

        if (rl.getKeyPressed() != .null or rl.isMouseButtonPressed(.left) or rl.isMouseButtonPressed(.right) or mouse_moved) {
            state.idle_ms = 0;
        } else {
            state.idle_ms += dt_ms;
        }

        state.timeline_ms = @min(rootTimelineMaxMs(root_entries.slice()), state.timeline_ms + dt_ms);
        state.focus_timer_ms = @max(0, state.focus_timer_ms - dt_ms);
    }

    if (runtime_assets == null) {
        state.hovered_index = null;
        updateHoverAmounts(state, dt_ms, root_entries.slice());
        return .{};
    }

    state.hovered_index = hoveredRootIndex(runtime_assets, root_entries.slice());
    if (state.hovered_index) |hovered_index| {
        if (rootEntryEnabled(root_entries.items[hovered_index].slot, state.timeline_ms)) {
            state.selection = hovered_index;
            state.focus_timer_ms = 1000;
        }
    }

    if (!activateRootSelection(state, root_entries.items[state.selection].slot)) {
        if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
            state.selection = previousEnabledRootSelection(state.selection, state.timeline_ms, root_entries.slice());
            state.focus_timer_ms = 1000;
        }
        if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
            state.selection = nextEnabledRootSelection(state.selection, state.timeline_ms, root_entries.slice());
            state.focus_timer_ms = 1000;
        }
        updateHoverAmounts(state, dt_ms, root_entries.slice());
        return .{
            .play_panel_click = dt_ms > 0 and state.timeline_ms >= rootTimelineMaxMs(root_entries.slice()) and !state.panel_open_sfx_played,
        };
    }

    var result: UpdateResult = .{ .play_button_click = true };
    result.action = switch (root_entries.items[state.selection].row) {
        label_row_play_game => .open_play_game,
        label_row_options => .open_options,
        label_row_statistics => .open_statistics,
        label_row_mods => .open_mods,
        label_row_other_games => .open_other_games,
        label_row_quit => .quit,
        else => null,
    };
    updateHoverAmounts(state, dt_ms, root_entries.slice());
    if (dt_ms > 0 and state.timeline_ms >= rootTimelineMaxMs(root_entries.slice()) and !state.panel_open_sfx_played) {
        result.play_panel_click = true;
    }
    return result;
}

pub fn draw(state: *const State, runtime_assets: ?*const window_assets.RuntimeAssets, flags: Flags) void {
    const assets = runtime_assets orelse {
        rl.clearBackground(rl.Color.black);
        return;
    };
    const root_entries = rootEntries(flags);

    drawMenuBackdrop(assets);
    drawSign(state.timeline_ms, assets);
    for (root_entries.slice(), 0..) |entry, idx| {
        drawRootEntry(state, assets, entry, idx, idx == state.selection);
    }
}

pub fn drawMenuBackdrop(runtime_assets: *const window_assets.RuntimeAssets) void {
    window_ui.drawTextureFit(
        runtime_assets.texture(.backplasma),
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(rl.getScreenWidth()), @floatFromInt(rl.getScreenHeight())),
        rl.Color.init(255, 255, 255, 92),
    );
    rl.drawRectangle(0, 0, rl.getScreenWidth(), rl.getScreenHeight(), rl.Color.init(16, 11, 9, 160));
}

pub fn drawSign(timeline_ms: i32, runtime_assets: *const window_assets.RuntimeAssets) void {
    const screen_w = rl.getScreenWidth();
    const sign = runtime_assets.texture(.ui_sign_crimson);
    const layout = mainMenuSignLayoutScale(screen_w);
    const sign_pos = rl.Vector2.init(
        @as(f32, @floatFromInt(screen_w)) + menu_sign_pos_x_pad,
        if (screen_w > menu_scale_small_threshold) menu_sign_pos_y else menu_sign_pos_y_small,
    );
    const sign_w = menu_sign_width * layout.scale;
    const sign_h = menu_sign_height * layout.scale;
    const offset_x = menu_sign_offset_x * layout.scale + layout.shift_x;
    const offset_y = menu_sign_offset_y * layout.scale;
    const anim = uiElementAnim(0, 300, 0, sign_w, timeline_ms);
    const rotation_deg = radiansToDegrees(anim.angle_rad);

    rl.drawTexturePro(
        sign,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(sign.width), @floatFromInt(sign.height)),
        rl.Rectangle.init(sign_pos.x, sign_pos.y, sign_w, sign_h),
        rl.Vector2.init(-offset_x, -offset_y),
        rotation_deg,
        rl.Color.white,
    );
}

pub fn drawAtlasLabelCentered(runtime_assets: *const window_assets.RuntimeAssets, row: i32, y: f32, tint: rl.Color) void {
    const texture = runtime_assets.texture(.ui_item_texts);
    const src = rl.Rectangle.init(0.0, @as(f32, @floatFromInt(row)) * menu_label_row_height, menu_label_width, menu_label_row_height);
    const x = (@as(f32, @floatFromInt(rl.getScreenWidth())) - menu_label_width) * 0.5;
    rl.drawTexturePro(
        texture,
        src,
        rl.Rectangle.init(x, y, menu_label_width, menu_label_height),
        rl.Vector2.zero(),
        0.0,
        tint,
    );
}

pub fn uiElementAnim(index: usize, start_ms: i32, end_ms: i32, width: f32, timeline_ms: i32) struct { angle_rad: f32, offset_x: f32 } {
    if (start_ms <= end_ms or width <= 0.0) return .{ .angle_rad = 0.0, .offset_x = 0.0 };
    var angle: f32 = 0.0;
    var offset_x: f32 = 0.0;
    if (timeline_ms < end_ms) {
        angle = 1.5707964;
        offset_x = -@abs(width);
    } else if (timeline_ms < start_ms) {
        const p = @as(f32, @floatFromInt(timeline_ms - end_ms)) / @as(f32, @floatFromInt(start_ms - end_ms));
        angle = 1.5707964 * (1.0 - p);
        offset_x = (1.0 - p) * -@abs(width);
    }
    if (index == 0) angle = -@abs(angle);
    return .{ .angle_rad = angle, .offset_x = offset_x };
}

pub fn menuWidescreenYShift(screen_w: f32) f32 {
    return (screen_w / 640.0) * 150.0 - 150.0;
}

pub fn menuScale(screen_w: i32) struct { scale: f32, shift_x: f32 } {
    return mainMenuSignLayoutScale(screen_w);
}

pub fn panelBackHitRect(runtime_assets: *const window_assets.RuntimeAssets, timeline_ms: i32) rl.Rectangle {
    const item = runtime_assets.texture(.ui_menu_item);
    const item_w = @as(f32, @floatFromInt(item.width));
    const item_h = @as(f32, @floatFromInt(item.height));
    const scale_info = menuItemScale(0);
    const anim = uiElementAnim(2, 300, 0, item_w * scale_info.scale, timeline_ms);
    const pos = rl.Vector2.init(panel_back_pos_x + anim.offset_x, panel_back_pos_y + menuWidescreenYShift(@floatFromInt(rl.getScreenWidth())));
    const offset_min = rl.Vector2.init(
        menu_item_offset_x * scale_info.scale,
        menu_item_offset_y * scale_info.scale - scale_info.local_y_shift,
    );
    const offset_max = rl.Vector2.init(
        (menu_item_offset_x + item_w) * scale_info.scale,
        (menu_item_offset_y + item_h) * scale_info.scale - scale_info.local_y_shift,
    );
    const size = rl.Vector2.init(offset_max.x - offset_min.x, offset_max.y - offset_min.y);
    const top_left = rl.Vector2.init(pos.x + offset_min.x + size.x * 0.54, pos.y + offset_min.y + size.y * 0.28);
    const bottom_right = rl.Vector2.init(pos.x + offset_max.x - size.x * 0.05, pos.y + offset_max.y - size.y * 0.10);
    return rl.Rectangle.init(top_left.x, top_left.y, bottom_right.x - top_left.x, bottom_right.y - top_left.y);
}

pub fn drawPanelBackEntry(runtime_assets: *const window_assets.RuntimeAssets, timeline_ms: i32, hover_amount: i32) void {
    const item = runtime_assets.texture(.ui_menu_item);
    const labels = runtime_assets.texture(.ui_item_texts);
    const item_w = @as(f32, @floatFromInt(item.width));
    const item_h = @as(f32, @floatFromInt(item.height));
    const scale_info = menuItemScale(0);
    const pos_x = panel_back_pos_x;
    const pos_y = panel_back_pos_y + menuWidescreenYShift(@floatFromInt(rl.getScreenWidth()));
    const anim = uiElementAnim(2, 300, 0, item_w * scale_info.scale, timeline_ms);
    const dst = rl.Rectangle.init(pos_x + anim.offset_x, pos_y, item_w * scale_info.scale, item_h * scale_info.scale);
    const origin = rl.Vector2.init(-(menu_item_offset_x * scale_info.scale), -(menu_item_offset_y * scale_info.scale - scale_info.local_y_shift));
    const rotation_deg = radiansToDegrees(anim.angle_rad);

    rl.drawTexturePro(
        item,
        rl.Rectangle.init(0.0, 0.0, item_w, item_h),
        dst,
        origin,
        rotation_deg,
        rl.Color.white,
    );

    const label_alpha = mainMenuLabelAlpha(hover_amount);
    const tint = rl.Color.init(255, 255, 255, label_alpha);
    const src = rl.Rectangle.init(0.0, @as(f32, @floatFromInt(label_row_back)) * menu_label_row_height, menu_label_width, menu_label_row_height);
    const label_dst = rl.Rectangle.init(pos_x + anim.offset_x, pos_y, menu_label_width * scale_info.scale, menu_label_height * scale_info.scale);
    const label_origin = rl.Vector2.init(-(menu_label_offset_x * scale_info.scale), -(menu_label_offset_y * scale_info.scale - scale_info.local_y_shift));
    rl.drawTexturePro(labels, src, label_dst, label_origin, rotation_deg, tint);
    rl.beginBlendMode(.additive);
    rl.drawTexturePro(labels, src, label_dst, label_origin, rotation_deg, tint);
    rl.endBlendMode();
}

fn drawRootEntry(state: *const State, runtime_assets: *const window_assets.RuntimeAssets, entry: RootEntry, idx: usize, selected: bool) void {
    const item = runtime_assets.texture(.ui_menu_item);
    const labels = runtime_assets.texture(.ui_item_texts);
    const scale_info = menuItemScale(entry.slot);
    const pos_x = menuSlotPosX(entry.slot);
    const pos_y = menu_label_base_y + @as(f32, @floatFromInt(entry.slot)) * menu_label_step + menuWidescreenYShift(@floatFromInt(rl.getScreenWidth()));
    const anim = uiElementAnim(entry.slot + 2, menuSlotStartMs(entry.slot), menuSlotEndMs(entry.slot), @as(f32, @floatFromInt(item.width)) * scale_info.scale, state.timeline_ms);
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
    const label_alpha = if (rootEntryEnabled(entry.slot, state.timeline_ms)) mainMenuLabelAlpha(hover_counter) else @as(u8, 100);
    const tint = rl.Color.init(255, 255, 255, label_alpha);
    const src = rl.Rectangle.init(0.0, @as(f32, @floatFromInt(entry.row)) * menu_label_row_height, menu_label_width, menu_label_row_height);
    const label_dst = rl.Rectangle.init(pos_x, pos_y, menu_label_width * scale_info.scale, menu_label_height * scale_info.scale);
    const label_origin = rl.Vector2.init(-(menu_label_offset_x * scale_info.scale), -(menu_label_offset_y * scale_info.scale - scale_info.local_y_shift));
    rl.drawTexturePro(labels, src, label_dst, label_origin, rotation_deg, tint);
    if (rootEntryEnabled(entry.slot, state.timeline_ms)) {
        rl.beginBlendMode(.additive);
        rl.drawTexturePro(labels, src, label_dst, label_origin, rotation_deg, rl.Color.init(255, 255, 255, label_alpha));
        rl.endBlendMode();
    }
}

fn hoveredRootIndex(runtime_assets: ?*const window_assets.RuntimeAssets, root_entries: []const RootEntry) ?usize {
    const mouse = rl.getMousePosition();
    const assets = runtime_assets orelse return null;
    const item = assets.texture(.ui_menu_item);
    for (root_entries, 0..) |entry, idx| {
        if (rl.checkCollisionPointRec(mouse, rootButtonRect(entry.slot, item))) return idx;
    }
    return null;
}

fn activateRootSelection(state: *State, selected_slot: usize) bool {
    if (!rootEntryEnabled(selected_slot, state.timeline_ms)) return false;
    return if (window_ui.confirmPressed())
        true
    else if (!rl.isMouseButtonPressed(.left))
        false
    else blk: {
        const hovered = state.hovered_index orelse break :blk false;
        break :blk hovered == state.selection;
    };
}

fn rootButtonRect(slot: usize, item_texture: rl.Texture2D) rl.Rectangle {
    const scale = menuItemScale(slot);
    const width = @as(f32, @floatFromInt(item_texture.width)) * scale.scale;
    const height = @as(f32, @floatFromInt(item_texture.height)) * scale.scale;
    const x = menuSlotPosX(slot) + menu_item_offset_x * scale.scale;
    const y = menu_label_base_y + @as(f32, @floatFromInt(slot)) * menu_label_step + menuWidescreenYShift(@floatFromInt(rl.getScreenWidth())) + menu_item_offset_y * scale.scale - scale.local_y_shift;
    return rl.Rectangle.init(x, y, width, height);
}

fn rootEntryEnabled(slot: usize, timeline_ms: i32) bool {
    return timeline_ms >= menuSlotStartMs(slot);
}

fn previousEnabledRootSelection(selection: usize, timeline_ms: i32, root_entries: []const RootEntry) usize {
    var idx = selection;
    var attempts: usize = 0;
    while (attempts < root_entries.len) : (attempts += 1) {
        idx = if (idx == 0) root_entries.len - 1 else idx - 1;
        if (rootEntryEnabled(root_entries[idx].slot, timeline_ms)) return idx;
    }
    return selection;
}

fn nextEnabledRootSelection(selection: usize, timeline_ms: i32, root_entries: []const RootEntry) usize {
    var idx = selection;
    var attempts: usize = 0;
    while (attempts < root_entries.len) : (attempts += 1) {
        idx = (idx + 1) % root_entries.len;
        if (rootEntryEnabled(root_entries[idx].slot, timeline_ms)) return idx;
    }
    return selection;
}

fn updateHoverAmounts(state: *State, dt_ms: i32, root_entries: []const RootEntry) void {
    for (0..root_entries.len) |idx| {
        const hovered = state.hovered_index != null and state.hovered_index.? == idx;
        if (hovered) {
            state.hover_amounts[idx] = std.math.clamp(state.hover_amounts[idx] + dt_ms * 6, 0, 1000);
        } else {
            state.hover_amounts[idx] = std.math.clamp(state.hover_amounts[idx] - dt_ms * 2, 0, 1000);
        }
    }
}

fn rootTimelineMaxMs(root_entries: []const RootEntry) i32 {
    var max_ms: i32 = 300;
    for (root_entries) |entry| {
        max_ms = @max(max_ms, menuSlotStartMs(entry.slot));
    }
    return max_ms;
}

fn rootEntries(flags: Flags) RootEntries {
    var entries: RootEntries = .{};
    const rows = if (flags.other_games_enabled)
        [_]i32{ label_row_mods, label_row_play_game, label_row_options, label_row_statistics, label_row_other_games, label_row_quit }
    else
        [_]i32{ label_row_mods, label_row_play_game, label_row_options, label_row_statistics, label_row_quit, label_row_back };
    const active = [_]bool{ flags.mods_available, true, true, true, true, flags.other_games_enabled };

    for (rows, 0..) |row, slot| {
        if (!active[slot]) continue;
        entries.items[entries.len] = .{ .slot = slot, .row = row };
        entries.len += 1;
    }
    return entries;
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

fn mainMenuSignLayoutScale(screen_w: i32) struct { scale: f32, shift_x: f32 } {
    if (screen_w <= menu_scale_small_threshold) return .{ .scale = menu_scale_small, .shift_x = menu_scale_shift };
    if (screen_w >= menu_scale_large_min and screen_w <= menu_scale_large_max) return .{ .scale = menu_scale_large, .shift_x = menu_scale_shift };
    return .{ .scale = 1.0, .shift_x = 0.0 };
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
