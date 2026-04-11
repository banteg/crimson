const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;

const input_codes = @import("input_codes.zig");
const local_input = cz.local_input;
const window_assets = @import("window_assets.zig");
const window_menu = @import("window_menu.zig");
const window_ui = @import("window_ui.zig");

const text_color = rl.Color.init(245, 236, 225, 255);
const muted_text = rl.Color.init(171, 150, 132, 255);
const value_color = rl.Color.init(70, 180, 240, 255);
const value_dim = rl.Color.init(70, 180, 240, 153);
const active_color = rl.Color.init(255, 228, 170, 255);

const panel_timeline_max_ms: i32 = 300;

const DropdownKind = enum {
    none,
    player,
    movement,
    aim,
};

const RebindTarget = enum {
    player_move_codes,
    player_fire_code,
    player_keyboard_aim_codes,
    player_aim_axis_codes,
    player_move_axis_codes,
    global_pick_perk_code,
    global_reload_code,
};

const RebindRow = struct {
    label: []const u8,
    target: RebindTarget,
    target_index: ?usize = null,
    axis: bool = false,
};

const DropdownItem = struct {
    label: []const u8,
    value: i32,
};

pub const OptionsAction = enum {
    none,
    open_controls,
    back_to_menu,
};

pub const ControlsAction = enum {
    none,
    back_to_options,
};

pub const OptionsUpdate = struct {
    action: OptionsAction = .none,
    config_dirty: bool = false,
    reload_audio: bool = false,
    play_panel_click: bool = false,
    play_button_click: bool = false,
};

pub const ControlsUpdate = struct {
    action: ControlsAction = .none,
    config_dirty: bool = false,
    play_panel_click: bool = false,
    play_button_click: bool = false,
};

const PanelState = struct {
    selection: usize = 0,
    timeline_ms: i32 = 0,
    panel_open_sfx_played: bool = false,

    fn advance(self: *PanelState, frame_dt: f32) i32 {
        const dt_ms = @as(i32, @intFromFloat(@min(frame_dt, 0.1) * 1000.0));
        if (dt_ms > 0) {
            self.timeline_ms = @min(panel_timeline_max_ms, self.timeline_ms + dt_ms);
        }
        return dt_ms;
    }
};

pub const OptionsState = struct {
    panel: PanelState = .{},

    pub fn reset(self: *OptionsState) void {
        self.* = .{};
    }
};

pub const ControlsState = struct {
    left_selection: usize = 0,
    right_selection: usize = 0,
    player_index: usize = 0,
    focus_right: bool = false,
    timeline_ms: i32 = 0,
    panel_open_sfx_played: bool = false,
    open_dropdown: DropdownKind = .none,
    dropdown_selection: usize = 0,
    rebinding_row_index: ?usize = null,
    rebinding_player_index: usize = 0,

    pub fn reset(self: *ControlsState) void {
        self.* = .{};
    }
};

const OptionButton = window_ui.UiButton;

pub fn updateOptions(state: *OptionsState, frame_dt: f32, config: *formats.crimson_cfg.CrimsonCfg) OptionsUpdate {
    const dt_ms = state.panel.advance(frame_dt);
    const buttons = optionsButtons();
    window_ui.updateSelectionFromPointer(&state.panel.selection, buttons[0..]);

    if (rl.isKeyPressed(.escape)) {
        return .{ .action = .back_to_menu, .play_button_click = true };
    }
    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        state.panel.selection = if (state.panel.selection == 0) buttons.len - 1 else state.panel.selection - 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.panel.selection = (state.panel.selection + 1) % buttons.len;
    }

    const adjust_left = rl.isKeyPressed(.left) or rl.isKeyPressed(.a);
    const adjust_right = rl.isKeyPressed(.right) or rl.isKeyPressed(.d);
    const activated = window_ui.buttonActivated(buttons[0..], state.panel.selection);
    if (!(adjust_left or adjust_right or activated)) {
        return .{
            .play_panel_click = dt_ms > 0 and state.panel.timeline_ms >= panel_timeline_max_ms and !state.panel.panel_open_sfx_played,
        };
    }

    var result: OptionsUpdate = .{ .play_button_click = true };
    switch (state.panel.selection) {
        0 => {
            var value = if (config.sound_disable != 0) @as(i32, 0) else @as(i32, @intFromFloat(std.math.clamp(config.sfx_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5));
            if (adjust_left or adjust_right) {
                value = std.math.clamp(value + (if (adjust_left and !adjust_right) @as(i32, -1) else @as(i32, 1)), @as(i32, 0), @as(i32, 10));
            } else {
                value = if (value == 0) 10 else 0;
            }
            config.sfx_volume = @as(f32, @floatFromInt(value)) * 0.1;
            config.sound_disable = @intFromBool(value == 0);
            result.config_dirty = true;
            result.reload_audio = true;
        },
        1 => {
            var value = if (config.music_disable != 0) @as(i32, 0) else @as(i32, @intFromFloat(std.math.clamp(config.music_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5));
            if (adjust_left or adjust_right) {
                value = std.math.clamp(value + (if (adjust_left and !adjust_right) @as(i32, -1) else @as(i32, 1)), @as(i32, 0), @as(i32, 10));
            } else {
                value = if (value == 0) 10 else 0;
            }
            config.music_volume = @as(f32, @floatFromInt(value)) * 0.1;
            config.music_disable = @intFromBool(value == 0);
            result.config_dirty = true;
            result.reload_audio = true;
        },
        2 => {
            var value: i32 = @intCast(std.math.clamp(config.detail_preset, @as(u32, 1), @as(u32, 5)));
            if (adjust_left and !adjust_right) value -= 1 else value += 1;
            config.detail_preset = @intCast(std.math.clamp(value, @as(i32, 1), @as(i32, 5)));
            result.config_dirty = true;
        },
        3 => {
            var value = std.math.clamp(@as(i32, @intFromFloat(std.math.clamp(config.mouse_sensitivity, @as(f32, 0.1), @as(f32, 1.0)) * 10.0 + 0.5)), @as(i32, 1), @as(i32, 10));
            if (adjust_left and !adjust_right) value -= 1 else value += 1;
            value = std.math.clamp(value, @as(i32, 1), @as(i32, 10));
            config.mouse_sensitivity = @as(f32, @floatFromInt(value)) * 0.1;
            result.config_dirty = true;
        },
        4 => {
            config.ui_info_texts = if (config.ui_info_texts == 0) 1 else 0;
            result.config_dirty = true;
        },
        5 => result.action = .open_controls,
        6 => result.action = .back_to_menu,
        else => {},
    }

    return result;
}

pub fn drawOptions(state: *const OptionsState, runtime_assets: ?*const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg) void {
    if (runtime_assets) |assets| {
        drawMenuPanelShell(state.panel.timeline_ms, assets, .{ .x = 360.0, .y = 148.0, .width = 510.0, .height = 364.0 }, window_menu.label_row_options);
        drawOptionsContents(state, assets, config);
        return;
    }
    rl.clearBackground(rl.Color.init(37, 24, 20, 255));
}

pub fn updateControls(state: *ControlsState, frame_dt: f32, config: *formats.crimson_cfg.CrimsonCfg) ControlsUpdate {
    const dt_ms = @as(i32, @intFromFloat(@min(frame_dt, 0.1) * 1000.0));
    if (dt_ms > 0) {
        state.timeline_ms = @min(panel_timeline_max_ms, state.timeline_ms + dt_ms);
    }

    if (state.rebinding_row_index != null) {
        return updateControlsRebinding(state, config);
    }

    if (rl.isKeyPressed(.escape)) {
        if (state.open_dropdown != .none) {
            state.open_dropdown = .none;
            return .{};
        }
        return .{ .action = .back_to_options, .play_button_click = true };
    }

    if (state.open_dropdown != .none) {
        return updateControlsDropdown(state, config);
    }

    const button_count = leftControlButtonCount();
    const rebind_rows = controlsRebindRows(config, currentPlayerIndex(state));
    if (rebind_rows.len == 0) {
        state.right_selection = 0;
    } else if (state.right_selection >= rebind_rows.len) {
        state.right_selection = rebind_rows.len - 1;
    }

    updateControlsFocusFromPointer(state, rebind_rows[0..]);

    if (rl.isKeyPressed(.tab)) {
        state.focus_right = !state.focus_right;
    }
    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        if (state.focus_right and rebind_rows.len > 0) {
            state.right_selection = if (state.right_selection == 0) rebind_rows.len - 1 else state.right_selection - 1;
        } else {
            state.left_selection = if (state.left_selection == 0) button_count - 1 else state.left_selection - 1;
        }
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        if (state.focus_right and rebind_rows.len > 0) {
            state.right_selection = (state.right_selection + 1) % rebind_rows.len;
        } else {
            state.left_selection = (state.left_selection + 1) % button_count;
        }
    }

    var result: ControlsUpdate = .{
        .play_panel_click = dt_ms > 0 and state.timeline_ms >= panel_timeline_max_ms and !state.panel_open_sfx_played,
    };
    const activated = rl.isKeyPressed(.enter) or rl.isKeyPressed(.space) or rl.isMouseButtonPressed(.left);

    if (state.focus_right and rebind_rows.len > 0) {
        if (!activated) return result;
        state.rebinding_row_index = state.right_selection;
        state.rebinding_player_index = currentPlayerIndex(state);
        result.play_button_click = true;
        return result;
    }

    if (!activated) return result;
    result.play_button_click = true;
    switch (state.left_selection) {
        0 => {
            openDropdown(state, config, .player, 4);
        },
        1 => {
            openDropdown(state, config, .aim, aimItemCount(config, currentPlayerIndex(state)));
        },
        2 => {
            openDropdown(state, config, .movement, movement_items.len);
        },
        3 => {
            formats.crimson_cfg.setPlayerShowDirectionArrow(config, currentPlayerIndex(state), !formats.crimson_cfg.playerShowDirectionArrow(config, currentPlayerIndex(state)));
            result.config_dirty = true;
        },
        4 => result.action = .back_to_options,
        else => {},
    }
    return result;
}

pub fn drawControls(state: *const ControlsState, runtime_assets: ?*const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg) void {
    if (runtime_assets) |assets| {
        drawMenuBackdropAndSign(state.timeline_ms, assets);
        drawControlsPanels(state, assets, config);
        return;
    }
    rl.clearBackground(rl.Color.init(37, 24, 20, 255));
}

fn drawOptionsContents(state: *const OptionsState, runtime_assets: *const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg) void {
    const buttons = optionsButtons();
    for (buttons[5..], 5..) |button, idx| {
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), button.rect);
        window_ui.drawButton(button, idx == state.panel.selection, hovered, runtime_assets);
    }

    const labels = [_][]const u8{
        "Sound volume:",
        "Music volume:",
        "Graphics detail:",
        "Mouse sensitivity:",
        "UI Info texts",
    };
    for (labels, 0..) |label, idx| {
        const y = 236.0 + @as(f32, @floatFromInt(idx)) * 36.0;
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), buttons[idx].rect);
        const selected = idx == state.panel.selection;
        window_ui.drawSmallText(runtime_assets, label, 420.0, y, if (selected or hovered) text_color else muted_text);
    }

    drawSlider(runtime_assets, rl.Vector2.init(625.0, 234.0), 10, if (config.sound_disable != 0) 0 else @intFromFloat(std.math.clamp(config.sfx_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5));
    drawSlider(runtime_assets, rl.Vector2.init(625.0, 270.0), 10, if (config.music_disable != 0) 0 else @intFromFloat(std.math.clamp(config.music_volume, @as(f32, 0.0), @as(f32, 1.0)) * 10.0 + 0.5));
    drawSlider(runtime_assets, rl.Vector2.init(625.0, 306.0), 5, @intCast(std.math.clamp(config.detail_preset, @as(u32, 1), @as(u32, 5))));
    drawSlider(runtime_assets, rl.Vector2.init(625.0, 342.0), 10, @intFromFloat(std.math.clamp(config.mouse_sensitivity, @as(f32, 0.1), @as(f32, 1.0)) * 10.0 + 0.5));

    const checkbox_tex: window_assets.TextureId = if (config.ui_info_texts != 0) .ui_check_on else .ui_check_off;
    window_ui.drawTextureFit(runtime_assets.texture(checkbox_tex), rl.Rectangle.init(625.0, 378.0, 16.0, 16.0), rl.Color.white);
    window_ui.drawSmallText(runtime_assets, "UI Info texts", 647.0, 379.0, if (state.panel.selection == 4 or rl.checkCollisionPointRec(rl.getMousePosition(), buttons[4].rect)) text_color else muted_text);
}

fn drawControlsPanels(state: *const ControlsState, runtime_assets: *const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg) void {
    const left_rect = rl.Rectangle.init(132.0, 174.0, 510.0, 292.0);
    const right_rect = rl.Rectangle.init(598.0, 118.0, 510.0, 392.0);
    window_ui.drawTextureFit(runtime_assets.texture(.ui_menu_panel), left_rect, window_ui.colorWithAlpha(rl.Color.white, 0.96));
    window_ui.drawTextureFit(runtime_assets.texture(.ui_menu_panel), right_rect, window_ui.colorWithAlpha(rl.Color.white, 0.96));

    window_ui.drawTextureFit(runtime_assets.texture(.ui_text_controls), rl.Rectangle.init(322.0, 202.0, 128.0, 32.0), rl.Color.white);
    window_ui.drawSmallText(runtime_assets, "Configured controls", 746.0, 156.0, text_color);
    rl.drawRectangle(746, 169, @intFromFloat(window_ui.measureSmallText(runtime_assets, "Configured controls")), 1, rl.Color.init(255, 255, 255, 204));

    const player_idx = currentPlayerIndex(state);
    drawDropdownLabel(runtime_assets, "Configure for:", 182.0, 244.0);
    drawDropdown(runtime_assets, dropdownRect(182.0, 262.0), player_items[0..], player_idx, state.open_dropdown == .player, state.dropdown_selection);

    drawDropdownLabel(runtime_assets, "Aiming method:", 182.0, 300.0);
    const current_aim_items = aimItems(&config, player_idx);
    drawDropdown(runtime_assets, dropdownRect(182.0, 318.0), current_aim_items, aimItemIndex(&config, player_idx), state.open_dropdown == .aim, state.dropdown_selection);

    drawDropdownLabel(runtime_assets, "Moving method:", 182.0, 356.0);
    drawDropdown(runtime_assets, dropdownRect(182.0, 374.0), movement_items[0..], movementItemIndex(&config, player_idx), state.open_dropdown == .movement, state.dropdown_selection);

    const direction_checked: window_assets.TextureId = if (formats.crimson_cfg.playerShowDirectionArrow(&config, player_idx)) .ui_check_on else .ui_check_off;
    window_ui.drawTextureFit(runtime_assets.texture(direction_checked), rl.Rectangle.init(182.0, 418.0, 16.0, 16.0), rl.Color.white);
    window_ui.drawSmallText(runtime_assets, "Show direction arrow", 204.0, 418.0, if (state.left_selection == 3 and !state.focus_right) text_color else muted_text);

    const back = controlsBackButton();
    const back_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), back.rect);
    window_ui.drawButton(back, state.left_selection == 4 and !state.focus_right, back_hovered, runtime_assets);

    const rows = controlsRebindRows(&config, player_idx);
    var y: f32 = 198.0;
    for (rows, 0..) |row, idx| {
        const selected = state.focus_right and idx == state.right_selection;
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), rebindRect(y));
        const color = if (state.rebinding_row_index != null and state.rebinding_row_index.? == idx) active_color else if (selected or hovered) value_color else value_dim;
        window_ui.drawSmallText(runtime_assets, row.label, 650.0, y, muted_text);
        window_ui.drawSmallText(runtime_assets, bindingValueText(row, &config, player_idx, state.rebinding_row_index != null and state.rebinding_row_index.? == idx), 868.0, y, color);
        y += 24.0;
    }
}

fn drawMenuBackdropAndSign(timeline_ms: i32, runtime_assets: *const window_assets.RuntimeAssets) void {
    window_menu.drawMenuBackdrop(runtime_assets);
    window_menu.drawSign(timeline_ms, runtime_assets);
}

fn drawMenuPanelShell(timeline_ms: i32, runtime_assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle, title_row: i32) void {
    drawMenuBackdropAndSign(timeline_ms, runtime_assets);
    const anim = window_menu.uiElementAnim(1, panel_timeline_max_ms, 0, rect.width, timeline_ms);
    const panel_rect = rl.Rectangle.init(rect.x + anim.offset_x, rect.y, rect.width, rect.height);
    window_ui.drawTextureFit(runtime_assets.texture(.ui_menu_panel), panel_rect, window_ui.colorWithAlpha(rl.Color.white, 0.96));
    window_menu.drawAtlasLabelCentered(runtime_assets, title_row, rect.y + 38.0, rl.Color.white);
}

fn optionsButtons() [7]OptionButton {
    return .{
        .{ .label = "Sfx", .rect = rl.Rectangle.init(404.0, 226.0, 320.0, 28.0) },
        .{ .label = "Music", .rect = rl.Rectangle.init(404.0, 262.0, 320.0, 28.0) },
        .{ .label = "Detail", .rect = rl.Rectangle.init(404.0, 298.0, 320.0, 28.0) },
        .{ .label = "Mouse", .rect = rl.Rectangle.init(404.0, 334.0, 320.0, 28.0) },
        .{ .label = "UiInfo", .rect = rl.Rectangle.init(404.0, 370.0, 320.0, 28.0) },
        .{ .label = "Controls", .rect = rl.Rectangle.init(404.0, 414.0, 240.0, 44.0) },
        .{ .label = "Back", .rect = rl.Rectangle.init(404.0, 470.0, 180.0, 44.0) },
    };
}

fn controlsBackButton() OptionButton {
    return .{ .label = "Back", .rect = rl.Rectangle.init(182.0, 448.0, 180.0, 44.0) };
}

fn drawSlider(runtime_assets: *const window_assets.RuntimeAssets, pos: rl.Vector2, count: i32, value: i32) void {
    var idx: i32 = 0;
    while (idx < count) : (idx += 1) {
        const id: window_assets.TextureId = if (idx < value) .ui_rect_on else .ui_rect_off;
        const tint = if (idx < value) rl.Color.white else rl.Color.init(255, 255, 255, 128);
        window_ui.drawTextureFit(runtime_assets.texture(id), rl.Rectangle.init(pos.x + @as(f32, @floatFromInt(idx * 16)), pos.y, 16.0, 16.0), tint);
    }
}

fn drawDropdownLabel(runtime_assets: *const window_assets.RuntimeAssets, label: []const u8, x: f32, y: f32) void {
    window_ui.drawSmallText(runtime_assets, label, x, y, muted_text);
}

fn dropdownRect(x: f32, y: f32) rl.Rectangle {
    return rl.Rectangle.init(x, y, 148.0, 16.0);
}

fn drawDropdown(
    runtime_assets: *const window_assets.RuntimeAssets,
    rect: rl.Rectangle,
    items: []const DropdownItem,
    current_index: usize,
    open: bool,
    dropdown_selection: usize,
) void {
    const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), rect);
    const texture = if (open or hovered) runtime_assets.texture(.ui_drop_on) else runtime_assets.texture(.ui_drop_off);
    rl.drawRectangleRec(rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(rect.x + 1.0), @intFromFloat(rect.y + 1.0), @intFromFloat(rect.width - 2.0), @intFromFloat(rect.height - 2.0), rl.Color.black);
    const safe_index = @min(current_index, items.len - 1);
    window_ui.drawSmallText(runtime_assets, items[safe_index].label, rect.x + 4.0, rect.y + 1.0, if (hovered or open) text_color else muted_text);
    rl.drawTexturePro(texture, rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)), rl.Rectangle.init(rect.x + rect.width - 17.0, rect.y, 16.0, 16.0), rl.Vector2.zero(), 0.0, rl.Color.white);

    if (!open) return;
    const list_rect = rl.Rectangle.init(rect.x, rect.y, rect.width, 16.0 + 16.0 * @as(f32, @floatFromInt(items.len)));
    rl.drawRectangleRec(list_rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(list_rect.x + 1.0), @intFromFloat(list_rect.y + 1.0), @intFromFloat(list_rect.width - 2.0), @intFromFloat(list_rect.height - 2.0), rl.Color.black);
    for (items, 0..) |item, idx| {
        const row_y = rect.y + 17.0 + @as(f32, @floatFromInt(idx)) * 16.0;
        const row_rect = rl.Rectangle.init(rect.x, row_y, rect.width, 16.0);
        const row_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), row_rect);
        window_ui.drawSmallText(runtime_assets, item.label, rect.x + 4.0, row_y + 1.0, if (row_hovered or idx == dropdown_selection) text_color else muted_text);
    }
}

fn leftControlButtonCount() usize {
    return 5;
}

fn rebindRect(y: f32) rl.Rectangle {
    return rl.Rectangle.init(640.0, y - 2.0, 360.0, 18.0);
}

fn updateControlsFocusFromPointer(state: *ControlsState, rows: []const RebindRow) void {
    const mouse = rl.getMousePosition();
    const left_rects = [_]rl.Rectangle{
        dropdownRect(182.0, 262.0),
        dropdownRect(182.0, 374.0),
        dropdownRect(182.0, 318.0),
        rl.Rectangle.init(182.0, 416.0, 220.0, 20.0),
    };
    for (left_rects, 0..) |rect, idx| {
        if (rl.checkCollisionPointRec(mouse, rect)) {
            state.focus_right = false;
            state.left_selection = idx;
            return;
        }
    }
    if (rl.checkCollisionPointRec(mouse, controlsBackButton().rect)) {
        state.focus_right = false;
        state.left_selection = 4;
        return;
    }
    for (rows, 0..) |row, row_idx| {
        _ = row;
        if (rl.checkCollisionPointRec(mouse, rebindRect(198.0 + @as(f32, @floatFromInt(row_idx)) * 24.0))) {
            state.focus_right = true;
            state.right_selection = row_idx;
            return;
        }
    }
}

fn updateControlsDropdown(state: *ControlsState, config: *formats.crimson_cfg.CrimsonCfg) ControlsUpdate {
    const items = switch (state.open_dropdown) {
        .player => player_items[0..],
        .movement => movement_items[0..],
        .aim => aimItems(config, currentPlayerIndex(state)),
        .none => return .{},
    };

    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        state.dropdown_selection = if (state.dropdown_selection == 0) items.len - 1 else state.dropdown_selection - 1;
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.dropdown_selection = (state.dropdown_selection + 1) % items.len;
    }

    const mouse = rl.getMousePosition();
    const base_rect = switch (state.open_dropdown) {
        .player => dropdownRect(182.0, 262.0),
        .movement => dropdownRect(182.0, 374.0),
        .aim => dropdownRect(182.0, 318.0),
        .none => unreachable,
    };
    for (items, 0..) |item, idx| {
        _ = item;
        const row_rect = rl.Rectangle.init(base_rect.x, base_rect.y + 17.0 + @as(f32, @floatFromInt(idx)) * 16.0, base_rect.width, 16.0);
        if (rl.checkCollisionPointRec(mouse, row_rect)) {
            state.dropdown_selection = idx;
        }
    }
    for (items, 0..) |item, idx| {
        _ = item;
        const row_rect = rl.Rectangle.init(base_rect.x, base_rect.y + 17.0 + @as(f32, @floatFromInt(idx)) * 16.0, base_rect.width, 16.0);
        if (rl.checkCollisionPointRec(mouse, row_rect) and rl.isMouseButtonPressed(.left)) {
            state.dropdown_selection = idx;
            return applyControlsDropdownSelection(state, config, items[idx].value);
        }
    }

    if (rl.isKeyPressed(.enter) or rl.isKeyPressed(.space)) {
        return applyControlsDropdownSelection(state, config, items[state.dropdown_selection].value);
    }
    if (rl.isMouseButtonPressed(.left) and !rl.checkCollisionPointRec(mouse, base_rect)) {
        state.open_dropdown = .none;
    }
    return .{};
}

fn applyControlsDropdownSelection(state: *ControlsState, config: *formats.crimson_cfg.CrimsonCfg, value: i32) ControlsUpdate {
    const player_index = currentPlayerIndex(state);
    switch (state.open_dropdown) {
        .player => state.left_selection = 0,
        .movement => formats.crimson_cfg.setPlayerMovement(config, player_index, @intCast(value)),
        .aim => formats.crimson_cfg.setPlayerAimScheme(config, player_index, @intCast(value)),
        .none => {},
    }

    if (state.open_dropdown == .player) {
        setCurrentPlayerIndex(state, @intCast(std.math.clamp(value, @as(i32, 0), @as(i32, 3))));
        state.right_selection = 0;
        state.focus_right = false;
    }
    state.open_dropdown = .none;
    return .{ .config_dirty = true, .play_button_click = true };
}

fn updateControlsRebinding(state: *ControlsState, config: *formats.crimson_cfg.CrimsonCfg) ControlsUpdate {
    if (rl.isKeyPressed(.escape)) {
        state.rebinding_row_index = null;
        return .{};
    }

    const rows = controlsRebindRows(config, state.rebinding_player_index);
    const row_index = state.rebinding_row_index orelse return .{};
    if (row_index >= rows.len) {
        state.rebinding_row_index = null;
        return .{};
    }
    const row = rows[row_index];
    const code = input_codes.captureFirstPressedInputCode(
        @intCast(state.rebinding_player_index),
        !row.axis,
        !row.axis,
        !row.axis,
        row.axis,
        0.5,
    ) orelse return .{};

    setBindingValue(config, state.rebinding_player_index, row, code);
    state.rebinding_row_index = null;
    return .{ .config_dirty = true, .play_button_click = true };
}

fn controlsRebindRows(config: *const formats.crimson_cfg.CrimsonCfg, player_index: usize) []const RebindRow {
    const move_mode = formats.crimson_cfg.playerMovement(config, player_index);
    const aim_scheme = formats.crimson_cfg.playerAimScheme(config, player_index);
    if (player_index == 0) {
        if (move_mode == @as(u32, @intCast(local_input.movement_control_mouse_point_click))) {
            return switch (aim_scheme) {
                @as(u32, @bitCast(@as(i32, local_input.aim_scheme_keyboard))) => controls_rows_p1_mouseclick_keyboard[0..],
                @as(u32, @bitCast(@as(i32, local_input.aim_scheme_dual_action_pad))) => controls_rows_p1_mouseclick_dual_pad[0..],
                else => controls_rows_p1_mouseclick_default[0..],
            };
        }
        return switch (aim_scheme) {
            @as(u32, @bitCast(@as(i32, local_input.aim_scheme_keyboard))) => switch (move_mode) {
                @as(u32, @intCast(local_input.movement_control_relative)) => controls_rows_p1_relative_keyboard[0..],
                @as(u32, @intCast(local_input.movement_control_static)) => controls_rows_p1_static_keyboard[0..],
                else => controls_rows_p1_other_keyboard[0..],
            },
            @as(u32, @bitCast(@as(i32, local_input.aim_scheme_dual_action_pad))) => switch (move_mode) {
                @as(u32, @intCast(local_input.movement_control_dual_action_pad)) => controls_rows_p1_dual_pad[0..],
                else => controls_rows_p1_other_dual_pad[0..],
            },
            else => switch (move_mode) {
                @as(u32, @intCast(local_input.movement_control_relative)) => controls_rows_p1_relative_default[0..],
                @as(u32, @intCast(local_input.movement_control_static)) => controls_rows_p1_static_default[0..],
                @as(u32, @intCast(local_input.movement_control_dual_action_pad)) => controls_rows_p1_move_pad_default[0..],
                else => controls_rows_p1_default[0..],
            },
        };
    }

    if (move_mode == @as(u32, @intCast(local_input.movement_control_mouse_point_click))) {
        return switch (aim_scheme) {
            @as(u32, @bitCast(@as(i32, local_input.aim_scheme_keyboard))) => controls_rows_mouseclick_keyboard[0..],
            @as(u32, @bitCast(@as(i32, local_input.aim_scheme_dual_action_pad))) => controls_rows_mouseclick_dual_pad[0..],
            else => controls_rows_mouseclick_default[0..],
        };
    }
    return switch (aim_scheme) {
        @as(u32, @bitCast(@as(i32, local_input.aim_scheme_keyboard))) => switch (move_mode) {
            @as(u32, @intCast(local_input.movement_control_relative)) => controls_rows_relative_keyboard[0..],
            @as(u32, @intCast(local_input.movement_control_static)) => controls_rows_static_keyboard[0..],
            else => controls_rows_other_keyboard[0..],
        },
        @as(u32, @bitCast(@as(i32, local_input.aim_scheme_dual_action_pad))) => switch (move_mode) {
            @as(u32, @intCast(local_input.movement_control_dual_action_pad)) => controls_rows_dual_pad[0..],
            else => controls_rows_other_dual_pad[0..],
        },
        else => switch (move_mode) {
            @as(u32, @intCast(local_input.movement_control_relative)) => controls_rows_relative_default[0..],
            @as(u32, @intCast(local_input.movement_control_static)) => controls_rows_static_default[0..],
            @as(u32, @intCast(local_input.movement_control_dual_action_pad)) => controls_rows_move_pad_default[0..],
            else => controls_rows_default[0..],
        },
    };
}

fn bindingValueText(row: RebindRow, config: *const formats.crimson_cfg.CrimsonCfg, player_index: usize, rebinding: bool) []const u8 {
    if (rebinding) return if (row.axis) "<press axis>" else "<press input>";
    return input_codes.inputCodeName(getBindingValue(config, player_index, row));
}

fn getBindingValue(config: *const formats.crimson_cfg.CrimsonCfg, player_index: usize, row: RebindRow) i32 {
    var binds = formats.crimson_cfg.playerBindBlock(config, player_index);
    return switch (row.target) {
        .player_move_codes => bindBlockMoveValue(&binds, row.target_index.?),
        .player_fire_code => binds.fire,
        .player_keyboard_aim_codes => if (row.target_index.? == 0) binds.aim_left else binds.aim_right,
        .player_aim_axis_codes => if (row.target_index.? == 0) binds.axis_aim_y else binds.axis_aim_x,
        .player_move_axis_codes => if (row.target_index.? == 0) binds.axis_move_y else binds.axis_move_x,
        .global_pick_perk_code => @bitCast(config.keybind_pick_perk),
        .global_reload_code => @bitCast(config.keybind_reload),
    };
}

fn setBindingValue(config: *formats.crimson_cfg.CrimsonCfg, player_index: usize, row: RebindRow, code: i32) void {
    var binds = formats.crimson_cfg.playerBindBlock(config, player_index);
    switch (row.target) {
        .player_move_codes => setBindBlockMoveValue(&binds, row.target_index.?, code),
        .player_fire_code => binds.fire = code,
        .player_keyboard_aim_codes => {
            if (row.target_index.? == 0) binds.aim_left = code else binds.aim_right = code;
        },
        .player_aim_axis_codes => {
            if (row.target_index.? == 0) binds.axis_aim_y = code else binds.axis_aim_x = code;
        },
        .player_move_axis_codes => {
            if (row.target_index.? == 0) binds.axis_move_y = code else binds.axis_move_x = code;
        },
        .global_pick_perk_code => config.keybind_pick_perk = @bitCast(code),
        .global_reload_code => config.keybind_reload = @bitCast(code),
    }
    switch (row.target) {
        .player_move_codes, .player_fire_code, .player_keyboard_aim_codes, .player_aim_axis_codes, .player_move_axis_codes => formats.crimson_cfg.setPlayerBindBlock(config, player_index, binds),
        .global_pick_perk_code, .global_reload_code => {},
    }
}

fn movementItemIndex(config: *const formats.crimson_cfg.CrimsonCfg, player_index: usize) usize {
    const value = formats.crimson_cfg.playerMovement(config, player_index);
    for (movement_items, 0..) |item, idx| {
        if (@as(u32, @intCast(item.value)) == value) return idx;
    }
    return 0;
}

fn aimItemCount(config: *const formats.crimson_cfg.CrimsonCfg, player_index: usize) usize {
    const items = aimItems(config, player_index);
    return items.len;
}

fn aimItemIndex(config: *const formats.crimson_cfg.CrimsonCfg, player_index: usize) usize {
    const value = formats.crimson_cfg.playerAimScheme(config, player_index);
    const items = aimItems(config, player_index);
    for (items, 0..) |item, idx| {
        if (@as(u32, @bitCast(item.value)) == value) return idx;
    }
    return 0;
}

fn aimItems(config: *const formats.crimson_cfg.CrimsonCfg, player_index: usize) []const DropdownItem {
    const current = formats.crimson_cfg.playerAimScheme(config, player_index);
    if (current == @as(u32, @bitCast(@as(i32, local_input.aim_scheme_computer)))) return aim_items_with_computer[0..];
    return aim_items[0..];
}

const player_items = [_]DropdownItem{
    .{ .label = "Player 1", .value = 0 },
    .{ .label = "Player 2", .value = 1 },
    .{ .label = "Player 3", .value = 2 },
    .{ .label = "Player 4", .value = 3 },
};

const movement_items = [_]DropdownItem{
    .{ .label = "Relative", .value = local_input.movement_control_relative },
    .{ .label = "Static", .value = local_input.movement_control_static },
    .{ .label = "Dual Action Pad", .value = local_input.movement_control_dual_action_pad },
    .{ .label = "Mouse point click", .value = local_input.movement_control_mouse_point_click },
    .{ .label = "Computer", .value = local_input.movement_control_computer },
};

const aim_items = [_]DropdownItem{
    .{ .label = "Mouse", .value = local_input.aim_scheme_mouse },
    .{ .label = "Keyboard", .value = local_input.aim_scheme_keyboard },
    .{ .label = "Joystick", .value = local_input.aim_scheme_joystick },
    .{ .label = "Mouse relative", .value = local_input.aim_scheme_mouse_relative },
    .{ .label = "Dual Action Pad", .value = local_input.aim_scheme_dual_action_pad },
};

const aim_items_with_computer = [_]DropdownItem{
    .{ .label = "Mouse", .value = local_input.aim_scheme_mouse },
    .{ .label = "Keyboard", .value = local_input.aim_scheme_keyboard },
    .{ .label = "Joystick", .value = local_input.aim_scheme_joystick },
    .{ .label = "Mouse relative", .value = local_input.aim_scheme_mouse_relative },
    .{ .label = "Dual Action Pad", .value = local_input.aim_scheme_dual_action_pad },
    .{ .label = "Computer", .value = local_input.aim_scheme_computer },
};

const controls_rows_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
};
const controls_rows_p1_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
    .{ .label = "Reload:", .target = .global_reload_code },
};
const controls_rows_relative_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Forward:", .target = .player_move_codes, .target_index = 0 },
    .{ .label = "Backwards:", .target = .player_move_codes, .target_index = 1 },
    .{ .label = "Turn left:", .target = .player_move_codes, .target_index = 2 },
    .{ .label = "Turn right:", .target = .player_move_codes, .target_index = 3 },
};
const controls_rows_p1_relative_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Forward:", .target = .player_move_codes, .target_index = 0 },
    .{ .label = "Backwards:", .target = .player_move_codes, .target_index = 1 },
    .{ .label = "Turn left:", .target = .player_move_codes, .target_index = 2 },
    .{ .label = "Turn right:", .target = .player_move_codes, .target_index = 3 },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
    .{ .label = "Reload:", .target = .global_reload_code },
};
const controls_rows_static_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move Up:", .target = .player_move_codes, .target_index = 0 },
    .{ .label = "Move Down:", .target = .player_move_codes, .target_index = 1 },
    .{ .label = "Move Left:", .target = .player_move_codes, .target_index = 2 },
    .{ .label = "Move Right:", .target = .player_move_codes, .target_index = 3 },
};
const controls_rows_p1_static_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move Up:", .target = .player_move_codes, .target_index = 0 },
    .{ .label = "Move Down:", .target = .player_move_codes, .target_index = 1 },
    .{ .label = "Move Left:", .target = .player_move_codes, .target_index = 2 },
    .{ .label = "Move Right:", .target = .player_move_codes, .target_index = 3 },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
    .{ .label = "Reload:", .target = .global_reload_code },
};
const controls_rows_move_pad_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Up/Down Axis:", .target = .player_move_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Left/Right Axis:", .target = .player_move_axis_codes, .target_index = 1, .axis = true },
};
const controls_rows_p1_move_pad_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Up/Down Axis:", .target = .player_move_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Left/Right Axis:", .target = .player_move_axis_codes, .target_index = 1, .axis = true },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
    .{ .label = "Reload:", .target = .global_reload_code },
};
const controls_rows_mouseclick_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move to cursor:", .target = .global_reload_code },
};
const controls_rows_p1_mouseclick_default = [_]RebindRow{
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move to cursor:", .target = .global_reload_code },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
};
const controls_rows_other_keyboard = [_]RebindRow{
    .{ .label = "Torso left:", .target = .player_keyboard_aim_codes, .target_index = 0 },
    .{ .label = "Torso right:", .target = .player_keyboard_aim_codes, .target_index = 1 },
    .{ .label = "Fire:", .target = .player_fire_code },
};
const controls_rows_p1_other_keyboard = [_]RebindRow{
    .{ .label = "Torso left:", .target = .player_keyboard_aim_codes, .target_index = 0 },
    .{ .label = "Torso right:", .target = .player_keyboard_aim_codes, .target_index = 1 },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
    .{ .label = "Reload:", .target = .global_reload_code },
};
const controls_rows_relative_keyboard = [_]RebindRow{
    .{ .label = "Torso left:", .target = .player_keyboard_aim_codes, .target_index = 0 },
    .{ .label = "Torso right:", .target = .player_keyboard_aim_codes, .target_index = 1 },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Forward:", .target = .player_move_codes, .target_index = 0 },
    .{ .label = "Backwards:", .target = .player_move_codes, .target_index = 1 },
    .{ .label = "Turn left:", .target = .player_move_codes, .target_index = 2 },
    .{ .label = "Turn right:", .target = .player_move_codes, .target_index = 3 },
};
const controls_rows_p1_relative_keyboard = [_]RebindRow{
    .{ .label = "Torso left:", .target = .player_keyboard_aim_codes, .target_index = 0 },
    .{ .label = "Torso right:", .target = .player_keyboard_aim_codes, .target_index = 1 },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Forward:", .target = .player_move_codes, .target_index = 0 },
    .{ .label = "Backwards:", .target = .player_move_codes, .target_index = 1 },
    .{ .label = "Turn left:", .target = .player_move_codes, .target_index = 2 },
    .{ .label = "Turn right:", .target = .player_move_codes, .target_index = 3 },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
    .{ .label = "Reload:", .target = .global_reload_code },
};
const controls_rows_static_keyboard = [_]RebindRow{
    .{ .label = "Torso left:", .target = .player_keyboard_aim_codes, .target_index = 0 },
    .{ .label = "Torso right:", .target = .player_keyboard_aim_codes, .target_index = 1 },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move Up:", .target = .player_move_codes, .target_index = 0 },
    .{ .label = "Move Down:", .target = .player_move_codes, .target_index = 1 },
    .{ .label = "Move Left:", .target = .player_move_codes, .target_index = 2 },
    .{ .label = "Move Right:", .target = .player_move_codes, .target_index = 3 },
};
const controls_rows_p1_static_keyboard = [_]RebindRow{
    .{ .label = "Torso left:", .target = .player_keyboard_aim_codes, .target_index = 0 },
    .{ .label = "Torso right:", .target = .player_keyboard_aim_codes, .target_index = 1 },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move Up:", .target = .player_move_codes, .target_index = 0 },
    .{ .label = "Move Down:", .target = .player_move_codes, .target_index = 1 },
    .{ .label = "Move Left:", .target = .player_move_codes, .target_index = 2 },
    .{ .label = "Move Right:", .target = .player_move_codes, .target_index = 3 },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
    .{ .label = "Reload:", .target = .global_reload_code },
};
const controls_rows_dual_pad = [_]RebindRow{
    .{ .label = "Aim Up/Down Axis:", .target = .player_aim_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Aim Left/Right Axis:", .target = .player_aim_axis_codes, .target_index = 1, .axis = true },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Up/Down Axis:", .target = .player_move_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Left/Right Axis:", .target = .player_move_axis_codes, .target_index = 1, .axis = true },
};
const controls_rows_p1_dual_pad = [_]RebindRow{
    .{ .label = "Aim Up/Down Axis:", .target = .player_aim_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Aim Left/Right Axis:", .target = .player_aim_axis_codes, .target_index = 1, .axis = true },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Up/Down Axis:", .target = .player_move_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Left/Right Axis:", .target = .player_move_axis_codes, .target_index = 1, .axis = true },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
    .{ .label = "Reload:", .target = .global_reload_code },
};
const controls_rows_other_dual_pad = [_]RebindRow{
    .{ .label = "Aim Up/Down Axis:", .target = .player_aim_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Aim Left/Right Axis:", .target = .player_aim_axis_codes, .target_index = 1, .axis = true },
    .{ .label = "Fire:", .target = .player_fire_code },
};
const controls_rows_p1_other_dual_pad = [_]RebindRow{
    .{ .label = "Aim Up/Down Axis:", .target = .player_aim_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Aim Left/Right Axis:", .target = .player_aim_axis_codes, .target_index = 1, .axis = true },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
    .{ .label = "Reload:", .target = .global_reload_code },
};
const controls_rows_mouseclick_keyboard = [_]RebindRow{
    .{ .label = "Torso left:", .target = .player_keyboard_aim_codes, .target_index = 0 },
    .{ .label = "Torso right:", .target = .player_keyboard_aim_codes, .target_index = 1 },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move to cursor:", .target = .global_reload_code },
};
const controls_rows_p1_mouseclick_keyboard = [_]RebindRow{
    .{ .label = "Torso left:", .target = .player_keyboard_aim_codes, .target_index = 0 },
    .{ .label = "Torso right:", .target = .player_keyboard_aim_codes, .target_index = 1 },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move to cursor:", .target = .global_reload_code },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
};
const controls_rows_mouseclick_dual_pad = [_]RebindRow{
    .{ .label = "Aim Up/Down Axis:", .target = .player_aim_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Aim Left/Right Axis:", .target = .player_aim_axis_codes, .target_index = 1, .axis = true },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move to cursor:", .target = .global_reload_code },
};
const controls_rows_p1_mouseclick_dual_pad = [_]RebindRow{
    .{ .label = "Aim Up/Down Axis:", .target = .player_aim_axis_codes, .target_index = 0, .axis = true },
    .{ .label = "Aim Left/Right Axis:", .target = .player_aim_axis_codes, .target_index = 1, .axis = true },
    .{ .label = "Fire:", .target = .player_fire_code },
    .{ .label = "Move to cursor:", .target = .global_reload_code },
    .{ .label = "Level Up:", .target = .global_pick_perk_code },
};

fn bindBlockMoveValue(binds: *const formats.crimson_cfg.PlayerBindBlock, index: usize) i32 {
    return switch (index) {
        0 => binds.move_forward,
        1 => binds.move_backward,
        2 => binds.turn_left,
        3 => binds.turn_right,
        else => formats.crimson_cfg.keybind_unbound_code,
    };
}

fn setBindBlockMoveValue(binds: *formats.crimson_cfg.PlayerBindBlock, index: usize, value: i32) void {
    switch (index) {
        0 => binds.move_forward = value,
        1 => binds.move_backward = value,
        2 => binds.turn_left = value,
        3 => binds.turn_right = value,
        else => {},
    }
}

fn currentPlayerIndex(state: *const ControlsState) usize {
    return @min(state.player_index, 3);
}

fn setCurrentPlayerIndex(state: *ControlsState, value: usize) void {
    state.player_index = @min(value, 3);
}

fn openDropdown(state: *ControlsState, config: *const formats.crimson_cfg.CrimsonCfg, kind: DropdownKind, item_count: usize) void {
    state.open_dropdown = kind;
    if (item_count == 0) {
        state.dropdown_selection = 0;
        return;
    }
    state.dropdown_selection = switch (kind) {
        .player => currentPlayerIndex(state),
        .movement => movementItemIndex(config, currentPlayerIndex(state)),
        .aim => aimItemIndex(config, currentPlayerIndex(state)),
        .none => @min(state.dropdown_selection, item_count - 1),
    };
    if (state.dropdown_selection >= item_count) {
        state.dropdown_selection = item_count - 1;
    }
}
