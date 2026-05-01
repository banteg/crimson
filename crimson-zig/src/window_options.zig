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
const options_panel_rect = rl.Rectangle.init(360.0, 148.0, 510.0, 364.0);
const controls_left_panel_rect = rl.Rectangle.init(132.0, 174.0, 510.0, 254.0);
const controls_right_panel_rect = rl.Rectangle.init(598.0, 118.0, 510.0, 378.0);

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

const OptionSlider = enum {
    none,
    sfx,
    music,
    detail,
    mouse,
    resolution,
    bpp,
    texture_scale,
};

const OptionsPage = enum {
    gameplay,
    display,
};

const option_slider_labels = [_][]const u8{
    "Sound volume:",
    "Music volume:",
    "Graphics detail:",
    "Mouse sensitivity:",
};

const display_slider_labels = [_][]const u8{
    "Resolution:",
    "Color depth:",
    "Texture scale:",
};

const ResolutionPreset = struct {
    width: u32,
    height: u32,
    label: []const u8,
};

const resolution_presets = [_]ResolutionPreset{
    .{ .width = 800, .height = 600, .label = "800 x 600" },
    .{ .width = 1024, .height = 768, .label = "1024 x 768" },
    .{ .width = 1280, .height = 720, .label = "1280 x 720" },
    .{ .width = 1280, .height = 960, .label = "1280 x 960" },
    .{ .width = 1600, .height = 900, .label = "1600 x 900" },
    .{ .width = 1920, .height = 1080, .label = "1920 x 1080" },
};

const texture_scale_presets = [_]f32{ 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0, 4.0 };

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
    page: OptionsPage = .gameplay,
    active_slider: OptionSlider = .none,
    back_hover_amount: i32 = 0,

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
    back_hover_amount: i32 = 0,

    pub fn reset(self: *ControlsState) void {
        self.* = .{};
    }
};

const OptionButton = window_ui.UiButton;

pub fn updateOptions(state: *OptionsState, frame_dt: f32, config: *formats.crimson_cfg.CrimsonCfg, runtime_assets: ?*const window_assets.RuntimeAssets) OptionsUpdate {
    const dt_ms = state.panel.advance(frame_dt);
    const mouse = rl.getMousePosition();
    const click = rl.isMouseButtonPressed(.left);
    const mouse_down = rl.isMouseButtonDown(.left);
    const panel_rect = animatedLeftPanelRect(options_panel_rect, state.panel.timeline_ms);
    const back_hovered = if (runtime_assets) |assets|
        state.panel.timeline_ms >= panel_timeline_max_ms and rl.checkCollisionPointRec(mouse, window_menu.panelBackHitRect(assets, state.panel.timeline_ms))
    else
        false;

    if (back_hovered) {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount + dt_ms * 6, 0, 1000);
    } else {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount - dt_ms * 2, 0, 1000);
    }

    if (rl.isKeyPressed(.escape) or window_ui.confirmPressed() or (back_hovered and click)) {
        state.active_slider = .none;
        return .{ .action = .back_to_menu, .play_button_click = true };
    }

    var result: OptionsUpdate = .{
        .play_panel_click = dt_ms > 0 and state.panel.timeline_ms >= panel_timeline_max_ms and !state.panel.panel_open_sfx_played,
    };

    const display = displayButton(panel_rect);
    const gameplay = gameplayButton(panel_rect);
    if (state.page == .gameplay and click and rl.checkCollisionPointRec(mouse, display.rect)) {
        state.page = .display;
        state.active_slider = .none;
        result.play_button_click = true;
        return result;
    }
    if (state.page == .display and click and rl.checkCollisionPointRec(mouse, gameplay.rect)) {
        state.page = .gameplay;
        state.active_slider = .none;
        result.play_button_click = true;
        return result;
    }

    if (state.page == .display) {
        return updateDisplayOptions(state, config, panel_rect, mouse, click, mouse_down, result);
    }

    if (updateOptionSlider(state, .sfx, optionSliderRect(panel_rect, 265.0, 82.0, 10), 0, 10, if (config.sound_disable != 0) 0 else audioSliderValue(config.sfx_volume), mouse, click, mouse_down)) |value| {
        config.sfx_volume = @as(f32, @floatFromInt(value)) * 0.1;
        config.sound_disable = @intFromBool(value == 0);
        result.config_dirty = true;
        result.reload_audio = true;
        result.play_button_click = true;
    }
    if (updateOptionSlider(state, .music, optionSliderRect(panel_rect, 265.0, 116.0, 10), 0, 10, if (config.music_disable != 0) 0 else audioSliderValue(config.music_volume), mouse, click, mouse_down)) |value| {
        config.music_volume = @as(f32, @floatFromInt(value)) * 0.1;
        config.music_disable = @intFromBool(value == 0);
        result.config_dirty = true;
        result.reload_audio = true;
        result.play_button_click = true;
    }
    if (updateOptionSlider(state, .detail, optionSliderRect(panel_rect, 265.0, 150.0, 5), 1, 5, @intCast(std.math.clamp(config.detail_preset, @as(u32, 1), @as(u32, 5))), mouse, click, mouse_down)) |value| {
        _ = formats.crimson_cfg.applyDetailPreset(config, value);
        result.config_dirty = true;
        result.play_button_click = true;
    }
    if (updateOptionSlider(state, .mouse, optionSliderRect(panel_rect, 265.0, 184.0, 10), 1, 10, sensitivitySliderValue(config.mouse_sensitivity), mouse, click, mouse_down)) |value| {
        config.mouse_sensitivity = std.math.clamp(@as(f32, @floatFromInt(value)) * 0.1, @as(f32, 0.1), @as(f32, 1.0));
        result.config_dirty = true;
        result.play_button_click = true;
    }
    if (click and rectContains(optionCheckboxRect(panel_rect), mouse)) {
        config.ui_info_texts = if (config.ui_info_texts == 0) 1 else 0;
        result.config_dirty = true;
        result.play_button_click = true;
    }

    const controls = controlsButton(panel_rect);
    if (click and rl.checkCollisionPointRec(mouse, controls.rect)) {
        result.action = .open_controls;
        result.play_button_click = true;
    }

    return result;
}

fn updateDisplayOptions(
    state: *OptionsState,
    config: *formats.crimson_cfg.CrimsonCfg,
    panel_rect: rl.Rectangle,
    mouse: rl.Vector2,
    click: bool,
    mouse_down: bool,
    base_result: OptionsUpdate,
) OptionsUpdate {
    var result = base_result;

    if (updateOptionSlider(state, .resolution, optionSliderRect(panel_rect, 265.0, 88.0, @intCast(resolution_presets.len)), 1, @intCast(resolution_presets.len), @intCast(resolutionPresetIndex(config) + 1), mouse, click, mouse_down)) |value| {
        if (applyResolutionPreset(config, @intCast(value - 1))) {
            result.config_dirty = true;
            result.play_button_click = true;
        }
    }
    if (click and rectContains(windowModeRect(panel_rect), mouse)) {
        config.windowed_flag = if (config.windowed_flag == 0) 1 else 0;
        result.config_dirty = true;
        result.play_button_click = true;
    }
    if (updateOptionSlider(state, .bpp, optionSliderRect(panel_rect, 265.0, 160.0, 2), 1, 2, screenBppSliderValue(config), mouse, click, mouse_down)) |value| {
        const bpp = screenBppFromSliderValue(value);
        if (config.screen_bpp != bpp) {
            config.screen_bpp = bpp;
            result.config_dirty = true;
            result.play_button_click = true;
        }
    }
    if (updateOptionSlider(state, .texture_scale, optionSliderRect(panel_rect, 265.0, 196.0, @intCast(texture_scale_presets.len)), 1, @intCast(texture_scale_presets.len), @intCast(textureScalePresetIndex(config.texture_scale) + 1), mouse, click, mouse_down)) |value| {
        const scale = textureScaleFromSliderValue(value);
        if (config.texture_scale != scale) {
            config.texture_scale = scale;
            result.config_dirty = true;
            result.play_button_click = true;
        }
    }

    return result;
}

pub fn drawOptions(state: *const OptionsState, runtime_assets: ?*const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg) void {
    if (runtime_assets) |assets| {
        drawMenuPanelShellNoTitle(state.panel.timeline_ms, assets, options_panel_rect);
        drawOptionsContents(state, assets, config);
        return;
    }
    rl.clearBackground(rl.Color.init(37, 24, 20, 255));
}

pub fn updateControls(state: *ControlsState, frame_dt: f32, config: *formats.crimson_cfg.CrimsonCfg, runtime_assets: ?*const window_assets.RuntimeAssets) ControlsUpdate {
    const dt_ms = @as(i32, @intFromFloat(@min(frame_dt, 0.1) * 1000.0));
    if (dt_ms > 0) {
        state.timeline_ms = @min(panel_timeline_max_ms, state.timeline_ms + dt_ms);
    }
    const left_rect = animatedLeftPanelRect(controls_left_panel_rect, state.timeline_ms);
    const right_rect = animatedRightPanelRect(controls_right_panel_rect, state.timeline_ms);
    const mouse = rl.getMousePosition();
    const back_hovered = if (runtime_assets) |assets|
        state.timeline_ms >= panel_timeline_max_ms and rl.checkCollisionPointRec(mouse, window_menu.panelBackHitRect(assets, state.timeline_ms))
    else
        false;
    if (back_hovered) {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount + dt_ms * 6, 0, 1000);
    } else {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount - dt_ms * 2, 0, 1000);
    }

    if (state.rebinding_row_index != null) {
        return updateControlsRebinding(state, config);
    }

    if (rl.isKeyPressed(.escape) or window_ui.confirmPressed() or (back_hovered and rl.isMouseButtonPressed(.left))) {
        if (state.open_dropdown != .none) {
            state.open_dropdown = .none;
            return .{};
        }
        return .{ .action = .back_to_options, .play_button_click = true };
    }

    if (state.open_dropdown != .none) {
        return updateControlsDropdown(state, config, left_rect);
    }

    const button_count = leftControlButtonCount();
    const rebind_rows = controlsRebindRows(config, currentPlayerIndex(state));
    if (rebind_rows.len == 0) {
        state.right_selection = 0;
    } else if (state.right_selection >= rebind_rows.len) {
        state.right_selection = rebind_rows.len - 1;
    }

    updateControlsFocusFromPointer(state, rebind_rows[0..], left_rect, right_rect);

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
    const activated = window_ui.confirmPressed() or rl.isMouseButtonPressed(.left);

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
    const panel_rect = animatedLeftPanelRect(options_panel_rect, state.panel.timeline_ms);
    const controls = controlsButton(panel_rect);
    const display = displayButton(panel_rect);
    const gameplay = gameplayButton(panel_rect);
    const controls_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), controls.rect);
    const display_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), display.rect);
    const gameplay_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), gameplay.rect);

    if (state.page == .gameplay) {
        window_ui.drawButton(controls, false, controls_hovered, runtime_assets);
        window_ui.drawButton(display, false, display_hovered, runtime_assets);
    } else {
        window_ui.drawButton(gameplay, false, gameplay_hovered, runtime_assets);
    }

    const labels_tex = runtime_assets.texture(.ui_item_texts);
    rl.drawTexturePro(
        labels_tex,
        rl.Rectangle.init(0.0, @as(f32, @floatFromInt(window_menu.label_row_options)) * 32.0, 128.0, 32.0),
        rl.Rectangle.init(panel_rect.x + 212.0, panel_rect.y + 40.0, 128.0, 32.0),
        rl.Vector2.zero(),
        0.0,
        rl.Color.white,
    );

    if (state.page == .display) {
        drawDisplayOptionsContents(runtime_assets, panel_rect, config);
        window_menu.drawPanelBackEntry(runtime_assets, state.panel.timeline_ms, state.back_hover_amount);
        return;
    }

    for (option_slider_labels, 0..) |label, idx| {
        const hovered = switch (idx) {
            0 => rectContains(optionSliderRect(panel_rect, 265.0, 82.0, 10), rl.getMousePosition()),
            1 => rectContains(optionSliderRect(panel_rect, 265.0, 116.0, 10), rl.getMousePosition()),
            2 => rectContains(optionSliderRect(panel_rect, 265.0, 150.0, 5), rl.getMousePosition()),
            3 => rectContains(optionSliderRect(panel_rect, 265.0, 184.0, 10), rl.getMousePosition()),
            else => false,
        };
        window_ui.drawSmallText(runtime_assets, label, panel_rect.x + 60.0, panel_rect.y + 84.0 + @as(f32, @floatFromInt(idx)) * 34.0, if (hovered) text_color else muted_text);
    }

    drawSlider(runtime_assets, rl.Vector2.init(panel_rect.x + 265.0, panel_rect.y + 82.0), 10, if (config.sound_disable != 0) 0 else audioSliderValue(config.sfx_volume));
    drawSlider(runtime_assets, rl.Vector2.init(panel_rect.x + 265.0, panel_rect.y + 116.0), 10, if (config.music_disable != 0) 0 else audioSliderValue(config.music_volume));
    drawSlider(runtime_assets, rl.Vector2.init(panel_rect.x + 265.0, panel_rect.y + 150.0), 5, @intCast(std.math.clamp(config.detail_preset, @as(u32, 1), @as(u32, 5))));
    drawSlider(runtime_assets, rl.Vector2.init(panel_rect.x + 265.0, panel_rect.y + 184.0), 10, sensitivitySliderValue(config.mouse_sensitivity));

    const checkbox_tex: window_assets.TextureId = if (config.ui_info_texts != 0) .ui_check_on else .ui_check_off;
    window_ui.drawTextureFit(runtime_assets.texture(checkbox_tex), rl.Rectangle.init(panel_rect.x + 265.0, panel_rect.y + 230.0, 16.0, 16.0), rl.Color.white);
    window_ui.drawSmallText(runtime_assets, "UI Info texts", panel_rect.x + 287.0, panel_rect.y + 231.0, if (rectContains(optionCheckboxRect(panel_rect), rl.getMousePosition())) text_color else muted_text);
    window_menu.drawPanelBackEntry(runtime_assets, state.panel.timeline_ms, state.back_hover_amount);
}

fn drawDisplayOptionsContents(runtime_assets: *const window_assets.RuntimeAssets, panel_rect: rl.Rectangle, config: formats.crimson_cfg.CrimsonCfg) void {
    const mouse = rl.getMousePosition();
    const label_ys = [_]f32{ 90.0, 162.0, 198.0 };
    for (display_slider_labels, 0..) |label, idx| {
        const count: i32 = switch (idx) {
            0 => @intCast(resolution_presets.len),
            1 => 2,
            2 => @intCast(texture_scale_presets.len),
            else => 0,
        };
        const rel_y = label_ys[idx] - 2.0;
        const hovered = rectContains(optionSliderRect(panel_rect, 265.0, rel_y, count), mouse);
        window_ui.drawSmallText(runtime_assets, label, panel_rect.x + 60.0, panel_rect.y + label_ys[idx], if (hovered) text_color else muted_text);
    }

    drawSlider(runtime_assets, rl.Vector2.init(panel_rect.x + 265.0, panel_rect.y + 88.0), @intCast(resolution_presets.len), @intCast(resolutionPresetIndex(&config) + 1));
    drawSlider(runtime_assets, rl.Vector2.init(panel_rect.x + 265.0, panel_rect.y + 160.0), 2, screenBppSliderValue(&config));
    drawSlider(runtime_assets, rl.Vector2.init(panel_rect.x + 265.0, panel_rect.y + 196.0), @intCast(texture_scale_presets.len), @intCast(textureScalePresetIndex(config.texture_scale) + 1));

    var resolution_buf: [32]u8 = undefined;
    const resolution_text = resolutionValueText(&config, &resolution_buf);
    window_ui.drawSmallText(runtime_assets, resolution_text, panel_rect.x + 374.0, panel_rect.y + 90.0, value_color);

    const windowed_tex: window_assets.TextureId = if (config.windowed_flag != 0) .ui_check_on else .ui_check_off;
    window_ui.drawSmallText(runtime_assets, "Window mode:", panel_rect.x + 60.0, panel_rect.y + 126.0, if (rectContains(windowModeRect(panel_rect), mouse)) text_color else muted_text);
    window_ui.drawTextureFit(runtime_assets.texture(windowed_tex), rl.Rectangle.init(panel_rect.x + 265.0, panel_rect.y + 124.0, 16.0, 16.0), rl.Color.white);
    window_ui.drawSmallText(runtime_assets, if (config.windowed_flag != 0) "Windowed" else "Fullscreen", panel_rect.x + 287.0, panel_rect.y + 125.0, value_color);

    window_ui.drawSmallText(runtime_assets, if (screenBppSliderValue(&config) == 1) "16 bpp" else "32 bpp", panel_rect.x + 310.0, panel_rect.y + 162.0, value_color);

    var texture_scale_buf: [16]u8 = undefined;
    const scale_text = std.fmt.bufPrint(&texture_scale_buf, "{d:.2}", .{texture_scale_presets[textureScalePresetIndex(config.texture_scale)]}) catch "";
    window_ui.drawSmallText(runtime_assets, scale_text, panel_rect.x + 406.0, panel_rect.y + 198.0, value_color);
    window_ui.drawSmallText(runtime_assets, "Display changes apply on next launch.", panel_rect.x + 128.0, panel_rect.y + 238.0, muted_text);
}

fn drawControlsPanels(state: *const ControlsState, runtime_assets: *const window_assets.RuntimeAssets, config: formats.crimson_cfg.CrimsonCfg) void {
    const left_rect = animatedLeftPanelRect(controls_left_panel_rect, state.timeline_ms);
    const right_rect = animatedRightPanelRect(controls_right_panel_rect, state.timeline_ms);
    window_ui.drawClassicMenuPanel(runtime_assets.texture(.ui_menu_panel), left_rect, rl.Color.white, false);
    window_ui.drawClassicMenuPanel(runtime_assets.texture(.ui_menu_panel), right_rect, rl.Color.white, true);

    window_ui.drawTextureFit(runtime_assets.texture(.ui_text_controls), rl.Rectangle.init(left_rect.x + 206.0, left_rect.y + 44.0, 128.0, 32.0), rl.Color.white);
    window_ui.drawSmallText(runtime_assets, "Configured controls", right_rect.x + 120.0, right_rect.y + 38.0, text_color);
    rl.drawRectangle(
        @intFromFloat(right_rect.x + 120.0),
        @intFromFloat(right_rect.y + 51.0),
        @intFromFloat(window_ui.measureSmallText(runtime_assets, "Configured controls")),
        1,
        rl.Color.init(255, 255, 255, 204),
    );

    const player_idx = currentPlayerIndex(state);
    const player_rect = controlsDropdownRect(left_rect, 340.0, 56.0, dropdownWidth(player_items[0..], runtime_assets));
    drawDropdownLabel(runtime_assets, "Configure for:", left_rect.x + 339.0, left_rect.y + 41.0);
    drawDropdown(runtime_assets, player_rect, player_items[0..], player_idx, state.open_dropdown == .player, state.dropdown_selection);

    drawDropdownLabel(runtime_assets, "Aiming method:", left_rect.x + 213.0, left_rect.y + 86.0);
    const current_aim_items = aimItems(&config, player_idx);
    const aim_rect = controlsDropdownRect(left_rect, 214.0, 102.0, dropdownWidth(current_aim_items, runtime_assets));
    drawDropdown(runtime_assets, aim_rect, current_aim_items, aimItemIndex(&config, player_idx), state.open_dropdown == .aim, state.dropdown_selection);

    drawDropdownLabel(runtime_assets, "Moving method:", left_rect.x + 213.0, left_rect.y + 128.0);
    const move_rect = controlsDropdownRect(left_rect, 214.0, 144.0, dropdownWidth(movement_items[0..], runtime_assets));
    drawDropdown(runtime_assets, move_rect, movement_items[0..], movementItemIndex(&config, player_idx), state.open_dropdown == .movement, state.dropdown_selection);

    const direction_checked: window_assets.TextureId = if (formats.crimson_cfg.playerShowDirectionArrow(&config, player_idx)) .ui_check_on else .ui_check_off;
    window_ui.drawTextureFit(runtime_assets.texture(direction_checked), rl.Rectangle.init(left_rect.x + 213.0, left_rect.y + 174.0, 16.0, 16.0), rl.Color.white);
    window_ui.drawSmallText(runtime_assets, "Show direction arrow", left_rect.x + 235.0, left_rect.y + 175.0, if (state.left_selection == 3 and !state.focus_right) text_color else muted_text);
    window_menu.drawPanelBackEntry(runtime_assets, state.timeline_ms, state.back_hover_amount);

    const rows = controlsRebindRows(&config, player_idx);
    var y: f32 = right_rect.y + 82.0;
    for (rows, 0..) |row, idx| {
        const selected = state.focus_right and idx == state.right_selection;
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), rebindRect(right_rect, y));
        const color = if (state.rebinding_row_index != null and state.rebinding_row_index.? == idx) active_color else if (selected or hovered) value_color else value_dim;
        window_ui.drawSmallText(runtime_assets, row.label, right_rect.x + 52.0, y, muted_text);
        window_ui.drawSmallText(runtime_assets, bindingValueText(row, &config, player_idx, state.rebinding_row_index != null and state.rebinding_row_index.? == idx), right_rect.x + 180.0, y, color);
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
    window_ui.drawClassicMenuPanel(runtime_assets.texture(.ui_menu_panel), panel_rect, rl.Color.white, false);
    window_menu.drawAtlasLabelCentered(runtime_assets, title_row, panel_rect.y + 38.0, rl.Color.white);
}

fn drawMenuPanelShellNoTitle(timeline_ms: i32, runtime_assets: *const window_assets.RuntimeAssets, rect: rl.Rectangle) void {
    drawMenuBackdropAndSign(timeline_ms, runtime_assets);
    const anim = window_menu.uiElementAnim(1, panel_timeline_max_ms, 0, rect.width, timeline_ms);
    const panel_rect = rl.Rectangle.init(rect.x + anim.offset_x, rect.y, rect.width, rect.height);
    window_ui.drawClassicMenuPanel(runtime_assets.texture(.ui_menu_panel), panel_rect, rl.Color.white, false);
}

fn controlsButton(panel_rect: rl.Rectangle) OptionButton {
    return window_ui.buttonAt("Controls", panel_rect.x + 212.0, panel_rect.y + 252.0, true);
}

fn displayButton(panel_rect: rl.Rectangle) OptionButton {
    return window_ui.buttonAt("Display", panel_rect.x + 212.0, panel_rect.y + 288.0, true);
}

fn gameplayButton(panel_rect: rl.Rectangle) OptionButton {
    return window_ui.buttonAt("Gameplay", panel_rect.x + 212.0, panel_rect.y + 288.0, true);
}

fn controlsBackButton() OptionButton {
    return window_ui.buttonAt("Back", 182.0, 448.0, false);
}

fn optionSliderRect(panel_rect: rl.Rectangle, rel_x: f32, rel_y: f32, count: i32) rl.Rectangle {
    return rl.Rectangle.init(panel_rect.x + rel_x - 3.0, panel_rect.y + rel_y - 1.0, @as(f32, @floatFromInt(count * 16)) + 6.0, 18.0);
}

fn optionCheckboxRect(panel_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(panel_rect.x + 265.0, panel_rect.y + 230.0, 96.0, 16.0);
}

fn windowModeRect(panel_rect: rl.Rectangle) rl.Rectangle {
    return rl.Rectangle.init(panel_rect.x + 265.0, panel_rect.y + 124.0, 112.0, 16.0);
}

fn updateOptionSlider(
    state: *OptionsState,
    slider: OptionSlider,
    rect: rl.Rectangle,
    min_value: i32,
    max_value: i32,
    current_value: i32,
    mouse: rl.Vector2,
    click: bool,
    mouse_down: bool,
) ?i32 {
    const hovered = rectContains(rect, mouse);
    if (hovered and rl.isKeyPressed(.left)) return adjustOptionSliderValue(current_value, min_value, max_value, -1);
    if (hovered and rl.isKeyPressed(.right)) return adjustOptionSliderValue(current_value, min_value, max_value, 1);
    if (hovered and click) state.active_slider = slider;
    if (state.active_slider == slider and mouse_down) {
        const relative = mouse.x - (rect.x + 3.0);
        var idx = @as(i32, @intFromFloat(@floor(relative / 16.0))) + 1;
        idx = std.math.clamp(idx, min_value, max_value);
        return idx;
    }
    if (state.active_slider == slider and !mouse_down) state.active_slider = .none;
    return null;
}

fn adjustOptionSliderValue(current_value: i32, min_value: i32, max_value: i32, delta: i32) i32 {
    return std.math.clamp(current_value + delta, min_value, max_value);
}

fn audioSliderValue(value: f32) i32 {
    return @intFromFloat(std.math.clamp(value, @as(f32, 0.0), @as(f32, 1.0)) * 10.0);
}

fn sensitivitySliderValue(value: f32) i32 {
    return @intFromFloat(std.math.clamp(value, @as(f32, 0.1), @as(f32, 1.0)) * 10.0 + 0.5);
}

fn resolutionPresetIndex(config: *const formats.crimson_cfg.CrimsonCfg) usize {
    for (resolution_presets, 0..) |preset, idx| {
        if (preset.width == config.screen_width and preset.height == config.screen_height) return idx;
    }
    return 1;
}

fn applyResolutionPreset(config: *formats.crimson_cfg.CrimsonCfg, preset_index: usize) bool {
    const preset = resolution_presets[@min(preset_index, resolution_presets.len - 1)];
    if (config.screen_width == preset.width and config.screen_height == preset.height) return false;
    config.screen_width = preset.width;
    config.screen_height = preset.height;
    return true;
}

fn resolutionValueText(config: *const formats.crimson_cfg.CrimsonCfg, buffer: []u8) []const u8 {
    for (resolution_presets) |preset| {
        if (preset.width == config.screen_width and preset.height == config.screen_height) return preset.label;
    }
    return std.fmt.bufPrint(buffer, "{d} x {d}", .{ config.screen_width, config.screen_height }) catch "";
}

fn screenBppSliderValue(config: *const formats.crimson_cfg.CrimsonCfg) i32 {
    return if (config.screen_bpp == 16) 1 else 2;
}

fn screenBppFromSliderValue(value: i32) u32 {
    return if (value <= 1) 16 else 32;
}

fn textureScalePresetIndex(value: f32) usize {
    var best_index: usize = 0;
    var best_delta = @abs(value - texture_scale_presets[0]);
    for (texture_scale_presets[1..], 1..) |preset, idx| {
        const delta = @abs(value - preset);
        if (delta < best_delta) {
            best_delta = delta;
            best_index = idx;
        }
    }
    return best_index;
}

fn textureScaleFromSliderValue(value: i32) f32 {
    const idx: usize = @intCast(std.math.clamp(value - 1, 0, @as(i32, @intCast(texture_scale_presets.len - 1))));
    return texture_scale_presets[idx];
}

fn rectContains(rect: rl.Rectangle, point: rl.Vector2) bool {
    return point.x >= rect.x and point.x <= rect.x + rect.width and point.y >= rect.y and point.y <= rect.y + rect.height;
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

fn controlsDropdownRect(panel_rect: rl.Rectangle, rel_x: f32, rel_y: f32, width: f32) rl.Rectangle {
    return rl.Rectangle.init(panel_rect.x + rel_x, panel_rect.y + rel_y, width, 16.0);
}

fn dropdownWidth(items: []const DropdownItem, runtime_assets: ?*const window_assets.RuntimeAssets) f32 {
    var max_label_w: f32 = 0.0;
    for (items) |item| {
        const width = if (runtime_assets) |assets|
            window_ui.measureSmallText(assets, item.label)
        else
            approxTextWidth(item.label);
        max_label_w = @max(max_label_w, width);
    }
    return max_label_w + 48.0;
}

fn approxTextWidth(text: []const u8) f32 {
    var width: f32 = 0.0;
    for (text) |ch| {
        width += switch (ch) {
            'i', 'l', '!', '.', ',', '\'', ':' => 4.0,
            ' ' => 5.0,
            else => 8.0,
        };
    }
    return width;
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
    const active = open or hovered;
    const texture = if (active) runtime_assets.texture(.ui_drop_on) else runtime_assets.texture(.ui_drop_off);
    rl.drawRectangleRec(rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(rect.x + 1.0), @intFromFloat(rect.y + 1.0), @intFromFloat(rect.width - 2.0), @intFromFloat(rect.height - 2.0), rl.Color.black);
    if (active) {
        rl.drawRectangle(@intFromFloat(rect.x), @intFromFloat(rect.y + 15.0), @intFromFloat(rect.width), 1, rl.Color.init(255, 255, 255, 128));
    }
    const safe_index = @min(current_index, items.len - 1);
    window_ui.drawSmallText(runtime_assets, items[safe_index].label, rect.x + 4.0, rect.y + 1.0, rl.Color.init(255, 255, 255, if (active) 242 else 191));
    rl.drawTexturePro(texture, rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)), rl.Rectangle.init(rect.x + rect.width - 17.0, rect.y, 16.0, 16.0), rl.Vector2.zero(), 0.0, rl.Color.white);

    if (!open) return;
    const list_rect = rl.Rectangle.init(rect.x, rect.y, rect.width, 16.0 + 16.0 * @as(f32, @floatFromInt(items.len)));
    rl.drawRectangleRec(list_rect, rl.Color.white);
    rl.drawRectangle(@intFromFloat(list_rect.x + 1.0), @intFromFloat(list_rect.y + 1.0), @intFromFloat(list_rect.width - 2.0), @intFromFloat(list_rect.height - 2.0), rl.Color.black);
    for (items, 0..) |item, idx| {
        const row_y = rect.y + 17.0 + @as(f32, @floatFromInt(idx)) * 16.0;
        const row_rect = rl.Rectangle.init(rect.x, row_y, rect.width, 16.0);
        const row_hovered = rl.checkCollisionPointRec(rl.getMousePosition(), row_rect);
        const alpha: u8 = if (row_hovered) 242 else if (idx == dropdown_selection) 245 else 153;
        window_ui.drawSmallText(runtime_assets, item.label, rect.x + 4.0, row_y + 1.0, rl.Color.init(255, 255, 255, alpha));
    }
}

fn leftControlButtonCount() usize {
    return 4;
}

fn rebindRect(right_rect: rl.Rectangle, y: f32) rl.Rectangle {
    return rl.Rectangle.init(right_rect.x + 48.0, y - 2.0, 360.0, 18.0);
}

fn updateControlsFocusFromPointer(state: *ControlsState, rows: []const RebindRow, left_rect: rl.Rectangle, right_rect: rl.Rectangle) void {
    const mouse = rl.getMousePosition();
    const left_rects = [_]rl.Rectangle{
        controlsDropdownRect(left_rect, 340.0, 56.0, dropdownWidth(player_items[0..], null)),
        controlsDropdownRect(left_rect, 214.0, 102.0, dropdownWidth(aim_items_with_computer[0..], null)),
        controlsDropdownRect(left_rect, 214.0, 144.0, dropdownWidth(movement_items[0..], null)),
        rl.Rectangle.init(left_rect.x + 213.0, left_rect.y + 174.0, 220.0, 20.0),
    };
    for (left_rects, 0..) |rect, idx| {
        if (rl.checkCollisionPointRec(mouse, rect)) {
            state.focus_right = false;
            state.left_selection = idx;
            return;
        }
    }
    for (rows, 0..) |row, row_idx| {
        _ = row;
        if (rl.checkCollisionPointRec(mouse, rebindRect(right_rect, right_rect.y + 82.0 + @as(f32, @floatFromInt(row_idx)) * 24.0))) {
            state.focus_right = true;
            state.right_selection = row_idx;
            return;
        }
    }
}

fn updateControlsDropdown(state: *ControlsState, config: *formats.crimson_cfg.CrimsonCfg, left_rect: rl.Rectangle) ControlsUpdate {
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
        .player => controlsDropdownRect(left_rect, 340.0, 56.0, dropdownWidth(player_items[0..], null)),
        .movement => controlsDropdownRect(left_rect, 214.0, 144.0, dropdownWidth(movement_items[0..], null)),
        .aim => controlsDropdownRect(left_rect, 214.0, 102.0, dropdownWidth(items, null)),
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

    if (window_ui.confirmPressed()) {
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

fn animatedLeftPanelRect(rect: rl.Rectangle, timeline_ms: i32) rl.Rectangle {
    const anim = window_menu.uiElementAnim(1, panel_timeline_max_ms, 0, rect.width, timeline_ms);
    return rl.Rectangle.init(rect.x + anim.offset_x, rect.y, rect.width, rect.height);
}

fn animatedRightPanelRect(rect: rl.Rectangle, timeline_ms: i32) rl.Rectangle {
    const anim = window_menu.uiElementAnim(1, panel_timeline_max_ms, 0, rect.width, timeline_ms);
    return rl.Rectangle.init(rect.x - anim.offset_x, rect.y, rect.width, rect.height);
}

test "options panel slider labels do not duplicate checkbox label" {
    try std.testing.expectEqual(@as(usize, 4), option_slider_labels.len);
    for (option_slider_labels) |label| {
        try std.testing.expect(!std.mem.eql(u8, label, "UI Info texts"));
    }
}

test "option slider keyboard adjustment clamps to slider bounds" {
    try std.testing.expectEqual(@as(i32, 0), adjustOptionSliderValue(0, 0, 10, -1));
    try std.testing.expectEqual(@as(i32, 1), adjustOptionSliderValue(0, 0, 10, 1));
    try std.testing.expectEqual(@as(i32, 10), adjustOptionSliderValue(10, 0, 10, 1));
    try std.testing.expectEqual(@as(i32, 1), adjustOptionSliderValue(1, 1, 5, -1));
}

test "audio slider value truncates and clamps normalized volumes" {
    try std.testing.expectEqual(@as(i32, 0), audioSliderValue(-0.5));
    try std.testing.expectEqual(@as(i32, 2), audioSliderValue(0.26));
    try std.testing.expectEqual(@as(i32, 10), audioSliderValue(1.5));
}

test "sensitivity slider value rounds and clamps normalized values" {
    try std.testing.expectEqual(@as(i32, 1), sensitivitySliderValue(-0.5));
    try std.testing.expectEqual(@as(i32, 3), sensitivitySliderValue(0.26));
    try std.testing.expectEqual(@as(i32, 10), sensitivitySliderValue(1.5));
}

test "display option helpers update persisted config fields" {
    var cfg = formats.crimson_cfg.defaultConfig();

    try std.testing.expectEqual(@as(usize, 1), resolutionPresetIndex(&cfg));
    try std.testing.expect(applyResolutionPreset(&cfg, 2));
    try std.testing.expectEqual(@as(u32, 1280), cfg.screen_width);
    try std.testing.expectEqual(@as(u32, 720), cfg.screen_height);
    try std.testing.expect(!applyResolutionPreset(&cfg, 2));

    cfg.windowed_flag = 1;
    cfg.windowed_flag = if (cfg.windowed_flag == 0) 1 else 0;
    try std.testing.expectEqual(@as(u8, 0), cfg.windowed_flag);

    try std.testing.expectEqual(@as(i32, 2), screenBppSliderValue(&cfg));
    cfg.screen_bpp = screenBppFromSliderValue(1);
    try std.testing.expectEqual(@as(u32, 16), cfg.screen_bpp);
    cfg.screen_bpp = screenBppFromSliderValue(2);
    try std.testing.expectEqual(@as(u32, 32), cfg.screen_bpp);

    cfg.texture_scale = textureScaleFromSliderValue(6);
    try std.testing.expectEqual(@as(f32, 2.0), cfg.texture_scale);
    try std.testing.expectEqual(@as(usize, 5), textureScalePresetIndex(cfg.texture_scale));
}
