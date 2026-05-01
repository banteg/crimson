const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const formats = cz.formats;
const game_ids = cz.game_ids;
const live_runner = cz.live_runner;
const runtime_perks = cz.perks;
const input_codes = @import("input_codes.zig");
const window_assets = @import("window_assets.zig");
const window_ui = @import("window_ui.zig");

pub const perk_menu_transition_ms: f32 = 400.0;
const perk_menu_anim_end_ms: f32 = 100.0;
const perk_prompt_max_timer_ms: f32 = 200.0;

const menu_panel_pos_x: f32 = -108.0;
const menu_panel_pos_y: f32 = 29.0;
const menu_panel_width: f32 = 510.0;
const menu_panel_height: f32 = 378.0;
const menu_panel_anchor_x: f32 = 224.0;
const menu_panel_anchor_y: f32 = 40.0;
const menu_title_x: f32 = 54.0;
const menu_title_y: f32 = 6.0;
const menu_title_w: f32 = 128.0;
const menu_title_h: f32 = 32.0;
const menu_sponsor_y: f32 = -8.0;
const menu_sponsor_x_expert: f32 = -26.0;
const menu_sponsor_x_master: f32 = -28.0;
const menu_list_y_normal: f32 = 50.0;
const menu_list_y_expert: f32 = 40.0;
const menu_list_step_normal: f32 = 19.0;
const menu_list_step_expert: f32 = 18.0;
const menu_desc_x: f32 = -12.0;
const menu_desc_y_after_list: f32 = 32.0;
const menu_desc_y_extra_tighten: f32 = 20.0;
const menu_button_x: f32 = 162.0;
const menu_button_y: f32 = 276.0;
const menu_desc_right_x: f32 = 480.0;

const perk_prompt_outset_x: f32 = 50.0;
const perk_prompt_bar_scale: f32 = 0.75;
const perk_prompt_bar_base_offset_x: f32 = -72.0;
const perk_prompt_bar_base_offset_y: f32 = -60.0;
const perk_prompt_bar_shift_x: f32 = -300.0;
const perk_prompt_level_up_scale: f32 = 0.85;
const perk_prompt_level_up_base_offset_x: f32 = -230.0;
const perk_prompt_level_up_base_offset_y: f32 = -27.0;
const perk_prompt_level_up_base_w: f32 = 75.0;
const perk_prompt_level_up_base_h: f32 = 25.0;
const perk_prompt_level_up_shift_x: f32 = -46.0;
const perk_prompt_level_up_shift_y: f32 = -4.0;
const perk_prompt_text_margin_x: f32 = 16.0;
const perk_prompt_text_offset_y: f32 = 8.0;

const menu_item_rgb = .{ .r = 0x46, .g = 0xB4, .b = 0xF0 };
const menu_item_alpha_idle: f32 = 0.6;
const menu_item_alpha_hover: f32 = 1.0;
const text_color = rl.Color.init(220, 220, 220, 255);
const sponsor_color = rl.Color.init(255, 255, 255, 127);

const UiButtonState = struct {
    label: [:0]const u8 = "Cancel",
    enabled: bool = true,
    hovered: bool = false,
    activated: bool = false,
    hover_t: i32 = 0,
    press_t: i32 = 0,
    alpha: f32 = 1.0,
    force_wide: bool = false,
};

pub const State = struct {
    prompt_timer_ms: f32 = 0.0,
    prompt_hover: bool = false,
    prompt_pulse: f32 = 0.0,
    menu_open: bool = false,
    selected_index: usize = 0,
    timeline_ms: f32 = 0.0,
    cancel_button: UiButtonState = .{},

    pub fn reset(self: *State) void {
        self.* = .{};
    }

    pub fn active(self: *const State) bool {
        return self.menu_open or self.timeline_ms > 1e-3;
    }
};

pub const UpdateResult = struct {
    perk_choice_index: ?i32 = null,
    play_panel_click: bool = false,
    play_button_click: bool = false,
    menu_active: bool = false,
};

const ComputedLayout = struct {
    panel: rl.Rectangle,
    title: rl.Rectangle,
    sponsor_pos: rl.Vector2,
    list_pos: rl.Vector2,
    list_step_y: f32,
    desc: rl.Rectangle,
    cancel_pos: rl.Vector2,
};

pub fn update(
    state: *State,
    frame_dt: f32,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    config: *const formats.crimson_cfg.CrimsonCfg,
    runner: *live_runner.LiveRunner,
    any_alive: bool,
) UpdateResult {
    const dt_ui_ms = @min(@max(frame_dt, 0.0), 0.1) * 1000.0;
    const pending_count = runner.perkPendingCount();
    _ = runner.player0Const() orelse {
        state.reset();
        return .{};
    };

    if (pending_count <= 0 or !any_alive) {
        state.menu_open = false;
        state.prompt_hover = false;
        state.prompt_timer_ms = clampf(state.prompt_timer_ms - dt_ui_ms, 0.0, perk_prompt_max_timer_ms);
        state.prompt_pulse = clampf(state.prompt_pulse - dt_ui_ms * 2.0, 0.0, 1000.0);
        state.timeline_ms = clampf(state.timeline_ms - dt_ui_ms, 0.0, perk_menu_transition_ms);
        return .{ .menu_active = state.active() };
    }

    const choices = runner.preparedPerkChoices();
    if (state.selected_index >= choices.len) state.selected_index = 0;
    if (state.menu_open and choices.len == 0) {
        closeMenu(state, pending_count);
    }

    var result: UpdateResult = .{};
    state.prompt_hover = false;

    if (state.menu_open and choices.len > 0) {
        if (rl.isKeyPressed(.escape)) {
            closeMenu(state, pending_count);
        } else {
            result = updateMenuInput(state, runtime_assets, config, runner, choices, dt_ui_ms);
        }
    } else {
        if (promptOpenRequested(state, runtime_assets, config, runner) and runner.openPerkMenu().len > 0) {
            state.menu_open = true;
            state.selected_index = 0;
            result.play_panel_click = true;
        }
    }

    const prompt_visible = pending_count > 0 and any_alive and !state.active();
    const timer_delta: f32 = if (prompt_visible) dt_ui_ms else -dt_ui_ms;
    state.prompt_timer_ms = clampf(state.prompt_timer_ms + timer_delta, 0.0, perk_prompt_max_timer_ms);
    const pulse_delta = dt_ui_ms * (if (state.prompt_hover) @as(f32, 6.0) else @as(f32, -2.0));
    state.prompt_pulse = clampf(state.prompt_pulse + pulse_delta, 0.0, 1000.0);
    const timeline_delta: f32 = if (state.menu_open) dt_ui_ms else -dt_ui_ms;
    state.timeline_ms = clampf(state.timeline_ms + timeline_delta, 0.0, perk_menu_transition_ms);
    result.menu_active = state.active();
    return result;
}

pub fn drawPrompt(
    state: *const State,
    runtime_assets: *const window_assets.RuntimeAssets,
    config: *const formats.crimson_cfg.CrimsonCfg,
    pending_count: i32,
) void {
    var label_buf: [64]u8 = undefined;
    const label = promptLabel(config, pending_count, &label_buf);
    if (label.len == 0) return;

    const alpha = state.prompt_timer_ms / perk_prompt_max_timer_ms;
    if (alpha <= 1e-3) return;

    const hinge = promptHinge();
    const rot_deg = -(1.0 - alpha) * 90.0;
    const tint = rl.Color.init(255, 255, 255, alphaByte(alpha));

    const text_w = window_ui.measureSmallText(runtime_assets, label);
    const x = @as(f32, @floatFromInt(rl.getScreenWidth())) - perk_prompt_text_margin_x - text_w;
    const y = hinge.y + perk_prompt_text_offset_y;
    window_ui.drawSmallText(runtime_assets, label, x, y, rl.Color.init(text_color.r, text_color.g, text_color.b, alphaByte(alpha)));

    const bar = runtime_assets.texture(.ui_menu_item);
    const bar_w = @as(f32, @floatFromInt(bar.width)) * perk_prompt_bar_scale;
    const bar_h = @as(f32, @floatFromInt(bar.height)) * perk_prompt_bar_scale;
    const local_x = (perk_prompt_bar_base_offset_x + perk_prompt_bar_shift_x) * perk_prompt_bar_scale;
    const local_y = perk_prompt_bar_base_offset_y * perk_prompt_bar_scale;
    rl.drawTexturePro(
        bar,
        rl.Rectangle.init(0.0, 0.0, -@as(f32, @floatFromInt(bar.width)), @as(f32, @floatFromInt(bar.height))),
        rl.Rectangle.init(hinge.x, hinge.y, bar_w, bar_h),
        rl.Vector2.init(-local_x, -local_y),
        rot_deg,
        tint,
    );

    const level_up = runtime_assets.texture(.ui_text_level_up);
    const level_local_x = perk_prompt_level_up_base_offset_x * perk_prompt_level_up_scale + perk_prompt_level_up_shift_x;
    const level_local_y = perk_prompt_level_up_base_offset_y * perk_prompt_level_up_scale + perk_prompt_level_up_shift_y;
    const level_w = perk_prompt_level_up_base_w * perk_prompt_level_up_scale;
    const level_h = perk_prompt_level_up_base_h * perk_prompt_level_up_scale;
    const pulse_alpha = clampf(alpha * ((100.0 + state.prompt_pulse * 0.155) / 255.0), 0.0, 1.0);
    const pulse_tint = rl.Color.init(255, 255, 255, alphaByte(pulse_alpha));
    const src = rl.Rectangle.init(0.0, 0.0, @floatFromInt(level_up.width), @floatFromInt(level_up.height));
    const dst = rl.Rectangle.init(hinge.x, hinge.y, level_w, level_h);
    const origin = rl.Vector2.init(-level_local_x, -level_local_y);
    rl.drawTexturePro(level_up, src, dst, origin, rot_deg, pulse_tint);
    if (pulse_alpha > 1e-3) {
        rl.beginBlendMode(.additive);
        rl.drawTexturePro(level_up, src, dst, origin, rot_deg, pulse_tint);
        rl.endBlendMode();
    }
}

pub fn drawMenu(
    state: *const State,
    runtime_assets: *const window_assets.RuntimeAssets,
    config: *const formats.crimson_cfg.CrimsonCfg,
    runner: *live_runner.LiveRunner,
) void {
    const menu_t = clampf(state.timeline_ms / perk_menu_transition_ms, 0.0, 1.0);
    if (menu_t <= 1e-3) return;

    const player = runner.player0Const() orelse return;
    const choices = runner.preparedPerkChoices();
    if (choices.len == 0) return;
    const selected_index = @min(state.selected_index, choices.len - 1);
    const expert_owned = runtime_perks.perkActive(player, .perk_expert);
    const master_owned = runtime_perks.perkActive(player, .perk_master);
    const layout = computeLayout(state, expert_owned, master_owned, choices.len);

    window_ui.drawClassicMenuPanel(runtime_assets.texture(.ui_menu_panel), layout.panel, rl.Color.white, false);
    window_ui.drawTextureFit(runtime_assets.texture(.ui_text_pick_a_perk), layout.title, rl.Color.white);

    if (master_owned) {
        window_ui.drawSmallText(runtime_assets, "extra perks sponsored by the Perk Master", layout.sponsor_pos.x, layout.sponsor_pos.y, sponsor_color);
    } else if (expert_owned) {
        window_ui.drawSmallText(runtime_assets, "extra perk sponsored by the Perk Expert", layout.sponsor_pos.x, layout.sponsor_pos.y, sponsor_color);
    }

    for (choices, 0..) |perk_id, idx| {
        const label = game_ids.perkDisplayName(perk_id, config.gore_disabled, runner.session.state.preserve_bugs);
        const pos = rl.Vector2.init(layout.list_pos.x, layout.list_pos.y + @as(f32, @floatFromInt(idx)) * layout.list_step_y);
        const hovered = rl.checkCollisionPointRec(rl.getMousePosition(), menuItemHitRect(runtime_assets, label, pos)) or idx == selected_index;
        drawMenuItem(runtime_assets, label, pos, hovered);
    }

    const selected = choices[selected_index];
    const desc = game_ids.perkDisplayDescription(selected, config.gore_disabled, runner.session.state.preserve_bugs);
    var wrapped_buf: [2048]u8 = undefined;
    const wrapped = wrapSmallTextNative(runtime_assets, desc, layout.desc.width, wrapped_buf[0..]);
    window_ui.drawSmallText(runtime_assets, wrapped, layout.desc.x, layout.desc.y, text_color);

    drawButton(runtime_assets, state.cancel_button, layout.cancel_pos);
}

fn updateMenuInput(
    state: *State,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    config: *const formats.crimson_cfg.CrimsonCfg,
    runner: *live_runner.LiveRunner,
    choices: []const game_ids.PerkId,
    dt_ui_ms: f32,
) UpdateResult {
    var result: UpdateResult = .{};
    const assets = runtime_assets orelse return result;
    if (choices.len == 0) return result;

    if (rl.isKeyPressed(.down)) {
        state.selected_index = (state.selected_index + 1) % choices.len;
    }
    if (rl.isKeyPressed(.up)) {
        state.selected_index = if (state.selected_index == 0) choices.len - 1 else state.selected_index - 1;
    }

    const player = runner.player0Const().?;
    const expert_owned = runtime_perks.perkActive(player, .perk_expert);
    const master_owned = runtime_perks.perkActive(player, .perk_master);
    const layout = computeLayout(state, expert_owned, master_owned, choices.len);
    const click = rl.isMouseButtonPressed(.left);

    for (choices, 0..) |perk_id, idx| {
        const label = game_ids.perkDisplayName(perk_id, config.gore_disabled, runner.session.state.preserve_bugs);
        const item_pos = rl.Vector2.init(layout.list_pos.x, layout.list_pos.y + @as(f32, @floatFromInt(idx)) * layout.list_step_y);
        const rect = menuItemHitRect(assets, label, item_pos);
        if (rl.checkCollisionPointRec(rl.getMousePosition(), rect)) {
            state.selected_index = idx;
            if (click) {
                closeMenu(state, runner.perkPendingCount());
                result.perk_choice_index = @intCast(idx);
                result.play_button_click = true;
            }
            break;
        }
    }

    const cancel_w = buttonWidth(assets, state.cancel_button.label, state.cancel_button.force_wide);
    if (buttonUpdate(&state.cancel_button, layout.cancel_pos, cancel_w, dt_ui_ms, rl.getMousePosition(), click)) {
        closeMenu(state, runner.perkPendingCount());
        result.play_button_click = true;
        return result;
    }

    if (window_ui.confirmPressed()) {
        closeMenu(state, runner.perkPendingCount());
        result.perk_choice_index = @intCast(state.selected_index);
        result.play_button_click = true;
    }
    return result;
}

fn computeLayout(
    state: *const State,
    expert_owned: bool,
    master_owned: bool,
    choice_count: usize,
) ComputedLayout {
    const panel_slide_x = panelSlideX(state.timeline_ms, menu_panel_width);
    const panel_pos_y = menu_panel_pos_y + menuWidescreenYShift(@as(f32, @floatFromInt(rl.getScreenWidth())));
    const panel = rl.Rectangle.init(
        menu_panel_pos_x + panel_slide_x,
        panel_pos_y,
        menu_panel_width,
        menu_panel_height,
    );
    const anchor_x = panel.x + menu_panel_anchor_x;
    const anchor_y = panel.y + menu_panel_anchor_y;
    const title = rl.Rectangle.init(anchor_x + menu_title_x, anchor_y + menu_title_y, menu_title_w, menu_title_h);
    const sponsor_pos = rl.Vector2.init(
        anchor_x + (if (master_owned) menu_sponsor_x_master else menu_sponsor_x_expert),
        anchor_y + menu_sponsor_y,
    );
    const list_step = if (expert_owned) menu_list_step_expert else menu_list_step_normal;
    const list_pos = rl.Vector2.init(
        anchor_x,
        anchor_y + (if (expert_owned) menu_list_y_expert else menu_list_y_normal),
    );
    var desc_y = list_pos.y + @as(f32, @floatFromInt(choice_count)) * list_step + menu_desc_y_after_list;
    if (choice_count > 5) desc_y -= menu_desc_y_extra_tighten;
    const cancel_pos = rl.Vector2.init(anchor_x + menu_button_x, anchor_y + menu_button_y);
    const desc = rl.Rectangle.init(
        anchor_x + menu_desc_x,
        desc_y,
        @max(0.0, panel.x + menu_desc_right_x - (anchor_x + menu_desc_x)),
        @max(0.0, cancel_pos.y - 12.0 - desc_y),
    );
    return .{
        .panel = panel,
        .title = title,
        .sponsor_pos = sponsor_pos,
        .list_pos = list_pos,
        .list_step_y = list_step,
        .desc = desc,
        .cancel_pos = cancel_pos,
    };
}

fn promptOpenRequested(
    state: *State,
    runtime_assets: ?*const window_assets.RuntimeAssets,
    config: *const formats.crimson_cfg.CrimsonCfg,
    runner: *live_runner.LiveRunner,
) bool {
    var label_buf: [64]u8 = undefined;
    const label = promptLabel(config, runner.perkPendingCount(), &label_buf);
    if (label.len > 0 and runtime_assets != null) {
        state.prompt_hover = rl.checkCollisionPointRec(rl.getMousePosition(), promptRect(runtime_assets.?));
    }
    const player_bind = formats.crimson_cfg.playerBindBlock(config, 0);
    const pick_code: i32 = @bitCast(config.keybind_pick_perk);
    const fire_code: i32 = @bitCast(player_bind.fire);
    if (input_codes.inputCodeIsPressed(pick_code, 0) and !input_codes.inputCodeIsDown(fire_code, 0)) {
        state.prompt_pulse = 1000.0;
        return true;
    }

    var fire_codes: [4]i32 = [_]i32{input_codes.input_code_unbound} ** 4;
    const player_count = std.math.clamp(runner.session.player_count, 1, 4);
    var idx: usize = 0;
    while (idx < @as(usize, @intCast(player_count))) : (idx += 1) {
        fire_codes[idx] = @bitCast(formats.crimson_cfg.playerBindBlock(config, idx).fire);
    }
    if (state.prompt_hover and input_codes.inputPrimaryJustPressed(fire_codes[0..], player_count)) {
        state.prompt_pulse = 1000.0;
        return true;
    }
    return false;
}

fn closeMenu(state: *State, pending_count: i32) void {
    state.menu_open = false;
    if (pending_count > 0) {
        state.prompt_timer_ms = 0.0;
        state.prompt_hover = false;
        state.prompt_pulse = 0.0;
    }
}

fn promptLabel(config: *const formats.crimson_cfg.CrimsonCfg, pending_count: i32, buf: []u8) []const u8 {
    if (config.ui_info_texts == 0 or pending_count <= 0) return "";
    if (pending_count == 1) return "Press Mouse2 to pick a perk";
    return std.fmt.bufPrint(buf, "Press Mouse2 to pick a perk ({d})", .{pending_count}) catch "Press Mouse2 to pick a perk";
}

fn promptHinge() rl.Vector2 {
    const screen_w = @as(f32, @floatFromInt(rl.getScreenWidth()));
    return rl.Vector2.init(screen_w + perk_prompt_outset_x, if (rl.getScreenWidth() == 640) 80.0 else 40.0);
}

fn promptRect(runtime_assets: *const window_assets.RuntimeAssets) rl.Rectangle {
    const hinge = promptHinge();
    const tex = runtime_assets.texture(.ui_menu_item);
    const bar_w = @as(f32, @floatFromInt(tex.width)) * perk_prompt_bar_scale;
    const bar_h = @as(f32, @floatFromInt(tex.height)) * perk_prompt_bar_scale;
    const local_x = (perk_prompt_bar_base_offset_x + perk_prompt_bar_shift_x) * perk_prompt_bar_scale;
    const local_y = perk_prompt_bar_base_offset_y * perk_prompt_bar_scale;
    return rl.Rectangle.init(hinge.x + local_x, hinge.y + local_y, bar_w, bar_h);
}

fn menuWidescreenYShift(layout_w: f32) f32 {
    return (layout_w / 640.0) * 150.0 - 150.0;
}

fn panelSlideX(t_ms: f32, width: f32) f32 {
    if (!(perk_menu_transition_ms > perk_menu_anim_end_ms) or !(width > 0.0)) return 0.0;
    if (t_ms < perk_menu_anim_end_ms) return -width;
    if (t_ms < perk_menu_transition_ms) {
        const p = (t_ms - perk_menu_anim_end_ms) / (perk_menu_transition_ms - perk_menu_anim_end_ms);
        return -(1.0 - p) * width;
    }
    return 0.0;
}

fn menuItemHitRect(runtime_assets: *const window_assets.RuntimeAssets, label: []const u8, pos: rl.Vector2) rl.Rectangle {
    return rl.Rectangle.init(pos.x, pos.y, window_ui.measureSmallText(runtime_assets, label), 16.0);
}

fn drawMenuItem(runtime_assets: *const window_assets.RuntimeAssets, label: []const u8, pos: rl.Vector2, hovered: bool) void {
    const alpha: f32 = if (hovered) menu_item_alpha_hover else menu_item_alpha_idle;
    const color = rl.Color.init(menu_item_rgb.r, menu_item_rgb.g, menu_item_rgb.b, alphaByte(alpha));
    window_ui.drawSmallText(runtime_assets, label, pos.x, pos.y, color);
    const width = window_ui.measureSmallText(runtime_assets, label);
    const line_y = pos.y + 13.0;
    rl.drawLine(@intFromFloat(pos.x), @intFromFloat(line_y), @intFromFloat(pos.x + width), @intFromFloat(line_y), color);
}

fn buttonWidth(runtime_assets: *const window_assets.RuntimeAssets, label: []const u8, force_wide: bool) f32 {
    const text_w = window_ui.measureSmallText(runtime_assets, label);
    if (force_wide) return 145.0;
    if (text_w < 40.0) return 82.0;
    return 145.0;
}

fn buttonHitRect(pos: rl.Vector2, width: f32) rl.Rectangle {
    return rl.Rectangle.init(pos.x, pos.y + 2.0, width, 28.0);
}

fn buttonUpdate(
    state: *UiButtonState,
    pos: rl.Vector2,
    width: f32,
    dt_ms: f32,
    mouse: rl.Vector2,
    click: bool,
) bool {
    state.hovered = state.enabled and rl.checkCollisionPointRec(mouse, buttonHitRect(pos, width));
    const delta: i32 = if (state.enabled and state.hovered) 6 else -4;
    state.hover_t = @intFromFloat(clampf(@as(f32, @floatFromInt(state.hover_t)) + dt_ms * @as(f32, @floatFromInt(delta)), 0.0, 1000.0));
    if (state.press_t > 0) {
        state.press_t = @intFromFloat(clampf(@as(f32, @floatFromInt(state.press_t)) - dt_ms * 6.0, 0.0, 1000.0));
    }
    state.activated = state.enabled and state.hovered and click;
    if (state.activated) state.press_t = 1000;
    return state.activated;
}

fn drawButton(runtime_assets: *const window_assets.RuntimeAssets, state: UiButtonState, pos: rl.Vector2) void {
    const width = buttonWidth(runtime_assets, state.label, state.force_wide);
    const texture = if (width > 120.0) runtime_assets.texture(.ui_button_md) else runtime_assets.texture(.ui_button_sm);
    if (state.hover_t > 0) {
        var r: f32 = 0.5;
        var g: f32 = 0.5;
        var b: f32 = 0.7;
        if (state.press_t > 0) {
            const click_t = @as(f32, @floatFromInt(state.press_t));
            g = @min(1.0, 0.5 + click_t * 0.0005);
            r = g;
            b = @min(1.0, 0.7 + click_t * 0.0007);
        }
        const a = @as(f32, @floatFromInt(state.hover_t)) * 0.001 * state.alpha;
        rl.drawRectangle(
            @intFromFloat(pos.x + 12.0),
            @intFromFloat(pos.y + 5.0),
            @intFromFloat(width - 24.0),
            22,
            rl.Color.init(alphaByte(r), alphaByte(g), alphaByte(b), alphaByte(a)),
        );
    }
    rl.drawTexturePro(
        texture,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)),
        rl.Rectangle.init(pos.x, pos.y, width, 32.0),
        rl.Vector2.zero(),
        0.0,
        rl.Color.init(255, 255, 255, alphaByte(state.alpha)),
    );
    const text_alpha: f32 = if (state.hovered) state.alpha else state.alpha * 0.7;
    const text_w = window_ui.measureSmallText(runtime_assets, state.label);
    window_ui.drawSmallText(
        runtime_assets,
        state.label,
        pos.x + width * 0.5 - text_w * 0.5 + 1.0,
        pos.y + 10.0,
        rl.Color.init(255, 255, 255, alphaByte(text_alpha)),
    );
}

fn wrapSmallTextNative(
    runtime_assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    max_width_px: f32,
    buf: []u8,
) []const u8 {
    const src = if (text.len < buf.len) text else text[0 .. buf.len - 1];
    @memcpy(buf[0..src.len], src);
    const len = src.len;
    if (len < buf.len) buf[len] = 0;

    var remaining = max_width_px;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const ch = buf[i];
        switch (ch) {
            '\r' => continue,
            '\n' => {
                remaining = max_width_px;
                continue;
            },
            else => {},
        }
        remaining -= @as(f32, @floatFromInt(runtime_assets.small_font_widths[ch]));
        if (remaining < 0.0) {
            var j = i;
            while (j > 0 and buf[j] != ' ' and buf[j] != '\n') : (j -= 1) {}
            if (buf[j] == ' ') {
                buf[j] = '\n';
                i = j;
            }
            remaining = max_width_px;
        }
    }
    return buf[0..len];
}

fn clampf(value: f32, lo: f32, hi: f32) f32 {
    return std.math.clamp(value, lo, hi);
}

fn alphaByte(value: f32) u8 {
    return @intFromFloat(clampf(value, 0.0, 1.0) * 255.0 + 0.5);
}

test "panel slide matches classic ui timeline" {
    try std.testing.expectApproxEqAbs(@as(f32, -510.0), panelSlideX(0.0, 510.0), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, -255.0), panelSlideX(250.0, 510.0), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), panelSlideX(400.0, 510.0), 1e-6);
}
