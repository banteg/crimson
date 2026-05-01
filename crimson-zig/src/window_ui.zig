const std = @import("std");
const rl = @import("raylib");

const window_assets = @import("window_assets.zig");

pub const UiButton = struct {
    label: [:0]const u8,
    rect: rl.Rectangle,
};

pub const ui_shadow_offset: f32 = 7.0;
pub const ui_shadow_tint = rl.Color.init(0x44, 0x44, 0x44, 0x44);
pub const button_plate_height: f32 = 32.0;

pub fn centeredRect(center_x: f32, top_y: f32, width: f32, height: f32) rl.Rectangle {
    return .{
        .x = center_x - width * 0.5,
        .y = top_y,
        .width = width,
        .height = height,
    };
}

pub fn updateSelectionFromPointer(selection: *usize, buttons: []const UiButton) void {
    const mouse = rl.getMousePosition();
    for (buttons, 0..) |button, idx| {
        if (rl.checkCollisionPointRec(mouse, buttonHitRect(button))) {
            selection.* = idx;
            return;
        }
    }
}

pub fn confirmPressed() bool {
    return rl.isKeyPressed(.enter) or rl.isKeyPressed(.kp_enter) or rl.isKeyPressed(.space);
}

pub fn buttonActivated(buttons: []const UiButton, selection: usize) bool {
    if (confirmPressed()) return true;

    if (!rl.isMouseButtonPressed(.left)) return false;
    const mouse = rl.getMousePosition();
    for (buttons, 0..) |button, idx| {
        if (idx == selection and rl.checkCollisionPointRec(mouse, buttonHitRect(button))) {
            return true;
        }
    }
    return false;
}

pub fn drawButton(
    button: UiButton,
    selected: bool,
    hovered: bool,
    runtime_assets: ?*const window_assets.RuntimeAssets,
) void {
    if (runtime_assets) |assets| {
        const scale: f32 = 1.0;
        const texture = if (button.rect.width > 120.0) assets.texture(.ui_button_md) else assets.texture(.ui_button_sm);
        const plate_rect = rl.Rectangle.init(button.rect.x, button.rect.y, button.rect.width, button_plate_height * scale);
        if (selected or hovered) {
            const highlight_alpha: u8 = if (hovered) 255 else 170;
            rl.drawRectangle(
                @intFromFloat(plate_rect.x + 12.0 * scale),
                @intFromFloat(plate_rect.y + 5.0 * scale),
                @intFromFloat(plate_rect.width - 24.0 * scale),
                @intFromFloat(22.0 * scale),
                rl.Color.init(128, 128, 178, highlight_alpha),
            );
        }
        rl.drawTexturePro(
            texture,
            rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)),
            plate_rect,
            rl.Vector2.zero(),
            0.0,
            rl.Color.white,
        );

        const label_width = measureSmallText(assets, button.label);
        drawSmallText(
            assets,
            button.label,
            plate_rect.x + (plate_rect.width - label_width) * 0.5 + 1.0 * scale,
            plate_rect.y + 10.0 * scale,
            colorWithAlpha(rl.Color.white, if (selected or hovered) 1.0 else 0.7),
        );
        return;
    }

    const fill = if (selected or hovered) rl.Color.init(218, 80, 46, 255) else rl.Color.init(37, 24, 20, 255);
    const outline = if (selected or hovered) rl.Color.gold else rl.Color.init(122, 78, 58, 255);
    rl.drawRectangleRounded(button.rect, 0.2, 8, fill);
    rl.drawRectangleRoundedLinesEx(button.rect, 0.2, 8, 2.0, outline);

    const label_width = rl.measureText(button.label, 24);
    const label_x = @as(i32, @intFromFloat(button.rect.x + (button.rect.width - @as(f32, @floatFromInt(label_width))) * 0.5));
    const label_y = @as(i32, @intFromFloat(button.rect.y + (button.rect.height - 24.0) * 0.5));
    rl.drawText(button.label, label_x, label_y, 24, rl.Color.init(245, 236, 225, 255));
}

fn buttonHitRect(button: UiButton) rl.Rectangle {
    return rl.Rectangle.init(button.rect.x, button.rect.y + 2.0, button.rect.width, 28.0);
}

pub fn buttonWidth(label: []const u8, force_wide: bool) f32 {
    if (force_wide) return 145.0;
    if (approxButtonTextWidth(label) < 40.0) return 82.0;
    return 145.0;
}

pub fn buttonAt(label: [:0]const u8, x: f32, y: f32, force_wide: bool) UiButton {
    return .{
        .label = label,
        .rect = rl.Rectangle.init(x, y, buttonWidth(label, force_wide), button_plate_height),
    };
}

fn approxButtonTextWidth(label: []const u8) f32 {
    var width: f32 = 0.0;
    for (label) |ch| {
        width += switch (ch) {
            'i', 'l', '!', '.', ',', '\'', ':' => 4.0,
            ' ' => 5.0,
            else => 8.0,
        };
    }
    return width;
}

pub fn colorWithAlpha(color: rl.Color, alpha: f32) rl.Color {
    return rl.Color.init(
        color.r,
        color.g,
        color.b,
        @intFromFloat(std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
    );
}

pub fn drawTextureFit(texture: rl.Texture2D, dest: rl.Rectangle, tint: rl.Color) void {
    const src = rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height));
    rl.drawTexturePro(texture, src, dest, rl.Vector2.zero(), 0.0, tint);
}

const menu_panel_inset: f32 = 1.0;
const menu_panel_src_slice_y1: f32 = 130.0;
const menu_panel_src_slice_y2: f32 = 150.0;
const menu_panel_dst_top_h: f32 = 138.0;
const menu_panel_dst_bottom_h: f32 = 116.0;

pub fn drawClassicMenuPanel(texture: rl.Texture2D, dst: rl.Rectangle, tint: rl.Color, flip_x: bool) void {
    const tex_w = @as(f32, @floatFromInt(texture.width));
    const tex_h = @as(f32, @floatFromInt(texture.height));
    if (tex_w <= 0.0 or tex_h <= 0.0) return;

    const src_x = menu_panel_inset;
    const src_y = menu_panel_inset;
    const src_w = @max(0.0, tex_w - menu_panel_inset * 2.0);
    const src_h = @max(0.0, tex_h - menu_panel_inset * 2.0);
    const scale = if (dst.width != 0.0) dst.width / 510.0 else 1.0;
    const top_h = menu_panel_dst_top_h * scale;
    const bottom_h = menu_panel_dst_bottom_h * scale;
    const mid_h = dst.height - top_h - bottom_h;

    const srcRect = struct {
        fn make(rect: rl.Rectangle, use_flip_x: bool) rl.Rectangle {
            if (!use_flip_x) return rect;
            return rl.Rectangle.init(rect.x, rect.y, -rect.width, rect.height);
        }
    }.make;

    if (mid_h <= 0.0) {
        drawPanelShadow(texture, srcRect(rl.Rectangle.init(src_x, src_y, src_w, src_h), flip_x), dst);
        rl.drawTexturePro(
            texture,
            srcRect(rl.Rectangle.init(src_x, src_y, src_w, src_h), flip_x),
            dst,
            rl.Vector2.zero(),
            0.0,
            tint,
        );
        return;
    }

    const src_top = srcRect(rl.Rectangle.init(src_x, src_y, src_w, @max(0.0, menu_panel_src_slice_y1 - menu_panel_inset)), flip_x);
    const src_mid = srcRect(rl.Rectangle.init(src_x, menu_panel_src_slice_y1, src_w, @max(0.0, menu_panel_src_slice_y2 - menu_panel_src_slice_y1)), flip_x);
    const src_bot = srcRect(rl.Rectangle.init(src_x, menu_panel_src_slice_y2, src_w, @max(0.0, (tex_h - menu_panel_inset) - menu_panel_src_slice_y2)), flip_x);

    const dst_top = rl.Rectangle.init(dst.x, dst.y, dst.width, top_h);
    const dst_mid = rl.Rectangle.init(dst.x, dst.y + top_h, dst.width, mid_h);
    const dst_bot = rl.Rectangle.init(dst.x, dst.y + top_h + mid_h, dst.width, bottom_h);

    drawPanelShadow(texture, src_top, dst_top);
    drawPanelShadow(texture, src_mid, dst_mid);
    drawPanelShadow(texture, src_bot, dst_bot);

    rl.drawTexturePro(texture, src_top, dst_top, rl.Vector2.zero(), 0.0, tint);
    rl.drawTexturePro(texture, src_mid, dst_mid, rl.Vector2.zero(), 0.0, tint);
    rl.drawTexturePro(texture, src_bot, dst_bot, rl.Vector2.zero(), 0.0, tint);
}

fn drawPanelShadow(texture: rl.Texture2D, src: rl.Rectangle, dst: rl.Rectangle) void {
    rl.gl.rlSetBlendFactors(rl.gl.rl_zero, rl.gl.rl_one_minus_src_alpha, rl.gl.rl_func_add);
    rl.beginBlendMode(.custom);
    rl.gl.rlSetBlendFactors(rl.gl.rl_zero, rl.gl.rl_one_minus_src_alpha, rl.gl.rl_func_add);
    defer rl.endBlendMode();

    rl.drawTexturePro(
        texture,
        src,
        rl.Rectangle.init(dst.x + ui_shadow_offset, dst.y + ui_shadow_offset, dst.width, dst.height),
        rl.Vector2.zero(),
        0.0,
        ui_shadow_tint,
    );
}

pub fn drawSmallText(
    runtime_assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    x: f32,
    y: f32,
    color: rl.Color,
) void {
    const texture = runtime_assets.texture(.small_white);
    var x_pos = @floor(x);
    var y_pos = @floor(y);
    const base_x = x_pos;
    for (text) |value| {
        switch (value) {
            '\n' => {
                x_pos = base_x;
                y_pos += 16.0;
                continue;
            },
            '\r' => continue,
            else => {},
        }

        const width = runtime_assets.small_font_widths[value];
        if (width == 0) continue;
        const col = value % 16;
        const row = value / 16;
        rl.drawTexturePro(
            texture,
            rl.Rectangle.init(@as(f32, @floatFromInt(col * 16)), @as(f32, @floatFromInt(row * 16)), @floatFromInt(width), 16.0),
            rl.Rectangle.init(x_pos, y_pos, @floatFromInt(width), 16.0),
            rl.Vector2.zero(),
            0.0,
            color,
        );
        x_pos += @as(f32, @floatFromInt(width));
    }
}

pub fn measureSmallText(runtime_assets: *const window_assets.RuntimeAssets, text: []const u8) f32 {
    var width: f32 = 0.0;
    var best: f32 = 0.0;
    for (text) |value| {
        switch (value) {
            '\n' => {
                best = @max(best, width);
                width = 0.0;
                continue;
            },
            '\r' => continue,
            else => {},
        }
        width += @as(f32, @floatFromInt(runtime_assets.small_font_widths[value]));
    }
    return @max(best, width);
}

pub fn drawSmallTextCentered(
    runtime_assets: *const window_assets.RuntimeAssets,
    text: []const u8,
    y: f32,
    color: rl.Color,
) void {
    const width = measureSmallText(runtime_assets, text);
    const x = (@as(f32, @floatFromInt(rl.getScreenWidth())) - width) * 0.5;
    drawSmallText(runtime_assets, text, x, y, color);
}

pub fn drawSmallTextFmt(
    comptime fmt: []const u8,
    runtime_assets: *const window_assets.RuntimeAssets,
    args: anytype,
    x: f32,
    y: f32,
    color: rl.Color,
) void {
    var buf: [256]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, args) catch return;
    drawSmallText(runtime_assets, text, x, y, color);
}
