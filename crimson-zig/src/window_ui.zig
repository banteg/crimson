const std = @import("std");
const rl = @import("raylib");

const window_assets = @import("window_assets.zig");

pub const UiButton = struct {
    label: [:0]const u8,
    rect: rl.Rectangle,
};

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
        if (rl.checkCollisionPointRec(mouse, button.rect)) {
            selection.* = idx;
            return;
        }
    }
}

pub fn buttonActivated(buttons: []const UiButton, selection: usize) bool {
    if (rl.isKeyPressed(.enter) or rl.isKeyPressed(.space)) return true;

    if (!rl.isMouseButtonPressed(.left)) return false;
    const mouse = rl.getMousePosition();
    for (buttons, 0..) |button, idx| {
        if (idx == selection and rl.checkCollisionPointRec(mouse, button.rect)) {
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
        const scale = button.rect.height / 32.0;
        const texture = if (button.rect.width > 120.0) assets.texture(.ui_button_md) else assets.texture(.ui_button_sm);
        const glow_alpha: f32 = if (selected or hovered) 0.92 else 0.72;
        if (selected or hovered) {
            rl.drawRectangleRounded(
                .{
                    .x = button.rect.x + 12.0 * scale,
                    .y = button.rect.y + 5.0 * scale,
                    .width = button.rect.width - 24.0 * scale,
                    .height = button.rect.height - 10.0 * scale,
                },
                0.18,
                8,
                rl.Color.init(128, 128, 178, @intFromFloat(glow_alpha * 120.0)),
            );
        }
        const plate_alpha: f32 = if (selected or hovered) 255.0 else 230.0;
        rl.drawTexturePro(
            texture,
            rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)),
            button.rect,
            rl.Vector2.zero(),
            0.0,
            rl.Color.init(255, 255, 255, @intFromFloat(plate_alpha)),
        );

        const label_width = measureSmallText(assets, button.label);
        drawSmallText(
            assets,
            button.label,
            button.rect.x + (button.rect.width - label_width) * 0.5 + 1.0,
            button.rect.y + 10.0,
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
