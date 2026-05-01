const std = @import("std");
const rl = @import("raylib");

const window_assets = @import("window_assets.zig");
const window_menu = @import("window_menu.zig");
const window_ui = @import("window_ui.zig");

const panel_rect = rl.Rectangle.init(360.0, 168.0, 510.0, 378.0);
const panel_timeline_max_ms: i32 = 300;
const max_mod_lines: usize = 16;
const max_line_bytes: usize = 224;

pub const Action = enum {
    none,
    back_to_menu,
};

pub const UpdateResult = struct {
    action: Action = .none,
    play_panel_click: bool = false,
    play_button_click: bool = false,
};

const PanelState = struct {
    timeline_ms: i32 = 0,
    panel_open_sfx_played: bool = false,
    back_hover_amount: i32 = 0,

    fn reset(self: *PanelState) void {
        self.* = .{};
    }
};

pub const ModsState = struct {
    panel: PanelState = .{},
    lines: [max_mod_lines][max_line_bytes]u8 = undefined,
    line_lens: [max_mod_lines]usize = [_]usize{0} ** max_mod_lines,
    line_count: usize = 0,

    pub fn reset(self: *ModsState, base_dir: []const u8) void {
        self.* = .{};
        self.rebuildLines(base_dir);
    }

    fn appendLine(self: *ModsState, comptime fmt: []const u8, args: anytype) void {
        if (self.line_count >= self.lines.len) return;
        const idx = self.line_count;
        const rendered = std.fmt.bufPrint(self.lines[idx][0..], fmt, args) catch return;
        self.line_lens[idx] = rendered.len;
        self.line_count += 1;
    }

    fn line(self: *const ModsState, idx: usize) []const u8 {
        return self.lines[idx][0..self.line_lens[idx]];
    }

    fn rebuildLines(self: *ModsState, base_dir: []const u8) void {
        var mods_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const mods_path = std.fmt.bufPrint(&mods_path_buf, "{s}/mods", .{base_dir}) catch {
            self.appendLine("No mod DLLs found.", .{});
            self.appendLine("", .{});
            self.appendLine("Expected location:", .{});
            self.appendLine("  {s}/mods", .{base_dir});
            self.appendLine("", .{});
            self.appendLine("Mod loading is not implemented yet.", .{});
            return;
        };

        const io = std.Io.Threaded.global_single_threaded.io();
        var dir = std.Io.Dir.openDirAbsolute(io, mods_path, .{ .iterate = true }) catch {
            self.appendLine("No mod DLLs found.", .{});
            self.appendLine("", .{});
            self.appendLine("Expected location:", .{});
            self.appendLine("  {s}", .{mods_path});
            self.appendLine("", .{});
            self.appendLine("Mod loading is not implemented yet.", .{});
            return;
        };
        defer dir.close(io);

        var iter = dir.iterate();
        var dll_count: usize = 0;
        var dll_names: [10][128]u8 = undefined;
        var dll_name_lens: [10]usize = [_]usize{0} ** 10;
        while (iter.next(io) catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.ascii.endsWithIgnoreCase(entry.name, ".dll")) continue;
            if (dll_count < dll_names.len) {
                const copied_len = @min(entry.name.len, dll_names[dll_count].len);
                @memcpy(dll_names[dll_count][0..copied_len], entry.name[0..copied_len]);
                dll_name_lens[dll_count] = copied_len;
            }
            dll_count += 1;
        }

        if (dll_count == 0) {
            self.appendLine("No mod DLLs found.", .{});
            self.appendLine("", .{});
            self.appendLine("Expected location:", .{});
            self.appendLine("  {s}", .{mods_path});
            self.appendLine("", .{});
            self.appendLine("Mod loading is not implemented yet.", .{});
            return;
        }

        self.appendLine("Found {d} mod DLL(s):", .{dll_count});
        self.appendLine("", .{});
        const shown = @min(dll_count, dll_names.len);
        for (0..shown) |idx| {
            self.appendLine("  {s}", .{dll_names[idx][0..dll_name_lens[idx]]});
        }
        if (dll_count > dll_names.len) {
            self.appendLine("  ... ({d} more)", .{dll_count - dll_names.len});
        }
        self.appendLine("", .{});
        self.appendLine("Mod loading is not implemented yet.", .{});
    }
};

pub const OtherGamesState = struct {
    panel: PanelState = .{},

    pub fn reset(self: *OtherGamesState) void {
        self.* = .{};
    }
};

pub fn updateMods(state: *ModsState, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets) UpdateResult {
    return updatePanel(&state.panel, frame_dt, runtime_assets);
}

pub fn drawMods(state: *const ModsState, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const assets = runtime_assets orelse {
        rl.clearBackground(rl.Color.black);
        return;
    };
    const animated_rect = drawPanelShell(&state.panel, assets);
    window_ui.drawSmallText(assets, "MODS", animated_rect.x + 212.0, animated_rect.y + 32.0, rl.Color.white);
    var y = animated_rect.y + 76.0;
    for (0..state.line_count) |idx| {
        window_ui.drawSmallText(assets, state.line(idx), animated_rect.x + 220.0, y, rl.Color.init(204, 204, 214, 255));
        y += 16.0;
    }
}

pub fn updateOtherGames(state: *OtherGamesState, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets) UpdateResult {
    return updatePanel(&state.panel, frame_dt, runtime_assets);
}

pub fn drawOtherGames(state: *const OtherGamesState, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const assets = runtime_assets orelse {
        rl.clearBackground(rl.Color.black);
        return;
    };
    const animated_rect = drawPanelShell(&state.panel, assets);
    window_ui.drawSmallText(assets, "Other games", animated_rect.x + 184.0, animated_rect.y + 40.0, rl.Color.white);
    window_ui.drawSmallText(assets, "This menu is out of scope for the rewrite.", animated_rect.x + 152.0, animated_rect.y + 88.0, rl.Color.init(204, 204, 214, 255));
}

fn updatePanel(state: *PanelState, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets) UpdateResult {
    const dt_ms = @as(i32, @intFromFloat(@min(frame_dt, 0.1) * 1000.0));
    if (dt_ms > 0) {
        state.timeline_ms = @min(panel_timeline_max_ms, state.timeline_ms + dt_ms);
    }

    const back_hovered = if (runtime_assets) |assets|
        state.timeline_ms >= panel_timeline_max_ms and rl.checkCollisionPointRec(rl.getMousePosition(), window_menu.panelBackHitRect(assets, state.timeline_ms))
    else
        false;

    if (back_hovered) {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount + dt_ms * 6, 0, 1000);
    } else {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount - dt_ms * 2, 0, 1000);
    }

    if (rl.isKeyPressed(.escape) or window_ui.confirmPressed() or (back_hovered and rl.isMouseButtonPressed(.left))) {
        return .{ .action = .back_to_menu, .play_button_click = true };
    }

    return .{
        .play_panel_click = dt_ms > 0 and state.timeline_ms >= panel_timeline_max_ms and !state.panel_open_sfx_played,
    };
}

fn drawPanelShell(state: *const PanelState, assets: *const window_assets.RuntimeAssets) rl.Rectangle {
    window_menu.drawMenuBackdrop(assets);
    window_menu.drawSign(state.timeline_ms, assets);
    const animated_rect = animatedPanelRect(state.timeline_ms);
    window_ui.drawClassicMenuPanel(assets.texture(.ui_menu_panel), animated_rect, rl.Color.white, false);
    window_menu.drawPanelBackEntry(assets, state.timeline_ms, state.back_hover_amount);
    return animated_rect;
}

fn animatedPanelRect(timeline_ms: i32) rl.Rectangle {
    const anim = window_menu.uiElementAnim(1, panel_timeline_max_ms, 0, panel_rect.width, timeline_ms);
    return rl.Rectangle.init(panel_rect.x + anim.offset_x, panel_rect.y, panel_rect.width, panel_rect.height);
}
