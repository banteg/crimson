const std = @import("std");
const rl = @import("raylib");

const window_assets = @import("window_assets.zig");
const window_menu = @import("window_menu.zig");
const window_ui = @import("window_ui.zig");

const panel_rect = rl.Rectangle.init(360.0, 168.0, 510.0, 378.0);
const panel_timeline_max_ms: i32 = 300;
const max_mod_lines: usize = 16;
const max_line_bytes: usize = 224;
const max_shown_mod_dlls: usize = 10;
const max_mod_dll_name_bytes: usize = 128;
const network_row_count: usize = 6;
const network_status_bytes: usize = 96;
const network_join_endpoint_max_bytes: usize = 48;
const default_network_port: u16 = 31993;
const mod_runtime_scope_text = "Native DLL mod loading is outside this port.";
const other_games_scope_text = "Other Games ads are outside this port.";
const network_runtime_scope_text = "Lockstep runtime available; rollback relay is config-only.";
const network_room_codes = [_][]const u8{ "ab12", "cd34", "ef56", "gh78" };
const default_network_join_endpoint = "127.0.0.1:31993";

const NetworkRole = enum {
    host,
    join,
};

const NetworkMode = enum {
    survival,
    rush,
    quests,
};

const NetworkNetcode = enum {
    rollback,
    lockstep,
};

const NetworkSelection = enum(u8) {
    role,
    mode,
    players,
    netcode,
    endpoint,
    launch,
};

pub const Action = enum {
    none,
    back_to_menu,
    launch_network,
};

pub const UpdateResult = struct {
    action: Action = .none,
    play_panel_click: bool = false,
    play_button_click: bool = false,
};

pub const NetworkLaunchRole = enum {
    host,
    join,
};

pub const NetworkLaunchNetcode = enum {
    rollback,
    lockstep,
};

pub const NetworkLaunchRequest = struct {
    role: NetworkLaunchRole,
    mode_id: i32,
    player_count: i32,
    netcode: NetworkLaunchNetcode,
    bind_host: []const u8 = "0.0.0.0",
    host: []const u8 = "127.0.0.1",
    port: u16 = 31993,
};

const PanelState = struct {
    timeline_ms: i32 = 0,
    panel_open_sfx_played: bool = false,
    back_hover_amount: i32 = 0,

    fn reset(self: *PanelState) void {
        self.* = .{};
    }
};

const ModDllName = struct {
    bytes: [max_mod_dll_name_bytes]u8 = undefined,
    len: usize = 0,

    fn set(self: *ModDllName, name: []const u8) void {
        const copied_len = @min(name.len, self.bytes.len);
        @memcpy(self.bytes[0..copied_len], name[0..copied_len]);
        self.len = copied_len;
    }

    fn slice(self: *const ModDllName) []const u8 {
        return self.bytes[0..self.len];
    }
};

const NetworkJoinEndpointInput = struct {
    bytes: [network_join_endpoint_max_bytes]u8 = defaultNetworkJoinEndpointBytes(),
    len: usize = default_network_join_endpoint.len,

    fn set(self: *NetworkJoinEndpointInput, endpoint: []const u8) void {
        const copied_len = @min(endpoint.len, self.bytes.len);
        @memcpy(self.bytes[0..copied_len], endpoint[0..copied_len]);
        self.len = copied_len;
    }

    fn slice(self: *const NetworkJoinEndpointInput) []const u8 {
        return self.bytes[0..self.len];
    }

    fn insertChar(self: *NetworkJoinEndpointInput, ch: u8) bool {
        if (self.len >= self.bytes.len) return false;
        self.bytes[self.len] = ch;
        self.len += 1;
        return true;
    }

    fn backspace(self: *NetworkJoinEndpointInput) bool {
        if (self.len == 0) return false;
        self.len -= 1;
        return true;
    }
};

fn defaultNetworkJoinEndpointBytes() [network_join_endpoint_max_bytes]u8 {
    var bytes: [network_join_endpoint_max_bytes]u8 = undefined;
    @memcpy(bytes[0..default_network_join_endpoint.len], default_network_join_endpoint);
    return bytes;
}

const NetworkEndpoint = struct {
    host: []const u8,
    port: u16 = default_network_port,
};

const NetworkEndpointInputEdits = struct {
    typed: bool = false,
    backspaced: bool = false,

    fn any(self: NetworkEndpointInputEdits) bool {
        return self.typed or self.backspaced;
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

    fn appendScopeLine(self: *ModsState) void {
        self.appendLine(mod_runtime_scope_text, .{});
    }

    fn rebuildLines(self: *ModsState, base_dir: []const u8) void {
        var mods_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const mods_path = std.fmt.bufPrint(&mods_path_buf, "{s}/mods", .{base_dir}) catch {
            self.appendLine("No mod DLLs found.", .{});
            self.appendLine("", .{});
            self.appendLine("Expected location:", .{});
            self.appendLine("  {s}/mods", .{base_dir});
            self.appendLine("", .{});
            self.appendScopeLine();
            return;
        };

        const io = std.Io.Threaded.global_single_threaded.io();
        var dir = std.Io.Dir.openDirAbsolute(io, mods_path, .{ .iterate = true }) catch {
            self.appendLine("No mod DLLs found.", .{});
            self.appendLine("", .{});
            self.appendLine("Expected location:", .{});
            self.appendLine("  {s}", .{mods_path});
            self.appendLine("", .{});
            self.appendScopeLine();
            return;
        };
        defer dir.close(io);

        var iter = dir.iterate();
        var dll_count: usize = 0;
        var dll_names: [max_shown_mod_dlls]ModDllName = undefined;
        while (iter.next(io) catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.ascii.endsWithIgnoreCase(entry.name, ".dll")) continue;
            if (dll_count < dll_names.len) {
                dll_names[dll_count].set(entry.name);
            }
            dll_count += 1;
        }

        if (dll_count == 0) {
            self.appendLine("No mod DLLs found.", .{});
            self.appendLine("", .{});
            self.appendLine("Expected location:", .{});
            self.appendLine("  {s}", .{mods_path});
            self.appendLine("", .{});
            self.appendScopeLine();
            return;
        }

        self.appendLine("Found {d} mod DLL(s):", .{dll_count});
        self.appendLine("", .{});
        const shown = @min(dll_count, dll_names.len);
        sortModDllNames(dll_names[0..shown]);
        for (0..shown) |idx| {
            self.appendLine("  {s}", .{dll_names[idx].slice()});
        }
        if (dll_count > dll_names.len) {
            self.appendLine("  ... ({d} more)", .{dll_count - dll_names.len});
        }
        self.appendLine("", .{});
        self.appendScopeLine();
    }
};

fn sortModDllNames(names: []ModDllName) void {
    std.sort.heap(ModDllName, names, {}, modDllNameLessThan);
}

fn modDllNameLessThan(_: void, left: ModDllName, right: ModDllName) bool {
    return std.mem.lessThan(u8, left.slice(), right.slice());
}

pub const OtherGamesState = struct {
    panel: PanelState = .{},

    pub fn reset(self: *OtherGamesState) void {
        self.* = .{};
    }
};

pub const NetworkState = struct {
    panel: PanelState = .{},
    selection: NetworkSelection = .role,
    role: NetworkRole = .host,
    mode: NetworkMode = .survival,
    player_count: i32 = 2,
    netcode: NetworkNetcode = .lockstep,
    room_code_index: usize = 0,
    join_endpoint: NetworkJoinEndpointInput = .{},
    status_bytes: [network_status_bytes]u8 = undefined,
    status_len: usize = 0,

    pub fn reset(self: *NetworkState) void {
        self.* = .{};
        self.setStatus("Lockstep ready.");
    }

    pub fn setStatus(self: *NetworkState, message: []const u8) void {
        const len = @min(message.len, self.status_bytes.len);
        @memcpy(self.status_bytes[0..len], message[0..len]);
        self.status_len = len;
    }

    pub fn setStatusFmt(self: *NetworkState, comptime fmt: []const u8, args: anytype) void {
        const rendered = std.fmt.bufPrint(self.status_bytes[0..], fmt, args) catch return;
        self.status_len = rendered.len;
    }

    pub fn statusText(self: *const NetworkState) []const u8 {
        return self.status_bytes[0..self.status_len];
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

pub fn updateNetwork(state: *NetworkState, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets) UpdateResult {
    const result = updatePanelEx(&state.panel, frame_dt, runtime_assets, false);
    if (result.action != .none) return result;
    if (state.panel.timeline_ms < panel_timeline_max_ms) return result;

    if (rl.isKeyPressed(.up) or rl.isKeyPressed(.w)) {
        state.selection = networkSelectionFromIndex(if (networkSelectionIndex(state.selection) == 0)
            network_row_count - 1
        else
            networkSelectionIndex(state.selection) - 1);
    }
    if (rl.isKeyPressed(.down) or rl.isKeyPressed(.s)) {
        state.selection = networkSelectionFromIndex((networkSelectionIndex(state.selection) + 1) % network_row_count);
    }
    if (rl.isKeyPressed(.left) or rl.isKeyPressed(.a)) {
        changeSelectedNetworkValue(state, -1);
        return .{ .play_button_click = true };
    }
    if (collectNetworkEndpointInput(state).any()) {
        return .{ .play_button_click = true };
    }
    if (window_ui.confirmPressed() and state.selection == .launch and state.netcode == .lockstep) {
        return .{ .action = .launch_network, .play_button_click = true };
    }
    if (rl.isKeyPressed(.right) or rl.isKeyPressed(.d) or window_ui.confirmPressed()) {
        changeSelectedNetworkValue(state, 1);
        return .{ .play_button_click = true };
    }

    return result;
}

pub fn drawOtherGames(state: *const OtherGamesState, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const assets = runtime_assets orelse {
        rl.clearBackground(rl.Color.black);
        return;
    };
    const animated_rect = drawPanelShell(&state.panel, assets);
    window_ui.drawSmallText(assets, "Other games", animated_rect.x + 184.0, animated_rect.y + 40.0, rl.Color.white);
    window_ui.drawSmallText(assets, other_games_scope_text, animated_rect.x + 152.0, animated_rect.y + 88.0, rl.Color.init(204, 204, 214, 255));
}

pub fn drawNetwork(state: *const NetworkState, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const assets = runtime_assets orelse {
        rl.clearBackground(rl.Color.black);
        return;
    };
    drawNetworkPanel(state, assets, true);
}

pub fn drawNetworkOverlay(state: *const NetworkState, runtime_assets: ?*const window_assets.RuntimeAssets) void {
    const assets = runtime_assets orelse return;
    drawNetworkPanel(state, assets, false);
}

fn drawNetworkPanel(state: *const NetworkState, assets: *const window_assets.RuntimeAssets, draw_backdrop: bool) void {
    const animated_rect = drawPanelShellEx(&state.panel, assets, draw_backdrop);
    window_ui.drawSmallText(assets, "Network Session", animated_rect.x + 174.0, animated_rect.y + 40.0, rl.Color.white);

    var line_buf: [96]u8 = undefined;
    var value_buf: [96]u8 = undefined;
    drawNetworkRow(assets, animated_rect, 0, state.selection == .role, "Role", networkRoleLabel(state.role), &line_buf);
    drawNetworkRow(assets, animated_rect, 1, state.selection == .mode, "Mode", networkModeValueLabel(state), &line_buf);
    drawNetworkRow(assets, animated_rect, 2, state.selection == .players, "Players", networkPlayersValueLabel(state, &value_buf), &line_buf);
    drawNetworkRow(assets, animated_rect, 3, state.selection == .netcode, "Netcode", networkNetcodeLabel(state.netcode), &line_buf);
    drawNetworkRow(assets, animated_rect, 4, state.selection == .endpoint, "Endpoint", networkEndpointValueLabel(state, &value_buf), &line_buf);
    drawNetworkRow(assets, animated_rect, 5, state.selection == .launch, "Launch", networkLaunchValueLabel(state), &line_buf);

    window_ui.drawSmallText(assets, network_runtime_scope_text, animated_rect.x + 96.0, animated_rect.y + 264.0, rl.Color.init(214, 190, 170, 255));
    if (state.status_len != 0) {
        window_ui.drawSmallText(assets, state.statusText(), animated_rect.x + 136.0, animated_rect.y + 286.0, rl.Color.init(204, 204, 214, 255));
    }
}

pub fn networkLaunchRequest(state: *const NetworkState) ?NetworkLaunchRequest {
    if (state.netcode != .lockstep) return null;
    const endpoint = if (state.role == .join)
        parseLockstepJoinEndpoint(state.join_endpoint.slice()) orelse return null
    else
        NetworkEndpoint{ .host = "127.0.0.1" };
    return .{
        .role = switch (state.role) {
            .host => .host,
            .join => .join,
        },
        .mode_id = networkModeId(state.mode),
        .player_count = std.math.clamp(state.player_count, @as(i32, 1), @as(i32, 4)),
        .netcode = .lockstep,
        .bind_host = "0.0.0.0",
        .host = endpoint.host,
        .port = endpoint.port,
    };
}

pub fn networkLaunchUnavailableMessage(state: *const NetworkState) []const u8 {
    if (state.netcode != .lockstep) return "Rollback relay is config-only.";
    if (state.role == .join and parseLockstepJoinEndpoint(state.join_endpoint.slice()) == null) {
        return "Lockstep endpoint must be IPv4[:port].";
    }
    return "Network session is not ready.";
}

fn updatePanel(state: *PanelState, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets) UpdateResult {
    return updatePanelEx(state, frame_dt, runtime_assets, true);
}

fn updatePanelEx(state: *PanelState, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets, confirm_backs: bool) UpdateResult {
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

    if (rl.isKeyPressed(.escape) or (confirm_backs and window_ui.confirmPressed()) or (back_hovered and rl.isMouseButtonPressed(.left))) {
        return .{ .action = .back_to_menu, .play_button_click = true };
    }

    return .{
        .play_panel_click = dt_ms > 0 and state.timeline_ms >= panel_timeline_max_ms and !state.panel_open_sfx_played,
    };
}

fn drawPanelShell(state: *const PanelState, assets: *const window_assets.RuntimeAssets) rl.Rectangle {
    return drawPanelShellEx(state, assets, true);
}

fn drawPanelShellEx(state: *const PanelState, assets: *const window_assets.RuntimeAssets, draw_backdrop: bool) rl.Rectangle {
    if (draw_backdrop) window_menu.drawMenuBackdrop(assets);
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

fn drawNetworkRow(
    assets: *const window_assets.RuntimeAssets,
    panel: rl.Rectangle,
    row_index: usize,
    selected: bool,
    label: []const u8,
    value: []const u8,
    scratch: *[96]u8,
) void {
    const y = panel.y + 84.0 + @as(f32, @floatFromInt(row_index)) * 28.0;
    const color = if (selected) rl.Color.init(255, 228, 170, 255) else rl.Color.init(204, 204, 214, 255);
    const marker = if (selected) ">" else " ";
    const line = std.fmt.bufPrint(scratch[0..], "{s} {s}: {s}", .{ marker, label, value }) catch return;
    window_ui.drawSmallText(assets, line, panel.x + 136.0, y, color);
}

fn networkSelectionIndex(selection: NetworkSelection) usize {
    return @intFromEnum(selection);
}

fn networkSelectionFromIndex(index: usize) NetworkSelection {
    return switch (index % network_row_count) {
        0 => .role,
        1 => .mode,
        2 => .players,
        3 => .netcode,
        4 => .endpoint,
        else => .launch,
    };
}

fn changeSelectedNetworkValue(state: *NetworkState, direction: i32) void {
    switch (state.selection) {
        .role => {
            state.role = switch (state.role) {
                .host => .join,
                .join => .host,
            };
        },
        .mode => {
            if (state.role == .host) state.mode = cycleNetworkMode(state.mode, direction);
        },
        .players => {
            if (state.role == .host) {
                state.player_count += direction;
                if (state.player_count < 1) state.player_count = 4;
                if (state.player_count > 4) state.player_count = 1;
            }
        },
        .netcode => {
            state.netcode = switch (state.netcode) {
                .rollback => .lockstep,
                .lockstep => .rollback,
            };
        },
        .endpoint => {
            if (state.netcode == .lockstep) return;
            state.room_code_index = if (direction < 0)
                (state.room_code_index + network_room_codes.len - 1) % network_room_codes.len
            else
                (state.room_code_index + 1) % network_room_codes.len;
        },
        .launch => {},
    }
}

fn cycleNetworkMode(mode: NetworkMode, direction: i32) NetworkMode {
    const index: usize = switch (mode) {
        .survival => 0,
        .rush => 1,
        .quests => 2,
    };
    const next = if (direction < 0)
        (index + 2) % 3
    else
        (index + 1) % 3;
    return switch (next) {
        0 => .survival,
        1 => .rush,
        else => .quests,
    };
}

fn networkRoleLabel(role: NetworkRole) []const u8 {
    return switch (role) {
        .host => "Host",
        .join => "Join",
    };
}

fn networkModeValueLabel(state: *const NetworkState) []const u8 {
    if (state.role == .join) return "from lobby";
    return switch (state.mode) {
        .survival => "Survival",
        .rush => "Rush",
        .quests => "Quests 1.1",
    };
}

fn networkModeId(mode: NetworkMode) i32 {
    return switch (mode) {
        .survival => 1,
        .rush => 2,
        .quests => 3,
    };
}

fn networkNetcodeLabel(netcode: NetworkNetcode) []const u8 {
    return switch (netcode) {
        .rollback => "Rollback",
        .lockstep => "Lockstep",
    };
}

fn networkPlayersValueLabel(state: *const NetworkState, scratch: *[96]u8) []const u8 {
    if (state.role == .join) return "from lobby";
    return std.fmt.bufPrint(scratch[0..], "{d}", .{state.player_count}) catch "";
}

fn networkEndpointValueLabel(state: *const NetworkState, scratch: *[96]u8) []const u8 {
    return switch (state.netcode) {
        .rollback => switch (state.role) {
            .host => "relay 127.0.0.1:31993",
            .join => std.fmt.bufPrint(scratch[0..], "room {s} via relay", .{network_room_codes[state.room_code_index]}) catch "",
        },
        .lockstep => switch (state.role) {
            .host => std.fmt.bufPrint(scratch[0..], "bind 0.0.0.0:{d}", .{default_network_port}) catch "",
            .join => std.fmt.bufPrint(scratch[0..], "host {s}", .{state.join_endpoint.slice()}) catch "",
        },
    };
}

fn collectNetworkEndpointInput(state: *NetworkState) NetworkEndpointInputEdits {
    var edits: NetworkEndpointInputEdits = .{};
    if (state.selection != .endpoint or state.netcode != .lockstep or state.role != .join) return edits;

    while (true) {
        const codepoint = rl.getCharPressed();
        if (codepoint == 0) break;
        if (!networkEndpointCharAllowed(codepoint)) continue;
        edits.typed = state.join_endpoint.insertChar(@intCast(codepoint)) or edits.typed;
    }

    if (rl.isKeyPressed(.backspace) or rl.isKeyPressedRepeat(.backspace)) {
        edits.backspaced = state.join_endpoint.backspace();
    }
    return edits;
}

fn networkEndpointCharAllowed(codepoint: i32) bool {
    return (codepoint >= '0' and codepoint <= '9') or codepoint == '.' or codepoint == ':';
}

fn networkLaunchValueLabel(state: *const NetworkState) []const u8 {
    return switch (state.netcode) {
        .lockstep => switch (state.role) {
            .host => "Start host",
            .join => if (parseLockstepJoinEndpoint(state.join_endpoint.slice()) == null) "Invalid endpoint" else "Join host",
        },
        .rollback => "Config only",
    };
}

fn parseLockstepJoinEndpoint(text_raw: []const u8) ?NetworkEndpoint {
    const text = std.mem.trim(u8, text_raw, " \t\r\n");
    if (text.len == 0) return null;

    const colon_index = std.mem.indexOfScalar(u8, text, ':');
    const host = if (colon_index) |idx| text[0..idx] else text;
    if (!networkIpv4TextValid(host)) return null;

    const port = if (colon_index) |idx| blk: {
        if (std.mem.indexOfScalar(u8, text[idx + 1 ..], ':') != null) return null;
        const port_text = text[idx + 1 ..];
        if (port_text.len == 0) return null;
        const parsed = std.fmt.parseInt(u16, port_text, 10) catch return null;
        if (parsed == 0) return null;
        break :blk parsed;
    } else default_network_port;

    return .{ .host = host, .port = port };
}

fn networkIpv4TextValid(host: []const u8) bool {
    if (host.len == 0) return false;
    var part_count: usize = 0;
    var idx: usize = 0;
    while (idx < host.len) {
        if (part_count == 4) return false;
        var value: u16 = 0;
        var digit_count: usize = 0;
        while (idx < host.len and host[idx] != '.') : (idx += 1) {
            const ch = host[idx];
            if (ch < '0' or ch > '9') return false;
            value = value * 10 + @as(u16, ch - '0');
            if (value > 255) return false;
            digit_count += 1;
        }
        if (digit_count == 0) return false;
        part_count += 1;
        if (idx < host.len and host[idx] == '.') {
            idx += 1;
            if (idx == host.len) return false;
        }
    }
    return part_count == 4;
}

test "mods dll names are sorted before display" {
    var names = [_]ModDllName{ .{}, .{}, .{} };
    names[0].set("zeta.dll");
    names[1].set("alpha.dll");
    names[2].set("middle.dll");

    sortModDllNames(names[0..]);

    try std.testing.expectEqualStrings("alpha.dll", names[0].slice());
    try std.testing.expectEqualStrings("middle.dll", names[1].slice());
    try std.testing.expectEqualStrings("zeta.dll", names[2].slice());
}

test "mods panel explains deliberate native dll scope" {
    var state: ModsState = .{};
    state.appendScopeLine();

    try std.testing.expectEqual(@as(usize, 1), state.line_count);
    try std.testing.expectEqualStrings(mod_runtime_scope_text, state.line(0));
}

test "network panel scope text stays explicit" {
    try std.testing.expectEqualStrings("Lockstep runtime available; rollback relay is config-only.", network_runtime_scope_text);
}

test "network panel defaults to host lockstep session" {
    var state: NetworkState = .{};
    state.reset();

    try std.testing.expectEqual(NetworkRole.host, state.role);
    try std.testing.expectEqual(NetworkMode.survival, state.mode);
    try std.testing.expectEqual(NetworkNetcode.lockstep, state.netcode);
    try std.testing.expectEqual(@as(i32, 2), state.player_count);
    try std.testing.expectEqualStrings("Host", networkRoleLabel(state.role));
    try std.testing.expectEqualStrings("Survival", networkModeValueLabel(&state));
    try std.testing.expectEqualStrings("Lockstep ready.", state.statusText());
    var buf: [96]u8 = undefined;
    try std.testing.expectEqualStrings("bind 0.0.0.0:31993", networkEndpointValueLabel(&state, &buf));
}

test "network panel cycles host mode and player count" {
    var state: NetworkState = .{ .selection = .mode };

    changeSelectedNetworkValue(&state, 1);
    try std.testing.expectEqual(NetworkMode.rush, state.mode);
    changeSelectedNetworkValue(&state, -1);
    try std.testing.expectEqual(NetworkMode.survival, state.mode);

    state.selection = .players;
    state.player_count = 4;
    changeSelectedNetworkValue(&state, 1);
    try std.testing.expectEqual(@as(i32, 1), state.player_count);
    changeSelectedNetworkValue(&state, -1);
    try std.testing.expectEqual(@as(i32, 4), state.player_count);
}

test "network panel join uses lobby-derived mode and lockstep endpoint by default" {
    var state: NetworkState = .{ .role = .join, .selection = .endpoint };
    var buf: [96]u8 = undefined;

    try std.testing.expectEqualStrings("from lobby", networkModeValueLabel(&state));
    try std.testing.expectEqualStrings("from lobby", networkPlayersValueLabel(&state, &buf));
    try std.testing.expectEqualStrings("host 127.0.0.1:31993", networkEndpointValueLabel(&state, &buf));

    state.netcode = .rollback;
    try std.testing.expectEqualStrings("room ab12 via relay", networkEndpointValueLabel(&state, &buf));

    changeSelectedNetworkValue(&state, 1);
    try std.testing.expectEqualStrings("room cd34 via relay", networkEndpointValueLabel(&state, &buf));
}

test "network panel edits lockstep join endpoint" {
    var state: NetworkState = .{ .role = .join, .selection = .endpoint };
    var buf: [96]u8 = undefined;

    state.join_endpoint.set("192.168.1.44:32001");
    try std.testing.expectEqualStrings("host 192.168.1.44:32001", networkEndpointValueLabel(&state, &buf));

    const request = networkLaunchRequest(&state) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(NetworkLaunchRole.join, request.role);
    try std.testing.expectEqualStrings("192.168.1.44", request.host);
    try std.testing.expectEqual(@as(u16, 32001), request.port);

    try std.testing.expect(state.join_endpoint.backspace());
    try std.testing.expect(state.join_endpoint.insertChar('2'));
    try std.testing.expectEqualStrings("192.168.1.44:32002", state.join_endpoint.slice());
}

test "network panel keeps rollback endpoint cycling separate from lockstep host input" {
    var state: NetworkState = .{ .role = .join, .selection = .endpoint };

    changeSelectedNetworkValue(&state, 1);
    try std.testing.expectEqual(@as(usize, 0), state.room_code_index);

    state.netcode = .rollback;
    changeSelectedNetworkValue(&state, 1);
    try std.testing.expectEqual(@as(usize, 1), state.room_code_index);
}

test "network panel endpoint input accepts ipv4 port characters only" {
    try std.testing.expect(networkEndpointCharAllowed('0'));
    try std.testing.expect(networkEndpointCharAllowed('9'));
    try std.testing.expect(networkEndpointCharAllowed('.'));
    try std.testing.expect(networkEndpointCharAllowed(':'));
    try std.testing.expect(!networkEndpointCharAllowed('a'));
}

test "network panel validates lockstep join endpoint" {
    const parsed = parseLockstepJoinEndpoint("192.168.1.44:32001") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("192.168.1.44", parsed.host);
    try std.testing.expectEqual(@as(u16, 32001), parsed.port);

    const default_port = parseLockstepJoinEndpoint("192.168.1.44") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(u16, default_network_port), default_port.port);

    try std.testing.expect(parseLockstepJoinEndpoint("192.168.1.44:0") == null);
    try std.testing.expect(parseLockstepJoinEndpoint("192.168.1.44:") == null);
    try std.testing.expect(parseLockstepJoinEndpoint("192.168.1.999:32001") == null);
    try std.testing.expect(parseLockstepJoinEndpoint("192.168.1:32001") == null);
}

test "network panel builds launch requests only for lockstep" {
    var state: NetworkState = .{};

    const host_request = networkLaunchRequest(&state) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(NetworkLaunchRole.host, host_request.role);
    try std.testing.expectEqual(NetworkLaunchNetcode.lockstep, host_request.netcode);
    try std.testing.expectEqual(@as(i32, 1), host_request.mode_id);
    try std.testing.expectEqual(@as(i32, 2), host_request.player_count);
    try std.testing.expectEqualStrings("0.0.0.0", host_request.bind_host);
    try std.testing.expectEqual(@as(u16, 31993), host_request.port);

    state.role = .join;
    state.player_count = 4;
    const join_request = networkLaunchRequest(&state) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(NetworkLaunchRole.join, join_request.role);
    try std.testing.expectEqual(@as(i32, 4), join_request.player_count);
    try std.testing.expectEqualStrings("127.0.0.1", join_request.host);
    try std.testing.expectEqual(@as(u16, default_network_port), join_request.port);

    state.join_endpoint.set("127.0.0.1:0");
    try std.testing.expect(networkLaunchRequest(&state) == null);
    try std.testing.expectEqualStrings("Lockstep endpoint must be IPv4[:port].", networkLaunchUnavailableMessage(&state));

    state.netcode = .rollback;
    try std.testing.expect(networkLaunchRequest(&state) == null);
    try std.testing.expectEqualStrings("Rollback relay is config-only.", networkLaunchUnavailableMessage(&state));
}
