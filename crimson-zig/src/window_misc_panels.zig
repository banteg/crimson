const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const room_code = cz.net.room_code;

const window_assets = @import("window_assets.zig");
const window_menu = @import("window_menu.zig");
const window_ui = @import("window_ui.zig");

const panel_rect = rl.Rectangle.init(360.0, 168.0, 510.0, 378.0);
const panel_timeline_max_ms: i32 = 300;
const max_mod_lines: usize = 16;
const max_line_bytes: usize = 224;
const max_shown_mod_dlls: usize = 10;
const max_mod_dll_name_bytes: usize = 128;
const network_row_count: usize = 7;
const network_status_bytes: usize = 96;
const network_join_endpoint_max_bytes: usize = 48;
const default_network_port: u16 = 31993;
const mod_runtime_scope_text = "Native DLL mod loading is outside this port.";
const other_games_scope_text = "Other Games ads are outside this port.";
const network_runtime_scope_text = "Rollback and lockstep runtimes available.";
const default_network_room_code = "ab12";
const default_network_host_endpoint = "0.0.0.0:31993";
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
    room_code,
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
    room_code_text: ?[]const u8 = null,
};

const PanelState = struct {
    timeline_ms: i32 = 0,
    panel_open_sfx_played: bool = false,
    back_hover_amount: i32 = 0,
    closing: bool = false,
    close_action: Action = .none,

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
    bytes: [network_join_endpoint_max_bytes]u8,
    len: usize,

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

const NetworkRoomCodeInput = struct {
    bytes: [room_code.room_code_length]u8,
    len: usize,

    fn set(self: *NetworkRoomCodeInput, code: []const u8) void {
        self.len = 0;
        for (code) |ch| {
            if (!networkRoomCodeCharAllowed(ch)) continue;
            _ = self.insertChar(ch);
        }
    }

    fn slice(self: *const NetworkRoomCodeInput) []const u8 {
        return self.bytes[0..self.len];
    }

    fn insertChar(self: *NetworkRoomCodeInput, ch: u8) bool {
        if (self.len >= self.bytes.len) return false;
        if (!networkRoomCodeCharAllowed(ch)) return false;
        self.bytes[self.len] = std.ascii.toLower(ch);
        self.len += 1;
        return true;
    }

    fn backspace(self: *NetworkRoomCodeInput) bool {
        if (self.len == 0) return false;
        self.len -= 1;
        return true;
    }
};

fn networkEndpointInput(default_endpoint: []const u8) NetworkJoinEndpointInput {
    return .{
        .bytes = defaultNetworkEndpointBytes(default_endpoint),
        .len = default_endpoint.len,
    };
}

fn defaultNetworkEndpointBytes(default_endpoint: []const u8) [network_join_endpoint_max_bytes]u8 {
    var bytes: [network_join_endpoint_max_bytes]u8 = undefined;
    @memcpy(bytes[0..default_endpoint.len], default_endpoint);
    return bytes;
}

fn networkRoomCodeInput(default_code: []const u8) NetworkRoomCodeInput {
    var input: NetworkRoomCodeInput = .{
        .bytes = undefined,
        .len = 0,
    };
    input.set(default_code);
    return input;
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
    netcode: NetworkNetcode = .rollback,
    room_code_input: NetworkRoomCodeInput = networkRoomCodeInput(default_network_room_code),
    relay_endpoint: NetworkJoinEndpointInput = networkEndpointInput(default_network_join_endpoint),
    host_endpoint: NetworkJoinEndpointInput = networkEndpointInput(default_network_host_endpoint),
    join_endpoint: NetworkJoinEndpointInput = networkEndpointInput(default_network_join_endpoint),
    status_bytes: [network_status_bytes]u8 = undefined,
    status_len: usize = 0,

    pub fn reset(self: *NetworkState) void {
        self.* = .{};
        self.setStatus("Rollback ready.");
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

    fn lockstepEndpointInput(self: *const NetworkState) *const NetworkJoinEndpointInput {
        return switch (self.role) {
            .host => &self.host_endpoint,
            .join => &self.join_endpoint,
        };
    }

    fn lockstepEndpointInputMut(self: *NetworkState) *NetworkJoinEndpointInput {
        return switch (self.role) {
            .host => &self.host_endpoint,
            .join => &self.join_endpoint,
        };
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
    if (window_ui.confirmPressed() and state.selection == .launch) {
        beginPanelClose(&state.panel, .launch_network);
        return .{ .play_button_click = true };
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

fn drawNetworkPanel(state: *const NetworkState, assets: *const window_assets.RuntimeAssets, draw_backdrop: bool) void {
    const animated_rect = drawPanelShellEx(&state.panel, assets, draw_backdrop);
    window_ui.drawSmallText(assets, "Network Session", animated_rect.x + 174.0, animated_rect.y + 40.0, rl.Color.white);

    var line_buf: [96]u8 = undefined;
    var value_buf: [96]u8 = undefined;
    drawNetworkRow(assets, animated_rect, 0, state.selection == .role, "Role", networkRoleLabel(state.role), &line_buf);
    drawNetworkRow(assets, animated_rect, 1, state.selection == .mode, "Mode", networkModeValueLabel(state), &line_buf);
    drawNetworkRow(assets, animated_rect, 2, state.selection == .players, "Players", networkPlayersValueLabel(state, &value_buf), &line_buf);
    drawNetworkRow(assets, animated_rect, 3, state.selection == .netcode, "Netcode", networkNetcodeLabel(state.netcode), &line_buf);
    drawNetworkRow(assets, animated_rect, 4, state.selection == .endpoint, networkEndpointLabel(state), networkEndpointValueLabel(state, &value_buf), &line_buf);
    drawNetworkRow(assets, animated_rect, 5, state.selection == .room_code, "Code", networkCodeValueLabel(state), &line_buf);
    drawNetworkRow(assets, animated_rect, 6, state.selection == .launch, "Launch", networkLaunchValueLabel(state), &line_buf);

    window_ui.drawSmallText(assets, network_runtime_scope_text, animated_rect.x + 96.0, animated_rect.y + 292.0, rl.Color.init(214, 190, 170, 255));
    if (state.status_len != 0) {
        window_ui.drawSmallText(assets, state.statusText(), animated_rect.x + 136.0, animated_rect.y + 314.0, rl.Color.init(204, 204, 214, 255));
    }
}

pub fn networkLaunchRequest(state: *const NetworkState) ?NetworkLaunchRequest {
    return switch (state.netcode) {
        .lockstep => blk: {
            const endpoint = parseLockstepEndpoint(state.lockstepEndpointInput().slice()) orelse return null;
            break :blk .{
                .role = switch (state.role) {
                    .host => .host,
                    .join => .join,
                },
                .mode_id = networkModeId(state.mode),
                .player_count = std.math.clamp(state.player_count, @as(i32, 1), @as(i32, 4)),
                .netcode = .lockstep,
                .bind_host = switch (state.role) {
                    .host => endpoint.host,
                    .join => "0.0.0.0",
                },
                .host = endpoint.host,
                .port = endpoint.port,
            };
        },
        .rollback => blk: {
            const endpoint = parseNetworkEndpoint(state.relay_endpoint.slice()) orelse return null;
            const maybe_room_code: ?[]const u8 = switch (state.role) {
                .host => null,
                .join => blk_code: {
                    _ = room_code.parseRoomCode(state.room_code_input.slice()) catch return null;
                    break :blk_code state.room_code_input.slice();
                },
            };
            break :blk .{
                .role = switch (state.role) {
                    .host => .host,
                    .join => .join,
                },
                .mode_id = networkModeId(state.mode),
                .player_count = std.math.clamp(state.player_count, @as(i32, 1), @as(i32, 4)),
                .netcode = .rollback,
                .bind_host = "0.0.0.0",
                .host = endpoint.host,
                .port = endpoint.port,
                .room_code_text = maybe_room_code,
            };
        },
    };
}

pub fn networkLaunchUnavailableMessage(state: *const NetworkState) []const u8 {
    switch (state.netcode) {
        .lockstep => {
            if (parseLockstepEndpoint(state.lockstepEndpointInput().slice()) == null) {
                return switch (state.role) {
                    .host => "Lockstep bind must be IPv4[:port].",
                    .join => "Lockstep endpoint must be IPv4[:port].",
                };
            }
        },
        .rollback => {
            if (parseNetworkEndpoint(state.relay_endpoint.slice()) == null) {
                return "Relay endpoint must be IPv4[:port].";
            }
            if (state.role == .join) {
                _ = room_code.parseRoomCode(state.room_code_input.slice()) catch return "Room code must be 4 letters or digits.";
            }
        },
    }
    return "Network session is not ready.";
}

fn updatePanel(state: *PanelState, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets) UpdateResult {
    return updatePanelEx(state, frame_dt, runtime_assets, true);
}

fn updatePanelEx(state: *PanelState, frame_dt: f32, runtime_assets: ?*const window_assets.RuntimeAssets, confirm_backs: bool) UpdateResult {
    const dt_ms = @as(i32, @intFromFloat(@min(frame_dt, 0.1) * 1000.0));
    if (dt_ms > 0 and state.closing) {
        state.timeline_ms -= dt_ms;
        if (state.timeline_ms < 0 and state.close_action != .none) {
            const action = state.close_action;
            state.closing = false;
            state.close_action = .none;
            return .{ .action = action };
        }
    } else if (dt_ms > 0) {
        state.timeline_ms = @min(panel_timeline_max_ms, state.timeline_ms + dt_ms);
    }

    const back_hovered = if (runtime_assets) |assets|
        !state.closing and state.timeline_ms >= panel_timeline_max_ms and rl.checkCollisionPointRec(rl.getMousePosition(), window_menu.panelBackHitRect(assets, state.timeline_ms))
    else
        false;

    if (back_hovered) {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount + dt_ms * 6, 0, 1000);
    } else {
        state.back_hover_amount = std.math.clamp(state.back_hover_amount - dt_ms * 2, 0, 1000);
    }

    if (state.closing) return .{};

    if (rl.isKeyPressed(.escape) or (confirm_backs and window_ui.confirmPressed()) or (back_hovered and rl.isMouseButtonPressed(.left))) {
        beginPanelClose(state, .back_to_menu);
        return .{ .play_button_click = true };
    }

    return .{
        .play_panel_click = dt_ms > 0 and state.timeline_ms >= panel_timeline_max_ms and !state.panel_open_sfx_played,
    };
}

fn beginPanelClose(state: *PanelState, action: Action) void {
    if (state.closing) return;
    state.closing = true;
    state.close_action = action;
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
        5 => .room_code,
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
        .endpoint => {},
        .room_code => {},
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

fn networkEndpointLabel(state: *const NetworkState) []const u8 {
    return switch (state.netcode) {
        .rollback => "Relay",
        .lockstep => "Endpoint",
    };
}

fn networkEndpointValueLabel(state: *const NetworkState, scratch: *[96]u8) []const u8 {
    return switch (state.netcode) {
        .rollback => std.fmt.bufPrint(scratch[0..], "{s}", .{state.relay_endpoint.slice()}) catch "",
        .lockstep => switch (state.role) {
            .host => std.fmt.bufPrint(scratch[0..], "bind {s}", .{state.host_endpoint.slice()}) catch "",
            .join => std.fmt.bufPrint(scratch[0..], "host {s}", .{state.join_endpoint.slice()}) catch "",
        },
    };
}

fn networkCodeValueLabel(state: *const NetworkState) []const u8 {
    return switch (state.netcode) {
        .rollback => switch (state.role) {
            .host => "assigned by relay",
            .join => networkRoomCodeLabel(state),
        },
        .lockstep => "n/a",
    };
}

fn networkRoomCodeLabel(state: *const NetworkState) []const u8 {
    const code = state.room_code_input.slice();
    if (code.len == 0) return "-";
    return code;
}

fn collectNetworkEndpointInput(state: *NetworkState) NetworkEndpointInputEdits {
    var edits: NetworkEndpointInputEdits = .{};
    if (state.selection == .room_code and state.netcode == .rollback and state.role == .join) {
        return collectNetworkRoomCodeInput(state);
    }
    if (state.selection != .endpoint) return edits;

    if (state.netcode == .rollback) {
        while (true) {
            const codepoint = rl.getCharPressed();
            if (codepoint == 0) break;
            if (!networkEndpointCharAllowed(codepoint)) continue;
            edits.typed = state.relay_endpoint.insertChar(@intCast(codepoint)) or edits.typed;
        }

        if (rl.isKeyPressed(.backspace) or rl.isKeyPressedRepeat(.backspace)) {
            edits.backspaced = state.relay_endpoint.backspace();
        }
        return edits;
    }

    if (state.netcode != .lockstep or state.role != .join) return edits;

    while (true) {
        const codepoint = rl.getCharPressed();
        if (codepoint == 0) break;
        if (!networkEndpointCharAllowed(codepoint)) continue;
        edits.typed = state.lockstepEndpointInputMut().insertChar(@intCast(codepoint)) or edits.typed;
    }

    if (rl.isKeyPressed(.backspace) or rl.isKeyPressedRepeat(.backspace)) {
        edits.backspaced = state.lockstepEndpointInputMut().backspace();
    }
    return edits;
}

fn collectNetworkRoomCodeInput(state: *NetworkState) NetworkEndpointInputEdits {
    var edits: NetworkEndpointInputEdits = .{};
    while (true) {
        const codepoint = rl.getCharPressed();
        if (codepoint == 0) break;
        if (!networkRoomCodeCharAllowed(codepoint)) continue;
        edits.typed = state.room_code_input.insertChar(@intCast(codepoint)) or edits.typed;
    }

    if (rl.isKeyPressed(.backspace) or rl.isKeyPressedRepeat(.backspace)) {
        edits.backspaced = state.room_code_input.backspace();
    }
    return edits;
}

fn networkEndpointCharAllowed(codepoint: i32) bool {
    return (codepoint >= '0' and codepoint <= '9') or codepoint == '.' or codepoint == ':';
}

fn networkRoomCodeCharAllowed(codepoint: i32) bool {
    return (codepoint >= '0' and codepoint <= '9') or
        (codepoint >= 'a' and codepoint <= 'z') or
        (codepoint >= 'A' and codepoint <= 'Z');
}

fn networkLaunchValueLabel(state: *const NetworkState) []const u8 {
    return switch (state.netcode) {
        .lockstep => switch (state.role) {
            .host => if (parseLockstepEndpoint(state.host_endpoint.slice()) == null) "Invalid bind" else "Start host",
            .join => if (parseLockstepEndpoint(state.join_endpoint.slice()) == null) "Invalid endpoint" else "Join host",
        },
        .rollback => switch (state.role) {
            .host => if (parseNetworkEndpoint(state.relay_endpoint.slice()) == null) "Invalid relay" else "Create room",
            .join => if (parseNetworkEndpoint(state.relay_endpoint.slice()) == null)
                "Invalid relay"
            else if (room_code.parseRoomCode(state.room_code_input.slice())) |_|
                "Join room"
            else |_|
                "Invalid code",
        },
    };
}

fn parseLockstepEndpoint(text_raw: []const u8) ?NetworkEndpoint {
    return parseNetworkEndpoint(text_raw);
}

fn parseNetworkEndpoint(text_raw: []const u8) ?NetworkEndpoint {
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
    try std.testing.expectEqualStrings("Rollback and lockstep runtimes available.", network_runtime_scope_text);
}

test "misc panel close timeline gates action dispatch" {
    var panel: PanelState = .{ .timeline_ms = panel_timeline_max_ms };
    beginPanelClose(&panel, .back_to_menu);

    try std.testing.expect(panel.closing);
    try std.testing.expectEqual(Action.none, updatePanelEx(&panel, 0.10, null, true).action);
    try std.testing.expectEqual(panel_timeline_max_ms - 100, panel.timeline_ms);
    try std.testing.expectEqual(Action.none, updatePanelEx(&panel, 0.10, null, true).action);
    try std.testing.expectEqual(Action.none, updatePanelEx(&panel, 0.10, null, true).action);
    try std.testing.expect(panel.closing);

    const update_result = updatePanelEx(&panel, 0.01, null, true);
    try std.testing.expectEqual(Action.back_to_menu, update_result.action);
    try std.testing.expect(!panel.closing);
    try std.testing.expectEqual(Action.none, panel.close_action);
}

test "misc panel open timeline emits panel click when fully open" {
    var panel: PanelState = .{};

    for (0..2) |_| {
        const update_result = updatePanelEx(&panel, 0.10, null, true);
        try std.testing.expect(!update_result.play_panel_click);
    }

    var update_result = updatePanelEx(&panel, 0.10, null, true);
    try std.testing.expect(update_result.play_panel_click);

    panel.panel_open_sfx_played = true;
    update_result = updatePanelEx(&panel, 0.01, null, true);
    try std.testing.expect(!update_result.play_panel_click);
}

test "network panel defaults to host rollback session" {
    var state: NetworkState = .{};
    state.reset();

    try std.testing.expectEqual(NetworkRole.host, state.role);
    try std.testing.expectEqual(NetworkMode.survival, state.mode);
    try std.testing.expectEqual(NetworkNetcode.rollback, state.netcode);
    try std.testing.expectEqual(@as(i32, 2), state.player_count);
    try std.testing.expectEqualStrings("Host", networkRoleLabel(state.role));
    try std.testing.expectEqualStrings("Survival", networkModeValueLabel(&state));
    try std.testing.expectEqualStrings("Rollback ready.", state.statusText());
    var buf: [96]u8 = undefined;
    try std.testing.expectEqualStrings("Relay", networkEndpointLabel(&state));
    try std.testing.expectEqualStrings("127.0.0.1:31993", networkEndpointValueLabel(&state, &buf));
    try std.testing.expectEqualStrings("assigned by relay", networkCodeValueLabel(&state));
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

test "network panel join uses lobby-derived mode with editable rollback relay and room" {
    var state: NetworkState = .{ .role = .join, .selection = .endpoint };
    var buf: [96]u8 = undefined;

    try std.testing.expectEqualStrings("from lobby", networkModeValueLabel(&state));
    try std.testing.expectEqualStrings("from lobby", networkPlayersValueLabel(&state, &buf));
    try std.testing.expectEqualStrings("Relay", networkEndpointLabel(&state));
    try std.testing.expectEqualStrings("127.0.0.1:31993", networkEndpointValueLabel(&state, &buf));
    try std.testing.expectEqualStrings("ab12", networkCodeValueLabel(&state));

    state.room_code_input.set("ZX9Q!");
    try std.testing.expectEqualStrings("zx9q", networkCodeValueLabel(&state));
    state.relay_endpoint.set("203.0.113.20:32031");
    try std.testing.expectEqualStrings("203.0.113.20:32031", networkEndpointValueLabel(&state, &buf));

    state.netcode = .lockstep;
    try std.testing.expectEqualStrings("Endpoint", networkEndpointLabel(&state));
    try std.testing.expectEqualStrings("host 127.0.0.1:31993", networkEndpointValueLabel(&state, &buf));
    try std.testing.expectEqualStrings("n/a", networkCodeValueLabel(&state));
}

test "network panel edits lockstep join endpoint" {
    var state: NetworkState = .{ .role = .join, .selection = .endpoint, .netcode = .lockstep };
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

test "network panel edits rollback room code separately from lockstep host input" {
    var state: NetworkState = .{ .role = .join, .selection = .room_code };

    state.room_code_input.set("");
    try std.testing.expect(state.room_code_input.insertChar('A'));
    try std.testing.expect(state.room_code_input.insertChar('b'));
    try std.testing.expect(state.room_code_input.insertChar('1'));
    try std.testing.expect(state.room_code_input.insertChar('2'));
    try std.testing.expect(!state.room_code_input.insertChar('3'));
    try std.testing.expectEqualStrings("ab12", state.room_code_input.slice());
    try std.testing.expect(state.room_code_input.backspace());
    try std.testing.expectEqualStrings("ab1", state.room_code_input.slice());

    state.netcode = .lockstep;
    changeSelectedNetworkValue(&state, 1);
    try std.testing.expectEqualStrings("ab1", state.room_code_input.slice());
}

test "network panel endpoint input accepts ipv4 port characters only" {
    try std.testing.expect(networkEndpointCharAllowed('0'));
    try std.testing.expect(networkEndpointCharAllowed('9'));
    try std.testing.expect(networkEndpointCharAllowed('.'));
    try std.testing.expect(networkEndpointCharAllowed(':'));
    try std.testing.expect(!networkEndpointCharAllowed('a'));
}

test "network panel room code input accepts alnum only" {
    try std.testing.expect(networkRoomCodeCharAllowed('0'));
    try std.testing.expect(networkRoomCodeCharAllowed('z'));
    try std.testing.expect(networkRoomCodeCharAllowed('Z'));
    try std.testing.expect(!networkRoomCodeCharAllowed('-'));
    try std.testing.expect(!networkRoomCodeCharAllowed(':'));
}

test "network panel validates lockstep endpoint" {
    const parsed = parseLockstepEndpoint("192.168.1.44:32001") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("192.168.1.44", parsed.host);
    try std.testing.expectEqual(@as(u16, 32001), parsed.port);

    const default_port = parseLockstepEndpoint("192.168.1.44") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(u16, default_network_port), default_port.port);

    try std.testing.expect(parseLockstepEndpoint("192.168.1.44:0") == null);
    try std.testing.expect(parseLockstepEndpoint("192.168.1.44:") == null);
    try std.testing.expect(parseLockstepEndpoint("192.168.1.999:32001") == null);
    try std.testing.expect(parseLockstepEndpoint("192.168.1:32001") == null);
}

test "network panel builds launch requests for lockstep and rollback" {
    var state: NetworkState = .{};

    const rollback_host_default = networkLaunchRequest(&state) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(NetworkLaunchRole.host, rollback_host_default.role);
    try std.testing.expectEqual(NetworkLaunchNetcode.rollback, rollback_host_default.netcode);
    try std.testing.expect(rollback_host_default.room_code_text == null);
    try std.testing.expectEqualStrings("Network session is not ready.", networkLaunchUnavailableMessage(&state));

    state.netcode = .lockstep;
    const host_request = networkLaunchRequest(&state) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(NetworkLaunchRole.host, host_request.role);
    try std.testing.expectEqual(NetworkLaunchNetcode.lockstep, host_request.netcode);
    try std.testing.expectEqual(@as(i32, 1), host_request.mode_id);
    try std.testing.expectEqual(@as(i32, 2), host_request.player_count);
    try std.testing.expectEqualStrings("0.0.0.0", host_request.bind_host);
    try std.testing.expectEqualStrings("0.0.0.0", host_request.host);
    try std.testing.expectEqual(@as(u16, 31993), host_request.port);

    state.host_endpoint.set("127.0.0.1:32011");
    const custom_host_request = networkLaunchRequest(&state) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("127.0.0.1", custom_host_request.bind_host);
    try std.testing.expectEqual(@as(u16, 32011), custom_host_request.port);

    state.host_endpoint.set("127.0.0.1:0");
    try std.testing.expect(networkLaunchRequest(&state) == null);
    try std.testing.expectEqualStrings("Lockstep bind must be IPv4[:port].", networkLaunchUnavailableMessage(&state));
    state.host_endpoint.set(default_network_host_endpoint);

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
    state.relay_endpoint.set("203.0.113.20:32031");
    const rollback_join_request = networkLaunchRequest(&state) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(NetworkLaunchNetcode.rollback, rollback_join_request.netcode);
    try std.testing.expectEqual(NetworkLaunchRole.join, rollback_join_request.role);
    try std.testing.expectEqualStrings("203.0.113.20", rollback_join_request.host);
    try std.testing.expectEqual(@as(u16, 32031), rollback_join_request.port);
    try std.testing.expectEqualStrings("ab12", rollback_join_request.room_code_text.?);
    try std.testing.expectEqualStrings("Network session is not ready.", networkLaunchUnavailableMessage(&state));

    state.room_code_input.set("A1");
    try std.testing.expect(networkLaunchRequest(&state) == null);
    try std.testing.expectEqualStrings("Room code must be 4 letters or digits.", networkLaunchUnavailableMessage(&state));

    state.room_code_input.set("AB12");
    state.relay_endpoint.set("203.0.113.999:32031");
    try std.testing.expect(networkLaunchRequest(&state) == null);
    try std.testing.expectEqualStrings("Relay endpoint must be IPv4[:port].", networkLaunchUnavailableMessage(&state));
    try std.testing.expectEqualStrings("Invalid relay", networkLaunchValueLabel(&state));
    state.relay_endpoint.set("203.0.113.20:32031");

    state.role = .host;
    const rollback_host_request = networkLaunchRequest(&state) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(NetworkLaunchNetcode.rollback, rollback_host_request.netcode);
    try std.testing.expectEqual(NetworkLaunchRole.host, rollback_host_request.role);
    try std.testing.expectEqualStrings("203.0.113.20", rollback_host_request.host);
    try std.testing.expectEqual(@as(u16, 32031), rollback_host_request.port);
    try std.testing.expect(rollback_host_request.room_code_text == null);
}
