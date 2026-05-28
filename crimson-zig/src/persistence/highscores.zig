const builtin = @import("builtin");
const std = @import("std");
const game_ids = @import("../game_ids.zig");

pub const record_size: usize = 0x48;
pub const record_wire_size: usize = record_size + 4;
pub const table_max: usize = 100;

pub const name_size: usize = 0x20;
pub const name_max_edit: usize = 0x14;
pub const uni_num_mask: u32 = 16348 * 16348 - 1;

const crt_rand_mult: u32 = 214_013;
const crt_rand_inc: u32 = 2_531_011;
var fallback_uni_num_counter: u32 = 0;

pub const DateStamp = struct {
    year: i32,
    month: u8,
    day: u8,
};

pub const HighScoreError = error{
    InvalidSize,
} || std.mem.Allocator.Error || std.Io.Dir.ReadFileAllocError || std.Io.Dir.WriteFileError || std.Io.Dir.CreateDirPathError;

pub const RecordList = struct {
    items: []HighScoreRecord,

    pub fn deinit(self: RecordList, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
    }
};

pub const UpsertResult = struct {
    records: []HighScoreRecord,
    rank_index: usize,

    pub fn deinit(self: UpsertResult, allocator: std.mem.Allocator) void {
        allocator.free(self.records);
    }
};

pub const HighScoreRecord = struct {
    data: [record_size]u8,

    pub fn blank() HighScoreRecord {
        return blankWithRandValue(nextFallbackRandValue());
    }

    pub fn blankWithRandValue(rand_value: u32) HighScoreRecord {
        var record: HighScoreRecord = .{ .data = [_]u8{0} ** record_size };
        record.data[0x46] = 0x7C;
        record.data[0x47] = 0xFF;
        record.setUniNum(uniNumFromRand(rand_value));
        return record;
    }

    pub fn fromBytes(bytes: []const u8) HighScoreError!HighScoreRecord {
        if (bytes.len != record_size) return error.InvalidSize;

        var record: HighScoreRecord = .{ .data = [_]u8{0} ** record_size };
        @memcpy(record.data[0..], bytes);
        return record;
    }

    pub fn copy(self: HighScoreRecord) HighScoreRecord {
        return self;
    }

    pub fn name(self: *const HighScoreRecord) []const u8 {
        const raw = self.data[0..name_size];
        const zero_index = std.mem.indexOfScalar(u8, raw, 0) orelse raw.len;
        return raw[0..zero_index];
    }

    pub fn setName(self: *HighScoreRecord, value: []const u8) void {
        @memset(self.data[0..name_size], 0);
        const len = @min(value.len, name_size - 1);
        @memcpy(self.data[0..len], value[0..len]);
        self.data[len] = 0;
    }

    pub fn trimTrailingSpaces(self: *HighScoreRecord) void {
        const raw = self.data[0..name_size];
        const end = std.mem.indexOfScalar(u8, raw, 0) orelse raw.len;
        var i = end;
        while (i > 0 and raw[i - 1] == 0x20) : (i -= 1) {
            raw[i - 1] = 0;
        }
    }

    pub fn survivalElapsedMs(self: *const HighScoreRecord) u32 {
        return readU32(self.data[0x20..][0..4]);
    }

    pub fn setSurvivalElapsedMs(self: *HighScoreRecord, value: u32) void {
        writeU32(self.data[0x20..][0..4], value);
    }

    pub fn scoreXp(self: *const HighScoreRecord) u32 {
        return readU32(self.data[0x24..][0..4]);
    }

    pub fn setScoreXp(self: *HighScoreRecord, value: u32) void {
        writeU32(self.data[0x24..][0..4], value);
    }

    pub fn gameModeRaw(self: *const HighScoreRecord) i32 {
        return self.data[0x28];
    }

    pub fn gameModeId(self: *const HighScoreRecord) ?game_ids.GameModeId {
        return std.enums.fromInt(game_ids.GameModeId, self.gameModeRaw()) orelse null;
    }

    pub fn setGameModeRaw(self: *HighScoreRecord, value: i32) void {
        self.data[0x28] = @intCast(value & 0xFF);
    }

    pub fn setGameModeId(self: *HighScoreRecord, value: game_ids.GameModeId) void {
        self.setGameModeRaw(@intFromEnum(value));
    }

    pub fn questStageMajor(self: *const HighScoreRecord) u8 {
        return self.data[0x29];
    }

    pub fn setQuestStageMajor(self: *HighScoreRecord, value: u8) void {
        self.data[0x29] = value;
    }

    pub fn questStageMinor(self: *const HighScoreRecord) u8 {
        return self.data[0x2A];
    }

    pub fn setQuestStageMinor(self: *HighScoreRecord, value: u8) void {
        self.data[0x2A] = value;
    }

    pub fn mostUsedWeaponId(self: *const HighScoreRecord) game_ids.WeaponId {
        return std.enums.fromInt(game_ids.WeaponId, self.data[0x2B]) orelse .none;
    }

    pub fn setMostUsedWeaponId(self: *HighScoreRecord, value: game_ids.WeaponId) void {
        self.data[0x2B] = @intCast(@intFromEnum(value));
    }

    pub fn shotsFired(self: *const HighScoreRecord) u32 {
        return readU32(self.data[0x2C..][0..4]);
    }

    pub fn setShotsFired(self: *HighScoreRecord, value: u32) void {
        writeU32(self.data[0x2C..][0..4], value);
    }

    pub fn shotsHit(self: *const HighScoreRecord) u32 {
        return readU32(self.data[0x30..][0..4]);
    }

    pub fn setShotsHit(self: *HighScoreRecord, value: u32) void {
        writeU32(self.data[0x30..][0..4], value);
    }

    pub fn creatureKillCount(self: *const HighScoreRecord) u32 {
        return readU32(self.data[0x34..][0..4]);
    }

    pub fn setCreatureKillCount(self: *HighScoreRecord, value: u32) void {
        writeU32(self.data[0x34..][0..4], value);
    }

    pub fn uniNum(self: *const HighScoreRecord) u32 {
        return readU32(self.data[0x38..][0..4]);
    }

    pub fn setUniNum(self: *HighScoreRecord, value: u32) void {
        writeU32(self.data[0x38..][0..4], value);
    }

    pub fn reserved(self: *const HighScoreRecord) u32 {
        return readU32(self.data[0x3C..][0..4]);
    }

    pub fn setReserved(self: *HighScoreRecord, value: u32) void {
        writeU32(self.data[0x3C..][0..4], value);
    }

    pub fn dateWeek(self: *const HighScoreRecord) u8 {
        return self.data[0x41];
    }

    pub fn setDateWeek(self: *HighScoreRecord, value: u8) void {
        self.data[0x41] = value;
    }

    pub fn flags(self: *const HighScoreRecord) u8 {
        return self.data[0x44];
    }

    pub fn setFlags(self: *HighScoreRecord, value: u8) void {
        self.data[0x44] = value;
    }

    pub fn hardcoreMarker(self: *const HighScoreRecord) u8 {
        return self.data[0x45];
    }

    pub fn setHardcoreMarker(self: *HighScoreRecord, value: u8) void {
        self.data[0x45] = value;
    }

    pub fn ensureDateFields(self: *HighScoreRecord, now: ?DateStamp) void {
        if (self.data[0x40] != 0) return;

        const stamp = now orelse currentDateStamp();
        self.data[0x40] = stamp.day;
        self.data[0x42] = stamp.month;
        self.data[0x43] = @intCast(@mod(stamp.year - 2000, 256));
        self.setDateWeek(@intCast(highscoreDateWeek(stamp.year, stamp.month, stamp.day) & 0xFF));
    }
};

pub const ScoresPathOptions = struct {
    hardcore: bool = false,
    quest_stage_major: i32 = 0,
    quest_stage_minor: i32 = 0,
    player_count: i32 = 1,
};

pub fn highscoreDateWeek(year: i32, month: u8, day: u8) i32 {
    var i_var1 = @divFloor(0x0E - @as(i32, month), 0x0C);
    var i_var2 = (year - i_var1) + 0x12C0;
    i_var1 = (((i_var2 + ((i_var2 >> 31) & 3)) >> 2) - 0x7D2D + @as(i32, day) + ((@divFloor(i_var2, 400) + (@divFloor(((@as(i32, month) + i_var1 * 0x0C) * 0x99) - 0x1C9, 5) + i_var2 * 0x16D)) - @divFloor(i_var2, 100)));
    i_var2 = @mod(@mod(@mod((i_var1 - @mod(i_var1, 7)) + 0x7BFD, 0x23AB1), 0x8EAC), 0x5B5);
    i_var1 = @divFloor(i_var2, 0x5B4);
    return @divFloor(@mod(i_var2 - i_var1, 0x16D) + i_var1, 7) + 1;
}

pub fn uniNumFromRand(rand_value: u32) u32 {
    return rand_value & uni_num_mask;
}

fn nextFallbackRandValue() u32 {
    fallback_uni_num_counter +%= 1;
    const seed: u32 = @truncate(currentEpochSeconds());
    const state = (seed +% fallback_uni_num_counter) *% crt_rand_mult +% crt_rand_inc;
    return (state >> 16) & 0x7fff;
}

pub fn scoresDirForBaseDir(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fs.path.join(allocator, &.{ base_dir, "scores5" });
}

pub fn scoresPathForMode(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    game_mode_id_raw: i32,
    options: ScoresPathOptions,
) std.mem.Allocator.Error![]u8 {
    const root = try scoresDirForBaseDir(allocator, base_dir);
    defer allocator.free(root);

    const file_name = try scoresFileName(allocator, game_mode_id_raw, options);
    defer allocator.free(file_name);

    return std.fs.path.join(allocator, &.{ root, file_name });
}

pub fn readHighscoreRecords(
    allocator: std.mem.Allocator,
    path: []const u8,
) HighScoreError!RecordList {
    const io = std.Io.Threaded.global_single_threaded.io();
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => return .{ .items = try allocator.alloc(HighScoreRecord, 0) },
        else => return err,
    };
    defer allocator.free(bytes);

    var records: std.ArrayList(HighScoreRecord) = .empty;
    defer records.deinit(allocator);

    var offset: usize = 0;
    while (offset + record_wire_size <= bytes.len) : (offset += record_wire_size) {
        const encoded = bytes[offset .. offset + record_size];
        const stored_checksum = readU32(bytes[offset + record_size .. offset + record_wire_size]);
        const decoded = try decodeRecordPayload(encoded);
        if (scoreChecksum(decoded) != stored_checksum) continue;
        try records.append(allocator, .{ .data = decoded });
    }

    return .{ .items = try records.toOwnedSlice(allocator) };
}

pub fn writeHighscoreRecords(
    allocator: std.mem.Allocator,
    path: []const u8,
    records: []const HighScoreRecord,
    now: ?DateStamp,
) HighScoreError!void {
    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |dir_path| {
        try std.Io.Dir.cwd().createDirPath(io, dir_path);
    }

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);

    for (records) |record_in| {
        var record = record_in.copy();
        record.trimTrailingSpaces();
        record.ensureDateFields(now);
        const encoded = encodeRecordPayload(record.data);
        const checksum = scoreChecksum(record.data);

        try bytes.appendSlice(allocator, encoded[0..]);
        try appendU32(allocator, &bytes, checksum);
    }

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes.items,
    });
}

pub fn readHighscoreTable(
    allocator: std.mem.Allocator,
    path: []const u8,
    game_mode_id_raw: i32,
) HighScoreError!RecordList {
    const records = try readHighscoreRecords(allocator, path);
    defer records.deinit(allocator);

    var filtered: std.ArrayList(HighScoreRecord) = .empty;
    defer filtered.deinit(allocator);

    for (records.items) |record| {
        if (record.gameModeRaw() != game_mode_id_raw) continue;
        try filtered.append(allocator, record);
    }

    sortHighscores(filtered.items, game_mode_id_raw);
    if (filtered.items.len > table_max) {
        filtered.shrinkRetainingCapacity(table_max);
    }

    return .{ .items = try filtered.toOwnedSlice(allocator) };
}

pub fn rankIndex(records_sorted: []const HighScoreRecord, record: HighScoreRecord) usize {
    const mode = normalizeGameMode(record.gameModeRaw());
    return switch (mode orelse .survival) {
        .rush => blk: {
            const score = record.survivalElapsedMs();
            for (records_sorted, 0..) |entry, idx| {
                if (score > entry.survivalElapsedMs()) break :blk idx;
            }
            break :blk records_sorted.len;
        },
        .quests => blk: {
            const score = record.survivalElapsedMs();
            for (records_sorted, 0..) |entry, idx| {
                const other = entry.survivalElapsedMs();
                if (other == 0) break :blk idx;
                if (score < other) break :blk idx;
            }
            break :blk records_sorted.len;
        },
        else => blk: {
            const score = record.scoreXp();
            for (records_sorted, 0..) |entry, idx| {
                if (score > entry.scoreXp()) break :blk idx;
            }
            break :blk records_sorted.len;
        },
    };
}

pub fn upsertHighscoreRecord(
    allocator: std.mem.Allocator,
    path: []const u8,
    record: HighScoreRecord,
    now: ?DateStamp,
) HighScoreError!UpsertResult {
    var records_sorted = try readHighscoreTable(allocator, path, record.gameModeRaw());

    const idx = rankIndex(records_sorted.items, record);
    if (idx >= table_max) {
        return .{ .records = records_sorted.items, .rank_index = idx };
    }

    var updated = std.ArrayList(HighScoreRecord).fromOwnedSlice(records_sorted.items);
    records_sorted.items = &.{};
    errdefer updated.deinit(allocator);
    try updated.insert(allocator, idx, record.copy());
    if (updated.items.len > table_max) {
        updated.shrinkRetainingCapacity(table_max);
    }

    try writeHighscoreRecords(allocator, path, updated.items, now);
    return .{
        .records = try updated.toOwnedSlice(allocator),
        .rank_index = idx,
    };
}

pub fn sortHighscores(records: []HighScoreRecord, game_mode_id_raw: i32) void {
    std.sort.heap(HighScoreRecord, records, game_mode_id_raw, highscoreLessThan);
}

fn normalizeGameMode(game_mode_id_raw: i32) ?game_ids.GameModeId {
    return std.enums.fromInt(game_ids.GameModeId, game_mode_id_raw) orelse null;
}

fn highscoreLessThan(game_mode_id_raw: i32, lhs: HighScoreRecord, rhs: HighScoreRecord) bool {
    const mode = normalizeGameMode(game_mode_id_raw);
    return switch (mode orelse .survival) {
        .rush => lhs.survivalElapsedMs() > rhs.survivalElapsedMs(),
        .quests => blk: {
            const lhs_time = lhs.survivalElapsedMs();
            const rhs_time = rhs.survivalElapsedMs();
            if (lhs_time == 0 and rhs_time != 0) break :blk false;
            if (lhs_time != 0 and rhs_time == 0) break :blk true;
            break :blk lhs_time < rhs_time;
        },
        else => lhs.scoreXp() > rhs.scoreXp(),
    };
}

fn scoreChecksum(data: [record_size]u8) u32 {
    var checksum: u32 = 0;
    for (data, 0..) |value, idx| {
        checksum +%= @as(u32, @intCast(idx + 3)) * @as(u32, value) * 7;
    }
    return checksum;
}

fn encodeByte(value: u8, idx: usize) u8 {
    return @intCast((@as(u32, value) + @as(u32, @intCast((idx * 5 + 1) * idx + 6))) & 0xFF);
}

fn decodeByte(value: u8, idx: usize) u8 {
    return @intCast((@as(u32, value) -% @as(u32, @intCast((idx * 5 + 1) * idx + 6))) & 0xFF);
}

fn decodeRecordPayload(encoded: []const u8) HighScoreError![record_size]u8 {
    if (encoded.len != record_size) return error.InvalidSize;

    var out: [record_size]u8 = undefined;
    for (encoded, 0..) |value, idx| {
        out[idx] = decodeByte(value, idx);
    }
    return out;
}

fn encodeRecordPayload(decoded: [record_size]u8) [record_size]u8 {
    var out: [record_size]u8 = undefined;
    for (decoded, 0..) |value, idx| {
        out[idx] = encodeByte(value, idx);
    }
    return out;
}

fn scoresFileName(
    allocator: std.mem.Allocator,
    game_mode_id_raw: i32,
    options: ScoresPathOptions,
) std.mem.Allocator.Error![]u8 {
    const mode = normalizeGameMode(game_mode_id_raw);
    const base = if (mode) |known_mode| switch (known_mode) {
        .survival => try allocator.dupe(u8, "survival.hi"),
        .rush => try allocator.dupe(u8, "rush.hi"),
        .typo => try allocator.dupe(u8, "typo.hi"),
        .quests => blk: {
            const prefix = if (options.hardcore) "quest" else "questhc";
            break :blk try std.fmt.allocPrint(
                allocator,
                "{s}{d}_{d}.hi",
                .{ prefix, options.quest_stage_major, options.quest_stage_minor },
            );
        },
        else => try allocator.dupe(u8, "unknown.hi"),
    } else try allocator.dupe(u8, "unknown.hi");

    errdefer allocator.free(base);

    if (options.player_count <= 1 or !std.mem.endsWith(u8, base, ".hi")) {
        return base;
    }

    const count = std.math.clamp(options.player_count, 2, 4);
    const stem_len = base.len - 3;
    const suffixed = try std.fmt.allocPrint(allocator, "{s}_{d}.hi", .{ base[0..stem_len], count });
    allocator.free(base);
    return suffixed;
}

fn appendU32(allocator: std.mem.Allocator, list: *std.ArrayList(u8), value: u32) std.mem.Allocator.Error!void {
    var bytes: [4]u8 = undefined;
    writeU32(bytes[0..], value);
    try list.appendSlice(allocator, bytes[0..]);
}

fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn writeU32(bytes: []u8, value: u32) void {
    std.mem.writeInt(u32, bytes[0..4], value, .little);
}

pub fn currentDateStamp() DateStamp {
    const epoch_seconds = currentEpochSeconds();
    return currentLocalDateStamp(epoch_seconds) orelse dateStampUtcFromEpochSeconds(epoch_seconds);
}

fn dateStampUtcFromEpochSeconds(seconds: u64) DateStamp {
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return .{
        .year = year_day.year,
        .month = @intCast(@intFromEnum(month_day.month) + 1),
        .day = @intCast(month_day.day_index + 1),
    };
}

const LocalTimeTm = extern struct {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: ?[*:0]const u8,
};

extern "c" fn localtime_r(timer: *const std.c.time_t, result: *LocalTimeTm) ?*LocalTimeTm;

fn currentLocalDateStamp(seconds: u64) ?DateStamp {
    if (builtin.os.tag == .freestanding or builtin.os.tag == .windows) return null;
    const max_time_t: u64 = @intCast(std.math.maxInt(std.c.time_t));
    if (seconds > max_time_t) return null;
    var timer: std.c.time_t = @intCast(seconds);
    var tm: LocalTimeTm = undefined;
    if (localtime_r(&timer, &tm) == null) return null;
    return dateStampFromLocalTm(tm);
}

fn dateStampFromLocalTm(tm: LocalTimeTm) DateStamp {
    return .{
        .year = @intCast(tm.tm_year + 1900),
        .month = @intCast(tm.tm_mon + 1),
        .day = @intCast(tm.tm_mday),
    };
}

fn currentEpochSeconds() u64 {
    if (builtin.os.tag == .freestanding) return 0;
    const io = std.Io.Threaded.global_single_threaded.io();
    const timestamp = std.Io.Timestamp.now(io, .real);
    return @intCast(@max(timestamp.toSeconds(), 0));
}

test "record name and field accessors roundtrip" {
    var record = HighScoreRecord.blankWithRandValue(0x7fff);
    record.setName("Alpha");
    record.setGameModeId(.survival);
    record.setSurvivalElapsedMs(5000);
    record.setScoreXp(1234);
    record.setMostUsedWeaponId(.shotgun);
    record.setShotsFired(20);
    record.setShotsHit(15);
    record.setCreatureKillCount(7);

    try std.testing.expectEqualStrings("Alpha", record.name());
    try std.testing.expectEqual(@as(?game_ids.GameModeId, .survival), record.gameModeId());
    try std.testing.expectEqual(@as(u32, 5000), record.survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 1234), record.scoreXp());
    try std.testing.expectEqual(game_ids.WeaponId.shotgun, record.mostUsedWeaponId());
    try std.testing.expectEqual(@as(u32, 20), record.shotsFired());
    try std.testing.expectEqual(@as(u32, 15), record.shotsHit());
    try std.testing.expectEqual(@as(u32, 7), record.creatureKillCount());
    try std.testing.expectEqual(@as(u32, 0x50f), record.uniNum());
    try std.testing.expectEqual(@as(u32, 0), record.reserved());
}

test "date fields use native dateWeek byte" {
    var record = HighScoreRecord.blankWithRandValue(0);
    record.ensureDateFields(.{ .year = 2026, .month = 5, .day = 28 });
    try std.testing.expectEqual(@as(u8, @intCast(highscoreDateWeek(2026, 5, 28) & 0xFF)), record.dateWeek());
}

test "date stamp utc conversion uses calendar day" {
    try std.testing.expectEqual(.{ .year = 1970, .month = 1, .day = 1 }, dateStampUtcFromEpochSeconds(0));
    try std.testing.expectEqual(.{ .year = 2026, .month = 3, .day = 3 }, dateStampUtcFromEpochSeconds(1772496000));
}

test "date stamp local conversion uses tm calendar fields" {
    const tm: LocalTimeTm = .{
        .tm_sec = 59,
        .tm_min = 58,
        .tm_hour = 23,
        .tm_mday = 3,
        .tm_mon = 2,
        .tm_year = 126,
        .tm_wday = 2,
        .tm_yday = 61,
        .tm_isdst = 0,
        .tm_gmtoff = 0,
        .tm_zone = null,
    };
    try std.testing.expectEqual(.{ .year = 2026, .month = 3, .day = 3 }, dateStampFromLocalTm(tm));
}

test "scores path builder mirrors Python naming rules" {
    const allocator = std.testing.allocator;

    const survival = try scoresPathForMode(allocator, "/tmp/runtime", @intFromEnum(game_ids.GameModeId.survival), .{});
    defer allocator.free(survival);
    try std.testing.expectEqualStrings("/tmp/runtime/scores5/survival.hi", survival);

    const survival_3 = try scoresPathForMode(allocator, "/tmp/runtime", @intFromEnum(game_ids.GameModeId.survival), .{ .player_count = 3 });
    defer allocator.free(survival_3);
    try std.testing.expectEqualStrings("/tmp/runtime/scores5/survival_3.hi", survival_3);

    const quest = try scoresPathForMode(allocator, "/tmp/runtime", @intFromEnum(game_ids.GameModeId.quests), .{
        .quest_stage_major = 2,
        .quest_stage_minor = 7,
    });
    defer allocator.free(quest);
    try std.testing.expectEqualStrings("/tmp/runtime/scores5/questhc2_7.hi", quest);

    const quest_hardcore_2p = try scoresPathForMode(allocator, "/tmp/runtime", @intFromEnum(game_ids.GameModeId.quests), .{
        .hardcore = true,
        .quest_stage_major = 2,
        .quest_stage_minor = 7,
        .player_count = 2,
    });
    defer allocator.free(quest_hardcore_2p);
    try std.testing.expectEqualStrings("/tmp/runtime/scores5/quest2_7_2.hi", quest_hardcore_2p);

    const unknown = try scoresPathForMode(allocator, "/tmp/runtime", 99, .{});
    defer allocator.free(unknown);
    try std.testing.expectEqualStrings("/tmp/runtime/scores5/unknown.hi", unknown);
}

test "quest and rush sorting mirror Python leaderboard rules" {
    var quest_records = [_]HighScoreRecord{
        blk: {
            var record = HighScoreRecord.blank();
            record.setGameModeId(.quests);
            record.setSurvivalElapsedMs(5000);
            break :blk record;
        },
        blk: {
            var record = HighScoreRecord.blank();
            record.setGameModeId(.quests);
            record.setSurvivalElapsedMs(2000);
            break :blk record;
        },
        blk: {
            var record = HighScoreRecord.blank();
            record.setGameModeId(.quests);
            record.setSurvivalElapsedMs(0);
            break :blk record;
        },
        blk: {
            var record = HighScoreRecord.blank();
            record.setGameModeId(.quests);
            record.setSurvivalElapsedMs(1000);
            break :blk record;
        },
    };
    sortHighscores(quest_records[0..], @intFromEnum(game_ids.GameModeId.quests));
    try std.testing.expectEqual(@as(u32, 1000), quest_records[0].survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 2000), quest_records[1].survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 5000), quest_records[2].survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 0), quest_records[3].survivalElapsedMs());

    var rush_records = [_]HighScoreRecord{
        blk: {
            var record = HighScoreRecord.blank();
            record.setGameModeId(.rush);
            record.setSurvivalElapsedMs(1000);
            break :blk record;
        },
        blk: {
            var record = HighScoreRecord.blank();
            record.setGameModeId(.rush);
            record.setSurvivalElapsedMs(5000);
            break :blk record;
        },
        blk: {
            var record = HighScoreRecord.blank();
            record.setGameModeId(.rush);
            record.setSurvivalElapsedMs(2000);
            break :blk record;
        },
    };
    sortHighscores(rush_records[0..], @intFromEnum(game_ids.GameModeId.rush));
    try std.testing.expectEqual(@as(u32, 5000), rush_records[0].survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 2000), rush_records[1].survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 1000), rush_records[2].survivalElapsedMs());
}

test "write and read highscore records preserve valid records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);

    const path = try scoresPathForMode(allocator, base_dir, @intFromEnum(game_ids.GameModeId.survival), .{});
    defer allocator.free(path);

    var record = HighScoreRecord.blank();
    record.setName("Player One");
    record.setGameModeId(.survival);
    record.setScoreXp(4321);
    record.setShotsFired(12);
    record.setShotsHit(9);

    try writeHighscoreRecords(allocator, path, &.{record}, .{
        .year = 2026,
        .month = 4,
        .day = 11,
    });

    const records = try readHighscoreRecords(allocator, path);
    defer records.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), records.items.len);
    try std.testing.expectEqualStrings("Player One", records.items[0].name());
    try std.testing.expectEqual(@as(u32, 4321), records.items[0].scoreXp());
    try std.testing.expectEqual(@as(u32, 12), records.items[0].shotsFired());
    try std.testing.expectEqual(@as(u32, 9), records.items[0].shotsHit());
}

test "upsert keeps quest tables sorted ascending with zero times last" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_dir = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer allocator.free(base_dir);

    const path = try scoresPathForMode(allocator, base_dir, @intFromEnum(game_ids.GameModeId.quests), .{
        .quest_stage_major = 1,
        .quest_stage_minor = 1,
    });
    defer allocator.free(path);

    inline for ([_]u32{ 5000, 2000, 0 }) |time_ms| {
        var record = HighScoreRecord.blank();
        record.setGameModeId(.quests);
        record.setSurvivalElapsedMs(time_ms);
        var result = try upsertHighscoreRecord(allocator, path, record, .{
            .year = 2026,
            .month = 4,
            .day = 11,
        });
        result.deinit(allocator);
    }

    const table = try readHighscoreTable(allocator, path, @intFromEnum(game_ids.GameModeId.quests));
    defer table.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), table.items.len);
    try std.testing.expectEqual(@as(u32, 2000), table.items[0].survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 5000), table.items[1].survivalElapsedMs());
    try std.testing.expectEqual(@as(u32, 0), table.items[2].survivalElapsedMs());
}
