const std = @import("std");
const rng_callers = @import("../rng_caller_static.zig");
const spawn_mod = @import("../runtime/spawn.zig");

pub const name_max_chars: usize = 16;
pub const max_dictionary_words: usize = 2048;
pub const max_highscore_names: usize = 512;
pub const max_name_entries: usize = 0x180;

const NameStorage = [name_max_chars]u8;
const candidate_storage_len: usize = name_max_chars * 4;
const name_parts = [_][]const u8{
    "lamb",  "gun",   "head", "tail",   "leg",   "nose",  "road",  "stab", "high",   "low",
    "hat",   "pie",   "hand", "jack",   "cube",  "ice",   "cow",   "king", "lord",   "mate",
    "mary",  "dick",  "bill", "cat",    "harry", "tom",   "fly",   "call", "shot",   "gate",
    "quick", "brown", "fox",  "jumper", "over",  "lazy",  "dog",   "zeta", "unique", "nerd",
    "earl",  "sleep", "onyx", "mill",   "blue",  "below", "scape", "reap", "damo",   "break",
    "boom",  "the",
};

fn zeroStorage(storage: *NameStorage) void {
    @memset(storage[0..], 0);
}

fn sliceStorage(storage: *const NameStorage) []const u8 {
    const len = std.mem.indexOfScalar(u8, storage[0..], 0) orelse storage.len;
    return storage[0..len];
}

fn copyIntoStorage(storage: *NameStorage, text: []const u8) void {
    zeroStorage(storage);
    const len = @min(text.len, storage.len);
    @memcpy(storage[0..len], text[0..len]);
}

pub const CreatureNameTable = struct {
    names: [max_name_entries]NameStorage = [_]NameStorage{[_]u8{0} ** name_max_chars} ** max_name_entries,

    pub fn clearAll(self: *CreatureNameTable) void {
        for (&self.names) |*name| zeroStorage(name);
    }

    pub fn clear(self: *CreatureNameTable, idx: usize) void {
        if (idx >= self.names.len) return;
        zeroStorage(&self.names[idx]);
    }

    pub fn nameSlice(self: *const CreatureNameTable, idx: usize) []const u8 {
        if (idx >= self.names.len) return "";
        return sliceStorage(&self.names[idx]);
    }

    pub fn findByName(
        self: *const CreatureNameTable,
        name: []const u8,
        active_mask: []const bool,
    ) ?usize {
        for (self.names, 0..) |_, idx| {
            if (idx >= active_mask.len or !active_mask[idx]) continue;
            if (std.mem.eql(u8, self.nameSlice(idx), name)) return idx;
        }
        return null;
    }

    pub fn isUnique(
        self: *const CreatureNameTable,
        name: []const u8,
        exclude_idx: usize,
        active_mask: []const bool,
    ) bool {
        for (self.names, 0..) |_, idx| {
            if (idx == exclude_idx) continue;
            if (idx >= active_mask.len or !active_mask[idx]) continue;
            if (std.mem.eql(u8, self.nameSlice(idx), name)) return false;
        }
        return true;
    }

    pub fn assignRandom(
        self: *CreatureNameTable,
        creature_idx: usize,
        rng: *spawn_mod.Crand,
        score_xp: i32,
        active_mask: []const bool,
        dictionary_words: []const []const u8,
        highscore_names: []const []const u8,
    ) []const u8 {
        var too_long_attempts: usize = 0;
        var attempts: usize = 0;
        var candidate_storage: [candidate_storage_len]u8 = undefined;
        while (true) {
            const candidate = typoBuildName(&candidate_storage, rng, score_xp, dictionary_words, highscore_names);
            if (!self.isUnique(candidate, creature_idx, active_mask)) {
                attempts += 1;
                if (attempts < 200) continue;
            }

            if (candidate.len < name_max_chars or too_long_attempts > 99) {
                copyIntoStorage(&self.names[creature_idx], candidate);
                return self.nameSlice(creature_idx);
            }
            too_long_attempts += 1;
        }
    }
};

fn drawTagged(rng: *spawn_mod.Crand, caller: rng_callers.Caller) u32 {
    return rng.randTagged(caller);
}

fn pickHighscoreName(rng: *spawn_mod.Crand, highscore_names: []const []const u8) []const u8 {
    if (highscore_names.len == 0) return "quickbrownfox";
    return highscore_names[drawTagged(rng, rng_callers.typo_word_pick_highscore_name) % highscore_names.len];
}

fn typoNamePart(rng: *spawn_mod.Crand, allow_the: bool) []const u8 {
    const mod: usize = if (allow_the) 52 else 51;
    const idx = drawTagged(rng, rng_callers.typo_word_pick_fragment) % mod;
    if (idx == 39) return "nerd";
    return name_parts[idx];
}

fn pickWord(rng: *spawn_mod.Crand, words: []const []const u8) []const u8 {
    if (words.len == 0) return "";
    return words[rng.rand() % words.len];
}

fn buildCustomName(
    storage: *[candidate_storage_len]u8,
    rng: *spawn_mod.Crand,
    score_xp: i32,
    dictionary_words: []const []const u8,
) []const u8 {
    if (dictionary_words.len == 0) return "";
    if (score_xp > 120) {
        if (rng.rand() % 100 < 10) return pickWord(rng, dictionary_words);
        if (rng.rand() % 100 < 80) return joinUniqueWords(storage, rng, dictionary_words, 4);
    }
    if ((score_xp > 80 and rng.rand() % 100 < 80) or
        (score_xp > 60 and rng.rand() % 100 < 40))
    {
        return joinUniqueWords(storage, rng, dictionary_words, 3);
    }
    if ((score_xp > 40 and rng.rand() % 100 < 80) or
        (score_xp > 20 and rng.rand() % 100 < 40))
    {
        return joinUniqueWords(storage, rng, dictionary_words, 2);
    }
    return pickWord(rng, dictionary_words);
}

fn joinUniqueWords(
    storage: *[candidate_storage_len]u8,
    rng: *spawn_mod.Crand,
    words: []const []const u8,
    count: usize,
) []const u8 {
    var len: usize = 0;
    var used: [4]usize = [_]usize{std.math.maxInt(usize)} ** 4;
    var used_len: usize = 0;
    @memset(storage[0..], 0);
    var picked: usize = 0;
    while (picked < count) : (picked += 1) {
        const idx = rng.rand() % words.len;
        if (words.len > count) {
            var seen = false;
            for (used[0..used_len]) |used_idx| {
                if (used_idx == idx) {
                    seen = true;
                    break;
                }
            }
            if (seen) {
                picked -= 1;
                continue;
            }
            used[used_len] = idx;
            used_len += 1;
        }
        const part = words[idx];
        const copy_len = @min(part.len, storage.len - len);
        @memcpy(storage[len .. len + copy_len], part[0..copy_len]);
        len += copy_len;
        if (len >= storage.len) break;
    }
    return storage[0..len];
}

fn buildTaggedName(
    storage: *[candidate_storage_len]u8,
    rng: *spawn_mod.Crand,
    score_xp: i32,
    highscore_names: []const []const u8,
) []const u8 {
    @memset(storage[0..], 0);
    if (score_xp > 120) {
        if (drawTagged(rng, rng_callers.typo_target_name_assign_random_highscore_gate) % 100 < 10) {
            return pickHighscoreName(rng, highscore_names);
        }
        if (drawTagged(rng, rng_callers.typo_target_name_assign_random_four_word_gate) % 100 < 80) {
            return joinTaggedParts(storage, rng, 4);
        }
    }
    if ((score_xp > 80 and drawTagged(rng, rng_callers.typo_target_name_assign_random_three_word_gate_gt80) % 100 < 80) or
        (score_xp > 60 and drawTagged(rng, rng_callers.typo_target_name_assign_random_three_word_gate_gt60) % 100 < 40))
    {
        return joinTaggedParts(storage, rng, 3);
    }
    if ((score_xp > 40 and drawTagged(rng, rng_callers.typo_target_name_assign_random_two_word_gate_gt40) % 100 < 80) or
        (score_xp > 20 and drawTagged(rng, rng_callers.typo_target_name_assign_random_two_word_gate_gt20) % 100 < 40))
    {
        return joinTaggedParts(storage, rng, 2);
    }
    return typoNamePart(rng, false);
}

fn joinTaggedParts(
    storage: *[candidate_storage_len]u8,
    rng: *spawn_mod.Crand,
    count: usize,
) []const u8 {
    var len: usize = 0;
    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        const part = typoNamePart(rng, idx == 0);
        const copy_len = @min(part.len, storage.len - len);
        @memcpy(storage[len .. len + copy_len], part[0..copy_len]);
        len += copy_len;
        if (len >= storage.len) break;
    }
    return storage[0..len];
}

pub fn typoBuildName(
    storage: *[candidate_storage_len]u8,
    rng: *spawn_mod.Crand,
    score_xp: i32,
    dictionary_words: []const []const u8,
    highscore_names: []const []const u8,
) []const u8 {
    if (dictionary_words.len > 0) return buildCustomName(storage, rng, score_xp, dictionary_words);
    return buildTaggedName(storage, rng, score_xp, highscore_names);
}

test "creature name table can assign and resolve random names" {
    var rng = spawn_mod.Crand.init(1);
    var names: CreatureNameTable = .{};
    var active = [_]bool{false} ** max_name_entries;
    active[0] = true;
    const assigned = names.assignRandom(0, &rng, 130, active[0..], &.{}, &.{"Alpha"});
    try std.testing.expect(assigned.len > 0);
    try std.testing.expect(names.findByName(assigned, active[0..]) != null);
}
