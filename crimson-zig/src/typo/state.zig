const names_mod = @import("names.zig");
const typing_mod = @import("typing.zig");

pub const max_dictionary_words = names_mod.max_dictionary_words;
pub const max_highscore_names = names_mod.max_highscore_names;
pub const name_max_chars = names_mod.name_max_chars;

pub const TypoState = struct {
    typing: typing_mod.TypingBuffer = .{},
    names: names_mod.CreatureNameTable = .{},
    spawn_cooldown_ms: i32 = 0,
    dictionary_word_count: usize = 0,
    dictionary_words: [max_dictionary_words][name_max_chars]u8 = [_][name_max_chars]u8{[_]u8{0} ** name_max_chars} ** max_dictionary_words,
    highscore_name_count: usize = 0,
    highscore_names: [max_highscore_names][name_max_chars]u8 = [_][name_max_chars]u8{[_]u8{0} ** name_max_chars} ** max_highscore_names,
    pending_fire_target_active: bool = false,
    pending_fire_target_x: f32 = 0.0,
    pending_fire_target_y: f32 = 0.0,
    pending_reload: bool = false,

    pub fn reset(
        self: *TypoState,
        dictionary_words: []const []const u8,
        highscore_names: []const []const u8,
    ) void {
        self.typing = .{};
        self.names.clearAll();
        self.spawn_cooldown_ms = 0;
        self.pending_fire_target_active = false;
        self.pending_fire_target_x = 0.0;
        self.pending_fire_target_y = 0.0;
        self.pending_reload = false;

        self.dictionary_word_count = 0;
        for (dictionary_words) |word| {
            if (self.dictionary_word_count >= self.dictionary_words.len) break;
            if (word.len >= name_max_chars) continue;
            @memset(self.dictionary_words[self.dictionary_word_count][0..], 0);
            @memcpy(self.dictionary_words[self.dictionary_word_count][0..word.len], word);
            self.dictionary_word_count += 1;
        }

        self.highscore_name_count = 0;
        for (highscore_names) |name| {
            if (self.highscore_name_count >= self.highscore_names.len) break;
            if (name.len >= name_max_chars) continue;
            @memset(self.highscore_names[self.highscore_name_count][0..], 0);
            @memcpy(self.highscore_names[self.highscore_name_count][0..name.len], name);
            self.highscore_name_count += 1;
        }
    }

    pub fn dictionaryWordSlice(self: *const TypoState, idx: usize) []const u8 {
        if (idx >= self.dictionary_word_count) return "";
        const storage = self.dictionary_words[idx][0..];
        const len = std.mem.indexOfScalar(u8, storage, 0) orelse storage.len;
        return storage[0..len];
    }

    pub fn highscoreNameSlice(self: *const TypoState, idx: usize) []const u8 {
        if (idx >= self.highscore_name_count) return "";
        const storage = self.highscore_names[idx][0..];
        const len = std.mem.indexOfScalar(u8, storage, 0) orelse storage.len;
        return storage[0..len];
    }
};

const std = @import("std");

test "typo state reset copies dictionary and name sources" {
    var state: TypoState = .{};
    state.reset(&.{"amber"}, &.{"Alpha"});
    try std.testing.expectEqual(@as(usize, 1), state.dictionary_word_count);
    try std.testing.expectEqualStrings("amber", state.dictionaryWordSlice(0));
    try std.testing.expectEqualStrings("Alpha", state.highscoreNameSlice(0));
}
