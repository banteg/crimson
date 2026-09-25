const names_mod = @import("names.zig");
const typing_mod = @import("typing.zig");

pub const max_dictionary_words = names_mod.max_dictionary_words;
pub const max_highscore_names = names_mod.max_highscore_names;
pub const name_max_chars = names_mod.name_max_chars;
pub const highscore_name_max_chars = names_mod.highscore_name_max_chars;

pub const TypoState = struct {
    typing: typing_mod.TypingBuffer = .{},
    names: names_mod.CreatureNameTable = .{},
    spawn_cooldown_ms: i32 = 0,
    dictionary_word_count: usize = 0,
    dictionary_words: [max_dictionary_words][name_max_chars]u8 = [_][name_max_chars]u8{[_]u8{0} ** name_max_chars} ** max_dictionary_words,
    highscore_name_count: usize = 0,
    highscore_names: [max_highscore_names][highscore_name_max_chars + 1]u8 = [_][highscore_name_max_chars + 1]u8{[_]u8{0} ** (highscore_name_max_chars + 1)} ** max_highscore_names,
    pending_fire_target_active: bool = false,
    pending_fire_target_x: f32 = 0.0,
    pending_fire_target_y: f32 = 0.0,
    pending_reload: bool = false,

    /// Load the name sources; they must satisfy the replay format's rules
    /// (`replay_codec.isTypoDictionaryWord` / `isTypoHighscoreName` and counts).
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

        self.dictionary_word_count = dictionary_words.len;
        for (dictionary_words, self.dictionary_words[0..dictionary_words.len]) |word, *slot| {
            @memset(slot, 0);
            @memcpy(slot[0..word.len], word);
        }
        // Score-table names of any valid length stay in the pool: picks index
        // the whole list, and the name-length rule applies after the pick.
        self.highscore_name_count = highscore_names.len;
        for (highscore_names, self.highscore_names[0..highscore_names.len]) |name, *slot| {
            @memset(slot, 0);
            @memcpy(slot[0..name.len], name);
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
    state.reset(&.{"amber"}, &.{ "Alpha", "A" ** 31 });
    try std.testing.expectEqual(@as(usize, 1), state.dictionary_word_count);
    try std.testing.expectEqualStrings("amber", state.dictionaryWordSlice(0));
    try std.testing.expectEqualStrings("Alpha", state.highscoreNameSlice(0));
    try std.testing.expectEqualStrings("A" ** 31, state.highscoreNameSlice(1));
}
