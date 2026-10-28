#pragma once
// Request IDs shared by the game import and desktop/browser hosts.
enum {
  HOST_LEADERBOARD_PROFILE = 1, HOST_LEADERBOARD_UPLOAD = 2, HOST_LEADERBOARD_SCORES = 3, HOST_LEADERBOARD_REPLAY = 4,
  HOST_LEADERBOARD_CUSTOM = 5, HOST_LEADERBOARD_QUEST = 6
};
// The game's room text for co-op (host/coop_ranked.inc): a room's id and its challenge, or a seat's key.
enum { COOP_ROOM_TEXT = 160 };
