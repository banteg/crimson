---
tags:
  - rewrite
  - parity
---

# Feature matrix

Where each way to play stands. Three clients play Crimsonland 1.9.93:

- **Python port**: the reimplementation in Python and raylib (`uvx crimsonland@latest`).
- **Web**: the original game, compiled from the recovered source, in the
  browser at [crimson.land/play](https://crimson.land/play/).
- **Native**: the same recovered game under an SDL3 host for desktop
  ([`crimson-core/PORT.md`](https://github.com/banteg/crimson/blob/master/crimson-core/PORT.md)).

The web and native clients run the original's own code, so they play as the
2003 game does, menus included. The Python port matches it tick by tick and adds
what a modern release needs. All three fix the
[original's documented bugs](original-bugs.md) by default.

## Getting it

| | Python port | Web | Native |
| --- | --- | --- | --- |
| Platforms | Windows, macOS, Linux | Any browser with WebGL2 | macOS, Linux; Windows not yet |
| Install | `uvx crimsonland@latest` | Nothing | CI builds only, no signed release channel |
| Game files | Downloaded on first launch | Downloaded on first visit, or your own Crimsonland folder | Downloaded on first launch, or a folder named on the command line |
| Saves | Per-user data directory | The browser's site storage | The Python port's per-user data directory, shared with it |

## Playing

| | Python port | Web | Native |
| --- | --- | --- | --- |
| Survival, Rush, Quests | Yes | Yes | Yes |
| Tutorial, Typ-o-Shooter | Yes | Yes | Yes |
| Local co-op | 2–4 players | 2 players, as the original | 2 players, as the original |
| Online co-op | No | 2 players from an invite link, with rollback | No |
| Original bugs | Fixed by default, kept with `--preserve-bugs` | Fixed | Fixed |
| Resolution | Any, with borderless fullscreen | 1024x768, scaled to the page; fullscreen button | 1024x768, scaled to the window; Alt+Enter fullscreen |
| Keyboard and mouse | Yes | Yes | Yes |
| Gamepads | PlayStation, Xbox and Switch Pro, twin-stick, every menu by pad | PlayStation, Xbox and Switch Pro, twin-stick, menus by pad; one pad at a time | PlayStation, Xbox and Switch Pro, twin-stick, menus by pad; one pad at a time |
| Music, sound, addon tunes | Yes | Yes | Yes |
| Uncompressed source art | Yes | Yes | With the distributed files |
| Mods | No | No | No |
| Custom quests | `crimson quest play` | Browse and play from the Mods entry, or open by link | Browse and play from the Mods entry |
| Console | Yes | Yes, outside runs | Yes, outside runs |

## Replays

| | Python port | Web | Native |
| --- | --- | --- | --- |
| Every run recorded | Yes, as `.crd` | Yes, in site storage, with no way to take it out | Yes, in the shared data directory |
| Watch a replay | From the high scores and `crimson replay play`, seeking anywhere | From the high scores and a run's link, seeking anywhere | From the high scores and `--watch` links, seeking anywhere |
| Verify or render a replay | `crimson replay verify`, `render` | No | No |
| Runs checked against the verifier | By the gate and the server | Every client build, in CI | Every client build, in CI |

## Leaderboard

| | Python port | Web | Native |
| --- | --- | --- | --- |
| Ranked play | Survival and Quests | Survival and Quests, alone or as an online co-op pair | Survival and Quests |
| Uploads, offline queue | Yes | Yes | Yes |
| Profile, signed in | Yes | Yes | Yes, in your browser |
| Update scores on the high score screen | Yes | Yes | Yes |
| Your key | `identity.key`; export and import with `crimson identity` | Site storage, no export; link an account to keep your runs | `identity.key` in the shared data directory |

## Next

- **Native releases**: a Windows host, signed builds and a release channel.
- **Web replays**: a way to download your recordings and your key, which today
  stay in the browser.
