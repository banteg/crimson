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
| Install | `uvx crimsonland@latest` | Nothing | CI builds only, not released or signed |
| Game files | Downloaded on first launch | Downloaded on first visit, or your own Crimsonland folder | Your own Crimsonland folder |
| Saves | Per-user data directory | The browser's site storage | The game folder |

## Playing

| | Python port | Web | Native |
| --- | --- | --- | --- |
| Survival, Rush, Quests | Yes | Yes | Yes |
| Tutorial, Typ-o-Shooter | Yes | Yes | Yes |
| Local co-op | 2–4 players | 2 players, as the original | 2 players, as the original |
| Original bugs | Fixed by default, kept with `--preserve-bugs` | Fixed | Fixed |
| Resolution | Any, with borderless fullscreen | 1024x768, scaled to the page; fullscreen button | 1024x768, scaled to the window |
| Keyboard and mouse | Yes | Yes | Yes |
| Gamepads | PlayStation, Xbox and Switch Pro, twin-stick, every menu by pad | One pad as the original's joystick | One pad as the original's joystick |
| Music, sound, addon tunes | Yes | Yes | Yes |
| Uncompressed source art | Yes | Yes | With the distributed files |
| Mods | No | No | No |
| Console | Yes | Yes, outside runs | Yes, outside runs |

## Replays

| | Python port | Web | Native |
| --- | --- | --- | --- |
| Every run recorded | Yes, as `.crd` | Yes, in site storage, with no way to take it out | Yes, in the game folder |
| Watch a replay | `crimson replay play` | No | No |
| Verify or render a replay | `crimson replay verify`, `render` | No | No |
| Runs checked against the verifier | By the gate and the server | Every client build, in CI | Every client build, in CI |

## Leaderboard

| | Python port | Web | Native |
| --- | --- | --- | --- |
| Ranked play | Survival and Quests | Survival and Quests | No |
| Uploads, offline queue | Yes | Yes | No |
| Profile, signed in | Yes | Yes | No |
| Update scores on the high score screen | Yes | Yes | No |
| Your key | `identity.key`; export and import with `crimson identity` | Site storage, no export; link an account to keep your runs | No |

## Next

- **Native leaderboard**: uploads and the profile need a network layer in the
  host, after which the Ranked box can show there too.
- **Native releases**: a Windows host, signed builds and a release channel.
- **Web replays**: a way to download your recordings and your key, which today
  stay in the browser.
