---
tags:
  - rewrite
  - contracts
---

# Leaderboard identity

Status: the game side is built (`src/crimson/leaderboard/`); the service (`service/`) runs at crimson.land, a
Solid app over a JSON API. The
[ranked rules](ranked-rules.md) decide which runs rank; this page decides whose runs they are and what name they
show under.

The original game had no accounts: it posted scores to `scores.crimsonland.com` as the HTTP user `guest` with the
chosen name in the payload ([online high scores](../crimsonland-exe/online-scores.md)). The port keeps that
low-friction spirit. Nobody needs an account to rank, and ranked play never needs to be online.

## Keys and accounts

- On first launch the game creates an Ed25519 keypair in the runtime directory with PyNaCl (libsodium, on the cffi
  the game already ships with). The public key is the player's identity; nothing else is asked for or stored.
- An account is a set of keys. A new key starts its own account.
- The key lives in `identity.key` (the 32-byte seed, readable by its owner only). `crimson identity show` prints
  the public key and its fingerprint; `crimson identity export` and `crimson identity import` move it to another
  machine, and import refuses to overwrite a different key without `--replace`.
- Linking a GitHub or Discord login to an account is optional, and happens on the site (see
  [Signing in on the site](#signing-in-on-the-site)). It lets a player add a new machine's key to their account by
  signing in with the linked login, and gives their entries a linked badge.

## Uploads

- Replays stay free of identity. A `.crd` carries the run, not the player, so anyone can still verify any replay.
- The game signs each upload: the replay, the name, the public key and an Ed25519 signature over the SHA-256 of the
  replay's uncompressed payload and the name. The service rejects an upload whose signature does not verify; Workers
  verify Ed25519 with WebCrypto, so the service needs no library for it.
- A finished ranked run waits in the game until its results screen closes, which settles its name; quitting on
  that screen queues it too. It is then signed into `leaderboard/outbox/<run id>.json` in the runtime directory.
- The game uploads the outbox after each queued run, at launch and every ten minutes while runs wait. A run the
  service cannot be reached for stays for a later pass, so a run played offline uploads later; quitting never waits
  on the network.
- The client draws the seed ([ranked rules](ranked-rules.md#the-ranked-profile)). Without a server-issued seed a
  player could play many seeds offline and submit the best; the game is chaotic enough that this is an accepted
  risk.

## Protocol

The API root is `https://crimson.land/api`. `CRIMSON_LEADERBOARD_URL` points the game at another one, such as a
local Worker, and an empty value keeps every run on the machine. Every request is a JSON `POST`; byte strings are
hex, except the replay, which is base64.

| Endpoint | Body | Answer |
| --- | --- | --- |
| `runs` | `replay` (the `.crd` file), `name`, `public_key`, `signature` | 200 or 201 accepted, 409 already accepted, other 4xx refused with a `reason`, 5xx retried later |
| `auth/challenge` | `public_key` | 200 with `challenge` (ASCII) |
| `auth/login` | `public_key`, `challenge`, `signature` | 200 with `url`, a login link on the service's own host |
| `scores` | `board`, `quest` (`"major.minor"`, empty for Survival) | 200 with `scores`: each account's best run, up to 100, as the run's name and a high score record's fields |

The signatures cover byte strings that start with their purpose, so a run signature never passes as a login:

- a run: `crimson-run-v1\n`, then the SHA-256 of the replay's uncompressed payload, then the name in Latin-1;
- a login: `crimson-login-v1\n`, then the challenge.

A refused run moves to `leaderboard/rejected/` with its reason, so it stops retrying but stays on disk. The game
opens a login link only when it leads to the service's own host.

## Duplicates and stolen runs

- A run's identity is the SHA-256 of its uncompressed replay payload, so recompressing a file does not make it a
  new run. The service accepts a run once; a second upload of the same run is rejected, whoever sends it.
- Replays become public only after the service accepts them. A copied replay can only beat its owner if it leaves
  their machine before they upload it.
- Ties keep the earlier accepted upload ahead.

## Names

- Each ranked run's name is the one typed into the high-score name entry when it ended: at most 31 characters in
  the range 0x20..0xFF, as the entry accepts.
- An account's display name is the name of its latest accepted run. Every board row belongs to the account, so a
  new name relabels its older entries too. The profile lists every name the account has used.
- Names are not unique. Where two unlinked accounts show the same name, compared without case, the board adds the
  first four hex digits of each key's hash: `banteg · 3f2a`. A linked account shows its GitHub or Discord handle
  with a badge instead, so an impersonator always looks different from the player they copy.
- Moderators can hide an entry, hide a name (the account then shows only its fingerprint) and ban a key or an
  account. Every action is logged.

## Signing in on the site

The game opens the site already signed in:

1. The game asks the service for a one-time challenge.
2. It signs the challenge with its key; the service answers with a login link that works once, within a minute.
3. The game opens the link in the browser, which is then signed in as that key's account.

The link sets a session cookie for 30 days, which the site keeps only as a hash.

## Linking

The signed-in profile links a GitHub, Discord or X account, each shown only once its client ID and secret are
configured. Linking uses the authorization-code flow with the least scope each provider offers (GitHub none,
Discord `identify`, X `users.read tweet.read` with PKCE). The state is bound to the site session, the callbacks
are `/auth/{github,discord,x}/callback` on the site's own origin (`https://crimson.land`, or
`http://localhost:8787` under `wrangler dev`), and the client secrets and token exchange stay in the Worker. The
provider's token reads the profile once and is discarded; the link keeps the account's id, handle and avatar URL.

Signing in with a login another account has linked, matched by the provider's account ID and never the handle,
shows that account and asks before moving this key, its runs and its names into it, which is how a second computer
joins. The move happens in one transaction once confirmed, from the session that asked. The profile unlinks a provider and deletes the account with its runs,
replays, names, links, keys and sessions. `/privacy` and `/terms` say the same in plain words.

## In the game

- The Play Game panel shows a **Profile** button at the left of its bottom row, opposite the Ranked box, only while
  Ranked is ticked; it follows the box in focus order. It opens the signed login link. The button's plate is 32 px
  tall against the box's 16, so the row is 40 px and the box sits centred on the plate. At 640x480 the grown panel
  would push Back off the window, so the panel and Back rise by the overflow instead.
- The Ranked tooltip names the player, "Play for the online leaderboard as banteg.", when that fits the panel. The
  Profile tooltip says how many runs wait to upload, or that the leaderboard can't be reached after a failed
  login. Both stay on one line, above the bottom row.
- The high score screen's **Update scores** works as the original's did against `scores.crimsonland.com`
  ([online high scores](../crimsonland-exe/online-scores.md)): it sends the waiting runs, then receives the shown
  board, with the original's status lines under the buttons and Play a game disabled meanwhile. Only the verified
  boards are received: one-player Survival and quests; in other modes it only sends. The received runs show in
  green beside the local scores while **Show internet scores** is ticked, which a receive turns on; a local run the
  board holds turns green instead of showing twice. Unlike the original, received runs stay in memory for the
  session instead of joining the local high score files, and a board not yet received is fetched when the box is
  ticked or the screen shows it.

## Run pages

Every accepted run has a page at `/runs/<run id>`, linked from its score on the boards and profiles. While the
service replays a run to verify it, crimson-core's `portable_probe` reads player one after every tick, and the service
keeps a timeline next to the replay (`runs/<id>.timeline.json` in R2, `service/src/timeline.ts`):

- once a second, experience, level, health, kills and the damage creatures took (overkill excluded);
- ten times a second, the position;
- weapon changes, level-ups, perk picks, Nukes and the spans of the timed bonuses.

The page draws them against the board's top run and the player's own best, and rebuilds the run's terrain from its
seed. A run accepted before timelines existed gets its timeline the first time its page asks, by replaying its file.

## Open

- The service itself is gate 5 in `crimson-core/ROADMAP.md`: the endpoints above, uploads verified by
  crimson-core, storage, the site and the boards. Until it answers, ranked runs wait in the outbox.
- Showing a linked handle in the game needs the service to say whether the key's account is linked.
