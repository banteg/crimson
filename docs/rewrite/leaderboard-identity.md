---
tags:
  - rewrite
  - contracts
---

# Leaderboard identity

The [ranked rules](ranked-rules.md) decide which runs rank; this page decides whose runs they are and what name
they show under. The game side is `src/crimson/leaderboard/`; the service (`service/`) runs at crimson.land.

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
  A Typ-o replay does carry the names of the local high score table its run read; Typ-o does not rank, so these
  never upload.
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
| `runs` | `replay` (the `.crd` file), `name`, `public_key`, `signature`; or for a [co-op run](#co-op-runs), `replay` and `signers` | 200 or 201 accepted, 409 already accepted, other 4xx refused with a `reason`, 5xx retried later |
| `auth/challenge` | `public_key` | 200 with `challenge` (ASCII) |
| `auth/login` | `public_key`, `challenge`, `signature` | 200 with `url`, a login link on the service's own host |
| `scores` | `board`, `quest` (`"major.minor"`, empty for Survival) | 200 with `scores`: each account's (or co-op pair's) best human run, up to 100, as the run's id (`run`), its name, its players' `names` and a high score record's fields |

The signatures cover byte strings that start with their purpose, so a run signature never passes as a login:

- a run: `crimson-run-v1\n`, then the SHA-256 of the replay's uncompressed payload, then the name in Latin-1;
- a co-op player's run: `crimson-coop-run-v1\n`, then the SHA-256 of the replay's uncompressed payload, then the
  player's seat as one byte (0 for player one), then their name in Latin-1;
- a login: `crimson-login-v1\n`, then the challenge.

A refused run moves to `leaderboard/rejected/` with its reason, so it stops retrying but stays on disk. The game
opens a login link only when it leads to the service's own host.

## Co-op runs

A run two players play together ([online co-op](network-coop.md)) is both players' and ranks on the co-op boards
([ranked rules](ranked-rules.md)). Its upload carries every player's signature, each binding its seat:

```json
{
  "replay": "<base64 .crd>",
  "signers": [
    {"seat": 0, "name": "banteg", "public_key": "<hex>", "signature": "<hex>"},
    {"seat": 1, "name": "razenpok", "public_key": "<hex>", "signature": "<hex>"}
  ]
}
```

- The replay records each seat's public key (`seat_keys`, [replay format](../formats/replay.md) 34), so the payload
  digest every signature covers names who sits where. Either partner holds the replay and could rewrite those keys,
  putting a throwaway key in the other's seat to sign both seats and take the run alone, so the room attests the pair:
  each seat proves its key to the co-op room ([network co-op](network-coop.md) §6.1), which issues a run's seed only
  once both seats have, and records the seed with their keys.
- The room's seeds leave bit 31 clear and the service refuses a co-op run whose seed sets it: the game's `rand` never
  reads that bit, so `s` and `s ^ 0x80000000` would play one run under two seeds.
- The service takes the run only when its replay records the seats' keys and a room issued its seed to those keys in
  seat order, with one signer for each of its players, every seat from 0 (player one, the room's host) once, signed by
  the key recorded for it, every signature verifying over its seat and name, and no key banned. A co-op run sent with
  fewer signatures, or in the one-player envelope, is refused with its reason, so the game holds it until both players
  have signed. A one-player run may use the envelope too, with its one signer in seat 0, and when its replay records a
  key, that key signs; it needs no room.
- Each key's account is credited with its seat, and each takes its seat's name as its latest. The run lists under
  player one's account, and the co-op board keeps each pair's best run, whichever seats they took: two players
  rank as a team, apart from either one's runs with someone else.
- A run is a bot run when either account is marked a bot, and leaves the boards when either is banned.
- Deleting an account keeps the runs it shares with a partner, who earned them too: its seat loses its key and name
  and shows as a deleted player, and the run lists under the partner. The seat still points at the account, which
  stays as a bare row (no name, keys, links, names or sessions, and no profile) with its bot and ban marks, so the
  partner's runs with different deleted players stay different teams and deleting an account lifts no moderator's
  decision. A run goes once only deleted players sit in it, and a bare account with its last run. Joining accounts
  moves the joined account's seats along.

## Duplicates and stolen runs

- A run's identity is the SHA-256 of its input stream (seed, settings and every tick's input) in the layout the
  service first verified, so recompressing a file or changing anything outside its play does not make it a new run,
  and ids stay put when the verifier's stream changes (`runIdentity` in `service/src/transport.ts`); a co-op run's
  stream holds both players' inputs and their count. The service
  accepts a run once; a second upload of the same run is rejected, whoever sends it.
- Replays become public only after the service accepts them. A copied replay can only beat its owner if it leaves
  their machine before they upload it.
- Ties keep the earlier accepted upload ahead.

## Names

- Each ranked run's name is the one typed into the high-score name entry when it ended: at most 31 characters in
  the range 0x20..0xFF, as the entry accepts.
- An unlinked account shows the name of its latest accepted run, or only its fingerprint while that is a fresh
  config's default `10tons`. Every board row belongs to the account, so a new name relabels its older entries too.
- A linked account shows a handle instead, beside its badges: the one its run's name matches, compared without case,
  else the one most of its links share, else the first in X, Discord, GitHub order, which is also where its avatar
  comes from. A mistyped name thus never hides who played, and each badge names its own handle where that differs.
  Run pages still say what a run was played as, and the profile lists every name the account has typed.
- Names are not unique. Where an unlinked account's name matches another account's name or handle, compared without
  case, the board adds the first four hex digits of its key's hash: `banteg · 3f2a`. A linked account shows its
  handle, so an impersonator always looks different from the player they copy.
- Moderators can hide an entry, hide a name (the account then shows only its fingerprint) and ban a key or an
  account. They also mark accounts as bots and move single runs between the human and bot boards, from the site
  ([bots and moderation](bots.md)). Every action is logged.

## Signing in on the site

The game opens the site already signed in:

1. The game asks the service for a one-time challenge.
2. It signs the challenge with its key; the service answers with a login link that works once, within five minutes.
3. The game opens the link in the browser. The page names the link's account, and the browser it is already signed
   in to if that is another one, and signs in only once the player confirms it. Confirming is a POST from the site's
   own page, so neither a link someone else sends nor another site can sign the browser in to their account unseen.
   The browser game shares the site's origin, so its Profile button spends the link itself and opens the profile.

Signing in sets a session cookie for 30 days, which the site keeps only as a hash, and ends the browser's previous
session. Each change the profile makes (unlinking, deleting, joining, starting a link) names the account its page
showed, and the service refuses it once the browser has signed in to another account, as a tab left open would. The
site's pages refuse to show inside another site's page (`frame-ancestors 'none'`); only the game does.

## Linking

The signed-in profile links a GitHub, Discord or X account, each shown only once its client ID and secret are
configured. Linking uses the authorization-code flow with the least scope each provider offers (GitHub none,
Discord `identify`, X `users.read tweet.read` with PKCE). The state is bound to the site session, the callbacks
are `/auth/{github,discord,x}/callback` on the site's own origin (`https://crimson.land`, or
`http://localhost:8787` under `wrangler dev`), and the client secrets and token exchange stay in the Worker. The
provider's token reads the profile once and is discarded; the link keeps the account's id, handle and avatar URL.

Signing in with a login another account has linked, matched by the provider's account ID and never the handle,
shows that account and asks before moving this key, its runs and its names into it, which is how a second computer
joins. The question names both accounts and warns that the key moved in signs in to the joined account from then
on, so a player signed in to someone else's account by mistake can tell. The move happens in one transaction once confirmed, from the session that asked. The profile unlinks a provider and deletes the account with its runs,
replays, names, links, keys and sessions, keeping the [co-op runs](#co-op-runs) a partner shares with a bare account
in its seat.
`/privacy` and `/terms` say the same in plain words.

## In the game

- The Play Game panel shows a **Profile** button at the left of its bottom row, opposite the Ranked box, only while
  Ranked is ticked; it follows the box in focus order. It opens the signed login link.
- Inside another site's page, such as a post's player card, the browser keeps the game's storage apart from
  crimson.land's, so the game there has a key of its own. It offers no Ranked box or Profile button, so that key
  never starts an account; it still receives the boards and plays their runs. The button's plate is 32 px
  tall against the box's 16, so the row is 40 px and the box sits centred on the plate. At 640x480 the grown panel
  would push Back off the window, so the panel and Back rise by the overflow instead.
- The Ranked tooltip names the player, "Play for the online leaderboard as banteg.", when that fits the panel and
  the name is not a fresh config's default `10tons`. The Profile tooltip says how many runs wait to upload, or that
  the leaderboard can't be reached after a failed login. Both stay on one line, above the bottom row.
- The high score screen's **Update scores** works as the original's did against `scores.crimsonland.com`
  ([online high scores](../crimsonland-exe/online-scores.md)): it sends the waiting runs, then receives the shown
  board, with the original's status lines under the buttons and Play a game disabled meanwhile. Only the verified
  boards are received: Survival and quests, for one player or a co-op pair; in other modes it only sends. The received runs show in
  green beside the local scores while **Show internet scores** is ticked, which a receive turns on; a local run the
  board holds turns green instead of showing twice. Unlike the original, received runs stay in memory for the
  session instead of joining the local high score files, and a board not yet received is fetched when the box is
  ticked or the screen shows it.

## Run pages

Every accepted run has a page at `/runs/<run id>`, linked from its score on the boards and profiles, and its replay
at `/runs/<run id>.crd`. The page, its API (`/api/runs/<run id>` and its timeline), its card (`/runs/<run id>.png`),
its ground (`/runs/<run id>.ground.jpg`) and the replay refuse a hidden run and a banned account's, as the boards do; a retired run keeps them. The replay
is cached only briefly (`REPLAY_MAX_AGE_S` in `service/src/index.ts`), so hiding, bans and deletions take effect
within that.

While the service replays a run to verify it, crimson-core's `portable_probe` reads player one (in co-op too) after
every tick,
and the service keeps a timeline next to the replay (`runs/<id>.timeline.json` in R2, `service/src/timeline.ts`):

- once a second, experience, level, health, kills and the damage creatures took (overkill excluded);
- ten times a second, the position;
- weapon changes, level-ups, perk picks, Nukes and the spans of the timed bonuses.

The page draws them against the board's top run and the player's own best. A run accepted before timelines existed
gets its timeline the first time its page asks, by replaying its file.

The same pass bakes the run's ground as it ended: `portable_bakes` hands out each tick's decals and corpses as the
original's `fx_queue_render` finds them, and the service stamps them into the terrain the run's seed generates, as
that function draws them into the game's terrain (`service/src/ground.ts`). A long run bakes over a million blood
splats, each pixel under hundreds, so the service draws them in chunks, newest first, and stops sampling a pixel once
what lies under it no longer shows. The ground is kept as a 1024² JPEG (`runs/<id>.ground.jpg` in R2, quality 88 at
full chroma) and drawn by the run's page and its card. Verifying every stored run for a deploy bakes its ground again,
in CI or in the deploy itself (`npm run reverify`), and the deploy puts them in R2 once the build is live (`npm run
grounds`), so grounds follow the
deployed baking and no run's first view waits for its replay; a run the service lacks one for still gets it on
first request, as it would a timeline.

## Open

- Showing a linked handle in the game needs the service to say whether the key's account is linked.

## Browser gameplay counts

Gameplay analytics are separate from leaderboard identity. Only the top-level browser game sends them, to
`POST /api/analytics` (anonymous totals) and `POST /api/analytics/unique` (daily presence). Ingestion runs before
cookie/session/account lookup; the client omits credentials and referrers. It sends no names, keys, accounts,
replays, quest IDs, URLs, browser details or IPs. Invocation logging remains disabled.
Requests are capped at 2 KiB with fixed fields and bounded numeric totals. A shared Cloudflare rate-limit
binding allows 1,000 ingestion requests per minute per Cloudflare location, using a constant application key
rather than an IP, token or browser fingerprint. Over-budget analytics are dropped or retried as described below.

A browser profile keeps only its latest `{day, token}` in `crimson.play-analytics` in localStorage. Actual
live gameplay creates a cryptographically random 128-bit token for the UTC day, independently of previous days.
A Web Lock serializes creation across tabs. D1's `(day, token)` primary key and insert trigger count retries
and concurrent submissions once. No timestamp, mode or activity is stored with the token. The current UTC day
and previous two days are accepted; an hourly cron removes older tokens even if traffic stops. D1 Time Travel
backups can retain deleted rows for up to 30 days. Daily aggregate counts remain indefinitely.

Gameplay totals contain loading, sessions starting live play, sessions reaching five accumulated active minutes,
and runs/active seconds by mode. The game exposes a local run generation and live mode, excluding Watch,
preparing, menus, run-down and paused practice. Practice takeover and retry count as attempts. The browser
samples visible, focused wall time about once a second, caps a sampling gap at two seconds, and flushes totals
each minute, on pause/background and on exit. Totals are best effort and never retried; unique presence retries
with its same token once a minute while playing. Anonymous totals carry no token or session identifier.

A co-op session that reached its partner's game sends one summary as it ends to `POST /api/analytics/coop`
([network co-op, Telemetry](network-coop.md#telemetry)): the kind of transport it last ran over, its round trip's
bucket, its minutes in runs, whether it desynced, and histograms of its rollback depths and frame work with its stalled
frames. It names no room, seat, partner or token; the service adds it to daily totals by transport and keeps nothing
per session.

`crimson.play-analytics-disabled` is the persistent opt-out preference, exposed on `/privacy`. Opting out keeps
only today's token, so opting back in the same day does not count the browser twice. Opt-out, Do Not Track,
Global Privacy Control, unavailable storage, embedding and unrelated hostnames suppress gameplay reporting.
This preference is separate from Cloudflare Web Analytics. Native clients send no gameplay analytics.
`GET /api/analytics` and `/analytics` expose only aggregates to the signed-in admin, never daily tokens. Daily
unique browser counts cannot be summed into weekly/monthly uniques; devices, storage resets and shared browsers
limit their interpretation as people. Reports are client supplied and are not proof of human play.

Deployment requires migration `0007_play_analytics.sql` before the Worker/client update and enables the hourly
cleanup trigger; co-op summaries need `0009_coop_analytics.sql`.
