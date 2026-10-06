---
tags:
  - rewrite
  - contracts
---

# Leaderboard identity

Status: design. Nothing here is built yet. The [ranked rules](ranked-rules.md) decide which runs rank; this page
decides whose runs they are and what name they show under.

The original game had no accounts: it posted scores to `scores.crimsonland.com` as the HTTP user `guest` with the
chosen name in the payload ([online high scores](../crimsonland-exe/online-scores.md)). The port keeps that
low-friction spirit. Nobody needs an account to rank, and ranked play never needs to be online.

## Keys and accounts

- On first launch the game creates an Ed25519 keypair in the runtime directory with PyNaCl (libsodium, on the cffi
  the game already ships with). The public key is the player's identity; nothing else is asked for or stored.
- An account is a set of keys. A new key starts its own account.
- The game can export the key to a file, so an unlinked player can move it to another machine.
- Linking a GitHub or Discord login to an account is optional, and happens on the site (see
  [Signing in on the site](#signing-in-on-the-site)). It lets a player add a new machine's key to their account by
  signing in with the linked login, and gives their entries a linked badge.

## Uploads

- Replays stay free of identity. A `.crd` carries the run, not the player, so anyone can still verify any replay.
- The game signs each upload: the replay, the name, the public key and an Ed25519 signature over the SHA-256 of the
  replay's uncompressed payload and the name. The service rejects an upload whose signature does not verify; Workers
  verify Ed25519 with WebCrypto, so the service needs no library for it.
- A finished ranked run goes into an upload queue in the runtime directory. The game sends queued runs when it can
  reach the service and keeps them until the service answers, so a run played offline uploads later.
- The client draws the seed ([ranked rules](ranked-rules.md#the-ranked-profile)). Without a server-issued seed a
  player could play many seeds offline and submit the best; the game is chaotic enough that this is an accepted
  risk.

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

From there the site shows the profile, links a GitHub or Discord login, and attaches a new key to an account the
player signs into with a linked login.

## In the game

- The Play Game panel shows a **Profile** button at the left of its bottom row, opposite the Ranked box, only while
  Ranked is ticked. It opens the signed login link. The button's plate is 32 px tall against the box's 16, so the
  row grows from 28 to 40 px and the box moves down 4 px to stay centred on the plate.
- The Ranked tooltip carries the account state, for example "Play for the online leaderboard as banteg (linked)",
  or how many runs are waiting to upload when the service cannot be reached.

## Open

- The service itself is gate 5 in `crimson-core/ROADMAP.md`: the challenge and login endpoints, uploads verified
  by crimson-core, storage and the boards.
