---
tags:
  - reverse-engineering
  - provenance
  - history
---

# Early Crimsonland history

The original `koti.mbnet.fi/temper/crimsonland/` site survives as 33 root-page
captures representing five distinct revisions. The complete CDX result, raw
HTML for each distinct revision, retained artwork, hashes, and local release
artifact paths are recorded in
[`analysis/historical/koti-mbnet-crimsonland/`](../../../../analysis/historical/koti-mbnet-crimsonland/manifest.json).

## Site revisions

| First capture | Content |
| --- | --- |
| 2002-06-15 | Freeware 1.2.2 downloads and release notes through 2002-05-30. |
| 2002-10-04 | “Crimsonland will be back” placeholder. |
| 2003-04-16 | Reflexive publishing announcement, dated 2002-12-16. |
| 2003-08-12 | Redirect to `crimsonland.reflexive.net/crimsonland`. |
| 2006-02-06 | Redirect to `www.crimsonland.com`. |

The committed CDX inventory preserves every capture timestamp even when several
captures have identical content. Raw page captures and recovered artwork remain
under ignored artifact directories. The archive retained four images from the
2003 design. The 2002 logo, background, thumbnails, full screenshots, and both
1.2.2 ZIPs are referenced by the HTML but were not retained by Wayback.

## Release inventory

Every version below has contemporary evidence that it was published. A version
is "recovered" only when a package survives and its contents confirm the number.

### Freeware (2002)

| Version | State | Evidence |
| --- | --- | --- |
| 1.0.x | missing | The 2002-05-13 news entry says older headlines were deleted; 1.0.2 is the only 1.0.x number known. |
| 1.0.2 | recovered | Original ZIP preserved on the project asset host. |
| 1.1.1 | missing | Release notes on the 2002 page (2002-05-09, patch only). |
| 1.1.6 | missing | Release notes on the 2002 page (2002-05-13, patch only). |
| 1.1.7 | missing | Release notes plus Pelit catalog record `CLAND117.ZIP`, dated 2002-05-23; no payload survives there. |
| 1.2.1 | missing | Release notes on the 2002 page (2002-05-28, update). |
| 1.2.2 | missing | Full and no-music links survive; Wayback only retained later 404 responses. |
| 1.2.4 | missing | Mentioned retrospectively by the 1.3.0 and 1.4.0 readmes. |
| 1.3.0 | recovered | Original ZIP and readme dated 2002-07-11; Pelit catalog record `CLAND130.ZIP` is dated 2002-07-24. |
| 1.3.1 | missing | Crimsongame forum posts mention a 1.3.1 ZIP. |
| 1.4.0 | recovered | Original ZIP and readme dated 2002-09-16; the last freeware release. |

### Commercial (2003-2010)

| Version | State | Evidence |
| --- | --- | --- |
| 1.8.7 | missing | A single Crimsongame forum request for "1.9.0 or 1.8.7"; possibly a pre-launch build. |
| 1.9.0 | missing | Crimsongame forum posts. |
| 1.9.1 | recovered | Reflexive installer; the payload's `crimsonland.exe` reads `crimsonland v.1.9.1` (built 2003-06-09). |
| 1.9.3 | missing | The MOD SDK 1.0 readme (2003-08-14) requires "v1.93 or above". 1.9.2 and 1.9.4-1.9.7 are not individually attested. |
| 1.9.8 | recovered | Reflexive installer; the payload's `crimsonland.exe` reads `Crimsonland 1.9.8` (built 2003-08-18). |
| 1.9.9 | recovered | Suomipelit ZIP dated 2008-12-07; crimsonland.com news of 2008-11-20. |
| 1.9.91 | missing | Listed in the 1.9.93 `whatsupdated.txt`; the 2009 news post counts from "1.9.90". |
| 1.9.92 | unverified | crimsonland.com news of 2009-03-06. The one known installer uses a custom self-extractor that has not been unpacked. |
| 1.9.93 | recovered | The GOG Classic 2.0.0.4 build decompiled by this project; crimsonland.com news of 2010-06-30. |

Recovered packages are deliberately stored under ignored `game_bins/`, with
their retrieval URLs, sizes, and SHA-256 hashes committed in the manifest.

Both archived Reflexive installers wrap an Inno Setup installer in a Reflexive
Arcade loader, so their outer PE timestamps (2003-04-25 and 2004-04-08) date the
loader, not the game. Carving the embedded Inno image (at offset `0x34c04` and
`0x30e04`) and running `innoextract` recovers the full game tree. The executable
version strings and each package's `whatsupdated.txt` both identify the builds
as 1.9.1 and 1.9.8. The 1.9.1 notes still carry an "UPDATE ONLY package" heading,
although the package holds the complete game.

The 2014 remaster, GOG's "Classic 2.0.0.4" installer label, the Russian "2.0"
crack bundle built on 1.9.8, and the CL:ONE fan mod releases are separate
version lines and are not listed here.

## Linked forum threads

The June 2002 page links to Pelit.fi thread `398570` and MuroBBS thread
`118962`. Neither thread has been recovered. The evidence and ignored raw
artifacts are inventoried in
[`analysis/historical/crimsonland-forum-links/`](../../../../analysis/historical/crimsonland-forum-links/manifest.json).

The April 2022 MuroBBS bulk crawl does contain a record for the migrated URL
`/threads/118962/`, but the archived response is HTTP 404 and says the thread
was not found. The neighboring title-sorted CDX block contains no Crimsonland
record, and public Wayback results contain no capture of the original thread
ID. This makes the bulk archive evidence of a pre-crawl gap, not a recovered
copy of the discussion.

Pelit.fi's public Wayback prefix and exact-URL indexes contain no capture of
thread `398570`. Its file catalog does independently preserve records for
`CLAND117.ZIP` (1.1.7, 7.2 MB, 2002-05-23) and `CLAND130.ZIP` (1.3.0, 9.5 MB,
2002-07-24), but neither catalog record has a downloadable payload or checksum.
The current Pelit forum search requires authentication, so a migrated private
thread remains an open lead.

## Useful behavioral evidence

- The 1.2.1 page describes four prototype levels unlocked by holding left Ctrl
  and typing `LEVELS` in the main menu.
- The 1.3.0 package contains seven `.lvl` files (`level_1` through `level_4`,
  `outdoors`, `redlight`, and `tolmec`), while the 1.4.0 readme says level mode
  was disabled for that release.
- The 1.3.0 readme documents 17 weapons with two hidden weapons. The 1.4.0
  readme changes that to three hidden weapons and explicitly hints that players
  can trace the game binary to discover them.
- Both freeware readmes say Vampyrism was disabled in 1.2.4 and later. That is
  stronger evidence for an otherwise missing 1.2.4 release.
- The original page names Grim 2D API for graphics, FMOD for audio, and DirectX
  8.1 as a runtime requirement. It also records the early two-player shared-perk
  design and encrypted high-score migration.
- The 2002-12-16 announcement describes the commercial design before launch:
  Quest, Rush, and Survival, more than 40 perks, more than 15 weapons, and
  Reflexive's in-game trial purchasing system.

## Preservation boundary

The archive is intentionally honest about gaps. A release mention or dead link
is evidence that a version existed, not evidence that its package was recovered.
No 1.2.2 binary, screenshot, or missing 2002 image is represented as present.
