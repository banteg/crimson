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

## Freeware release inventory

| Version | State | Evidence |
| --- | --- | --- |
| 1.0.2 | recovered | Original ZIP preserved on the project asset host. |
| 1.1.1 | missing | Release notes on the 2002 page. |
| 1.1.6 | missing | Release notes on the 2002 page. |
| 1.1.7 | missing | Release notes plus Pelit catalog record `CLAND117.ZIP`, dated 2002-05-23; no payload survives there. |
| 1.2.1 | missing | Release notes on the 2002 page. |
| 1.2.2 | missing | Full and no-music links survive; Wayback only retained later 404 responses. |
| 1.2.4 | missing | Mentioned retrospectively by the 1.3.0 and 1.4.0 readmes. |
| 1.3.0 | recovered | Original ZIP and readme dated 2002-07-11; Pelit catalog record `CLAND130.ZIP` is dated 2002-07-24. |
| 1.4.0 | recovered | Original ZIP and readme dated 2002-09-16. |

Recovered packages are deliberately stored under ignored `game_bins/`, with
their retrieval URLs, sizes, and SHA-256 hashes committed in the manifest.
Two historical Reflexive installers and the independently archived 1.9.9 ZIP
are preserved alongside them; the two installer versions remain undetermined
rather than inferred from upload metadata.

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
