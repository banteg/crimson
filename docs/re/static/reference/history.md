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

✅ Found means a package has been recovered and its contents confirm the version
number. ❌ Missing means a release is documented, but its package has not been
recovered. The 1.0.x row represents unspecified early releases.

### Freeware (2002)

| Version | State | Evidence |
| --- | --- | --- |
| 1.0.x | ❌ Missing | The 2002-05-13 news entry says older headlines were deleted; 1.0.2 is the only 1.0.x number known. |
| 1.0.2 | ✅ Found | Original ZIP preserved on the project asset host. |
| 1.1.1 | ❌ Missing | Release notes on the 2002 page (2002-05-09, patch only). |
| 1.1.6 | ❌ Missing | Release notes on the 2002 page (2002-05-13, patch only). |
| 1.1.7 | ❌ Missing | Release notes plus Pelit catalog record `CLAND117.ZIP`, dated 2002-05-23; no payload survives there. |
| 1.2.1 | ❌ Missing | Release notes on the 2002 page (2002-05-28, update). |
| 1.2.2 | ❌ Missing | Full and no-music links survive; Wayback only retained later 404 responses. |
| 1.2.4 | ❌ Missing | Mentioned retrospectively by the 1.3.0 and 1.4.0 readmes. |
| 1.3.0 | ✅ Found | Original ZIP and readme dated 2002-07-11; Pelit catalog record `CLAND130.ZIP` is dated 2002-07-24. |
| 1.3.1 | ✅ Found | `crimsonland_v131.zip` on the Computer Gaming World December 2002 disc; executable reads `v1.3.1`, readme dated 2002-09-08. |
| 1.4.0 | ✅ Found | Original ZIP and readme dated 2002-09-16; the last freeware release. |

### Commercial (2003-2010)

| Version | State | Evidence |
| --- | --- | --- |
| 1.8.7 | ✅ Found | Game.EXE June 2003 disc installer; executable reads `crimsonland v.1.8.7` (built 2003-04-22). |
| 1.9.0 | ✅ Found | PC Gamer August 2003 disc installer; executable reads `crimsonland v.1.9.0` (built 2003-05-21), with matching release notes. |
| 1.9.1 | ✅ Found | Reflexive installer; the payload's `crimsonland.exe` reads `crimsonland v.1.9.1` (built 2003-06-09). |
| 1.9.3 | ✅ Found | L'Encyclopedie Des Jeux Video 8 installer; executable reads `Crimsonland 1.9.3` (built 2003-06-30), with matching release notes. The PC Gamer October 2003 installer contains the same executable. |
| 1.9.8 | ✅ Found | Reflexive installer; the payload's `crimsonland.exe` reads `Crimsonland 1.9.8` (built 2003-08-18). |
| 1.9.9 | ✅ Found | Suomipelit ZIP dated 2008-12-07; crimsonland.com news of 2008-11-20. |
| 1.9.91 | ❌ Missing | Listed in the 1.9.93 `whatsupdated.txt`; the 2009 news post counts from "1.9.90". |
| 1.9.92 | ✅ Found | Reflexive installer from the RuTracker Reflexive Arcade corpus; the unwrapped `crimsonland.exe` reads `Crimsonland 1.9.92` (built 2009-02-23). crimsonland.com news of 2009-03-06. |
| 1.9.93 | ✅ Found | The GOG Classic 2.0.0.4 build decompiled by this project; crimsonland.com news of 2010-06-30. |

Recovered packages are deliberately stored under ignored `game_bins/`, with
their retrieval URLs, sizes, and SHA-256 hashes committed in the manifest.
Versions 1.9.2 and 1.9.4-1.9.7 are not individually attested.

### Recovery through disc contents

On 2026-09-28, filename searches in
[DiscMaster](https://discmaster.textfiles.com/search?q=crimsonland%2A)
recovered four previously missing builds: 1.3.1, 1.8.7, 1.9.0, and 1.9.3.
DiscMaster indexes files inside disc images and nested archives, allowing
packages to be found even when a disc's catalog description does not name the
game. Searching `crimsonland*` also finds `CrimsonlandSetup.exe`, which the
plain `crimsonland` search did not return.

The sources, original-package and executable hashes, exact version-string
offsets, PE timestamps, extraction details, and retained search results are in
[`analysis/historical/discmaster-recovery/manifest.json`](../../../../analysis/historical/discmaster-recovery/manifest.json).
The extracted trees are stored in `game_bins/crimsonland/{version}/` alongside
the previously recovered versions. All verification was static; these packages
have not been runtime-tested. Disc file dates and PE timestamps are not treated
as exact release dates.

The 1.8.7 recovery confirms the previously uncertain forum mention with an
actual distributed executable. The 1.9.0 installer contains a complete game
tree despite its release notes saying "UPDATE ONLY". The two 1.9.3 installers
have different hashes and differ in other files, but their game executables
are byte-identical. The `cland.exe` on Chip April 2002 was checked and excluded:
it is an unrelated puzzle game called C-Land.

The 2003 and 2004 Reflexive installers wrap an Inno Setup installer in a
Reflexive Arcade loader, so their outer PE timestamps (2003-04-25 and
2004-04-08) date the loader, not the game. Carving the embedded Inno image (at
offset `0x34c04` and `0x30e04`) and running `innoextract` recovers the full game
tree. The executable version strings and each package's `whatsupdated.txt` both
identify the builds as 1.9.1 and 1.9.8. The 1.9.1 notes still carry an "UPDATE
ONLY package" heading, although the package holds the complete game.

The 1.9.92 installer ships its game image as an encrypted `crimsonland.RWG`
behind the Reflexive wrapper, which
[reflexive](https://github.com/banteg/reflexive) unwraps. Its `whatsupdated.txt`
still stops at 1.9.91, so the 1.9.92 notes survive only in the 1.9.93 file. A
third-party WinRAR repack of the same build carries a byte-identical unwrapped
executable with rewritten 1.9.92 notes.

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
