# Credits-derived recovery leads

Checked 2026-09-28 against all twelve recovered historical executables. No
additional Crimsonland version was recovered in this pass.

[all-versions.json](all-versions.json) records executable SHA-256 hashes, all
freeware credits-block strings with file offsets, and commercial credits setter
calls with addresses and final nonempty lines. [extract.py](extract.py) reproduces
that evidence from the local binaries using `pefile`; run it from the repository
root with `.venv/bin/python analysis/historical/credits-leads/extract.py`.
[manifest.json](manifest.json) preserves the earlier handle extraction, source
URLs, capture hashes and checks. Raw captures and binaries remain ignored.

## Differences between recovered builds

These are first appearances **among recovered builds**, not exact introduction
versions. The freeware heading combines testers, thanks and greetings; it does
not establish that everybody listed was a beta tester.

| Version | Credits evidence / changes |
| --- | --- |
| ✅ 1.0.2 | 14 handles; full nine-person 10tons roster with handle/name mappings. |
| ✅ 1.3.0 | Adds crud, muzzy, PornReindeer, Quarot, Sniperwolf / Wolf_, Strombo: 20 handles. Explicit Pelit.fi / MuroPaketti.com thanks. Same team roster. |
| ✅ 1.3.1 | Adds matricks, Tieom, Womba!: 23 handles. Team roster replaced by short logo credit to pHx. |
| ✅ 1.4.0 | Same 23 handles. Adds Grim API & SFX API credit; forum thanks shortened to a single line. |
| ✅ 1.8.7 | Commercial role-based credits, including 24 play testers, manual authors and Remedy special thanks. |
| ✅ 1.9.0 | Adds play tester Dirk Bunk. |
| ✅ 1.9.1 | Adds play tester Avraham Petrosyan. |
| ✅ 1.9.3 | Same credited names as 1.9.1. |
| ✅ 1.9.8 | Same credited names as 1.9.1. |
| ✅ 1.9.9 | Same credited names as 1.9.1. |
| ✅ 1.9.92 | Same credited names as 1.9.1. |
| ✅ 1.9.93-gog | Same credited names as 1.9.1. |

The original 14 handles are Armas, epaz, exi, Jayzon, KySSe, lore, milzer,
monotonic, Outolintu, Skele, TeLa, Ukuli, Vulderi and Wiltsu.

## Explicit early team aliases

The 1.0.2 and 1.3.0 binaries themselves supply these mappings, so they do not
rely on guessing identities from similar forum handles. This is the broader
10tons roster, not a claim that each person worked on Crimsonland.

| Handle | Name in the roster | Role in the roster |
| --- | --- | --- |
| milzer | Miikka Kulmala | code, HTML, 2D graphics |
| vulder | Valtteri Pihlajamäki | ideas, music |
| jmp | Janne Papula | code |
| temper | Tero Alatalo | code, 2D/3D graphics |
| sampsas | Samppa Nevala | code |
| armas | Timo Palonen | 3D graphics |
| dimoon | Pertti Viitala | 3D graphics |
| crud | Ville Eriksson | music, 3D graphics |
| pHx | Pasi Heinonen | 2D graphics |

## Strongest new lead: milzer's preserved source

The commercial game credits **Miikka Kulmala** for its manual and play testing.
His credit profile led to [milzer.org](https://milzer.org/), which links to
[github.com/milzer](https://github.com/milzer); the public GitHub profile gives
his name. The explicit early roster independently connects the handle and name.

His [Pikku-ukot mesoo repository](https://github.com/milzer/pikku-ukot-mesoo)
preserves source and assets for a game developed in 1999–2001. Its original
`src/pumApp.cpp` credits 10tons entertainment in 2001, milzer and crud, and names
`www.10tons.org`. The exact inspected commit is recorded in the manifest.
This is a contemporary collaborator demonstrably preserving old material.

Inspected the nine-repository public listing, Pikku-ukot mesoo's complete
recursive tree and text source files, and the
[Burn'o'Priest 2025 README](https://github.com/milzer/burno2025). No Crimsonland
package or source reference was found in the inspected historical repository.
The Burn'o'Priest repository is a modern remake. This is a useful preservation
contact lead, not evidence that he has a missing Crimsonland build. No message
was sent.

## Earlier lead: matricks

The name appears in 1.3.1 but not 1.3.0. A contemporary
[SweClockers post by matricks](https://www.sweclockers.com/forum/post/988391)
on 2002-08-29 links to `http://www.birdie.org/~ascorbiq/paqer.zip` and
`http://batman.jypoly.fi/~94132/edgeboard/index.php?a=topic&forum=3&topic=42`.
The matching handle is suggestive, not independently proven to be the same
individual. The filename suggests an archive tool; its contents are unknown.

| Target | Result |
| --- | --- |
| ✅ Contemporary forum post | Recovered with its date and original outbound links. |
| ❌ paqer.zip payload | Live HTTPS target returned 404; DiscMaster query returned no entries. |
| ❓ Wayback copies of birdie / edgeboard / milzer | Service errors or timeouts; archive coverage remains unknown. |
| ❌ Additional Crimsonland build from credits leads | None recovered in this pass. |

## Stored greetings are overwritten

All eight commercial executables contain `Greeting to:`, `Chaos^`, `Matricks`
and `Muzzy`. However, their builders assign all four to one line index and then
replace it with an empty string: index 65 in 1.8.7 / 1.9.0, index 66 from 1.9.1
onward. These names are **residual strings, not final displayed credit lines**.
This was checked against the actual setter calls in every commercial binary,
not inferred from the latest decompiled source alone. The final tables also
retain the secret-screen hints, which supply no additional people or URLs.

Other handle/name searches produced credit databases or ambiguous matches;
none supplied another verified game archive. Similar handles on unrelated
forums were not treated as identity matches. All binary comparison was static;
no recovered executable was run for this investigation.
