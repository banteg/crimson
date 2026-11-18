# Arcade source art compared with 1.9.93 and Frankenassets

Compared on 2026-10-12. The new pack substantially improves **coverage of matching
lossless source artwork**. Most artwork already used by Frankenassets is unchanged.
The asset refresh in #673 adopted the arcade archive and copied full matching
sheets and individual crops directly. This report records the comparison that
informed that refresh. [Asset refresh #673](https://github.com/banteg/crimson/pull/673)

The file inventory and pixel measurements use Tero's October 2004 arcade asset
archive. [Arcade asset ZIP](https://www.crimsonland.com/assets/crimsonland-arcade-cabinet-game-assets-2004-10-14.zip)

## Findings

| Asset | Prior Frankenassets | New source coverage compatible with 1.9.93 |
| --- | --- | --- |
| Bonuses | 13 populated source sprites; Fire Bullets and MediKit retain released JPEG artwork | All 15 populated sprites, plus the empty cell; exact released alpha throughout |
| Projectiles | Source for Pulse, Ion/fire and Splitter; Blade Gun retains released JPEG artwork | All four logical projectile regions; exact released alpha throughout |
| Corpse/body sheet | Entire released JAZ; earlier TGA is a different 128×128 bonus sheet | Correct 256×256 corpse sheet, all eight populated 64×64 cells; exact released alpha |
| Weapon icons | 23 of 32 slots use earlier source; nine use released artwork | 28 matching slots in place, plus Shrinkifier recovered from a different slot: **29/32** |
| Six player/creature animation sheets | Earlier source TGA | Byte-identical to earlier source; no additional quality gain |
| Particle effects | Earlier source TGA | Byte-identical to earlier source; all 19 effect-table cuts match the released alpha |
| Menu-label atlas | Earlier source TGA | Byte-identical to earlier source |
| Small font | Released TGA and width table | New TGA and width table are byte-identical to release |
| Default courier font | Released TGA | Absent from new pack; retain release |

The weapon sheet needs a remap: **new slot 25 → released slot 23 (Shrinkifier
5k)**. That crop has an exact alpha mask and premultiplied RGB mean absolute error
of **0.634440/255** against the released JPEG. New slot 23 contains a different
weapon drawing. A same-position comparison alone misses this recovery.

The remaining unavailable matching weapon art is:

- Slot **25**, used by Spider Plasma, Evil Scythe and Plasma Cannon: the new slot
  contains Shrinkifier instead. Searching all 32 new slots found no exact-alpha
  match for the released sprite.
- Slot **30**, used by Gauss Shotgun and RayGun: empty in the new sheet.
- Slot **31**, used by Ion Shotgun: empty in the new sheet.

Five additional same-position weapon slots are newly recoverable: **24, 26, 27,
28 and 29**. Slots 26 and 27 are storage slots without a corresponding icon index
in the current weapon table. Recovered live icons include Blade Gun, Splitter Gun
and Flameburst, as well as the relocated Shrinkifier.

Seven complete textures newly gain matching lossless source compared with the
current PAQ: `ui_button_128x32`, `ui_button_64x32`, `ui_num5`, `ui_textLevComp`,
`load/mockup`, `game/arrow`, and `game/bodyset`. All have the released dimensions
and exact alpha masks. Their premultiplied RGB MAE ranges from **0.335 to 3.354/255**.
The two newly recoverable bonus icons and Blade projectile also have exact alpha;
their RGB differences are consistent with compression artifacts, as the zoomed
figures show. This is a source-art compatibility assessment, not a claim that
decoded JAZ RGB is pixel-identical to TGA RGB.

## File coverage and unchanged material

- New ZIP: **203 files**, all CRCs checked; 62 TGA, 51 JPEG, five JAZ, 79 Ogg,
  four text files, one font-width table and one HTML manual. Directory entries
  are excluded from these counts.
- Earlier ZIP: **144 files**; every extracted file was verified against its ZIP.
- **61 normalized paths** occur in both ZIPs; **57 are byte-identical**.
  The only changed common files are `game/bodyset.tga`, `game/bonuses.tga`,
  `game/projs.tga` and `ui/ui_wicons.tga`.
- The 1.9.93 `crimson.paq` contains **79 entries** (78 images and the font-width
  table). The new ZIP has same-stem material for **77/79**, compared with
  **60/79** in the earlier ZIP. This measures file availability, including JPEG
  and JAZ, not universal compatibility or lossless quality.
- The two absent reference paths are `load/default_font_courier.tga` and
  `balloon.tga`.
- All **73 sound files and six music tracks** are byte-identical to the 1.9.93
  PAQs after accounting for their bare archive entry names. They remain Ogg files.
- Nine supplied JPEGs are exactly the JPEG streams already embedded in release
  JAZs: four `ter/fb_q*`, `load/backplasma`, `load/esrb_mature`, `load/loading`,
  `load/splash10tons`, and `game/muzzleFlash`. Extracting them from JAZ changes
  packaging, not RGB quality.
- `ui_lifeHeart`, `ui_gameTop`, `ui_clockTable` and `ui_clockPointer` remain JAZ
  only and are unchanged from the earlier pack.
- `load/splashReflexive.jpg` contains different artwork (RGB MAE **23.145/255**);
  retain the released splash. The new 10tons JPEG retains the release's RGB but
  lacks its final-pixel alpha quirk; it adds no image quality.
- `ui_indPanel` (182×53 source versus 128×64 release) and `ui_textLevelUp`
  (75×25 versus 64×32) are identical to the earlier source. They retain the
  existing runtime-scaled treatment and are not new upgrades.

The ZIP filename says 2004-10-14. Individual art timestamps mostly date to 2002–2003,
and several sound timestamps say 2007; directory timestamps reflect 2026 packaging.
Those dates do not establish an exact executable version. The decoded artwork and
file hashes provide the compatibility evidence.

## Alpha blending in the prior pack

The prior build script started from the released image and called
`alpha_composite` for each selected crop. Even a fallback released crop was blended
over itself. Consequently, the prior atlas pixels were not exact copies of the
selected source: soft-alpha edges become more opaque, and old-source crops retain
a contribution from the compressed base.

For example, current Fire Bullets and MediKit crops have alpha MAE **6.705** and
**4.578/255** against release; their new TGA crops have alpha MAE **zero**.
The annotated figures use **O+R** and **R+R** to expose this composition.
The research-only proposed atlases copy selected RGBA crops exactly with `paste`,
and use release crops for the three missing weapon slots. Every populated selected
crop is asserted to be byte-identical to its chosen input crop.

The existing builder was reproduced **byte-for-byte** against the current
`artifacts/assets/crimson.paq`. Running that builder with the new archive increases
its replacement count from **55 to 71** and reduces fallback entries from **24 to
eight**. Those builder counts include identical original files and JPEG wrappers;
they are not counts of quality improvements. That generated PAQ still has the
alpha-over behavior and misses the Shrinkifier relocation. It is an analysis
artifact, not the proposed deployment.

## Comparison inputs and method

The input digests, audio comparisons and weapon-sheet counts are in
[evidence.json](evidence.json). The digest for the pre-refresh PAQ identifies the
historical input. The current build script uses the updated source archive and
direct copy behavior.

Path matching was case-insensitive and slash-normalized. TGA took precedence
over JPEG and same-name JAZ. Sprite comparison used the runtime UV rectangles,
matching dimensions and exact alpha, along with premultiplied RGB MAE to exclude
invisible RGB. The source-selection pass required an RGB MAE below 12/255 and
the builder's component compatibility guard. A search over all 32 weapon cells
found the Shrinkifier match in slot 25.

The full comparison inspected 1,004 UV cuts across 14 atlases, including empty
cells, overlapping effect regions, glyphs and the separate Pulse Gun cut.
