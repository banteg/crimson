# grim_draw_text_mono

Source shape is recovered from the native 0x5c-byte
frame and live Binary Ninja evidence. The renderer lazily binds the mono-font
texture, applies `grim_font_scale` to its 16px advance, 28px line step, and
32px draw cells, and batches direct 16x16 atlas lookups. Byte `0xa7` suppresses
the next normal glyph's pre-advance. The three extended cases are composites:
`0xe4` draws `a` plus `"`, `0xe5` draws `a` plus `.`, and `0xf6` draws `o` plus
`"`.

The function is exact when compiled after its immediate native predecessor,
`grim_draw_quad_points`, in address order. That shared translation-unit context
prevents VC6.5's global optimizer from tail-merging the identical `0xe4`/`0xf6`
mark-UV suffix: the clustered candidate preserves all 308 native instructions,
all 1,034 bytes, and all 41 masked references. The native audit emits the pair
once through the explicit `grim-mono-text-island` cluster.

The isolated scratch matched 94.39% (298 candidate instructions against 308
native instructions) with all 41 masked references resolved. Its only residual
was the ten-instruction folded suffix. The negative sweeps below remain useful
evidence that this was translation-unit optimizer state rather than missing
local semantics.

## Recorded composite-tail sweeps

Live native disassembly confirms separate endpoint-temporary pairs in the
`0xe4` and `0xf6` branches even though their mark suffixes are identical.
Three specs evaluated 30 commuted endpoint expressions, branch-specific
storage forms, and point-add operator shapes. Every compile-valid alternative
was byte-neutral or worse; incomplete dependent-site combinations that did
not compile remain visible in the machine record. No source change was
retained, strengthening the tail-merging compiler-residual classification.

`composite-continue-mutations.json` adds a direct loop-control bound around the
native-duplicated suffix. Adding an explicit `continue` after either composite
mark draw, or after both, is semantically neutral and compiles byte-identically
at 94.39% with 298 instructions and all 41 references resolved. Thus branch
fallthrough spelling is not what causes stock VC6.5 to merge the `0xe4` and
`0xf6` mark tails, and no variant is retained.

`composite-branch-shape-mutations.json` further tests branch-local scalar
endpoints, copy initialization, and explicit mark-pointer loads, including all
two-branch combinations. Live disassembly at
`0x10009500..0x1000960c` confirms that native allocates separate endpoint
temporaries and duplicates the `SetUV` call before the common final draw.
Pointer and copy-initialized forms remain byte-identical at 94.39%; scalar
forms shorten the candidate and regress by at least 77.00 fuzzy-weighted
bytes. These natural spelling differences cannot prevent VC6 from folding the
suffix, so no source change is retained.

`composite-call-topology-mutations.json` closes the remaining branch-local
source boundary with all 24 single and paired combinations of explicit
receivers, pointer/reference receiver aliases, and one-pass scopes. Every
variant is byte-identical at 94.39%, including asymmetric `0xe4`/`0xf6`
forms. A separate VC6.0/6.5/6.6 profile check also leaves the baseline
unchanged, while disabling global optimization with `/Og-` uniformly regresses
to 7.58% and 404 candidate instructions. The residual is therefore saturated
at the global tail-cross-jump pass rather than an unmodeled call receiver,
scope, or supported compiler profile.

`all-endpoint-storage-interactions.json` bounds the larger lifetime interaction
suggested by the native frame. It promotes all seven branch-specific glyph
endpoint pairs to function scope and independently rewrites the `0xe5`,
`0xe4`, `0xf6`, and generic paths to assign their components there. All 16
compile-valid combinations, including the five-site form, are byte-identical
to the 298-instruction baseline with the same 41 resolved references; the 15
dependent combinations without declarations fail compilation as expected.
This confirms that the already-identical 0x5c-byte frame and endpoint slots do
not control the missing cross-jump duplication. The seven recorded sweeps cover
103 variants with no improvement; the successful immediate-predecessor probe
then isolated the missing original-TU provenance.
