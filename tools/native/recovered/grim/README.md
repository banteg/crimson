# Recovered Grim source layout

This tree is the canonical home for recovered, project-owned Grim source.
Matcher scratch directories retain their `scratch.conf`, notes, experiments,
and build evidence, but their `SOURCE` fields point here instead of carrying a
second copy of the source body.

It covers all 139 canonical Grim functions plus 41 additional recovered
platform/provider functions: 180 function bindings across 171 source files.
The `runtime` directory holds recovered compiler-generated startup glue from
the Grim image; it is not presented as handwritten game code.

The directory and file names are a plausible reconstruction for maintainable
source, not a claim that the original project used these exact paths. Module
directories such as `app`, `input`, and `window` are inferred from behavior and
symbol ownership.

Physical translation-unit claims are deliberately narrower. Only these files
are proven to contain multiple native functions in one object:

- `state/slot_state.cpp`
- `render/line.cpp`
- `render/mono_text.cpp`
- `codec/jaz_decode.cpp`

Their member order and symbols are recorded in
`tools/native/translation_units/grim.dll.json`, and every member is still
matched independently. All other files remain isolated compile objects even
when they share a logical module directory. `layout.json` records both levels
of evidence and is validated by the native-link tests.

Third-party sources are intentionally excluded. D3DX, IJG libjpeg, zlib, and
the authenticated VC6 runtime-library bodies remain attached to their upstream
or archive provenance rather than being presented as recovered Grim-owned
source.
