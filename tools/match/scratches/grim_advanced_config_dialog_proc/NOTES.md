# grim_advanced_config_dialog_proc

`grim_advanced_config_dialog_proc` at `0x10001170` owns the legacy launcher's
advanced renderer controls. It probes five optional texture formats, builds a
selection-to-format map, and persists texture preference, dithering, smoothing,
and decal-storage scale back into the Grim config table.

The config byte at index `0x53` is compared to the canonical value `1`, while
the index `0x58` byte is treated as a general boolean. Invalid decal scales are
normalized to `1.0f`. The natural MSVC 6.5 `/O2 /GB` reconstruction matches all
459 native instructions and all 82 references. This function remains
`platform-replaced` for port ownership, but its exact object is included in the
recovered Grim platform provider.
