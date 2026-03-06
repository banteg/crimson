from __future__ import annotations

import grim.sfx as grim_sfx


def test_preload_sfx_samples_uses_native_order_before_extras(mocker) -> None:
    state = grim_sfx.init_sfx_state(ready=True, enabled=True, volume=1.0)
    native_a = grim_sfx.sfx_map.SFX_LOAD_ORDER[0][0]
    native_b = grim_sfx.sfx_map.SFX_LOAD_ORDER[1][0]
    unused = grim_sfx.sfx_map.SFX_UNREFERENCED[0][0]
    state.key_to_entry = {
        "sfx_custom": "custom.ogg",
        unused: "unused.ogg",
        native_b: "native-b.ogg",
        native_a: "native-a.ogg",
    }
    load_sample = mocker.patch.object(grim_sfx, "_load_sample", side_effect=lambda _state, _key: object())

    grim_sfx.preload_sfx_samples(state)

    assert [call.args[1] for call in load_sample.call_args_list] == [
        native_a,
        native_b,
        unused,
        "sfx_custom",
    ]
