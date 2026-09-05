from __future__ import annotations

from collections.abc import Iterable

from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest


def sfx_ids(requests: Iterable[SfxRequest]) -> list[SfxId]:
    """Project requests for tests concerned with sound selection/RNG ordering."""
    return [request.sfx_id for request in requests]


def make_sfx_state(*ids: SfxId):
    from grim.raylib_api import rl
    from grim.sfx import SfxSample, SfxVoice, init_sfx_state
    from grim.sfx_map import SFX_SPECS

    state = init_sfx_state(ready=True, enabled=True, volume=1.0)
    samples: dict[str, SfxSample] = {}
    for sfx_id in ids:
        entry = SFX_SPECS[sfx_id].entry_name
        if entry not in samples:
            samples[entry] = SfxSample(entry, SfxVoice(rl.Sound()), [])
        state.samples[sfx_id] = samples[entry]
    state.owned_samples = list(samples.values())
    return state


def stub_sfx_backend(mocker):
    from grim.raylib_api import rl

    backend = mocker.Mock()
    mocker.patch.object(rl, "is_sound_playing", return_value=False)
    for name in ("set_sound_pitch", "set_sound_pan", "set_sound_volume", "play_sound"):
        backend.attach_mock(mocker.patch.object(rl, name), name)
    return backend
