from __future__ import annotations

from collections.abc import Iterable

from grim.rand import Crand
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest


def sfx_ids(requests: Iterable[SfxRequest]) -> list[SfxId]:
    """Project requests for tests concerned with sound selection/RNG ordering."""
    return [request.sfx_id for request in requests]


def make_sfx_state(*ids: SfxId):
    from grim.raylib_api import rl
    from grim.sfx import SfxSample, SfxVoice, init_sfx_state
    from grim.sfx_map import SFX_SPECS

    state = init_sfx_state(ready=True, enabled=True, volume=1.0, rng=Crand(0x1234))
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



class HeadlessAudio:
    """A ready audio state whose sfx voices start on a recorded backend instead of a device."""

    def __init__(self, mocker) -> None:
        from grim.audio import AudioState
        from grim.music import init_music_state

        self.backend = stub_sfx_backend(mocker)
        self.state = AudioState(
            ready=True,
            music=init_music_state(ready=False, enabled=False, volume=1.0),
            sfx=make_sfx_state(*SfxId),
        )

    def played(self) -> list[SfxId]:
        """Sfx started so far, in order."""
        sfx = self.state.sfx
        by_entry: dict[str, SfxId] = {}
        for sfx_id, sample in sfx.samples.items():
            by_entry.setdefault(sample.entry_name, sfx_id)
        by_sound = {id(voice.sound): by_entry[sample.entry_name] for sample in sfx.owned_samples for voice in sample.voices()}
        return [by_sound[id(call.args[0])] for call in self.backend.play_sound.call_args_list]
