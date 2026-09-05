from __future__ import annotations

import struct
from collections.abc import Iterable
from contextlib import ExitStack
from pathlib import Path
from typing import cast

import msgspec

from grim.raylib_api import rl

from . import paq
from .console import ConsoleState
from .sfx_map import SFX_NATIVE_ORDER, SFX_SPECS, SfxId

SFX_PAK_NAME = "sfx.paq"
DEFAULT_VOICE_COUNT = 4
_F32_STRUCT = struct.Struct("<f")
_F32_PACK = _F32_STRUCT.pack
_F32_UNPACK = _F32_STRUCT.unpack
_SFX_RATE_BASE_HZ = 44100
_SFX_RATE_MIN_HZ = 22050


def _f32(value: float) -> float:
    return _F32_UNPACK(_F32_PACK(float(value)))[0]


def _next_rate_scale_hz(*, current_rate_scale_hz: int, reflex_boost_timer: float) -> int:
    # Native `sfx_play` / `sfx_play_panned` update a global rate scalar from
    # `bonus_reflex_boost_timer` before each voice start.
    reflex_f32 = _f32(float(reflex_boost_timer))
    if reflex_f32 <= 0.0:
        return int(_SFX_RATE_BASE_HZ)
    if reflex_f32 <= 1.0:
        if reflex_f32 < 1.0:
            rate_expr = _f32((_f32(1.0) - reflex_f32 + _f32(1.0)) * _f32(float(_SFX_RATE_MIN_HZ)))
            # `__ftol` follows host FP rounding mode (nearest on native defaults).
            return int(round(float(rate_expr)))
        # Native keeps prior `sfx_rate_scale` when timer is exactly 1.0.
        return int(current_rate_scale_hz)
    return int(_SFX_RATE_MIN_HZ)


def _pitch_scale_from_rate_hz(rate_scale_hz: int) -> float:
    return float(_f32(float(rate_scale_hz) / float(_SFX_RATE_BASE_HZ)))


class SfxSample(msgspec.Struct):
    entry_name: str
    source: rl.Sound
    aliases: list[rl.Sound]
    next_voice: int = 0

    def voices(self) -> Iterable[rl.Sound]:
        yield self.source
        yield from self.aliases

    def close(self) -> None:
        with ExitStack() as cleanup:
            cleanup.callback(rl.unload_sound, self.source)
            for alias in self.aliases:
                cleanup.callback(rl.unload_sound_alias, alias)

    def acquire_voice(self) -> rl.Sound:
        for voice in self.voices():
            if not rl.is_sound_playing(voice):
                return voice
        voices = [self.source, *self.aliases]
        idx = self.next_voice % len(voices)
        self.next_voice += 1
        return voices[idx]


class SfxState(msgspec.Struct):
    ready: bool
    enabled: bool
    volume: float
    voice_count: int
    samples: dict[SfxId, SfxSample]
    rate_scale_hz: int
    owned_samples: list[SfxSample] = msgspec.field(default_factory=list)

    def sample(self, sfx_id: SfxId) -> SfxSample:
        sample = self.samples.get(sfx_id)
        if sample is None:
            entry_name = SFX_SPECS[sfx_id].entry_name
            raise RuntimeError(f"runtime sfx is not available: {entry_name}")
        return sample


def init_sfx_state(
    *,
    ready: bool,
    enabled: bool,
    volume: float,
    voice_count: int = DEFAULT_VOICE_COUNT,
) -> SfxState:
    return SfxState(
        ready=ready,
        enabled=enabled,
        volume=float(volume),
        voice_count=max(1, int(voice_count)),
        samples={},
        rate_scale_hz=int(_SFX_RATE_BASE_HZ),
    )


def _load_sample_from_data(state: SfxState, *, entry_name: str, data: bytes) -> SfxSample:
    file_type = Path(entry_name).suffix.lower()
    with ExitStack() as cleanup:
        wave = rl.load_wave_from_memory(file_type, cast(str, data), len(data))
        try:
            if not rl.is_wave_valid(wave):
                raise ValueError(f"audio: failed to decode sfx '{entry_name}'")
            source = rl.load_sound_from_wave(wave)
            cleanup.callback(rl.unload_sound, source)
        finally:
            rl.unload_wave(wave)
        if not rl.is_sound_valid(source):
            raise ValueError(f"audio: failed to load sfx '{entry_name}'")
        aliases: list[rl.Sound] = []
        for _ in range(state.voice_count - 1):
            alias = rl.load_sound_alias(source)
            cleanup.callback(rl.unload_sound_alias, alias)
            if not rl.is_sound_valid(alias):
                raise ValueError(f"audio: failed to allocate sfx voice '{entry_name}'")
            aliases.append(alias)
        sample = SfxSample(entry_name=entry_name, source=source, aliases=aliases)
        for voice in sample.voices():
            rl.set_sound_volume(voice, state.volume)
        cleanup.pop_all()
    return sample


def load_sfx_index(state: SfxState, assets_dir: Path, console: ConsoleState) -> None:
    if not state.ready or not state.enabled:
        return

    paq_path = assets_dir / SFX_PAK_NAME
    if not paq_path.exists():
        raise FileNotFoundError(f"audio: missing {SFX_PAK_NAME} in {assets_dir}")

    paq_entries: dict[str, bytes] = {}
    for name, data in paq.iter_entries(paq_path):
        normalized = name.replace("\\", "/")
        if Path(normalized).suffix.lower() not in {".ogg", ".wav"}:
            continue
        paq_entries[normalized] = data

    missing_entries = [spec.entry_name for spec in SFX_SPECS.values() if spec.entry_name not in paq_entries]
    if missing_entries:
        missing = ", ".join(sorted(missing_entries))
        raise FileNotFoundError(f"audio: missing declared sfx assets in {SFX_PAK_NAME}: {missing}")

    loaded_by_entry_name: dict[str, SfxSample] = {}
    samples: dict[SfxId, SfxSample] = {}
    with ExitStack() as cleanup:
        for sfx_id, spec in SFX_SPECS.items():
            sample = loaded_by_entry_name.get(spec.entry_name)
            if sample is None:
                sample = _load_sample_from_data(state, entry_name=spec.entry_name, data=paq_entries[spec.entry_name])
                cleanup.callback(sample.close)
                loaded_by_entry_name[spec.entry_name] = sample
            samples[sfx_id] = sample
        previous = state.owned_samples
        state.samples = samples
        state.owned_samples = list(loaded_by_entry_name.values())
        cleanup.pop_all()
    _unload_samples(previous)

    console.log.log(
        f"audio: sfx loaded {len(loaded_by_entry_name)} samples for {len(state.samples)} ids from {SFX_PAK_NAME}",
    )
    console.log.flush()


def play_sfx(
    state: SfxState | None,
    sfx: SfxId,
    *,
    reflex_boost_timer: float = 0.0,
) -> None:
    if state is None or not state.ready or not state.enabled:
        return

    sample = state.sample(sfx)
    state.rate_scale_hz = _next_rate_scale_hz(
        current_rate_scale_hz=int(state.rate_scale_hz),
        reflex_boost_timer=float(reflex_boost_timer),
    )
    voice = sample.acquire_voice()
    rl.set_sound_pitch(voice, _pitch_scale_from_rate_hz(int(state.rate_scale_hz)))
    rl.play_sound(voice)


def sfx_id_for_native_id(sfx_id: int) -> SfxId | None:
    if sfx_id < 0:
        return None
    if sfx_id >= len(SFX_NATIVE_ORDER):
        return None
    return SFX_NATIVE_ORDER[sfx_id]


def play_sfx_id(state: SfxState | None, sfx_id: int) -> None:
    resolved = sfx_id_for_native_id(int(sfx_id))
    if resolved is None:
        return
    play_sfx(state, resolved)


def set_sfx_volume(state: SfxState | None, volume: float) -> None:
    if state is None:
        return
    volume = float(volume)
    if volume < 0.0:
        volume = 0.0
    if volume > 1.0:
        volume = 1.0
    state.volume = volume
    for sample in state.owned_samples:
        for voice in sample.voices():
            rl.set_sound_volume(voice, state.volume)


def _unload_samples(samples: Iterable[SfxSample]) -> None:
    with ExitStack() as cleanup:
        for sample in samples:
            cleanup.callback(sample.close)


def shutdown_sfx(state: SfxState) -> None:
    samples = state.owned_samples
    state.owned_samples = []
    state.samples.clear()
    state.ready = False
    _unload_samples(samples)
