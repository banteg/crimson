from __future__ import annotations

import struct
from collections.abc import Iterable
from pathlib import Path
from typing import cast

import msgspec

from grim.raylib_api import rl

from . import paq, sfx_map
from .console import ConsoleState
from .rand import Crand

SFX_PAK_NAME = "sfx.paq"
DEFAULT_VOICE_COUNT = 4
_SFX_RUNTIME_EXCEPTIONS = (RuntimeError, OSError, ValueError)
_SFX_PITCH_RUNTIME_EXCEPTIONS = _SFX_RUNTIME_EXCEPTIONS + (AttributeError, TypeError)
_F32_STRUCT = struct.Struct("<f")
_F32_PACK = _F32_STRUCT.pack
_F32_UNPACK = _F32_STRUCT.unpack
_SFX_RATE_BASE_HZ = 44100
_SFX_RATE_MIN_HZ = 22050


def _stop_sound_safe(sound: rl.Sound) -> bool:
    try:
        rl.stop_sound(sound)
        return True
    except _SFX_RUNTIME_EXCEPTIONS:
        return False


def _unload_sound_alias_safe(sound: rl.Sound) -> bool:
    try:
        rl.unload_sound_alias(sound)
        return True
    except _SFX_RUNTIME_EXCEPTIONS:
        return False


def _unload_sound_safe(sound: rl.Sound) -> bool:
    try:
        rl.unload_sound(sound)
        return True
    except _SFX_RUNTIME_EXCEPTIONS:
        return False


def _set_sound_pitch_safe(sound: rl.Sound, pitch: float) -> bool:
    try:
        rl.set_sound_pitch(sound, float(pitch))
        return True
    except _SFX_PITCH_RUNTIME_EXCEPTIONS:
        return False


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
    entries: dict[str, bytes]
    key_to_entry: dict[str, str]
    variants: dict[str, tuple[str, ...]]
    samples: dict[str, SfxSample]
    missing_keys: set[str]
    rate_scale_hz: int


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
        entries={},
        key_to_entry={},
        variants={},
        samples={},
        missing_keys=set(),
        rate_scale_hz=int(_SFX_RATE_BASE_HZ),
    )


def _derive_sfx_key(entry_name: str) -> str:
    return "sfx_" + Path(entry_name).stem.lower()


def _derive_sfx_base(key: str) -> str | None:
    if not key.startswith("sfx_"):
        return None
    stem = key[4:]
    if len(stem) < 3:
        return None
    if "_" not in stem:
        return None
    base, suffix = stem.rsplit("_", 1)
    if not suffix.isdigit():
        return None
    return "sfx_" + base


def _build_variants(keys: Iterable[str]) -> dict[str, tuple[str, ...]]:
    base_to_keys: dict[str, list[str]] = {}
    for key in keys:
        base = _derive_sfx_base(key)
        if base is None:
            continue
        base_to_keys.setdefault(base, []).append(key)
    return {base: tuple(sorted(values)) for base, values in base_to_keys.items()}


def _load_sample_from_data(state: SfxState, *, entry_name: str, data: bytes) -> SfxSample:
    file_type = Path(entry_name).suffix.lower()
    wave = rl.load_wave_from_memory(file_type, cast(str, data), len(data))
    source = rl.load_sound_from_wave(wave)
    rl.unload_wave(wave)
    aliases = [rl.load_sound_alias(source) for _ in range(max(1, state.voice_count) - 1)]
    sample = SfxSample(entry_name=entry_name, source=source, aliases=aliases)
    for voice in sample.voices():
        rl.set_sound_volume(voice, state.volume)
    return sample


def load_sfx_index(state: SfxState, assets_dir: Path, console: ConsoleState) -> None:
    if not state.ready or not state.enabled:
        return

    paq_path = assets_dir / SFX_PAK_NAME
    if not paq_path.exists():
        raise FileNotFoundError(f"audio: missing {SFX_PAK_NAME} in {assets_dir}")
    entries: dict[str, bytes] = {}
    for name, data in paq.iter_entries(paq_path):
        normalized = name.replace("\\", "/")
        if Path(normalized).suffix.lower() not in {".ogg", ".wav"}:
            continue
        entries[normalized] = data
    state.entries = {}
    available = set(entries.keys())
    state.key_to_entry = {_derive_sfx_key(name): name for name in entries.keys()}
    for key, name in sfx_map.SFX_ENTRY_BY_KEY.items():
        if name in available:
            state.key_to_entry[key] = name

    state.samples.clear()
    for entry_name in sorted(entries.keys()):
        canonical_key = _derive_sfx_key(entry_name)
        state.samples[canonical_key] = _load_sample_from_data(state, entry_name=entry_name, data=entries[entry_name])
    state.variants = _build_variants(state.samples.keys())

    console.log.log(f"audio: sfx loaded {len(state.samples)} samples from {SFX_PAK_NAME}")
    console.log.flush()


def _normalize_sfx_key(state: SfxState, key: str) -> str | None:
    key = key.strip().lstrip("_")
    if not key:
        return None
    key = sfx_map.SFX_KEY_ALIASES.get(key, key)
    if "_alias_" in key:
        key = key.split("_alias_", 1)[0]
    entry_name = state.key_to_entry.get(key)
    if entry_name is not None:
        return _derive_sfx_key(entry_name)
    if key.endswith("_alt"):
        cand = key[: -len("_alt")]
        entry_name = state.key_to_entry.get(cand)
        if entry_name is not None:
            return _derive_sfx_key(entry_name)
    return None


def _load_sample(state: SfxState, key: str) -> SfxSample | None:
    resolved = _normalize_sfx_key(state, key)
    if resolved is None:
        return None
    return state.samples.get(resolved)


def _play_resolved_sfx(
    state: SfxState,
    resolved: str,
    *,
    reflex_boost_timer: float = 0.0,
) -> None:
    sample = _load_sample(state, resolved)
    if sample is None:
        state.missing_keys.add(resolved)
        return
    state.rate_scale_hz = _next_rate_scale_hz(
        current_rate_scale_hz=int(state.rate_scale_hz),
        reflex_boost_timer=float(reflex_boost_timer),
    )
    voice = sample.acquire_voice()
    _set_sound_pitch_safe(voice, _pitch_scale_from_rate_hz(int(state.rate_scale_hz)))
    rl.play_sound(voice)


def play_sfx(
    state: SfxState | None,
    key: str | None,
    *,
    rng: Crand,
    reflex_boost_timer: float = 0.0,
) -> None:
    if state is None or not state.ready or not state.enabled:
        return
    if not key:
        return

    resolved = _normalize_sfx_key(state, key)
    if resolved is None:
        state.missing_keys.add(key)
        return

    base = _derive_sfx_base(resolved) or resolved
    variants = state.variants.get(base)
    if variants:
        resolved = variants[rng.rand() % len(variants)]
    _play_resolved_sfx(state, resolved, reflex_boost_timer=float(reflex_boost_timer))


def play_sfx_resolved(
    state: SfxState | None,
    key: str | None,
    *,
    reflex_boost_timer: float = 0.0,
) -> None:
    if state is None or not state.ready or not state.enabled:
        return
    if not key:
        return

    resolved = _normalize_sfx_key(state, key)
    if resolved is None:
        state.missing_keys.add(key)
        return

    _play_resolved_sfx(state, resolved, reflex_boost_timer=float(reflex_boost_timer))


def sfx_key_for_id(sfx_id: int) -> str | None:
    if sfx_id < 0:
        return None
    if sfx_id >= len(sfx_map.SFX_KEY_BY_ID):
        return None
    return sfx_map.SFX_KEY_BY_ID[sfx_id]


def play_sfx_id(state: SfxState | None, sfx_id: int) -> None:
    key = sfx_key_for_id(int(sfx_id))
    if key is None:
        return
    play_sfx_resolved(state, key)


def set_sfx_volume(state: SfxState | None, volume: float) -> None:
    if state is None:
        return
    volume = float(volume)
    if volume < 0.0:
        volume = 0.0
    if volume > 1.0:
        volume = 1.0
    state.volume = volume
    seen: set[int] = set()
    for sample in state.samples.values():
        sample_id = id(sample)
        if sample_id in seen:
            continue
        seen.add(sample_id)
        for voice in sample.voices():
            rl.set_sound_volume(voice, state.volume)


def shutdown_sfx(state: SfxState) -> None:
    if not state.ready:
        return
    seen: set[int] = set()
    for sample in state.samples.values():
        sample_id = id(sample)
        if sample_id in seen:
            continue
        seen.add(sample_id)
        for alias in sample.aliases:
            _stop_sound_safe(alias)
            _unload_sound_alias_safe(alias)
        _stop_sound_safe(sample.source)
        _unload_sound_safe(sample.source)
    state.samples.clear()
    state.entries.clear()
    state.key_to_entry.clear()
    state.variants.clear()
    state.missing_keys.clear()
