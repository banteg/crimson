from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random
from typing import Iterable

import pyray as rl

from .console import ConsoleState
from . import paq


SFX_PAK_NAME = "sfx.paq"
DEFAULT_VOICE_COUNT = 4

SFX_KEY_ALIASES: dict[str, str] = {
    "sfx_autorifle_reload_alt": "sfx_autorifle_reload",
    "sfx_shock_fire_alt": "sfx_shock_fire",
}


@dataclass(slots=True)
class SfxSample:
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


@dataclass(slots=True)
class SfxState:
    ready: bool
    enabled: bool
    volume: float
    voice_count: int
    entries: dict[str, bytes]
    directory: Path | None
    key_to_entry: dict[str, str]
    variants: dict[str, tuple[str, ...]]
    samples: dict[str, SfxSample]
    missing_keys: set[str]


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
        directory=None,
        key_to_entry={},
        variants={},
        samples={},
        missing_keys=set(),
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


def load_sfx_index(state: SfxState, assets_dir: Path, console: ConsoleState) -> None:
    if not state.ready or not state.enabled:
        return

    sfx_dir = assets_dir / "sfx"
    if sfx_dir.exists() and sfx_dir.is_dir():
        entry_names: list[str] = []
        for path in sorted(sfx_dir.iterdir()):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".ogg", ".wav"}:
                continue
            entry_names.append(path.name)

        state.directory = sfx_dir
        state.entries.clear()
        state.key_to_entry = {_derive_sfx_key(name): name for name in entry_names}
        state.variants = _build_variants(state.key_to_entry.keys())
        console.log.log(f"audio: sfx indexed {len(entry_names)} files from {sfx_dir}")
        console.log.flush()
        return

    paq_path = assets_dir / SFX_PAK_NAME
    if not paq_path.exists():
        raise FileNotFoundError(f"audio: missing {SFX_PAK_NAME} in {assets_dir}")
    entries: dict[str, bytes] = {}
    for name, data in paq.iter_entries(paq_path):
        entries[name.replace("\\", "/")] = data
    state.directory = None
    state.entries = entries
    state.key_to_entry = {_derive_sfx_key(name): name for name in entries.keys()}
    state.variants = _build_variants(state.key_to_entry.keys())
    console.log.log(f"audio: sfx indexed {len(entries)} entries from {SFX_PAK_NAME}")
    console.log.flush()


def _normalize_sfx_key(state: SfxState, key: str) -> str | None:
    if key in state.key_to_entry:
        return key
    if key.startswith("_"):
        stripped = key.lstrip("_")
        if stripped in state.key_to_entry:
            return stripped
        key = stripped
    alias = SFX_KEY_ALIASES.get(key)
    if alias and alias in state.key_to_entry:
        return alias
    if key.endswith("_alt"):
        cand = key[: -len("_alt")]
        if cand in state.key_to_entry:
            return cand
    if "_alias_" in key:
        cand = key.split("_alias_", 1)[0]
        if cand in state.key_to_entry:
            return cand
    return None


def _load_sample(state: SfxState, key: str) -> SfxSample | None:
    resolved = _normalize_sfx_key(state, key)
    if resolved is None:
        return None
    existing = state.samples.get(resolved)
    if existing is not None:
        return existing

    entry_name = state.key_to_entry.get(resolved)
    if entry_name is None:
        return None

    if state.directory is not None:
        path = state.directory / entry_name
        source = rl.load_sound(str(path))
    else:
        data = state.entries.get(entry_name)
        if data is None:
            return None
        file_type = Path(entry_name).suffix.lower()
        wave = rl.load_wave_from_memory(file_type, data, len(data))
        source = rl.load_sound_from_wave(wave)
        rl.unload_wave(wave)

    aliases = [rl.load_sound_alias(source) for _ in range(max(1, state.voice_count) - 1)]

    sample = SfxSample(entry_name=entry_name, source=source, aliases=aliases)
    for voice in sample.voices():
        rl.set_sound_volume(voice, state.volume)
    state.samples[resolved] = sample
    return sample


def play_sfx(
    state: SfxState | None,
    key: str | None,
    *,
    rng: random.Random | None = None,
    allow_variants: bool = True,
) -> None:
    if state is None or not state.ready or not state.enabled:
        return
    if not key:
        return

    resolved = _normalize_sfx_key(state, key)
    if resolved is None:
        state.missing_keys.add(key)
        return

    if allow_variants:
        base = _derive_sfx_base(resolved) or resolved
        variants = state.variants.get(base)
        if variants:
            rng = rng or random
            resolved = rng.choice(variants)

    sample = _load_sample(state, resolved)
    if sample is None:
        state.missing_keys.add(resolved)
        return
    rl.play_sound(sample.acquire_voice())


def set_sfx_volume(state: SfxState | None, volume: float) -> None:
    if state is None:
        return
    volume = float(volume)
    if volume < 0.0:
        volume = 0.0
    if volume > 1.0:
        volume = 1.0
    state.volume = volume
    for sample in state.samples.values():
        for voice in sample.voices():
            rl.set_sound_volume(voice, state.volume)


def shutdown_sfx(state: SfxState) -> None:
    if not state.ready:
        return
    for sample in state.samples.values():
        for alias in sample.aliases:
            try:
                rl.stop_sound(alias)
                rl.unload_sound_alias(alias)
            except Exception:
                pass
        try:
            rl.stop_sound(sample.source)
            rl.unload_sound(sample.source)
        except Exception:
            pass
    state.samples.clear()
    state.entries.clear()
    state.key_to_entry.clear()
    state.variants.clear()
    state.missing_keys.clear()
    state.directory = None

