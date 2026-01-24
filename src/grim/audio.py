from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random
from typing import Iterable

import pyray as rl

from .config import CrimsonConfig
from .console import ConsoleState
from . import paq


MUSIC_PAK_NAME = "music.paq"
SFX_PAK_NAME = "sfx.paq"
SFX_DEFAULT_VOICE_COUNT = 4
MUSIC_TRACKS: dict[str, tuple[str, ...]] = {
    "intro": ("music/intro.ogg", "intro.ogg"),
    "shortie_monk": ("music/shortie_monk.ogg", "shortie_monk.ogg"),
    "crimson_theme": ("music/crimson_theme.ogg", "crimson_theme.ogg"),
    "crimsonquest": ("music/crimsonquest.ogg", "crimsonquest.ogg"),
    "gt1_ingame": ("music/gt1_ingame.ogg", "gt1_ingame.ogg"),
    "gt2_harppen": ("music/gt2_harppen.ogg", "gt2_harppen.ogg"),
}

SFX_ALIASES: dict[str, str] = {
    "sfx_autorifle_reload_alt": "sfx_autorifle_reload",
    "sfx_shock_fire_alt": "sfx_shock_fire",
}


@dataclass(slots=True)
class SfxSample:
    entry_name: str
    base: rl.Sound
    aliases: list[rl.Sound]
    next_voice: int = 0

    def next_sound(self) -> rl.Sound:
        voices = 1 + len(self.aliases)
        idx = self.next_voice % voices
        self.next_voice += 1
        return self.base if idx == 0 else self.aliases[idx - 1]


@dataclass(slots=True)
class AudioState:
    ready: bool
    music_tracks: dict[str, rl.Music]
    active_track: str | None
    music_volume: float
    sfx_volume: float
    music_enabled: bool
    sfx_enabled: bool
    sfx_entries: dict[str, bytes]
    sfx_dir: Path | None
    sfx_key_to_entry: dict[str, str]
    sfx_variants: dict[str, tuple[str, ...]]
    sfx_samples: dict[str, SfxSample]
    sfx_missing: set[str]


def init_audio_state(config: CrimsonConfig, assets_dir: Path, console: ConsoleState) -> AudioState:
    music_disabled = int(config.data.get("music_disable", 0)) != 0
    sound_disabled = int(config.data.get("sound_disable", 0)) != 0
    music_volume = float(config.data.get("music_volume", 1.0))
    sfx_volume = float(config.data.get("sfx_volume", 1.0))

    music_enabled = not music_disabled
    sfx_enabled = not sound_disabled
    if not music_enabled and not sfx_enabled:
        console.log.log("audio: disabled (music + sfx)")
        console.log.flush()
        return AudioState(
            ready=False,
            music_tracks={},
            active_track=None,
            music_volume=music_volume,
            sfx_volume=sfx_volume,
            music_enabled=False,
            sfx_enabled=False,
            sfx_entries={},
            sfx_dir=None,
            sfx_key_to_entry={},
            sfx_variants={},
            sfx_samples={},
            sfx_missing=set(),
        )
    if not rl.is_audio_device_ready():
        rl.init_audio_device()
    ready = bool(rl.is_audio_device_ready())
    if not ready:
        console.log.log("audio: device init failed")
        console.log.flush()
        return AudioState(
            ready=False,
            music_tracks={},
            active_track=None,
            music_volume=music_volume,
            sfx_volume=sfx_volume,
            music_enabled=False,
            sfx_enabled=False,
            sfx_entries={},
            sfx_dir=None,
            sfx_key_to_entry={},
            sfx_variants={},
            sfx_samples={},
            sfx_missing=set(),
        )

    state = AudioState(
        ready=True,
        music_tracks={},
        active_track=None,
        music_volume=music_volume,
        sfx_volume=sfx_volume,
        music_enabled=music_enabled,
        sfx_enabled=sfx_enabled,
        sfx_entries={},
        sfx_dir=None,
        sfx_key_to_entry={},
        sfx_variants={},
        sfx_samples={},
        sfx_missing=set(),
    )
    load_sfx_index(state, assets_dir, console)
    load_music_tracks(state, assets_dir, console)
    return state


def load_music_tracks(state: AudioState, assets_dir: Path, console: ConsoleState) -> None:
    if not state.ready or not state.music_enabled:
        return
    music_dir = assets_dir / "music"
    if music_dir.exists() and music_dir.is_dir():
        loaded = 0
        for track_name, candidates in MUSIC_TRACKS.items():
            music = None
            for candidate in candidates:
                path = assets_dir / candidate
                if not path.exists():
                    continue
                music = rl.load_music_stream(str(path))
                if music is not None:
                    break
            if music is None:
                raise FileNotFoundError(f"audio: missing music file for track '{track_name}' in {music_dir}")
            rl.set_music_volume(music, state.music_volume)
            state.music_tracks[track_name] = music
            loaded += 1
        console.log.log(f"audio: music tracks loaded {loaded}/{len(MUSIC_TRACKS)} from files")
        console.log.flush()
        return
    paq_path = assets_dir / MUSIC_PAK_NAME
    if not paq_path.exists():
        raise FileNotFoundError(f"audio: missing {MUSIC_PAK_NAME} in {assets_dir}")
    entries: dict[str, bytes] = {}
    for name, data in paq.iter_entries(paq_path):
        entries[name.replace("\\", "/")] = data
    loaded = 0
    for track_name, candidates in MUSIC_TRACKS.items():
        data = None
        for candidate in candidates:
            data = entries.get(candidate)
            if data is not None:
                break
        if data is None:
            raise FileNotFoundError(f"audio: missing music entry for track '{track_name}' in {MUSIC_PAK_NAME}")
        music = rl.load_music_stream_from_memory(".ogg", data, len(data))
        rl.set_music_volume(music, state.music_volume)
        state.music_tracks[track_name] = music
        loaded += 1
    console.log.log(f"audio: music tracks loaded {loaded}/{len(MUSIC_TRACKS)}")
    console.log.flush()


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


def load_sfx_index(state: AudioState, assets_dir: Path, console: ConsoleState) -> None:
    if not state.ready or not state.sfx_enabled:
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
        state.sfx_dir = sfx_dir
        state.sfx_entries.clear()
        state.sfx_key_to_entry = {_derive_sfx_key(name): name for name in entry_names}
        state.sfx_variants = _build_sfx_variants(state.sfx_key_to_entry.keys())
        console.log.log(f"audio: sfx indexed {len(entry_names)} files from {sfx_dir}")
        console.log.flush()
        return

    paq_path = assets_dir / SFX_PAK_NAME
    if not paq_path.exists():
        raise FileNotFoundError(f"audio: missing {SFX_PAK_NAME} in {assets_dir}")
    entries: dict[str, bytes] = {}
    for name, data in paq.iter_entries(paq_path):
        entries[name.replace("\\", "/")] = data
    state.sfx_dir = None
    state.sfx_entries = entries
    state.sfx_key_to_entry = {_derive_sfx_key(name): name for name in entries.keys()}
    state.sfx_variants = _build_sfx_variants(state.sfx_key_to_entry.keys())
    console.log.log(f"audio: sfx indexed {len(entries)} entries from {SFX_PAK_NAME}")
    console.log.flush()


def _build_sfx_variants(keys: Iterable[str]) -> dict[str, tuple[str, ...]]:
    base_to_keys: dict[str, list[str]] = {}
    for key in keys:
        base = _derive_sfx_base(key)
        if base is None:
            continue
        base_to_keys.setdefault(base, []).append(key)
    return {base: tuple(sorted(values)) for base, values in base_to_keys.items()}


def _resolve_sfx_key(state: AudioState, key: str) -> str | None:
    if key in state.sfx_key_to_entry:
        return key
    if key.startswith("_"):
        stripped = key.lstrip("_")
        if stripped in state.sfx_key_to_entry:
            return stripped
        key = stripped
    alias = SFX_ALIASES.get(key)
    if alias and alias in state.sfx_key_to_entry:
        return alias
    if key.endswith("_alt"):
        cand = key[: -len("_alt")]
        if cand in state.sfx_key_to_entry:
            return cand
    if "_alias_" in key:
        cand = key.split("_alias_", 1)[0]
        if cand in state.sfx_key_to_entry:
            return cand
    return None


def _load_sfx_sample(state: AudioState, key: str, *, voice_count: int = SFX_DEFAULT_VOICE_COUNT) -> SfxSample | None:
    if not state.ready or not state.sfx_enabled:
        return None
    resolved = _resolve_sfx_key(state, key)
    if resolved is None:
        return None
    existing = state.sfx_samples.get(resolved)
    if existing is not None:
        return existing

    entry_name = state.sfx_key_to_entry.get(resolved)
    if entry_name is None:
        return None

    if state.sfx_dir is not None:
        path = state.sfx_dir / entry_name
        base = rl.load_sound(str(path))
    else:
        data = state.sfx_entries.get(entry_name)
        if data is None:
            return None
        file_type = Path(entry_name).suffix.lower()
        wave = rl.load_wave_from_memory(file_type, data, len(data))
        base = rl.load_sound_from_wave(wave)
        rl.unload_wave(wave)

    aliases: list[rl.Sound] = []
    for _ in range(max(1, int(voice_count)) - 1):
        aliases.append(rl.load_sound_alias(base))

    sample = SfxSample(entry_name=entry_name, base=base, aliases=aliases)
    for voice in (sample.base, *sample.aliases):
        rl.set_sound_volume(voice, state.sfx_volume)
    state.sfx_samples[resolved] = sample
    return sample


def play_sfx(
    state: AudioState | None,
    key: str | None,
    *,
    rng: random.Random | None = None,
    allow_variants: bool = True,
) -> None:
    if state is None or not state.ready or not state.sfx_enabled:
        return
    if not key:
        return
    resolved = _resolve_sfx_key(state, key)
    if resolved is None:
        if key not in state.sfx_missing:
            state.sfx_missing.add(key)
        return
    if allow_variants:
        base = _derive_sfx_base(resolved) or resolved
        variants = state.sfx_variants.get(base)
        if variants:
            rng = rng or random
            resolved = rng.choice(variants)

    sample = _load_sfx_sample(state, resolved)
    if sample is None:
        if resolved not in state.sfx_missing:
            state.sfx_missing.add(resolved)
        return
    rl.play_sound(sample.next_sound())


def set_sfx_volume(state: AudioState | None, volume: float) -> None:
    if state is None:
        return
    volume = float(volume)
    if volume < 0.0:
        volume = 0.0
    if volume > 1.0:
        volume = 1.0
    state.sfx_volume = volume
    for sample in state.sfx_samples.values():
        for voice in (sample.base, *sample.aliases):
            rl.set_sound_volume(voice, state.sfx_volume)


def play_music(state: AudioState, track_name: str) -> None:
    if not state.ready or not state.music_enabled:
        return
    music = state.music_tracks.get(track_name)
    if music is None:
        return
    if state.active_track == track_name and rl.is_music_stream_playing(music):
        return
    rl.play_music_stream(music)
    state.active_track = track_name


def stop_music(state: AudioState) -> None:
    if not state.ready or not state.music_enabled:
        return
    if state.active_track is None:
        return
    music = state.music_tracks.get(state.active_track)
    if music is None:
        state.active_track = None
        return
    rl.stop_music_stream(music)
    state.active_track = None


def update_audio(state: AudioState) -> None:
    if not state.ready:
        return
    if state.active_track is None or not state.music_enabled:
        return
    music = state.music_tracks.get(state.active_track)
    if music is None:
        return
    rl.update_music_stream(music)


def shutdown_audio(state: AudioState) -> None:
    if state.ready:
        for sample in state.sfx_samples.values():
            try:
                for alias in sample.aliases:
                    rl.stop_sound(alias)
                    rl.unload_sound_alias(alias)
            except Exception:
                pass
            try:
                rl.stop_sound(sample.base)
                rl.unload_sound(sample.base)
            except Exception:
                pass
        state.sfx_samples.clear()
        state.sfx_entries.clear()
        state.sfx_key_to_entry.clear()
        state.sfx_variants.clear()
        state.sfx_missing.clear()
        state.sfx_dir = None

        for music in state.music_tracks.values():
            try:
                rl.stop_music_stream(music)
                rl.unload_music_stream(music)
            except Exception:
                pass
        state.music_tracks.clear()
        rl.close_audio_device()
