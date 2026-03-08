from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import msgspec

from crimson.quests.level import QuestLevel

from .codec import KEYBINDS_BLOB_SIZE, PLAYER_NAME_MAX_BYTES, PLAYER_NAME_SIZE
from .controls import (
    aim_scheme_key,
    hud_indicator_enabled_for_player,
    player_keybind_block,
    player_keybind_value,
    player_mode_flag_key,
    set_hud_indicator_for_player,
    set_player_keybind_block,
    set_player_keybind_value,
)


def _coerce_sized_blob(raw: object, *, size: int, fill: int = 0) -> bytes:
    if isinstance(raw, (bytes, bytearray)):
        data = bytearray(raw)
    else:
        data = bytearray([int(fill) & 0xFF] * int(size))
    if len(data) < size:
        data.extend(bytes([int(fill) & 0xFF]) * (size - len(data)))
    if len(data) > size:
        del data[size:]
    return bytes(data)


class CrimsonConfig(msgspec.Struct):
    path: Path
    data: dict

    def raw_value(self, key: str, default: object = None) -> object:
        return self.data.get(str(key), default)

    def set_raw_value(self, key: str, value: object) -> None:
        self.data[str(key)] = value

    def int_value(self, key: str, default: int = 0) -> int:
        value = self.raw_value(key, default)
        if value is None:
            return int(default)
        return int(cast(Any, value))

    def set_int_value(self, key: str, value: int) -> None:
        self.data[str(key)] = int(value)

    def float_value(self, key: str, default: float = 0.0) -> float:
        value = self.raw_value(key, default)
        if value is None:
            return float(default)
        return float(cast(Any, value))

    def set_float_value(self, key: str, value: float) -> None:
        self.data[str(key)] = float(value)

    def bool_value(self, key: str, *, default: bool = False) -> bool:
        return self.int_value(str(key), 1 if bool(default) else 0) != 0

    def set_bool_value(self, key: str, enabled: bool) -> None:
        self.data[str(key)] = 1 if bool(enabled) else 0

    def blob_value(self, key: str, *, size: int, default: bytes | bytearray | None = None, fill: int = 0) -> bytes:
        raw = self.raw_value(key, default)
        if default is None:
            raw = self.raw_value(key)
        return _coerce_sized_blob(raw, size=int(size), fill=int(fill))

    def set_blob_value(self, key: str, value: bytes | bytearray, *, size: int, fill: int = 0) -> None:
        self.data[str(key)] = _coerce_sized_blob(value, size=int(size), fill=int(fill))

    @property
    def player_count(self) -> int:
        return self.int_value("player_count", 1)

    @player_count.setter
    def player_count(self, value: int) -> None:
        self.set_int_value("player_count", value)

    @property
    def game_mode(self) -> int:
        return self.int_value("game_mode", 1)

    @game_mode.setter
    def game_mode(self, value: int) -> None:
        self.set_int_value("game_mode", value)

    @property
    def hardcore(self) -> bool:
        return self.bool_value("hardcore_flag", default=False)

    @hardcore.setter
    def hardcore(self, enabled: bool) -> None:
        self.set_bool_value("hardcore_flag", enabled)

    def fx_detail(self, *, level: int = 0, default: bool = False) -> bool:
        idx = max(0, min(2, int(level)))
        return self.bool_value(f"fx_detail_{idx}", default=default)

    def set_fx_detail(self, *, level: int, enabled: bool) -> None:
        idx = max(0, min(2, int(level)))
        self.set_bool_value(f"fx_detail_{idx}", enabled)

    @property
    def detail_preset(self) -> int:
        return self.int_value("detail_preset", 5)

    @detail_preset.setter
    def detail_preset(self, value: int) -> None:
        self.set_int_value("detail_preset", value)

    @property
    def gore_disabled(self) -> int:
        return self.int_value("gore_disabled", 0)

    @gore_disabled.setter
    def gore_disabled(self, value: int) -> None:
        self.set_int_value("gore_disabled", value)

    @property
    def score_load_gate(self) -> bool:
        # Native: `config_score_load_gate` (byte) toggled by the High scores screen
        # "Show internet scores" checkbox.
        return self.bool_value("score_load_gate", default=False)

    @score_load_gate.setter
    def score_load_gate(self, enabled: bool) -> None:
        self.set_bool_value("score_load_gate", enabled=bool(enabled))

    @property
    def highscore_date_mode(self) -> int:
        # Native: `config_highscore_date_mode` (byte).
        # Values observed in `highscore_screen_update`:
        #   0 = all time, 1 = month, 2 = week, 3 = day.
        value = self.int_value("highscore_date_mode", 0)
        return max(0, min(3, int(value)))

    @highscore_date_mode.setter
    def highscore_date_mode(self, value: int) -> None:
        self.set_int_value("highscore_date_mode", max(0, min(3, int(value))) & 0xFF)

    @property
    def ui_info_texts(self) -> bool:
        return self.bool_value("ui_info_texts", default=True)

    @ui_info_texts.setter
    def ui_info_texts(self, enabled: bool) -> None:
        self.set_bool_value("ui_info_texts", enabled)

    @property
    def keybind_pick_perk(self) -> int:
        return self.int_value("keybind_pick_perk", 0x101)

    @keybind_pick_perk.setter
    def keybind_pick_perk(self, value: int) -> None:
        self.set_int_value("keybind_pick_perk", value)

    @property
    def keybind_reload(self) -> int:
        return self.int_value("keybind_reload", 0x102)

    @keybind_reload.setter
    def keybind_reload(self, value: int) -> None:
        self.set_int_value("keybind_reload", value)

    @property
    def quest_stage_major(self) -> int:
        return self.int_value("quest_stage_major", 0)

    @quest_stage_major.setter
    def quest_stage_major(self, value: int) -> None:
        self.set_int_value("quest_stage_major", value)

    @property
    def quest_stage_minor(self) -> int:
        return self.int_value("quest_stage_minor", 0)

    @quest_stage_minor.setter
    def quest_stage_minor(self, value: int) -> None:
        self.set_int_value("quest_stage_minor", value)

    @property
    def quest_level(self) -> str | None:
        value = self.raw_value("quest_level")
        if isinstance(value, str):
            return value
        return None

    @quest_level.setter
    def quest_level(self, value: str | None) -> None:
        if value is None:
            self.data.pop("quest_level", None)
            return
        self.set_raw_value("quest_level", str(value))

    @property
    def quest_level_value(self) -> QuestLevel | None:
        major = int(self.quest_stage_major)
        minor = int(self.quest_stage_minor)
        if major <= 0 or minor <= 0:
            return None
        return QuestLevel(major, minor)

    @quest_level_value.setter
    def quest_level_value(self, value: QuestLevel) -> None:
        self.quest_stage_major = int(value.major)
        self.quest_stage_minor = int(value.minor)

    @property
    def hud_indicators(self) -> bytes:
        return self.blob_value("hud_indicators", size=2, default=b"\x01\x01", fill=1)

    @hud_indicators.setter
    def hud_indicators(self, value: bytes | bytearray) -> None:
        self.set_blob_value("hud_indicators", value, size=2, fill=1)

    def player_mode_flag(self, *, player_index: int, default: int = 2) -> int:
        return self.int_value(player_mode_flag_key(player_index), default)

    def set_player_mode_flag(self, *, player_index: int, value: int) -> None:
        self.set_int_value(player_mode_flag_key(player_index), value)

    def aim_scheme_for_player(self, *, player_index: int, default: int = 0) -> int:
        return self.int_value(aim_scheme_key(player_index), default)

    def set_aim_scheme_for_player(self, *, player_index: int, value: int) -> None:
        self.set_int_value(aim_scheme_key(player_index), int(value))

    @property
    def sfx_volume(self) -> float:
        return self.float_value("sfx_volume", 1.0)

    @sfx_volume.setter
    def sfx_volume(self, value: float) -> None:
        self.set_float_value("sfx_volume", value)

    @property
    def music_volume(self) -> float:
        return self.float_value("music_volume", 1.0)

    @music_volume.setter
    def music_volume(self, value: float) -> None:
        self.set_float_value("music_volume", value)

    @property
    def mouse_sensitivity(self) -> float:
        return self.float_value("mouse_sensitivity", 1.0)

    @mouse_sensitivity.setter
    def mouse_sensitivity(self, value: float) -> None:
        self.set_float_value("mouse_sensitivity", value)

    @property
    def sound_disabled(self) -> bool:
        return self.bool_value("sound_disable", default=False)

    @sound_disabled.setter
    def sound_disabled(self, disabled: bool) -> None:
        self.set_bool_value("sound_disable", disabled)

    @property
    def music_disabled(self) -> bool:
        return self.bool_value("music_disable", default=False)

    @music_disabled.setter
    def music_disabled(self, disabled: bool) -> None:
        self.set_bool_value("music_disable", disabled)

    @property
    def keybinds(self) -> bytes:
        return self.blob_value("keybinds", size=KEYBINDS_BLOB_SIZE, default=bytes(KEYBINDS_BLOB_SIZE))

    @keybinds.setter
    def keybinds(self, value: bytes | bytearray) -> None:
        self.set_blob_value("keybinds", value, size=KEYBINDS_BLOB_SIZE)

    def player_keybind_block(self, *, player_index: int) -> tuple[int, ...]:
        return player_keybind_block(self.data, player_index=player_index)

    def set_player_keybind_block(self, *, player_index: int, values: Sequence[int]) -> None:
        set_player_keybind_block(self.data, player_index=player_index, values=values)

    def player_keybind_value(self, *, player_index: int, slot_index: int) -> int:
        return player_keybind_value(self.data, player_index=player_index, slot_index=slot_index)

    def set_player_keybind_value(self, *, player_index: int, slot_index: int, value: int) -> None:
        set_player_keybind_value(self.data, player_index=player_index, slot_index=slot_index, value=value)

    def hud_indicator_enabled_for_player(self, *, player_index: int) -> bool:
        return hud_indicator_enabled_for_player(self.data, player_index=player_index)

    def set_hud_indicator_for_player(self, *, player_index: int, enabled: bool) -> None:
        set_hud_indicator_for_player(self.data, player_index=player_index, enabled=enabled)

    @property
    def texture_scale(self) -> float:
        return float(self.data["texture_scale"])

    @texture_scale.setter
    def texture_scale(self, value: float) -> None:
        self.data["texture_scale"] = float(value)

    @property
    def screen_bpp(self) -> int:
        return int(self.data["screen_bpp"])

    @screen_bpp.setter
    def screen_bpp(self, value: int) -> None:
        self.data["screen_bpp"] = int(value)

    @property
    def screen_width(self) -> int:
        return int(self.data["screen_width"])

    @screen_width.setter
    def screen_width(self, value: int) -> None:
        self.data["screen_width"] = int(value)

    @property
    def screen_height(self) -> int:
        return int(self.data["screen_height"])

    @screen_height.setter
    def screen_height(self, value: int) -> None:
        self.data["screen_height"] = int(value)

    @property
    def windowed_flag(self) -> int:
        return int(self.data["windowed_flag"])

    @windowed_flag.setter
    def windowed_flag(self, value: int) -> None:
        self.data["windowed_flag"] = int(value) & 0xFF

    @property
    def player_name(self) -> str:
        raw = self.blob_value("player_name", size=PLAYER_NAME_SIZE, default=bytes(PLAYER_NAME_SIZE))
        return raw.split(b"\x00", 1)[0].decode("latin-1", errors="ignore")

    @player_name.setter
    def player_name(self, value: str) -> None:
        self.set_player_name(value)

    def set_player_name(self, name: str) -> None:
        # Config stores a 0x20 buffer (latin-1) and a mirrored length integer.
        encoded = name.encode("latin-1", errors="ignore")[:PLAYER_NAME_MAX_BYTES]
        buf = bytearray(PLAYER_NAME_SIZE)
        buf[: len(encoded)] = encoded
        buf[min(len(encoded), PLAYER_NAME_MAX_BYTES)] = 0

        # Match `highscore_save_record` trimming: strip trailing spaces in-place.
        end = buf.index(0)
        i = end - 1
        while i > 0 and buf[i] == 0x20:
            buf[i] = 0
            i -= 1

        self.data["player_name"] = bytes(buf)
        self.data["player_name_len"] = len(encoded)


def apply_detail_preset(config: CrimsonConfig, preset: int | None = None) -> int:
    if preset is None:
        preset = config.detail_preset
    preset = int(preset)
    if preset < 1:
        preset = 1
    if preset > 5:
        preset = 5
    config.detail_preset = preset
    if preset <= 1:
        config.set_fx_detail(level=0, enabled=False)
        config.set_fx_detail(level=1, enabled=False)
        config.set_fx_detail(level=2, enabled=False)
    elif preset == 2:
        config.set_fx_detail(level=0, enabled=False)
        config.set_fx_detail(level=1, enabled=False)
    else:
        config.set_fx_detail(level=0, enabled=True)
        config.set_fx_detail(level=1, enabled=True)
        config.set_fx_detail(level=2, enabled=True)
    return preset
