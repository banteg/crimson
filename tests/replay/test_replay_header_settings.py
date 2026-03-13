from __future__ import annotations

from typing import cast

import pytest

from crimson.game_modes import GameMode
from crimson.net.session_settings import LockstepSessionSettings, session_settings_for_lockstep
from crimson.quests.level import QuestLevel
from crimson.replay.header_settings import replay_header_from_session_settings, session_settings_from_replay_header
from crimson.replay.types import ReplayHeader, ReplayStatusSnapshot


def test_replay_header_from_session_settings_roundtrip() -> None:
    settings = session_settings_for_lockstep(
        mode_id=GameMode.RUSH,
        player_count=3,
        quest_level=None,
        preserve_bugs=True,
        tick_rate=75,
        input_delay_ticks=2,
    )
    status = ReplayStatusSnapshot(quest_unlock_index=4, quest_unlock_index_full=7)
    header = replay_header_from_session_settings(
        settings,
        seed=1234,
        quest_fail_retry_count=2,
        hardcore=True,
        detail_preset=4,
        violence_disabled=1,
        world_size=2048.0,
        status=status,
    )
    assert header.game_mode_id == GameMode.RUSH
    assert header.tick_rate == 75
    assert header.player_count == 3
    assert header.preserve_bugs is True
    assert header.seed == 1234
    assert header.status == status

    restored = session_settings_from_replay_header(header, input_delay_ticks=2)
    assert restored == settings


def test_replay_header_from_session_settings_rejects_unknown_mode() -> None:
    settings = LockstepSessionSettings(
        mode_id=cast(GameMode, 999),
        player_count=1,
        quest_level=None,
        preserve_bugs=False,
        tick_rate=60,
        input_delay_ticks=0,
    )
    with pytest.raises(ValueError, match="unsupported replay game_mode_id=999"):
        replay_header_from_session_settings(settings, seed=1)


def test_replay_header_from_session_settings_rejects_missing_quest_level() -> None:
    settings = session_settings_for_lockstep(
        mode_id=GameMode.QUESTS,
        player_count=1,
        quest_level=None,
        preserve_bugs=False,
        tick_rate=60,
        input_delay_ticks=0,
    )
    with pytest.raises(ValueError, match="quest replays require quest_level"):
        replay_header_from_session_settings(settings, seed=1)


def test_session_settings_from_replay_header_uses_lockstep_defaults() -> None:
    header = ReplayHeader(
        game_mode_id=GameMode.QUESTS,
        seed=42,
        quest_level=QuestLevel(2, 3),
        tick_rate=60,
        preserve_bugs=False,
        player_count=2,
    )
    settings = session_settings_from_replay_header(header)
    assert settings.mode_id == GameMode.QUESTS
    assert settings.player_count == 2
    assert settings.quest_level == QuestLevel(2, 3)
    assert settings.preserve_bugs is False
    assert settings.tick_rate == 60
    assert settings.input_delay_ticks == 1
