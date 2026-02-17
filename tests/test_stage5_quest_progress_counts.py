from __future__ import annotations

import random
import time
from pathlib import Path

from crimson.game.quest_views import QuestsMenuView
from crimson.game.types import GameState
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def _build_state(tmp_path: Path, *, status: save_status.GameStatus) -> GameState:
    cfg = ensure_crimson_cfg(tmp_path)
    return GameState(
        base_dir=tmp_path,
        assets_dir=tmp_path,
        rng=random.Random(0),
        config=cfg,
        status=status,
        console=create_console(tmp_path, assets_dir=tmp_path),
        demo_enabled=False,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=None,
        resource_paq=tmp_path / "crimson.paq",
        session_start=time.monotonic(),
    )


def test_quest_select_f1_counts_stage5_reads_tail_fields(tmp_path: Path) -> None:
    data = save_status.default_status_data()
    data["mode_play_survival"] = 111
    data["mode_play_rush"] = 222
    data["mode_play_typo"] = 333
    data["mode_play_other"] = 444
    data["game_sequence_id"] = 0x01020304
    data["unknown_tail"] = bytes(range(save_status.UNKNOWN_TAIL_SIZE))

    data["quest_play_counts"][51] = 123
    data["quest_play_counts"][55] = 456
    data["quest_play_counts"][56] = 789
    data["quest_play_counts"][60] = 999

    status = save_status.GameStatus(path=Path("game.cfg"), data=data, dirty=False)
    state = _build_state(tmp_path, status=status)
    view = QuestsMenuView(state)

    assert view._quest_counts(stage=5, row=0) == (111, 123)
    assert view._quest_counts(stage=5, row=1) == (222, int(status.quest_play_count(52)))
    assert view._quest_counts(stage=5, row=4) == (0x01020304, 456)

    tail_u32 = int.from_bytes(bytes(range(4)), "little")
    assert view._quest_counts(stage=5, row=5) == (tail_u32, 789)

    assert view._quest_counts(stage=5, row=9) == (0, 999)
