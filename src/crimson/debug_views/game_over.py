from __future__ import annotations

from pathlib import Path

from grim.assets import RuntimeResources, runtime_resources_for
from grim.config import CrimsonConfig, default_crimson_cfg_data
from grim.raylib_api import rl
from grim.view import ViewContext

from ..game_modes import GameMode
from ..persistence.highscores import HighScoreRecord, scores_path_for_config, write_highscore_records
from ..screens.results.game_over import GameOverUi
from ..weapons import WeaponId
from .registry import register_view

_BASE_DIR = Path("artifacts") / "game_over_debug"


def _config_game_mode(config: CrimsonConfig) -> GameMode:
    try:
        return GameMode(config.game_mode)
    except ValueError:
        return GameMode.DEMO


def _config_player_name_bytes(name: str) -> bytes:
    raw = name.encode("latin-1", errors="ignore")[: 0x20 - 1]
    return raw + b"\x00" * (0x20 - len(raw))


def _seed_highscores(config: CrimsonConfig) -> None:
    base_dir = _BASE_DIR
    path = scores_path_for_config(base_dir, config)
    records: list[HighScoreRecord] = []
    for idx in range(100):
        record = HighScoreRecord.blank()
        record.game_mode_id = _config_game_mode(config)
        record.set_name(f"bot{idx:03d}")
        record.score_xp = 10_000 - idx
        record.survival_elapsed_ms = (idx + 1) * 1000
        record.creature_kill_count = 500 - idx
        record.most_used_weapon_id = WeaponId.PISTOL
        record.shots_fired = 100
        record.shots_hit = 42
        records.append(record)
    write_highscore_records(path, records)


class GameOverDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        data = default_crimson_cfg_data()
        data["game_mode"] = 1
        data["player_name"] = _config_player_name_bytes("debugger")
        self._config = CrimsonConfig(path=_BASE_DIR / "crimson.cfg", data=data)
        self._hud_resources: RuntimeResources | None = None

        self._ui = GameOverUi(
            assets_root=self._assets_root,
            base_dir=_BASE_DIR,
            config=self._config,
            preserve_bugs=bool(ctx.preserve_bugs),
        )
        self._record = HighScoreRecord.blank()
        self._banner = "reaper"
        self._qualifies = True

        self.close_requested = False

    @property
    def hud_resources(self) -> RuntimeResources:
        resources = self._hud_resources
        assert resources is not None, "HUD resources must be loaded before game-over debug draw"
        return resources

    def open(self) -> None:
        self.close_requested = False
        rl.hide_cursor()
        self._hud_resources = runtime_resources_for(self._assets_root)
        _seed_highscores(self._config)
        self._reset_record()
        self._ui.open()

    def close(self) -> None:
        rl.show_cursor()
        self._ui.close()
        if self._hud_resources is not None:
            self._hud_resources = None

    def _reset_record(self) -> None:
        record = HighScoreRecord.blank()
        record.game_mode_id = _config_game_mode(self._config)
        record.score_xp = 20_000 if self._qualifies else 1
        record.survival_elapsed_ms = 123_456
        record.creature_kill_count = 123
        record.most_used_weapon_id = WeaponId.PISTOL
        record.shots_fired = 120
        record.shots_hit = 37
        self._record = record

    def update(self, dt: float) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            _seed_highscores(self._config)
            self._reset_record()
            self._ui.open()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_F1):
            self._qualifies = not self._qualifies
            self._reset_record()
            self._ui.open()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_B):
            self._banner = "well_done" if self._banner == "reaper" else "reaper"

        action = self._ui.update(dt, record=self._record, player_name_default="debugger")
        if action == "play_again":
            self._reset_record()
            self._ui.open()
            return
        if action in {"main_menu", "high_scores"}:
            self.close_requested = True

    def draw(self) -> None:
        rl.clear_background(rl.Color(8, 8, 10, 255))
        self._ui.draw(record=self._record, banner_kind=self._banner, hud_resources=self.hud_resources)
        rl.draw_text("F1 toggle qualify | B toggle banner | R reset | ESC close", 18, 18, 18, rl.Color(200, 200, 200, 255))


@register_view("game_over", "Game Over")
def _create_game_over_view(*, ctx: ViewContext) -> GameOverDebugView:
    return GameOverDebugView(ctx)
