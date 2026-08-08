from __future__ import annotations

import json
from pathlib import Path

import crimson.dbg.record as dbg_record
from grim import config as grim_config


def test_zig_config_human_output_matches_python_default(tmp_path: Path) -> None:
    cfg = grim_config.default_crimson_cfg(tmp_path / grim_config.CRIMSON_CFG_NAME)
    cfg_path = tmp_path / grim_config.CRIMSON_CFG_NAME
    cfg_path.write_bytes(grim_config.encode_crimson_cfg(cfg))

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "config", "--path", str(cfg_path)],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert f"path: {cfg_path}" in result.stdout
    assert "screen: 1024x768" in result.stdout
    assert "windowed: true" in result.stdout
    assert "bpp: 32" in result.stdout
    assert "texture_scale: 1" in result.stdout
    assert "fields:" in result.stdout
    assert "player_name: '10tons' (len=32)" in result.stdout


def test_zig_config_json_output_reports_summary_and_raw_fields(tmp_path: Path) -> None:
    cfg = grim_config.default_crimson_cfg(tmp_path / grim_config.CRIMSON_CFG_NAME)
    cfg.display.width = 1280
    cfg.display.height = 720
    cfg.display.windowed = False
    cfg.audio.sound_disabled = True
    cfg.gameplay.player_count = 2
    cfg_path = tmp_path / grim_config.CRIMSON_CFG_NAME
    cfg_path.write_bytes(grim_config.encode_crimson_cfg(cfg))

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "config", "--base-dir", str(tmp_path), "--format", "json"],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["status"] == "ok"
    assert payload["path"] == str(cfg_path)
    assert payload["summary"] == {
        "screen_width": 1280,
        "screen_height": 720,
        "windowed": False,
        "bpp": 32,
        "texture_scale": 1,
        "player_count": 2,
        "game_mode": 1,
        "detail_preset": 5,
        "sfx_volume": 1,
        "music_volume": 1,
    }
    assert payload["fields"]["sound_disabled"] == 1
    assert payload["fields"]["player_count"] == 2
    assert payload["fields"]["screen_width"] == 1280
    assert payload["fields"]["screen_height"] == 720
    assert payload["fields"]["windowed_flag"] == 0
