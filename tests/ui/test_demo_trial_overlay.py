from __future__ import annotations

from crimson.demo_trial import DemoTrialOverlayInfo
from crimson.ui.demo_trial_overlay import _overlay_body_lines


def test_overlay_body_lines_match_native_quest_limit_with_remaining() -> None:
    info = DemoTrialOverlayInfo(
        visible=True,
        kind="quest_tier_limit",
        remaining_ms=12_345,
        remaining_label="0:12.34",
        show_remaining_line=True,
    )

    assert _overlay_body_lines(info) == (
        (74.0, "You've completed all Quest mode levels available in the Demo version."),
        (92.0, "However, you still have 0:12.34 time left to play Survival and Rush game modes."),
        (124.0, "If you would like to have unlimited play time and access to all features,"),
        (142.0, "please upgrade to the full version of Crimsonland."),
        (164.0, "The full version features unrestricted access to all 3"),
        (182.0, "game modes and be able to post your scores on the Internet. Why not buy"),
        (200.0, "it now? You'll have a great time!"),
    )


def test_overlay_body_lines_match_native_quest_grace_branch() -> None:
    info = DemoTrialOverlayInfo(
        visible=True,
        kind="quest_grace_left",
        remaining_ms=299_999,
        remaining_label="4:59.99",
        show_remaining_line=False,
    )

    assert _overlay_body_lines(info) == (
        (73.0, "You have used up your play time in this game mode. However, you still"),
        (89.0, "have 4:59.99 time left to play Quest mode levels only."),
        (111.0, "If you would like to have unlimited play time and access to all features,"),
        (127.0, "please upgrade to the full version of Crimsonland.  The process is very easy"),
        (143.0, "and takes just minutes. "),
        (165.0, "Buy the full version to gain unrestricted access to all 3"),
        (181.0, "game modes and be able to post your scores on the Internet. Why not buy"),
        (197.0, "it now? You'll have a great time!"),
    )


def test_overlay_body_lines_match_native_time_up_branch() -> None:
    info = DemoTrialOverlayInfo(
        visible=True,
        kind="time_up",
        remaining_ms=0,
        remaining_label="0:00.00",
        show_remaining_line=False,
    )

    assert _overlay_body_lines(info) == (
        (80.0, "Trial time is up. If you would like to have unlimited play time and access to"),
        (98.0, "all features, please upgrade to the full version of Crimsonland.  The process"),
        (116.0, "is very easy and takes just minutes."),
        (140.0, "Buy the full version to gain unrestricted access to all 3"),
        (158.0, "game modes and be able to post your scores on the Internet. Why not buy"),
        (176.0, "it now? You'll have a great time!"),
    )
