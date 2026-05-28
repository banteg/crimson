from __future__ import annotations

from pathlib import Path

from PIL import Image

from grim import paq as grim_paq
from grim.assets import _select_texture_asset
from scripts.build_uncompressed_crimson_paq import (
    _allows_alpha_mismatch,
    _allows_visual_mismatch,
    _alpha_stats,
    _hybrid_rects,
    _replacement_differs_visibly,
    build_uncompressed_crimson_paq,
)


def test_select_texture_asset_prefers_source_art_for_jaz_specs() -> None:
    entries = {
        "ui/button.jaz": b"jaz",
        "ui/button.tga": b"tga",
    }

    assert _select_texture_asset(entries, "ui/button.jaz") == ("ui/button.tga", b"tga")
    assert _select_texture_asset(entries, "load/arrow.tga") == ("load/arrow.tga", None)


def test_build_uncompressed_crimson_paq_replaces_same_stem_assets(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    (source_root / "ui").mkdir(parents=True)
    (source_root / "game").mkdir()
    (source_root / "ui" / "button.tga").write_bytes(b"source-tga")
    (source_root / "game" / "flash.jpg").write_bytes(b"source-jpg")

    base_paq = tmp_path / "base.paq"
    grim_paq.write_paq(
        base_paq,
        [
            ("ui\\button.jaz", b"old-jaz"),
            ("game\\flash.jaz", b"old-flash"),
            ("load\\smallFnt.dat", b"font"),
        ],
    )

    output_paq = tmp_path / "out.paq"
    stats = build_uncompressed_crimson_paq(source_root, base_paq, output_paq)

    assert stats.entries == 3
    assert stats.replaced == 2
    assert stats.fallback == 1
    assert stats.skipped_alpha == 0
    assert stats.allowed_alpha == 0
    assert stats.skipped_visual == 0
    assert stats.hybrid == 0
    assert grim_paq.read_paq(output_paq) == [
        ("ui/button.tga", b"source-tga"),
        ("game/flash.jpg", b"source-jpg"),
        ("load/smallFnt.dat", b"font"),
    ]


def test_alpha_stats_counts_soft_and_nonopaque_pixels() -> None:
    image = Image.new("RGBA", (3, 1))
    image.putdata([(0, 0, 0, 255), (0, 0, 0, 128), (0, 0, 0, 0)])

    assert _alpha_stats(image).nonopaque == 2
    assert _alpha_stats(image).soft == 1


def test_source_art_allowlists_are_limited_to_known_runtime_matches() -> None:
    assert _allows_alpha_mismatch("ter/fb_q1.jaz")
    assert _allows_alpha_mismatch("ui/ui_indPanel.jaz")
    assert _allows_visual_mismatch("ui/ui_indPanel.jaz")
    assert _allows_alpha_mismatch("ui/ui_textLevelUp.jaz")
    assert _allows_visual_mismatch("ui/ui_textLevelUp.jaz")
    assert not _allows_alpha_mismatch("ui/ui_wicons.jaz")
    assert not _allows_visual_mismatch("ui/ui_wicons.jaz")


def test_hybrid_rects_use_runtime_sprite_bounds() -> None:
    wicons = [component.bbox for component in _hybrid_rects("ui/ui_wicons.jaz", (256, 256))]
    assert len(wicons) == 32
    assert wicons[0] == (0, 0, 64, 32)
    assert wicons[31] == (192, 224, 256, 256)

    bonuses = [component.bbox for component in _hybrid_rects("game/bonuses.jaz", (128, 128))]
    assert len(bonuses) == 16
    assert bonuses[12] == (0, 96, 32, 128)

    projs = [component.bbox for component in _hybrid_rects("game/projs.jaz", (128, 128))]
    assert projs == [
        (0, 0, 64, 64),
        (64, 0, 96, 32),
        (64, 32, 96, 64),
        (96, 0, 128, 32),
    ]


def test_visible_guard_flags_large_content_changes() -> None:
    original = Image.new("RGBA", (10, 10), (0, 0, 0, 255))
    replacement = Image.new("RGBA", (10, 10), (0, 0, 0, 255))
    replacement.putpixel((0, 0), (255, 255, 0, 255))
    replacement.putpixel((1, 0), (255, 255, 0, 255))

    assert _replacement_differs_visibly(original, replacement)
