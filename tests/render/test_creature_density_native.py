from __future__ import annotations

import ctypes
import importlib
import shutil
import subprocess
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from crimson.creatures.spawn import CreatureTypeId
from crimson.render.rtx.creature_translucency import build_heat_density
from crimson.render.rtx.heat_heads import heat_head_color


@pytest.fixture(scope="module")
def native_proxies(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    compiler = shutil.which("clang++") or shutil.which("c++")
    if compiler is None:
        pytest.skip("A C++ compiler is required for the native proxy contract")
    root = Path(__file__).resolve().parents[2]
    work = tmp_path_factory.mktemp("creature-proxy-contract")
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(root / "crimson-core"))
        game = importlib.import_module("game")
        (work / "rtx_heat_heads.h").write_text(game.heat_heads_header(root))
    (work / "game.h").write_text(
        "#pragma once\n#include <stdint.h>\n"
        "typedef uint8_t u8; typedef uint32_t u32; typedef float f32; struct w2c_game;\n",
    )
    source = work / "proxies.cpp"
    source.write_text(
        '#include <cstring>\n'
        f'#include "{root / "crimson-core/client/thickness.cpp"}"\n'
        '#include "rtx_heat_heads.h"\n'
        'extern "C" void head(int type, int frame, unsigned char *out) {\n'
        '  auto color = heat_head_color(type, frame);\n'
        '  out[0] = (unsigned char)(color.green * 255); out[1] = (unsigned char)(color.blue * 255);\n}\n'
        'extern "C" size_t heat(const unsigned char *pixels, int w, int h, unsigned char *out) {\n'
        '  auto result = renderer_heat_density(pixels, w, h);\n'
        '  if (!result.empty()) memcpy(out, result.data(), result.size());\n'
        '  return result.size();\n}\n'
        'extern "C" size_t thickness(const unsigned char *pixels, int w, int h, unsigned char *out) {\n'
        '  auto result = renderer_thickness(pixels, w, h);\n'
        '  if (!result.empty()) memcpy(out, result.data(), result.size());\n'
        '  return result.size();\n}\n',
    )
    library = work / "proxies.so"
    subprocess.run([
        compiler, "-std=c++17", "-shared", "-fPIC", "-O2", f"-I{work}", str(source), "-o", str(library),
    ], check=True)
    native = ctypes.CDLL(str(library))
    for function in (native.heat, native.thickness):
        function.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        function.restype = ctypes.c_size_t
    native.head.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    native.head.restype = None
    return native


@pytest.mark.parametrize("size", [(8, 8), (16, 24), (128, 64), (512, 512)])
def test_native_heat_density_matches_python_byte_for_byte(native_proxies: ctypes.CDLL, size: tuple[int, int]) -> None:
    w, h = size
    rgba = np.random.default_rng(813).integers(0, 256, (h, w, 4), dtype=np.uint8)
    source = ctypes.create_string_buffer(rgba.tobytes())
    output = ctypes.create_string_buffer(w * h)
    assert native_proxies.heat(source, w, h, output) == w * h
    expected = build_heat_density(Image.fromarray(rgba).getchannel("A"))
    assert output.raw == expected.tobytes()


@pytest.mark.parametrize("size", [(0, 0), (0, 8), (8, 0), (7, 8), (8, 7), (9, 8), (8, 9), (-8, 8), (8, -8)])
def test_native_proxies_reject_invalid_grids_without_accessing_pixels(
    native_proxies: ctypes.CDLL, size: tuple[int, int],
) -> None:
    # Even an intentionally short source must not be touched for invalid grids.
    source = ctypes.create_string_buffer(b"x")
    output = ctypes.create_string_buffer(b"unchanged")
    for function in (native_proxies.heat, native_proxies.thickness):
        assert function(source, *size, output) == 0
        assert output.value == b"unchanged"
        assert function(None, 8, 8, output) == 0


def test_native_packed_head_positions_match_python_for_every_cell(native_proxies: ctypes.CDLL) -> None:
    output = ctypes.create_string_buffer(2)
    for kind in CreatureTypeId:
        for frame in range(-1, 65):
            native_proxies.head(int(kind), frame, output)
            assert tuple(output.raw) == heat_head_color(kind, frame), (kind, frame)
