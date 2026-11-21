from __future__ import annotations

import ctypes
import shutil
import subprocess
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from crimson.render.rtx.creature_translucency import build_creature_surface_map, build_heat_density


@pytest.fixture(scope="module")
def native_density(tmp_path_factory: pytest.TempPathFactory):
    compiler = shutil.which("clang++") or shutil.which("c++")
    if compiler is None:
        pytest.skip("A C++ compiler is required for the native density")
    root = Path(__file__).resolve().parents[2]
    work = tmp_path_factory.mktemp("creature-density")
    (work / "game.h").write_text("#pragma once\n#include <stdint.h>\ntypedef uint8_t u8; typedef uint32_t u32; struct w2c_game;\n")
    source = work / "density.cpp"
    source.write_text(
        f'#include <cstring>\n#include "{root / "crimson-core/client/thickness.cpp"}"\n'
        'extern "C" void heat(const unsigned char *pixels, int w, int h, unsigned char *out) {\n'
        '  auto result = renderer_heat_density(pixels, w, h);\n'
        '  memcpy(out, result.data(), result.size());\n}\n'
        'extern "C" void surface(const unsigned char *pixels, int w, int h, unsigned char *out) {\n'
        '  auto result = renderer_creature_surface(pixels, w, h);\n'
        '  memcpy(out, result.data(), result.size());\n}\n',
    )
    library = work / "density.so"
    subprocess.run([compiler, "-std=c++17", "-shared", "-fPIC", "-O2", f"-I{work}", str(source), "-o", str(library)],
                   check=True)
    lib = ctypes.CDLL(str(library))
    lib.heat.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    lib.heat.restype = None
    lib.surface.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    lib.surface.restype = None
    return lib.heat, lib.surface


@pytest.mark.parametrize("size", [(16, 24), (512, 512)])
def test_native_heat_density_matches_python_byte_for_byte(native_density, size: tuple[int, int]) -> None:
    heat, _ = native_density
    w, h = size
    rgba = np.random.default_rng(813).integers(0, 256, (h, w, 4), dtype=np.uint8)
    output = ctypes.create_string_buffer(w * h)
    heat(rgba.tobytes(), w, h, output)
    assert output.raw == build_heat_density(Image.fromarray(rgba).getchannel("A")).tobytes()


@pytest.mark.parametrize("size", [(16, 24), (64, 64), (512, 512)])
def test_native_creature_surface_matches_python_byte_for_byte(native_density, size: tuple[int, int]) -> None:
    _, surface = native_density
    w, h = size
    rng = np.random.default_rng(814)
    rgba = rng.integers(0, 256, (h, w, 4), dtype=np.uint8)
    # Mix transparent, partial-alpha, and opaque patches to exercise all 4 channels.
    alpha_choices = np.array([0, 3, 4, 128, 255, 255, 255, 255], dtype=np.uint8)
    rgba[:, :, 3] = alpha_choices[rng.integers(0, len(alpha_choices), (h, w))]
    bgra = np.ascontiguousarray(rgba[:, :, [2, 1, 0, 3]])
    output = ctypes.create_string_buffer(w * h * 4)
    surface(bgra.tobytes(), w, h, output)
    assert output.raw == build_creature_surface_map(Image.fromarray(rgba, mode="RGBA")).tobytes()
