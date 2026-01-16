from __future__ import annotations

"""
Atlas slicing used by the Crimsonland Classic renderer.

Findings from decompiled code:
- FUN_0041fed0 precomputes UV grids for 2x2, 4x4, 8x8, 16x16 (steps 0.5/0.25/0.125/0.0625).
- FUN_0042e0a0 reads a table at VA 0x004755F0 with pairs (cell_code, group_id).
  cell_code maps to grid size: 0x80->2, 0x40->4, 0x20->8, 0x10->16.
  group_id is passed to the renderer alongside the grid size; semantics unknown.
- FUN_0042e120 uses the selected UV grid to build quad UVs by frame index.

This module replicates the atlas cutting: given a grid size and frame index,
compute UVs or crop subimages.
"""

from typing import Iterable

from PIL import Image

GRID_SIZE_BY_CODE = {
    0x80: 2,
    0x40: 4,
    0x20: 8,
    0x10: 16,
}

# DAT_004755f0 table (index -> (cell_code, group_id)) extracted from crimsonland.exe
SPRITE_TABLE = [
    (0x80, 0x2),
    (0x80, 0x3),
    (0x20, 0x0),
    (0x20, 0x1),
    (0x20, 0x2),
    (0x20, 0x3),
    (0x20, 0x4),
    (0x20, 0x5),
    (0x20, 0x8),
    (0x20, 0x9),
    (0x20, 0xA),
    (0x20, 0xB),
    (0x40, 0x5),
    (0x40, 0x3),
    (0x40, 0x4),
    (0x40, 0x5),
    (0x40, 0x6),
]


def grid_size_from_code(code: int) -> int:
    return GRID_SIZE_BY_CODE[code]


def grid_size_for_index(index: int) -> int:
    code, _ = SPRITE_TABLE[index]
    return grid_size_from_code(code)


def uv_for_index(grid: int, index: int) -> tuple[float, float, float, float]:
    row = index // grid
    col = index % grid
    step = 1.0 / grid
    u0 = col * step
    v0 = row * step
    u1 = u0 + step
    v1 = v0 + step
    return u0, v0, u1, v1


def rect_for_index(
    width: int, height: int, grid: int, index: int
) -> tuple[int, int, int, int]:
    row = index // grid
    col = index % grid
    cell_w = width // grid
    cell_h = height // grid
    x0 = col * cell_w
    y0 = row * cell_h
    return x0, y0, x0 + cell_w, y0 + cell_h


def slice_index(image: Image.Image, grid: int, index: int) -> Image.Image:
    return image.crop(rect_for_index(image.width, image.height, grid, index))


def slice_grid(image: Image.Image, grid: int) -> list[Image.Image]:
    frames = []
    for idx in range(grid * grid):
        frames.append(slice_index(image, grid, idx))
    return frames


def slice_by_indices(
    image: Image.Image, grid: int, indices: Iterable[int]
) -> list[Image.Image]:
    return [slice_index(image, grid, idx) for idx in indices]
