"""The freeze ice's surface for the RTX creature shader (src/crimson/render/rtx/ice_surface.tga), from the original art.

    uv run python tools/rtx/ice_surface.py --game <game folder>

The freeze's ice cube (the particles atlas's effect 0x0E) is a render of a rounded, lumpy cube, and the shatter's
shards (effects 0x08-0x0A) are chunks of the same ice. Each sprite gets a body: the cube a rounded box bent by smooth
3D terms, traced through the render's camera (both fitted to the sprite's corners, outline and shading), a shard a dome
grown from its outline. A height field on top makes each body's relative shading match the sprite's under one light
(the cube's, refitted per shard for its level only), and what that shading leaves of the sprite is the ice's own
mottling. The map keeps the atlas's layout, so a draw samples it at its own texture coordinates: RG the sprite-frame
normal's x and y (x right, y down, z toward the viewer, rebuilt), B the mottling over 2.5. An uncompressed TGA, so the
client's build reads it without an image library.
"""

import argparse
import io
from pathlib import Path

import numpy as np
from PIL import Image

from crimson.effects_atlas import EffectId, effect_src_rect
from grim import jaz
from grim.assets import PAQ_NAME, load_paq_entries_from_path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "src/crimson/render/rtx/ice_surface.tga"
# The cube render's camera: its rotation (cube to camera axes), the eye in cube coordinates and the lens's half-width
# over its focal length (a 46-degree field of view).
CUBE_R = np.array([[-0.69882, 0.71227, -0.06568], [0.55512, 0.48214, -0.67778], [-0.45110, -0.51011, -0.73232]])
EYE = np.array([2.08754, 2.32681, 3.31648])
LENS = 0.42884
# The cube's body: a rounded box's corner radius, then a displacement of its distance field by the products of
# degree-2 Legendre polynomials in x, y and z, i * 9 + j * 3 + k for the term in x's i-th, y's j-th and z's k-th.
BODY_RADIUS = 0.22876
BODY_TERMS = np.array([
    0.05769, -0.00928, 0.02869, -0.0143, 0.00928, 0.01074, 0.00363, 0.01964, -0.01478, 0.01593, -0.06056, -0.01295,
    -0.00576, 0.00583, 0.02491, -0.00617, 0.02251, 0.04193, 0.00864, -0.02478, -0.02127, -0.01489, 0.00313, 0.00859,
    0.00193, 0.0826, -0.00665,
])
LUMA = np.array([.2126, .7152, .0722])
EPS = .003


def particles(game: Path) -> np.ndarray:
    entries = load_paq_entries_from_path(game / PAQ_NAME)
    data = entries.get("game/particles.tga")
    image = Image.open(io.BytesIO(data)) if data else jaz.decode_jaz_bytes(entries["game/particles.jaz"]).composite_image()
    return np.asarray(image.convert("RGBA")).astype(float) / 255


def cell_rect(atlas: np.ndarray, effect_id: int) -> tuple[int, int, int]:
    x, y, w, _ = effect_src_rect(effect_id, texture_width=atlas.shape[1], texture_height=atlas.shape[0])
    return int(x), int(y), int(w)


def norm(v: np.ndarray) -> np.ndarray:
    return v / (np.linalg.norm(v, axis=-1, keepdims=True) + 1e-12)


def grow(values: np.ndarray, known: np.ndarray, passes: int) -> np.ndarray:
    """Carry known pixels' values outward, a pixel a pass, so filtering finds no seam at the outline."""
    values, known = values.copy(), known.copy()
    for _ in range(passes):
        acc = np.zeros_like(values)
        count = np.zeros(known.shape)
        for dy, dx in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            acc += np.roll(np.roll(values * known[..., None], dy, 0), dx, 1)
            count += np.roll(np.roll(known, dy, 0), dx, 1)
        fill = ~known & (count > 0)
        values[fill] = acc[fill] / count[fill][:, None]
        known |= fill
    return values


def cube_body(size: int) -> np.ndarray:
    """The cube's body traced through its camera: its sprite-frame normal per pixel."""
    ys, xs = np.mgrid[0:size, 0:size] + .5
    q = np.stack([xs / size * 2 - 1, ys / size * 2 - 1], -1).reshape(-1, 2)
    rays = norm(np.concatenate([q * LENS, np.ones((len(q), 1))], -1) @ CUBE_R)
    terms = [(i, j, k) for i in range(3) for j in range(3) for k in range(3)]

    def sdf(p):
        c = np.clip(p, -1.4, 1.4)
        legendre = [np.stack([np.ones_like(x), x, 1.5 * x * x - .5], -1) for x in c.T]
        disp = sum(a * legendre[0][:, i] * legendre[1][:, j] * legendre[2][:, k] for (i, j, k), a in zip(terms, BODY_TERMS, strict=True))
        box = np.abs(p) - (1 - BODY_RADIUS)
        return np.linalg.norm(np.maximum(box, 0), axis=1) + np.minimum(box.max(1), 0) - BODY_RADIUS - disp

    t = np.full(len(rays), 2.5)
    hit = np.zeros(len(rays), bool)
    for _ in range(96):
        s = sdf(EYE + rays * t[:, None])
        hit |= s < 2e-3
        t = np.where(hit, t, t + np.maximum(s, 2e-3) * .8)
    p = EYE + rays * t[:, None]
    gradient = np.stack([sdf(p + e) - sdf(p - e) for e in np.eye(3) * 4e-3], 1)
    c = norm(gradient) @ CUBE_R.T
    normals = np.stack([c[:, 0], c[:, 1], -c[:, 2]], 1).reshape(size, size, 3)
    # The sprite's soft fringe, which the body misses, takes the nearest traced normal.
    return norm(grow(normals, hit.reshape(size, size), 6))


def shard_body(alpha: np.ndarray) -> np.ndarray:
    """A shard's body: steep near its outline, flat-topped inside (height ~ the root of the distance in, capped)."""
    size = alpha.shape[0]
    inside = alpha > .5
    dist = np.where(inside, 99., 0.)
    # Chamfer distance passes, forward then back.
    for _ in range(2):
        for order, steps in ((range(size), ((-1, 0, 1), (0, -1, 1), (-1, -1, 1.414), (-1, 1, 1.414))),
                             (range(size - 1, -1, -1), ((1, 0, 1), (0, 1, 1), (1, 1, 1.414), (1, -1, 1.414)))):
            for y in order:
                for x in order:
                    if inside[y, x]:
                        for dy, dx, c in steps:
                            yy, xx = y + dy, x + dx
                            dist[y, x] = min(dist[y, x], (dist[yy, xx] if 0 <= yy < size and 0 <= xx < size else 0) + c)
    h = np.sqrt(np.minimum(dist, 6.) / 6.) * 4.
    for _ in range(2):
        h = (np.roll(h, 1, 0) + np.roll(h, -1, 0) + np.roll(h, 1, 1) + np.roll(h, -1, 1) + 4 * h) / 8
    gy, gx = np.gradient(h)
    return norm(np.stack([-gx, -gy, np.ones_like(h)], -1))


def solve(cell: np.ndarray, base: np.ndarray, *, smooth: float, across: float, light_dir: np.ndarray | None = None):
    """Shape from shading on `base`: a height field whose relative shading under one light matches the sprite's.

    Returns the normals, the mottling (what that shading leaves of the sprite, median 1) and the light (ambient, then
    the key's vector). With `light_dir`, the light keeps that direction and fits its level and ambient alone."""
    size = cell.shape[0]
    alpha = cell[..., 3]
    lin = (cell[..., :3] ** 2.2) @ LUMA
    mask = alpha > .5
    index = -np.ones((size, size), int)
    index[mask] = np.arange(mask.sum())
    count = int(mask.sum())
    n0, target = base[mask], lin[mask]

    # The sprite's light as a linear function of the normal, first plainly, then in relative (log) terms, so a dip on
    # the dark face counts as much as one on the bright top and the dark face's level is not read as a tilt.
    A = np.concatenate([np.ones((count, 1)), n0], 1)
    c0, *cn = np.linalg.lstsq(A, target, rcond=None)[0]
    cn = np.array(cn)
    # Highlights are not shading, and the outline's pixels mix with the background: trust the solid interior.
    w = ((lin < (c0 + base @ cn) * 2.2 + .01) * np.clip((alpha - .5) / .45, 0, 1))[mask]
    for _ in range(20):
        s0 = np.maximum(A @ np.concatenate([[c0], cn]), 1e-4)
        r0 = np.log(target + EPS) - np.log(s0 + EPS)
        J = A / (s0 + EPS)[:, None]
        if light_dir is not None:
            J = np.stack([J[:, 0], J[:, 1:] @ light_dir], 1)
        step = np.linalg.lstsq(J * np.sqrt(w)[:, None], r0 * np.sqrt(w), rcond=None)[0]
        c0, cn = c0 + step[0], cn + step[1:] if light_dir is None else light_dir * (cn @ light_dir + step[1])

    # Forward differences over the sprite's pixels.
    Dx, Dy = np.zeros((count, count)), np.zeros((count, count))
    for y, x in zip(*np.nonzero(mask), strict=True):
        i = index[y, x]
        for D, (dy, dx) in ((Dx, (0, 1)), (Dy, (1, 0))):
            ahead = index[y + dy, x + dx] if y + dy < size and x + dx < size else -1
            behind = index[y - dy, x - dx] if y - dy >= 0 and x - dx >= 0 else -1
            if ahead >= 0:
                D[i, ahead] += 1
                D[i, i] -= 1
            elif behind >= 0:
                D[i, i] += 1
                D[i, behind] -= 1
    Lap = Dx @ Dx + Dy @ Dy
    # One light sees slopes along its direction only; slopes across it are free and grow into streaks along the light.
    lxy = cn[:2] / np.linalg.norm(cn[:2])
    Dp = -lxy[1] * Dx + lxy[0] * Dy

    def normals(h):
        m = n0 - np.stack([Dx @ h, Dy @ h, np.zeros(count)], 1)
        return m / np.linalg.norm(m, axis=1, keepdims=True), np.linalg.norm(m, axis=1)

    h = np.zeros(count)
    for _ in range(8):
        n, length = normals(h)
        s = np.maximum(c0 + n @ cn, 1e-4)
        r = np.log(target + EPS) - np.log(s + EPS)
        # ds/dh_x = cn . dn/dh_x, dn/dh_x = -(e_x - n n_x) / |m|, in log terms
        jx = -(cn[0] - (n @ cn) * n[:, 0]) / length / (s + EPS)
        jy = -(cn[1] - (n @ cn) * n[:, 1]) / length / (s + EPS)
        J = jx[:, None] * Dx + jy[:, None] * Dy
        lhs = J.T @ (w[:, None] * J) + smooth * Lap.T @ Lap + across * Dp.T @ Dp + 1e-4 * np.eye(count)
        rhs = J.T @ (w * r) - smooth * Lap.T @ (Lap @ h) - across * Dp.T @ (Dp @ h) - 1e-4 * h
        h = h + np.linalg.solve(lhs, rhs)

    N = base.copy()
    N[mask] = normals(h)[0]
    N = norm(grow(N, mask, 8))
    shading = np.maximum(c0 + N @ cn, 1e-4)
    mottling = np.exp(np.log(lin + EPS) - np.log(shading + EPS))
    mottling = np.where(mask, np.clip(mottling / np.median(mottling[mask]), .4, 2.2), 1)
    return N, mottling, np.concatenate([[c0], cn])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--game", type=Path, required=True, help="a game folder holding crimson.paq")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    atlas = particles(args.game)
    surface = np.zeros(atlas.shape[:2] + (3,))
    surface[...] = .5, .5, .4

    def put(x, y, normals, mottling):
        size = normals.shape[0]
        surface[y:y + size, x:x + size] = np.stack([normals[..., 0] * .5 + .5, normals[..., 1] * .5 + .5, mottling / 2.5], -1)

    x, y, size = cell_rect(atlas, EffectId.FREEZE_SHATTER)
    cell = atlas[y:y + size, x:x + size]
    normals, mottling, light = solve(cell, cube_body(size), smooth=.3, across=.05)
    put(x, y, normals, mottling)
    for effect_id in (EffectId.FREEZE_SHARD_0, EffectId.FREEZE_SHARD_1, EffectId.FREEZE_SHARD_2):
        x, y, size = cell_rect(atlas, effect_id)
        cell = atlas[y:y + size, x:x + size]
        normals, mottling, _ = solve(cell, shard_body(cell[..., 3]), smooth=1., across=.5,
                                     light_dir=light[1:] / np.linalg.norm(light[1:]))
        put(x, y, normals, mottling)
    Image.fromarray(np.round(np.clip(surface, 0, 1) * 255).astype(np.uint8)).save(args.out, orientation=1)
    print(args.out)


if __name__ == "__main__":
    main()
