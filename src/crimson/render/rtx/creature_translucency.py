"""Atlas-local body proxies for artistic transmission and Monster Vision heat, and the freeze ice's surface."""

from importlib.resources import files
from typing import Any

from PIL import Image, ImageChops, ImageDraw, ImageFilter

from grim.assets import upload_texture
from grim.raylib_api import rl

_NP: Any = ...


def _numpy() -> Any:
    global _NP
    if _NP is ...:
        try:
            import numpy as np
        except ImportError:
            _NP = None
        else:
            _NP = np
    return _NP


def _cell_size(alpha: Image.Image) -> tuple[int, int]:
    width, height = alpha.size
    if alpha.mode != "L" or width <= 0 or height <= 0 or width % 8 or height % 8:
        raise ValueError("Creature proxies require an L alpha image with an 8x8 cell grid")
    return width // 8, height // 8


def build_thickness_proxy(alpha: Image.Image) -> Image.Image:
    """Encode largest covering odd-square support, capped at 31px, per 8x8 atlas cell."""
    width, height = alpha.size
    cell_width, cell_height = _cell_size(alpha)
    interior = Image.new("L", alpha.size, 255)
    grid = ImageDraw.Draw(interior)
    for cell in range(8):
        for x in (cell * cell_width, (cell + 1) * cell_width - 1):
            grid.line((x, 0, x, height - 1), fill=0)
        for y in (cell * cell_height, (cell + 1) * cell_height - 1):
            grid.line((0, y, width - 1, y), fill=0)
    mask = alpha.point([0] * 4 + [16] * 252)
    erosions: list[Image.Image] = []
    for _ in range(16):
        if mask.getbbox() is None:
            break
        erosions.append(mask)
        # Separable 3x3 minimum, processing all cells together. Each cell's border
        # survives the first level, then is erased as if padded with transparency.
        # Clearing borders also removes the wrap introduced by ImageChops.offset.
        horizontal = ImageChops.darker(
            ImageChops.darker(mask, ImageChops.offset(mask, 1, 0)),
            ImageChops.offset(mask, -1, 0),
        )
        eroded = ImageChops.darker(
            ImageChops.darker(horizontal, ImageChops.offset(horizontal, 0, 1)),
            ImageChops.offset(horizontal, 0, -1),
        )
        mask = ImageChops.darker(eroded, interior)
    thickness = Image.new("L", alpha.size)
    for radius in range(len(erosions) - 1, -1, -1):
        # A radius-k erosion seed covers its entire (2k+1)-square, not just its
        # distance from the nearest edge. Descending max-dilation reconstructs
        # all nested openings in 15 steps instead of dilating each separately.
        horizontal = ImageChops.lighter(
            ImageChops.lighter(thickness, ImageChops.offset(thickness, 1, 0)),
            ImageChops.offset(thickness, -1, 0),
        )
        expanded = ImageChops.lighter(
            ImageChops.lighter(horizontal, ImageChops.offset(horizontal, 0, 1)),
            ImageChops.offset(horizontal, 0, -1),
        )
        encoded = min(255, (radius + 1) * 16)
        seeds = erosions[radius].point([0] + [encoded] * 255)
        thickness = ImageChops.lighter(expanded, seeds)
    # Every expansion is contained by the seed's eroded cell/silhouette.
    return thickness


def blur_cells(proxy: Image.Image, radius: int) -> Image.Image:
    """A box blur inside each 8x8 atlas cell, edges extended: no animation frame bleeds into its neighbor."""
    width, height = proxy.size
    cell_width, cell_height = _cell_size(proxy)
    blurred = Image.new("L", proxy.size)
    for y in range(0, height, cell_height):
        for x in range(0, width, cell_width):
            box = (x, y, x + cell_width, y + cell_height)
            blurred.paste(proxy.crop(box).filter(ImageFilter.BoxBlur(radius)), box)
    return blurred


def build_heat_density(alpha: Image.Image) -> Image.Image:
    """Smooth silhouette coverage with two cell-local 5x5 boxes, preserving fractional alpha.

    Unlike square openings, this changes continuously as a pose gains or loses
    silhouette texels. The triangular footprint retains hot cores and cool tips
    without quantizing the whole torso to its largest surviving square.
    """
    return blur_cells(blur_cells(alpha, 2), 2)


def _encode_grad(diff: int) -> int:
    scaled = diff * 254
    q = (scaled + 255000) // 510000 if scaled >= 0 else -((-scaled + 255000) // 510000)
    return max(1, min(255, 128 + q))


def _build_opaque_interior_mask(alpha: Image.Image, cell_width: int, cell_height: int) -> Image.Image:
    width, height = alpha.size
    if cell_width < 5 or cell_height < 5:
        return Image.new("L", (width, height), 0)
    full = alpha.point([0] * 255 + [255])
    # Separable 5x5 minimum (erode by radius 2 horizontally then vertically).
    h = full
    for dx in (-2, -1, 1, 2):
        h = ImageChops.darker(h, ImageChops.offset(full, dx, 0))
    hv = h
    for dy in (-2, -1, 1, 2):
        hv = ImageChops.darker(hv, ImageChops.offset(h, 0, dy))
    # Keep strictly inside each 8x8 cell with a 2-texel margin so wrap/cross-cell neighbors never count.
    interior = Image.new("L", (width, height), 255)
    draw = ImageDraw.Draw(interior)
    for cell in range(8):
        x0, x1 = cell * cell_width, (cell + 1) * cell_width - 1
        y0, y1 = cell * cell_height, (cell + 1) * cell_height - 1
        for x in (x0, x0 + 1, x1 - 1, x1):
            draw.line((x, 0, x, height - 1), fill=0)
        for y in (y0, y0 + 1, y1 - 1, y1):
            draw.line((0, y, width - 1, y), fill=0)
    return ImageChops.darker(hv, interior)


def _build_creature_surface_map_numpy(rgba: Image.Image, thickness_img: Image.Image, np: Any) -> Image.Image:
    width, height = rgba.size
    cell_width, cell_height = width // 8, height // 8
    thickness = np.frombuffer(thickness_img.tobytes(), dtype=np.uint8).reshape(height, width)
    arr = np.frombuffer(rgba.tobytes(), dtype=np.uint8).reshape(height, width, 4)
    a = arr[:, :, 3]
    luma = np.where(
        a > 0,
        299 * arr[:, :, 0].astype(np.int32) + 587 * arr[:, :, 1].astype(np.int32) + 114 * arr[:, :, 2].astype(np.int32),
        0,
    )

    def encode_grad(diff: Any) -> Any:
        scaled = diff * 254
        q = np.where(scaled >= 0, (scaled + 255000) // 510000, -((-scaled + 255000) // 510000))
        return np.clip(128 + q, 1, 255).astype(np.uint8)

    cells_a = (a > 0).reshape(8, cell_height, 8, cell_width)
    cells_l = luma.reshape(8, cell_height, 8, cell_width)
    left_a = np.concatenate((cells_a[:, :, :, :1], cells_a[:, :, :, :-1]), axis=3)
    right_a = np.concatenate((cells_a[:, :, :, 1:], cells_a[:, :, :, -1:]), axis=3)
    up_a = np.concatenate((cells_a[:, :1, :, :], cells_a[:, :-1, :, :]), axis=1)
    down_a = np.concatenate((cells_a[:, 1:, :, :], cells_a[:, -1:, :, :]), axis=1)
    left_l = np.where(left_a, np.concatenate((cells_l[:, :, :, :1], cells_l[:, :, :, :-1]), axis=3), cells_l)
    right_l = np.where(right_a, np.concatenate((cells_l[:, :, :, 1:], cells_l[:, :, :, -1:]), axis=3), cells_l)
    up_l = np.where(up_a, np.concatenate((cells_l[:, :1, :, :], cells_l[:, :-1, :, :]), axis=1), cells_l)
    down_l = np.where(down_a, np.concatenate((cells_l[:, 1:, :, :], cells_l[:, -1:, :, :]), axis=1), cells_l)
    gx_cells = np.where(cells_a, encode_grad(right_l - left_l), np.uint8(128))
    gy_cells = np.where(cells_a, encode_grad(down_l - up_l), np.uint8(128))

    # 1-ring in-cell 3x3 average of opaque gradients into adjacent transparent texels.
    padded_a = np.pad(cells_a, ((0, 0), (1, 1), (0, 0), (1, 1)), constant_values=False)
    padded_gx = np.pad(gx_cells.astype(np.int32) * cells_a, ((0, 0), (1, 1), (0, 0), (1, 1)), constant_values=0)
    padded_gy = np.pad(gy_cells.astype(np.int32) * cells_a, ((0, 0), (1, 1), (0, 0), (1, 1)), constant_values=0)
    sum_n = np.zeros((8, cell_height, 8, cell_width), dtype=np.int32)
    sum_gx = np.zeros((8, cell_height, 8, cell_width), dtype=np.int32)
    sum_gy = np.zeros((8, cell_height, 8, cell_width), dtype=np.int32)
    for dy in range(3):
        ys = slice(dy, dy + cell_height)
        for dx in range(3):
            xs = slice(dx, dx + cell_width)
            sum_n += padded_a[:, ys, :, xs]
            sum_gx += padded_gx[:, ys, :, xs]
            sum_gy += padded_gy[:, ys, :, xs]
    has_neighbor = (~cells_a) & (sum_n > 0)
    safe_n = np.where(sum_n > 0, sum_n, 1)
    gx_out = np.where(has_neighbor, (sum_gx + safe_n // 2) // safe_n, gx_cells).astype(np.uint8)
    gy_out = np.where(has_neighbor, (sum_gy + safe_n // 2) // safe_n, gy_cells).astype(np.uint8)

    opaque_interior = np.zeros((8, cell_height, 8, cell_width), dtype=np.uint8)
    if cell_width >= 5 and cell_height >= 5:
        cells_full = (a == 255).reshape(8, cell_height, 8, cell_width)
        h_ok = (
            cells_full[:, :, :, 0 : cell_width - 4]
            & cells_full[:, :, :, 1 : cell_width - 3]
            & cells_full[:, :, :, 2 : cell_width - 2]
            & cells_full[:, :, :, 3 : cell_width - 1]
            & cells_full[:, :, :, 4:cell_width]
        )
        hv_ok = (
            h_ok[:, 0 : cell_height - 4, :, :]
            & h_ok[:, 1 : cell_height - 3, :, :]
            & h_ok[:, 2 : cell_height - 2, :, :]
            & h_ok[:, 3 : cell_height - 1, :, :]
            & h_ok[:, 4:cell_height, :, :]
        )
        opaque_interior[:, 2 : cell_height - 2, :, 2 : cell_width - 2] = np.where(hv_ok, 255, 0).astype(np.uint8)

    packed = np.stack(
        (thickness, gx_out.reshape(height, width), gy_out.reshape(height, width), opaque_interior.reshape(height, width)),
        axis=-1,
    )
    return Image.frombytes("RGBA", (width, height), packed.tobytes())


def _build_creature_surface_map_python(rgba: Image.Image, thickness_img: Image.Image) -> Image.Image:
    width, height = rgba.size
    cell_width, cell_height = width // 8, height // 8
    r_ch, g_ch, b_ch, a_ch = rgba.split()
    opaque_img = _build_opaque_interior_mask(a_ch, cell_width, cell_height)
    ab = a_ch.tobytes()
    # Skip transparent interior pixels (~80%+ of creature atlases) via PIL's C 3x3 max filter.
    near_opaque = a_ch.filter(ImageFilter.MaxFilter(3)).tobytes()
    rb, gb, bb = r_ch.tobytes(), g_ch.tobytes(), b_ch.tobytes()
    luma = [0] * (width * height)
    for idx, a in enumerate(ab):
        if a:
            luma[idx] = 299 * rb[idx] + 587 * gb[idx] + 114 * bb[idx]
    gx = bytearray([128]) * (width * height)
    gy = bytearray([128]) * (width * height)
    for cy in range(8):
        y0 = cy * cell_height
        y1 = y0 + cell_height - 1
        for y in range(y0, y1 + 1):
            y_lo = y - 1 if y > y0 else y0
            y_hi = y + 1 if y < y1 else y1
            row_off = y * width
            lo_off = y_lo * width
            hi_off = y_hi * width
            for cx in range(8):
                x0 = cx * cell_width
                x1 = x0 + cell_width - 1
                for x in range(x0, x1 + 1):
                    idx = row_off + x
                    if not ab[idx]:
                        continue
                    x_lo = x - 1 if x > x0 else x0
                    x_hi = x + 1 if x < x1 else x1
                    center = luma[idx]
                    l_xlo = luma[row_off + x_lo] if ab[row_off + x_lo] else center
                    l_xhi = luma[row_off + x_hi] if ab[row_off + x_hi] else center
                    l_ylo = luma[lo_off + x] if ab[lo_off + x] else center
                    l_yhi = luma[hi_off + x] if ab[hi_off + x] else center
                    gx[idx] = _encode_grad(l_xhi - l_xlo)
                    gy[idx] = _encode_grad(l_yhi - l_ylo)
    gx_out = bytearray(gx)
    gy_out = bytearray(gy)
    for cy in range(8):
        y0 = cy * cell_height
        y1 = y0 + cell_height - 1
        for y in range(y0, y1 + 1):
            ny0 = y - 1 if y > y0 else y0
            ny1 = y + 1 if y < y1 else y1
            row_off = y * width
            for cx in range(8):
                x0 = cx * cell_width
                x1 = x0 + cell_width - 1
                for x in range(x0, x1 + 1):
                    idx = row_off + x
                    if ab[idx] or not near_opaque[idx]:
                        continue
                    nx0 = x - 1 if x > x0 else x0
                    nx1 = x + 1 if x < x1 else x1
                    sum_x = sum_y = n = 0
                    for ny in range(ny0, ny1 + 1):
                        noff = ny * width
                        for nx in range(nx0, nx1 + 1):
                            ni = noff + nx
                            if ab[ni]:
                                sum_x += gx[ni]
                                sum_y += gy[ni]
                                n += 1
                    if n:
                        gx_out[idx] = (sum_x + n // 2) // n
                        gy_out[idx] = (sum_y + n // 2) // n
    gx_img = Image.frombytes("L", (width, height), bytes(gx_out))
    gy_img = Image.frombytes("L", (width, height), bytes(gy_out))
    return Image.merge("RGBA", (thickness_img, gx_img, gy_img, opaque_img))


def build_creature_surface_map(rgba: Image.Image) -> Image.Image:
    """Pack per-cell thickness (R), alpha-aware luminance gradient (GB), and 5x5 opaque interior mask (A)."""
    if rgba.mode != "RGBA":
        rgba = rgba.convert("RGBA")
    width, height = rgba.size
    if width <= 0 or height <= 0 or width % 8 or height % 8:
        raise ValueError("Creature surface map requires an RGBA image with an 8x8 cell grid")
    thickness_img = build_thickness_proxy(rgba.getchannel("A"))
    np = _numpy()
    if np is not None:
        return _build_creature_surface_map_numpy(rgba, thickness_img, np)
    return _build_creature_surface_map_python(rgba, thickness_img)


def _source_rgba(source: rl.Texture) -> Image.Image:
    image = rl.load_image_from_texture(source)
    try:
        if image.data == rl.ffi.NULL:
            raise RuntimeError("Could not read creature texture for body proxy")
        rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
        pixels = bytes(rl.ffi.buffer(image.data, image.width * image.height * 4))
        return Image.frombytes("RGBA", (image.width, image.height), pixels)
    finally:
        rl.unload_image(image)


def _source_alpha(source: rl.Texture) -> Image.Image:
    return _source_rgba(source).getchannel("A")


def load_thickness_texture(source: rl.Texture) -> rl.Texture:
    """Read source RGBA once and upload the packed creature surface map."""
    return upload_texture(build_creature_surface_map(_source_rgba(source)), clamp=True)


def load_heat_density_texture(source: rl.Texture) -> rl.Texture:
    """Read source alpha once and upload the single-channel heat density."""
    return upload_texture(build_heat_density(_source_alpha(source)), clamp=True)


def load_ice_texture() -> rl.Texture:
    """The freeze ice's surface in the particles atlas's layout (tools/rtx/ice_surface.py), as creature.frag reads it."""
    with files(__package__).joinpath("ice_surface.tga").open("rb") as source, Image.open(source) as image:
        return upload_texture(image.convert("RGB"), clamp=True)
