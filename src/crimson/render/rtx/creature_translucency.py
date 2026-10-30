"""Atlas-local body proxies for artistic transmission and Monster Vision heat, and the freeze ice's surface."""

from importlib.resources import files

from PIL import Image, ImageChops, ImageDraw, ImageFilter

from grim.assets import upload_texture
from grim.raylib_api import rl


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


def _source_alpha(source: rl.Texture) -> Image.Image:
    image = rl.load_image_from_texture(source)
    try:
        if image.data == rl.ffi.NULL:
            raise RuntimeError("Could not read creature texture for body proxy")
        rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
        pixels = bytes(rl.ffi.buffer(image.data, image.width * image.height * 4))
        return Image.frombytes("RGBA", (image.width, image.height), pixels).getchannel("A")
    finally:
        rl.unload_image(image)


def load_thickness_texture(source: rl.Texture) -> rl.Texture:
    """Read source alpha once and upload the single-channel transmission proxy."""
    return upload_texture(build_thickness_proxy(_source_alpha(source)), clamp=True)


def load_heat_density_texture(source: rl.Texture) -> rl.Texture:
    """Read source alpha once and upload the single-channel heat density."""
    return upload_texture(build_heat_density(_source_alpha(source)), clamp=True)


def load_ice_texture() -> rl.Texture:
    """The freeze ice's surface in the particles atlas's layout (tools/rtx/ice_surface.py), as creature.frag reads it."""
    with files(__package__).joinpath("ice_surface.tga").open("rb") as source, Image.open(source) as image:
        return upload_texture(image.convert("RGB"), clamp=True)
