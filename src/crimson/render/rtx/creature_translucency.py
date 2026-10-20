"""Silhouette-distance proxies for artistic creature transmission, not anatomical thickness."""

from PIL import Image, ImageChops, ImageDraw

from grim.raylib_api import rl


def build_thickness_proxy(alpha: Image.Image) -> Image.Image:
    """Encode up to sixteen erosion steps, independently inside each 8x8 atlas cell."""
    width, height = alpha.size
    if alpha.mode != "L" or width <= 0 or height <= 0 or width % 8 or height % 8:
        raise ValueError("Creature thickness requires an L alpha image with an 8x8 cell grid")
    cell_width, cell_height = width // 8, height // 8
    interior = Image.new("L", alpha.size, 255)
    grid = ImageDraw.Draw(interior)
    for cell in range(8):
        for x in (cell * cell_width, (cell + 1) * cell_width - 1):
            grid.line((x, 0, x, height - 1), fill=0)
        for y in (cell * cell_height, (cell + 1) * cell_height - 1):
            grid.line((0, y, width - 1, y), fill=0)
    mask = alpha.point([0] * 4 + [16] * 252)
    distance = Image.new("L", alpha.size)
    for _ in range(16):
        if mask.getbbox() is None:
            break
        distance = ImageChops.add(distance, mask)
        # Separable 3x3 minimum, processing all cells together. Each cell's border
        # survives the first count, then is erased as if padded with transparency.
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
    return distance


def load_thickness_texture(source: rl.Texture) -> rl.Texture:
    """Read source alpha once and upload a renderer-owned, single-channel proxy."""
    image = rl.load_image_from_texture(source)
    try:
        if image.data == rl.ffi.NULL:
            raise RuntimeError("Could not read creature texture for thickness")
        rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
        pixels = bytes(rl.ffi.buffer(image.data, image.width * image.height * 4))
        alpha = Image.frombytes("RGBA", (image.width, image.height), pixels).getchannel("A")
    finally:
        rl.unload_image(image)
    proxy = build_thickness_proxy(alpha)
    # The Image borrows this buffer only for the synchronous upload; raylib must not free it.
    buffer = rl.ffi.new("unsigned char[]", proxy.tobytes())
    upload = rl.Image(
        rl.ffi.cast("void *", buffer), proxy.width, proxy.height, 1,
        rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_GRAYSCALE,
    )
    texture = rl.load_texture_from_image(upload)
    if texture.id <= 0:
        raise RuntimeError("Could not upload creature thickness texture")
    try:
        rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
        rl.set_texture_wrap(texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
    except Exception:
        rl.unload_texture(texture)
        raise
    return texture
