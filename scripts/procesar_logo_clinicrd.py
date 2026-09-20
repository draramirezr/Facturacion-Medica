"""Quita el damero del JPEG de Gemini y deja solo la marca ClinicRD."""

from collections import deque
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter

SOURCE = Path(r"Z:\download\Gemini_Generated_Image_f50a1mf50a1mf50a.jfif")
DEST_DIR = Path(__file__).resolve().parents[1] / "static"
LOGO = DEST_DIR / "img" / "logo.png"
LOGO_DARK = DEST_DIR / "img" / "logo-on-dark.png"
ICON = DEST_DIR / "img" / "logo-icon.png"
FAVICON_DIR = DEST_DIR / "logos"


def flood_gray_background(rgb):
    """Marca el damero gris partiendo de los bordes, sin comer texto ni cruz."""
    height, width, _ = rgb.shape
    pixels = rgb.astype(np.float32)
    saturation = pixels.max(axis=2) - pixels.min(axis=2)
    value = pixels.max(axis=2)
    teal = ((pixels[..., 1] - pixels[..., 0]) > 14) & (pixels[..., 2] > 80)
    # Texto blanco, tinta oscura y cruz se protegen.
    protected = teal | (value >= 220) | ((value <= 48) & (saturation < 40))
    background = (saturation < 32) & (value > 48) & (value < 215) & ~protected

    seen = np.zeros((height, width), dtype=bool)
    queue = deque()
    border = (
        [(0, x) for x in range(width)]
        + [(height - 1, x) for x in range(width)]
        + [(y, 0) for y in range(height)]
        + [(y, width - 1) for y in range(height)]
    )
    for y, x in border:
        if background[y, x]:
            seen[y, x] = True
            queue.append((y, x))
    while queue:
        y, x = queue.popleft()
        for ny, nx in ((y - 1, x), (y + 1, x), (y, x - 1), (y, x + 1)):
            if 0 <= ny < height and 0 <= nx < width and not seen[ny, nx] and background[ny, nx]:
                seen[ny, nx] = True
                queue.append((ny, nx))
    return seen | (background & ~protected)


def remove_background(rgb):
    mask = flood_gray_background(rgb)
    alpha = np.where(mask, 0, 255).astype(np.uint8)
    rgba = np.dstack([rgb, alpha])
    image = Image.fromarray(rgba)
    # Cierra huecos sueltos del damero pegados al logo.
    binary = image.split()[-1].point(lambda value: 255 if value else 0)
    cleaned = binary.filter(ImageFilter.MedianFilter(size=3))
    image.putalpha(cleaned)
    return image


def crop_opaque(image, padding=8):
    alpha = np.array(image.split()[-1])
    rows = np.where(alpha.max(axis=1) > 10)[0]
    cols = np.where(alpha.max(axis=0) > 10)[0]
    top, bottom = max(0, int(rows[0]) - padding), min(image.height, int(rows[-1]) + padding + 1)
    left, right = max(0, int(cols[0]) - padding), min(image.width, int(cols[-1]) + padding + 1)
    return image.crop((left, top, right, bottom))


def light_variant(image):
    arr = np.array(image)
    rgb = arr[..., :3].astype(np.float32)
    alpha = arr[..., 3]
    saturation = rgb.max(axis=2) - rgb.min(axis=2)
    value = rgb.max(axis=2)
    white_ink = (alpha > 20) & (saturation < 50) & (value > 190)
    rgb[white_ink] = np.array([23, 32, 51], dtype=np.float32)
    return Image.fromarray(np.dstack([rgb.astype(np.uint8), alpha]))


def extract_icon(image):
    arr = np.array(image)
    rgb = arr[..., :3].astype(np.float32)
    alpha = arr[..., 3]
    teal = (alpha > 40) & ((rgb[..., 1] - rgb[..., 0]) > 16)
    cols = np.where(teal.any(axis=0))[0]
    start = int(cols[0])
    previous = start
    cut = int(cols[-1])
    for column in cols:
        if column - previous > 16 and previous - start > 40:
            cut = previous
            break
        previous = column
    rows = np.where(alpha.max(axis=1) > 20)[0]
    pad = 6
    return image.crop((
        max(0, start - pad),
        max(0, int(rows[0]) - pad),
        min(image.width, cut + pad),
        min(image.height, int(rows[-1]) + pad),
    ))


def save_favicon(icon):
    FAVICON_DIR.mkdir(parents=True, exist_ok=True)
    square = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    fitted = icon.copy()
    fitted.thumbnail((236, 236), Image.Resampling.LANCZOS)
    square.paste(fitted, ((256 - fitted.width) // 2, (256 - fitted.height) // 2), fitted)
    square.save(FAVICON_DIR / "favicon.png")
    square.save(FAVICON_DIR / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])


def main():
    source = Image.open(SOURCE).convert("RGB")
    transparent = crop_opaque(remove_background(np.array(source)))
    light = light_variant(transparent)
    icon = extract_icon(light)
    LOGO.parent.mkdir(parents=True, exist_ok=True)
    light.save(LOGO, "PNG")
    transparent.save(LOGO_DARK, "PNG")
    icon.save(ICON, "PNG")
    save_favicon(icon)
    arr = np.array(light)
    leftover = (
        (arr[..., 3] > 10)
        & ((arr[..., :3].max(axis=2) - arr[..., :3].min(axis=2)) < 25)
        & (arr[..., :3].max(axis=2) > 50)
        & (arr[..., :3].max(axis=2) < 210)
    )
    print(f"logo {light.size} leftover_gray={int(leftover.sum())}")


if __name__ == "__main__":
    main()
