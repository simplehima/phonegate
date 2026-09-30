"""Generates the setup wizard's side and header images (BMP) from the app icon and fonts.

Provenance: drawn by this script from `windows/companion/src-tauri/icons/icon.png` and the
bundled OFL fonts (Archivo). Re-run after changing the icon:
    python windows/installer/make-art.py
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
ICON = ROOT / "windows/companion/src-tauri/icons/icon.png"
FONT = ROOT / "windows/companion/ui/public/fonts/Archivo.ttf"
OUT = Path(__file__).resolve().parent / "art"

CANARY = (244, 196, 48)
INK = (31, 58, 147)
GRAPHITE = (52, 58, 70)
PAPER = (255, 255, 255)


def font(size: int, weight: int = 700) -> ImageFont.FreeTypeFont:
    f = ImageFont.truetype(str(FONT), size)
    try:  # Archivo is a variable font: pick the weight axis when available.
        f.set_variation_by_axes([weight, 100])
    except Exception:
        pass
    return f


def side(scale: int) -> Image.Image:
    w, h = 164 * scale, 314 * scale
    img = Image.new("RGB", (w, h), CANARY)
    d = ImageDraw.Draw(img)
    icon = Image.open(ICON).convert("RGBA").resize((72 * scale, 72 * scale), Image.LANCZOS)
    img.paste(icon, (18 * scale, 28 * scale), icon)
    d.text((18 * scale, 116 * scale), "PhoneGate", font=font(24 * scale, 750), fill=INK)
    # Perforation rule, as on the visitor slips.
    y = 154 * scale
    for x in range(18 * scale, w - 18 * scale, 7 * scale):
        d.ellipse((x, y, x + 3 * scale, y + 3 * scale), fill=INK)
    body = font(11 * scale, 450)
    lines = ["Your phone approves", "every unlock of", "this PC."]
    for i, line in enumerate(lines):
        d.text((18 * scale, (170 + i * 16) * scale), line, font=body, fill=GRAPHITE)
    return img


def header(scale: int) -> Image.Image:
    s = 55 * scale
    img = Image.new("RGB", (s, s), PAPER)
    icon = Image.open(ICON).convert("RGBA").resize((s - 6 * scale, s - 6 * scale), Image.LANCZOS)
    img.paste(icon, (3 * scale, 3 * scale), icon)
    return img


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for scale in (1, 2):
        side(scale).save(OUT / f"wizard-side@{scale}x.bmp")
        header(scale).save(OUT / f"wizard-header@{scale}x.bmp")
    print("installer art written to", OUT)


if __name__ == "__main__":
    main()
