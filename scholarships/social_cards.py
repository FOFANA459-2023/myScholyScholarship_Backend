"""Social preview card images.

Facebook, WhatsApp and LinkedIn show an image with every shared link, but
each crops it differently: Facebook and LinkedIn want a wide ~1.91:1 banner,
WhatsApp frequently shows a square thumbnail. Scholarships have no uploaded
artwork, so each one gets generated cards - one layout per platform shape -
carrying the brand navy-to-gold wash, the myScholy logo, the scholarship name
and its key facts. The frontend's crawler shim
(functions/scholarships/[slug].js) sniffs the crawler's user agent and points
``og:image`` at the right variant of :func:`scholarships.views.scholarship_card`.

Fonts are the freely redistributable Bitstream Vera faces, committed under
``assets/fonts`` so rendering is identical on every host.
"""

from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ASSETS = Path(__file__).parent / "assets"

NAVY = (12, 74, 110)  # brand-900
GOLD = (180, 83, 9)  # gold-700
GOLD_BRIGHT = (234, 179, 8)  # gold-500, for accents
WHITE = (255, 255, 255)
SOFT = (224, 236, 247)

TAGLINE = "Scholarships for students worldwide - free to browse, free to apply"

# Card variants and their pixel sizes. "wide" is the Facebook/default layout;
# "square" fits WhatsApp's thumbnail crop; "linkedin" is the wide shape with a
# quieter layout, because LinkedIn prints its own title bar under the image.
SIZES = {
    "wide": (1200, 630),
    "square": (1080, 1080),
    "linkedin": (1200, 627),
}
DEFAULT_VARIANT = "wide"


def _font(name, size):
    return ImageFont.truetype(str(ASSETS / "fonts" / name), size)


def _gradient(width, height):
    """The navy-to-gold diagonal wash used across the site."""
    base = Image.new("RGB", (width, height))
    px = base.load()
    for y in range(height):
        for x in range(0, width, 4):
            t = (x / width * 0.7) + (y / height * 0.3)
            colour = tuple(
                int(NAVY[i] + (GOLD[i] - NAVY[i]) * t) for i in range(3)
            )
            for dx in range(4):
                if x + dx < width:
                    px[x + dx, y] = colour
    return base


def _logo(height):
    logo = Image.open(ASSETS / "logo.png").convert("RGBA")
    width = int(logo.width * height / logo.height)
    return logo.resize((width, height))


def _wrap(draw, text, font, max_width, max_lines):
    """Greedy word wrap; the last line gets an ellipsis if text is cut."""
    words = text.split()
    lines, current = [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if draw.textlength(candidate, font=font) <= max_width or not current:
            current = candidate
        else:
            lines.append(current)
            current = word
        if len(lines) == max_lines:
            break
    if current and len(lines) < max_lines:
        lines.append(current)
    if len(lines) == max_lines and len(" ".join(lines)) < len(text):
        lines[-1] = lines[-1].rstrip(".,;:") + "..."
    return lines


def _facts(scholarship):
    return " | ".join(
        part
        for part in (
            scholarship.host_country,
            scholarship.degree_level,
            f"Apply by {scholarship.deadline:%d %b %Y}",
        )
        if part
    )


def _to_png(image):
    buffer = BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


def _render_wide(scholarship):
    """Facebook layout: logo header, left-aligned name, facts, tagline."""
    width, height = SIZES["wide"]
    margin = 80
    text_width = width - 2 * margin
    image = _gradient(width, height)
    draw = ImageDraw.Draw(image)

    logo = _logo(96)
    image.paste(logo, (margin, 64), logo)
    draw.text(
        (margin + logo.width + 28, 88), "myScholy",
        font=_font("VeraBd.ttf", 44), fill=WHITE,
    )

    name_font = _font("VeraBd.ttf", 58)
    y = 240
    for line in _wrap(draw, scholarship.name, name_font, text_width, max_lines=3):
        draw.text((margin, y), line, font=name_font, fill=WHITE)
        y += 74

    facts_font = _font("Vera.ttf", 30)
    for line in _wrap(draw, _facts(scholarship), facts_font, text_width, max_lines=1):
        draw.text((margin, y + 18), line, font=facts_font, fill=SOFT)

    draw.text(
        (margin, height - 78), TAGLINE, font=_font("Vera.ttf", 24), fill=SOFT
    )
    return _to_png(image)


def _render_square(scholarship):
    """WhatsApp layout: everything centred so a square (or further-cropped)
    thumbnail still reads. The name sits in the vertical middle."""
    width, height = SIZES["square"]
    margin = 90
    text_width = width - 2 * margin
    image = _gradient(width, height)
    draw = ImageDraw.Draw(image)

    def centred(text, font, y, fill):
        x = (width - draw.textlength(text, font=font)) / 2
        draw.text((x, y), text, font=font, fill=fill)

    logo = _logo(150)
    image.paste(logo, ((width - logo.width) // 2, 96), logo)
    centred("myScholy", _font("VeraBd.ttf", 52), 280, WHITE)

    # Gold rule between the brand block and the scholarship.
    draw.rectangle(
        (width // 2 - 90, 392, width // 2 + 90, 398), fill=GOLD_BRIGHT
    )

    name_font = _font("VeraBd.ttf", 60)
    lines = _wrap(draw, scholarship.name, name_font, text_width, max_lines=4)
    line_height = 78
    y = 520 - (len(lines) - 1) * line_height // 2
    for line in lines:
        centred(line, name_font, y, WHITE)
        y += line_height

    facts_font = _font("Vera.ttf", 34)
    for line in _wrap(draw, _facts(scholarship), facts_font, text_width, max_lines=2):
        centred(line, facts_font, y + 26, SOFT)
        y += 48

    centred("free to browse, free to apply", _font("Vera.ttf", 30), height - 110, SOFT)
    return _to_png(image)


def _render_linkedin(scholarship):
    """LinkedIn layout: LinkedIn prints the page title in its own bar under
    the image, so the card drops the tagline, adds a gold accent and gives the
    name more air."""
    width, height = SIZES["linkedin"]
    margin = 90
    text_width = width - 2 * margin
    image = _gradient(width, height)
    draw = ImageDraw.Draw(image)

    logo = _logo(88)
    image.paste(logo, (margin, 70), logo)
    draw.text(
        (margin + logo.width + 26, 92), "myScholy",
        font=_font("VeraBd.ttf", 40), fill=WHITE,
    )

    # Gold accent above the name.
    draw.rectangle((margin, 226, margin + 170, 234), fill=GOLD_BRIGHT)

    name_font = _font("VeraBd.ttf", 64)
    y = 276
    for line in _wrap(draw, scholarship.name, name_font, text_width, max_lines=3):
        draw.text((margin, y), line, font=name_font, fill=WHITE)
        y += 82

    facts_font = _font("Vera.ttf", 32)
    for line in _wrap(draw, _facts(scholarship), facts_font, text_width, max_lines=1):
        draw.text((margin, y + 22), line, font=facts_font, fill=SOFT)

    domain_font = _font("Vera.ttf", 26)
    domain = "myscholy.pages.dev"
    draw.text(
        (width - margin - draw.textlength(domain, font=domain_font), height - 74),
        domain, font=domain_font, fill=SOFT,
    )
    return _to_png(image)


_RENDERERS = {
    "wide": _render_wide,
    "square": _render_square,
    "linkedin": _render_linkedin,
}


def render_card(scholarship, variant=DEFAULT_VARIANT):
    """Render one scholarship's PNG card. Unknown variants fall back to wide."""
    renderer = _RENDERERS.get(variant, _render_wide)
    return renderer(scholarship)
