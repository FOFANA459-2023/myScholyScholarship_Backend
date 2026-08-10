"""Social preview card images.

Facebook, WhatsApp and Twitter show a large image with every shared link.
Scholarships have no uploaded artwork, so each one gets a generated 1200x630
card: the brand navy-to-gold wash, the myScholy logo, the scholarship name and
its key facts. The frontend's crawler shim (functions/scholarships/[slug].js)
points ``og:image`` at :func:`scholarships.views.scholarship_card` which
renders through here.

Fonts are the freely redistributable Bitstream Vera faces, committed under
``assets/fonts`` so rendering is identical on every host.
"""

from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 1200, 630
ASSETS = Path(__file__).parent / "assets"

NAVY = (12, 74, 110)  # brand-900
GOLD = (180, 83, 9)  # gold-700
WHITE = (255, 255, 255)
SOFT = (224, 236, 247)

MARGIN = 80
TEXT_WIDTH = WIDTH - 2 * MARGIN


def _font(name, size):
    return ImageFont.truetype(str(ASSETS / "fonts" / name), size)


def _gradient():
    """The navy-to-gold diagonal wash used across the site."""
    base = Image.new("RGB", (WIDTH, HEIGHT))
    px = base.load()
    for y in range(HEIGHT):
        for x in range(0, WIDTH, 4):
            # Diagonal blend factor, matching a ~35 degree gradient.
            t = (x / WIDTH * 0.7) + (y / HEIGHT * 0.3)
            colour = tuple(
                int(NAVY[i] + (GOLD[i] - NAVY[i]) * t) for i in range(3)
            )
            for dx in range(4):
                if x + dx < WIDTH:
                    px[x + dx, y] = colour
    return base


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


def render_card(scholarship):
    """Render the 1200x630 PNG for one scholarship. Returns bytes."""
    image = _gradient()
    draw = ImageDraw.Draw(image)

    # Logo, top-left, with the site name beside it.
    logo = Image.open(ASSETS / "logo.png").convert("RGBA")
    logo_h = 96
    logo_w = int(logo.width * logo_h / logo.height)
    image.paste(logo.resize((logo_w, logo_h)), (MARGIN, 64), logo.resize((logo_w, logo_h)))
    draw.text(
        (MARGIN + logo_w + 28, 88),
        "myScholy",
        font=_font("VeraBd.ttf", 44),
        fill=WHITE,
    )

    # Scholarship name: the headline of the card.
    name_font = _font("VeraBd.ttf", 58)
    lines = _wrap(draw, scholarship.name, name_font, TEXT_WIDTH, max_lines=3)
    y = 240
    for line in lines:
        draw.text((MARGIN, y), line, font=name_font, fill=WHITE)
        y += 74

    # Key facts: country, degree level, deadline.
    facts = " | ".join(
        part
        for part in (
            scholarship.host_country,
            scholarship.degree_level,
            f"Apply by {scholarship.deadline:%d %b %Y}",
        )
        if part
    )
    facts_font = _font("Vera.ttf", 30)
    for line in _wrap(draw, facts, facts_font, TEXT_WIDTH, max_lines=1):
        draw.text((MARGIN, y + 18), line, font=facts_font, fill=SOFT)

    # Footer.
    draw.text(
        (MARGIN, HEIGHT - 78),
        "Scholarships for students worldwide - free to browse, free to apply",
        font=_font("Vera.ttf", 24),
        fill=SOFT,
    )

    buffer = BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()
