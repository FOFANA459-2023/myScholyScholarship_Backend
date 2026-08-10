"""Add the public slug used in detail-page URLs.

Three steps because the table already has rows: add the column nullable,
backfill unique slugs from the names, then enforce uniqueness.
"""

from django.db import migrations, models
from django.utils.text import slugify


def _base_slug(name):
    # Mirrors scholarships.models.scholarship_base_slug (migrations must not
    # import app code that can drift under them).
    base = slugify(name)[:260].strip("-")
    if not base:
        return "scholarship"
    if base.isdigit():
        return f"scholarship-{base}"
    return base


def backfill_slugs(apps, schema_editor):
    Scholarship = apps.get_model("scholarships", "Scholarship")
    taken = set()
    for row in Scholarship.objects.order_by("pk").only("pk", "name"):
        base = _base_slug(row.name)
        slug = base
        n = 2
        while slug in taken:
            slug = f"{base}-{n}"
            n += 1
        taken.add(slug)
        Scholarship.objects.filter(pk=row.pk).update(slug=slug)


class Migration(migrations.Migration):
    dependencies = [
        ("scholarships", "0005_digestrun"),
    ]

    operations = [
        # db_index=False here: the AlterField below creates the unique index,
        # and letting both steps build one collides on the *_like index name.
        migrations.AddField(
            model_name="scholarship",
            name="slug",
            field=models.SlugField(
                max_length=280, null=True, blank=True, db_index=False
            ),
        ),
        migrations.RunPython(backfill_slugs, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="scholarship",
            name="slug",
            field=models.SlugField(max_length=280, unique=True, blank=True),
        ),
    ]
