from django.db import migrations, models


class Migration(migrations.Migration):
    """Rename nationality -> country_of_citizenship and add education_level.

    makemigrations proposes a RemoveField + AddField pair here, which would
    drop every existing value. RenameField keeps the column and its data - the
    field holds exactly the same thing under a clearer name that pairs with
    country_of_residence on the signup form.
    """

    dependencies = [
        ("scholarships", "0003_contactmessage_alter_admin_options_and_more"),
    ]

    operations = [
        migrations.RenameField(
            model_name="student",
            old_name="nationality",
            new_name="country_of_citizenship",
        ),
        migrations.AlterField(
            model_name="student",
            name="country_of_citizenship",
            field=models.CharField(blank=True, db_index=True, max_length=100),
        ),
        migrations.AddField(
            model_name="student",
            name="education_level",
            field=models.CharField(
                blank=True,
                choices=[
                    ("high_school", "High school"),
                    ("undergraduate", "Undergraduate"),
                    ("graduate", "Graduate"),
                ],
                db_index=True,
                max_length=20,
            ),
        ),
    ]
