from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oauth2", "0001_initial"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="refreshtoken",
            index=models.Index(
                fields=["token", "client", "expired"], name="token_client_expired_idx"
            ),
        ),
    ]
