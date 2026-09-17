from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0009_websitescan_ai_security_report"),
    ]

    operations = [
        migrations.AddField(
            model_name="websitescan",
            name="redirect_chain",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="websitescan",
            name="redirect_cross_host_count",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="websitescan",
            name="redirect_has_scheme_downgrade",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="websitescan",
            name="redirect_loop_detected",
            field=models.BooleanField(default=False),
        ),
    ]
