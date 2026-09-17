from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [("email_scans", "0002_emailscan_failure_stage_emailscan_link_findings_and_more")]
    operations = [
        migrations.AddField(model_name="emailscan", name="input_source", field=models.CharField(choices=[("manual", "Manual"), ("pasted", "Pasted"), ("pdf_import", "PDF import")], default="manual", max_length=20)),
        migrations.AddField(model_name="emailscan", name="pdf_extraction_confidence", field=models.PositiveSmallIntegerField(blank=True, null=True)),
        migrations.AddField(model_name="emailscan", name="pdf_extraction_warnings", field=models.JSONField(blank=True, default=list)),
    ]
