from django import forms
from .models import EmailScan

class EmailScanForm(forms.ModelForm):
    # Preview/manual forms submit human-editable metadata text, not a
    # database JSON literal.  Parse it in clean_attachment_metadata below.
    attachment_metadata = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 3, "class": "form-control", "placeholder": "Metadata only; no file uploads"}))
    def clean_email_body(self):
        body = self.cleaned_data["email_body"]
        if not body.strip():
            raise forms.ValidationError("Email body is required.")
        if len(body) > 100000:
            raise forms.ValidationError("Email body is too long.")
        return body

    def clean_attachment_metadata(self):
        value = self.cleaned_data.get("attachment_metadata")
        if not value:
            return []
        if isinstance(value, str):
            import json
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                # Preview forms may submit Python-style escaped metadata from
                # a template; parse it as data only, never execute it.
                try:
                    import ast
                    parsed = ast.literal_eval(value)
                    value = parsed if isinstance(parsed, list) else [parsed]
                except (ValueError, SyntaxError):
                    value = [item.strip() for item in value.split(",") if item.strip()]
        if not isinstance(value, list) or len(value) > 20:
            raise forms.ValidationError("Attachment metadata must be a short JSON list or filename list.")
        return value

    class Meta:
        model = EmailScan
        fields = ["subject", "sender_name", "sender_email", "reply_to", "email_body", "body_type", "attachment_metadata"]
        widgets = {"email_body": forms.Textarea(attrs={"rows": 12, "class": "form-control"})}
