from django import forms

from .models import WebsiteScan


class WebsiteScanForm(forms.ModelForm):
    class Meta:
        model = WebsiteScan
        fields = ["submitted_url"]
        widgets = {
            "submitted_url": forms.URLInput(
                attrs={
                    "class": "form-control form-control-lg",
                    "placeholder": "https://example.com",
                    "autocomplete": "url",
                }
            )
        }
        labels = {
            "submitted_url": "Website URL",
        }

    def clean_submitted_url(self):
        url = self.cleaned_data["submitted_url"].strip()

        if not url.startswith(("http://", "https://")):
            raise forms.ValidationError(
                "Enter a complete URL starting with http:// or https://."
            )

        return url