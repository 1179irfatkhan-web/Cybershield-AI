from django import forms
from urllib.parse import urlsplit,urlunsplit
class AssessmentForm(forms.Form):
    submitted_url=forms.URLField(label='Website URL',widget=forms.URLInput(attrs={'class':'form-control','placeholder':'https://example.com'}))
    authorization_confirmed=forms.BooleanField(label='I confirm that I own this website or have explicit authorization to perform this security assessment.')
    def clean_submitted_url(self):
        value=self.cleaned_data['submitted_url'].strip(); parts=urlsplit(value)
        if parts.scheme.lower() not in {'http','https'} or not parts.netloc: raise forms.ValidationError('Enter a valid HTTP or HTTPS website URL.')
        return urlunsplit((parts.scheme.lower(),parts.netloc.lower(),parts.path or '/',parts.query,''))
