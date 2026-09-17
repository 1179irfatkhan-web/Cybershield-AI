from django import forms
class AttachmentUploadForm(forms.Form):
    file=forms.FileField(widget=forms.ClearableFileInput(attrs={'class':'form-control','accept':'.pdf,.docx,.xlsx,.xlsm,.pptx,.pptm,.zip,.exe,.dll,.js,.jse,.vbs,.bat,.cmd,.ps1,.apk,.jar,.rtf,.html,.svg,.jpg,.jpeg,.png,.gif,.webp,.bmp,.tif,.tiff'}))
    consent=forms.BooleanField(label='I understand that CyberShield AI performs static analysis only and cannot guarantee that a file is safe.')
