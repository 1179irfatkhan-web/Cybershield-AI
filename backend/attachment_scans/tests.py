from io import BytesIO
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase
from services.file_validator import validate_upload
from services.image_attachment_analyzer import analyze_image
from PIL import Image
import tempfile, os

class ImageAttachmentTests(SimpleTestCase):
    def image(self, fmt, name=None):
        b=BytesIO(); Image.new('RGB',(32,24),'blue').save(b,format=fmt); return SimpleUploadedFile(name or 'sample.'+fmt.lower(),b.getvalue(),content_type='image/'+fmt.lower())
    def test_supported_png(self):
        f=self.image('PNG'); self.assertTrue(validate_upload(f)['allowed'])
    def test_jpeg_magic_and_analyzer(self):
        f=self.image('JPEG','photo.jpg'); v=validate_upload(f); self.assertTrue(v['allowed']); fd,path=tempfile.mkstemp(suffix='.jpg'); os.close(fd)
        try:
            open(path,'wb').write(f.read()); result=analyze_image(path); self.assertEqual(result['format'],'JPEG'); self.assertEqual(result['pixel_count'],768)
        finally: os.remove(path)
    def test_executable_renamed_image_rejected(self):
        f=SimpleUploadedFile('bad.png',b'MZ'+b'\0'*20,content_type='image/png'); self.assertFalse(validate_upload(f)['allowed'])
    def test_unsupported_type_rejected(self):
        self.assertFalse(validate_upload(SimpleUploadedFile('x.txt',b'hello',content_type='text/plain'))['allowed'])
