import os,re
SUPPORTED={'pdf':('application/pdf',b'%PDF-'),'docx':('application/vnd.openxmlformats-officedocument.wordprocessingml.document',b'PK'),'xlsx':('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',b'PK'),'xlsm':('application/vnd.ms-excel.sheet.macroEnabled.12',b'PK'),'zip':('application/zip',b'PK'),'exe':('application/vnd.microsoft.portable-executable',b'MZ'),'dll':('application/vnd.microsoft.portable-executable',b'MZ'),'js':('text/javascript',None),'vbs':('text/vbscript',None),'bat':('text/plain',None),'cmd':('text/plain',None),'ps1':('text/plain',None),'apk':('application/vnd.android.package-archive',b'PK'),'jar':('application/java-archive',b'PK'),'rtf':('application/rtf',b'{\\rtf'),'html':('text/html',None),'svg':('image/svg+xml',b'<'),'jpg':('image/jpeg',b'\\xff\\xd8\\xff'),'jpeg':('image/jpeg',b'\\xff\\xd8\\xff'),'png':('image/png',b'\\x89PNG\\r\\n\\x1a\\n'),'gif':('image/gif',b'GIF8'),'webp':('image/webp',b'RIFF'),'bmp':('image/bmp',b'BM'),'tif':('image/tiff',b'II*\\x00'),'tiff':('image/tiff',b'II*\\x00')}
SUPPORTED.update({'jpg':('image/jpeg',bytes.fromhex('ffd8ff')),'jpeg':('image/jpeg',bytes.fromhex('ffd8ff')),'png':('image/png',bytes.fromhex('89504e470d0a1a0a')),'gif':('image/gif',b'GIF8'),'webp':('image/webp',b'RIFF'),'bmp':('image/bmp',b'BM'),'tif':('image/tiff',bytes.fromhex('49492a00')),'tiff':('image/tiff',bytes.fromhex('49492a00'))})
def validate_upload(f,max_size=10*1024*1024):
    name=f.name or ''; low=name.lower(); ext=low.rsplit('.',1)[-1] if '.' in low else ''
    if f.size == 0: return {'allowed':False,'reason':'The uploaded file is empty.'}
    if f.size>max_size: return {'allowed':False,'reason':'File exceeds the maximum size.'}
    if not ext or ext not in SUPPORTED:return {'allowed':False,'reason':'This file type is unsupported.'}
    if '\x00' in name or '\u202e' in name or '/' in name or '\\' in name:return {'allowed':False,'reason':'Unsafe filename.'}
    f.seek(0); head=f.read(8); f.seek(0); magic=SUPPORTED[ext][1]
    if magic and not head.startswith(magic):return {'allowed':False,'reason':'File signature does not match its extension.'}
    declared=f.content_type or 'application/octet-stream'; expected=SUPPORTED[ext][0]
    image_mimes={x[0] for k,x in SUPPORTED.items() if k in {'jpg','jpeg','png','gif','webp','bmp','tif','tiff'}}
    if ext in {'jpg','jpeg','png','gif','webp','bmp','tif','tiff'} and declared not in image_mimes and declared != 'application/octet-stream': return {'allowed':False,'reason':'The declared MIME type does not match an image.'}
    return {'allowed':True,'extension':ext,'mime':declared,'expected_mime':expected,'category':'image' if ext in {'jpg','jpeg','png','gif','webp','bmp','tif','tiff'} else 'executable' if ext in {'exe','dll','msi'} else 'script' if ext in {'js','jse','vbs','bat','cmd','ps1'} else ext}
