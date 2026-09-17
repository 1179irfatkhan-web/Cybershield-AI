import hashlib
def calculate_hashes(fileobj, chunk_size=1024*1024):
    hashes=[hashlib.md5(),hashlib.sha1(),hashlib.sha256()]; fileobj.seek(0)
    for chunk in iter(lambda:fileobj.read(chunk_size),b''):
        for h in hashes:h.update(chunk)
    fileobj.seek(0); return {'md5':hashes[0].hexdigest(),'sha1':hashes[1].hexdigest(),'sha256':hashes[2].hexdigest()}
