def analyze_apk(path):
    import zipfile
    with zipfile.ZipFile(path) as z:
        names=z.namelist(); return {'manifest_present':'AndroidManifest.xml' in names,'native_libraries':[n for n in names if n.startswith('lib/') and n.endswith('.so')],'entry_count':len(names)}
