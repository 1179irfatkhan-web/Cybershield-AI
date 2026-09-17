def analyze_office(path, extension):
    import zipfile
    with zipfile.ZipFile(path) as z:
        names=z.namelist(); macro=extension in {'xlsm','pptm'} or any('vbaProject' in n for n in names)
        return {'valid_zip':True,'macro_enabled_type':extension if extension in {'xlsm','pptm'} else '','macro_detected':macro,'ole_objects':any('embeddings' in n for n in names),'external_relationships':any('externalLinks' in n for n in names),'entry_count':len(names)}
