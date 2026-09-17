def analyze_archive(path, max_entries=1000, max_total_size=100*1024*1024, max_ratio=1000):
    import zipfile, os
    with zipfile.ZipFile(path) as z:
        infos=z.infolist(); names=[i.filename for i in infos]; total=sum(i.file_size for i in infos); compressed=max(1,sum(i.compress_size for i in infos));
        return {'entry_count':len(infos),'total_expanded_size':total,'path_traversal':any(n.startswith(('/', '\\')) or '..' in n.split('/') for n in names),'executable_entries':[n for n in names if n.lower().endswith(('.exe','.dll','.js','.vbs','.bat','.cmd','.ps1'))],'nested_archives':[n for n in names if n.lower().endswith(('.zip','.jar','.apk'))],'zip_bomb':len(infos)>max_entries or total>max_total_size or total/compressed>max_ratio}
