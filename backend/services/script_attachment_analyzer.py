def analyze_script(path, max_text=200000):
    data=open(path,'rb').read(max_text).decode('utf-8','ignore'); import re
    return {'encoded_commands':bool(re.search(r'EncodedCommand|FromBase64String',data,re.I)),'download_execute':bool(re.search(r'(Invoke-WebRequest|curl|wget).*(iex|exec|powershell)',data,re.I|re.S)),'shell_invocation':bool(re.search(r'cmd\.exe|powershell|wscript|cscript',data,re.I)),'suspicious_urls':re.findall(r'https?://[^\s"\']+',data)[:20]}
