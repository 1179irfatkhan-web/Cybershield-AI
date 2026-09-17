def analyze_pdf(path, max_pages=50):
    from pypdf import PdfReader
    r=PdfReader(path); text=''; findings={'encrypted':r.is_encrypted,'page_count':len(r.pages),'javascript':False,'open_action':False,'launch_action':False,'uri_actions':False,'embedded_files':False,'metadata':dict(r.metadata or {})}
    if len(r.pages)>max_pages: findings['page_limit_exceeded']=True
    raw=open(path,'rb').read(2_000_000); findings['javascript']=b'/JavaScript' in raw or b'/JS ' in raw; findings['open_action']=b'/OpenAction' in raw; findings['launch_action']=b'/Launch' in raw; findings['uri_actions']=b'/URI' in raw; findings['embedded_files']=b'/EmbeddedFile' in raw
    return findings
