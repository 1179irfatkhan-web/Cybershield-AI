def analyze_executable(path):
    data=open(path,'rb').read(4096); return {'pe_valid':data[:2]==b'MZ','pe_offset':int.from_bytes(data[0x3c:0x40],'little') if len(data)>=64 else None,'signature_present':b'WIN_CERTIFICATE' in data}
