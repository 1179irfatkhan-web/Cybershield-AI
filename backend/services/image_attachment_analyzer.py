def analyze_image(path, max_width=10000, max_height=10000, max_pixels=50_000_000, max_frames=100):
    from PIL import Image, ImageFile
    Image.MAX_IMAGE_PIXELS = max_pixels
    findings={'format':'','width':None,'height':None,'pixel_count':None,'frame_count':1,'animated':False,'metadata_present':False,'exif_present':False,'gps_metadata_present':False,'icc_profile_present':False,'comments_present':False,'truncated_or_malformed':False,'decompression_bomb_risk':False,'trailing_data_detected':False,'polyglot_indicators':[],'metadata_findings':[],'warnings':[],'check_status':'ok'}
    try:
        with Image.open(path) as image:
            findings['format']=image.format or ''; findings['width'],findings['height']=image.size; findings['pixel_count']=image.width*image.height; findings['frame_count']=getattr(image,'n_frames',1); findings['animated']=findings['frame_count']>1
            if findings['width']>max_width or findings['height']>max_height or findings['pixel_count']>max_pixels: findings['decompression_bomb_risk']=True; findings['warnings'].append('Image dimensions exceed safe limits.')
            if findings['frame_count']>max_frames: findings['warnings'].append('Image contains too many frames.'); findings['check_status']='warning'
            exif=image.getexif(); findings['exif_present']=bool(exif); findings['metadata_present']=bool(exif or image.info); findings['gps_metadata_present']=34853 in exif; findings['icc_profile_present']=bool(image.info.get('icc_profile')); findings['comments_present']=bool(image.info.get('comment'))
            if findings['gps_metadata_present']: findings['metadata_findings'].append('Location metadata is present.')
            image.verify()
    except Exception:
        findings['truncated_or_malformed']=True; findings['check_status']='warning'; findings['warnings'].append('Image structure could not be fully verified.')
    return findings
