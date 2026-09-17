import logging, os, tempfile, shutil
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404,redirect,render
from django.utils import timezone
from .forms import AttachmentUploadForm
from .models import AttachmentScan
from services.file_validator import validate_upload
from services.file_hashing import calculate_hashes
from services.attachment_scoring import calculate_attachment_score
from services.image_attachment_analyzer import analyze_image
logger=logging.getLogger(__name__)
@login_required
def create_scan(request):
    form=AttachmentUploadForm(request.POST or None,request.FILES or None)
    if request.method=='POST' and form.is_valid():
        f=request.FILES['file']; v=validate_upload(f,getattr(settings,'ATTACHMENT_MAX_UPLOAD_SIZE',200*1024*1024))
        if f.size > getattr(settings,'ATTACHMENT_MAX_UPLOAD_SIZE',200*1024*1024): v={'allowed':False,'reason':'This file is larger than the supported upload limit. Please choose a smaller file.'}
        if not v['allowed']: form.add_error('file',v['reason'])
        else:
            scan=AttachmentScan.objects.create(user=request.user,original_filename=f.name,declared_extension=v['extension'],declared_mime_type=v['mime'],file_size=f.size,file_type_category=v['category'],status='pending')
            tmp=tempfile.NamedTemporaryFile(prefix='attachment-',suffix='.bin',delete=False); tmp_path=tmp.name
            try:
                for chunk in f.chunks(): tmp.write(chunk)
                tmp.close(); h=calculate_hashes(open(tmp_path,'rb')); scan.md5_hash=h['md5'];scan.sha1_hash=h['sha1'];scan.sha256_hash=h['sha256'];scan.detected_extension=v['extension'];scan.detected_mime_type=v['mime']; image_findings=analyze_image(tmp_path,getattr(settings,'ATTACHMENT_IMAGE_MAX_WIDTH',10000),getattr(settings,'ATTACHMENT_IMAGE_MAX_HEIGHT',10000),getattr(settings,'ATTACHMENT_IMAGE_MAX_PIXELS',50000000),getattr(settings,'ATTACHMENT_IMAGE_MAX_FRAMES',100)) if v['extension'] in {'jpg','jpeg','png','gif','webp','bmp','tif','tiff'} else {}; scan.image_findings=image_findings; decoded=(image_findings.get('format','').lower() if image_findings else ''); mismatch=bool(image_findings and ((v['extension'] in {'jpg','jpeg'} and decoded!='jpeg') or (v['extension']=='png' and decoded!='png') or (v['extension']=='gif' and decoded!='gif') or (v['extension']=='webp' and decoded!='webp') or (v['extension']=='bmp' and decoded!='bmp') or (v['extension'] in {'tif','tiff'} and decoded not in {'tiff','tif'}))); evidence={'confidence_score':85 if image_findings else 70,'completeness_percentage':85 if image_findings else 60,'extension_mismatch':mismatch,'executable_detected':v['extension'] in {'exe','dll'},'script_detected':v['extension'] in {'js','jse','vbs','bat','cmd','ps1'},'macro_detected':v['extension'] in {'xlsm','pptm'}}; score=calculate_attachment_score(evidence); scan.extension_mismatch=mismatch; scan.safety_score=score['safety_score'];scan.confidence_score=score['confidence_score'];scan.completeness_percentage=score['completeness_percentage'];scan.risk_level=score['risk_level'];scan.methodology_version=score['methodology_version'];scan.positive_findings=score['positive_findings'];scan.warning_findings=score['warnings'] + image_findings.get('warnings',[]);scan.score_breakdown=score['deductions'];scan.check_results=score['check_results'];scan.status='completed';scan.completed_at=timezone.now();scan.save()
            except Exception as exc:
                logger.exception('attachment_scan_failed scan_id=%s category=%s',scan.id,type(exc).__name__);scan.status='failed';scan.error_message='The file could not be analyzed safely.';scan.failure_stage='analysis';scan.completed_at=timezone.now();scan.save()
            finally:
                try: os.remove(tmp_path)
                except OSError: pass
            return redirect('attachment_scans:result',scan_id=scan.id)
    return render(request,'attachment_scans/create.html',{'form':form})
@login_required
def result(request,scan_id):
    return render(request,'attachment_scans/result.html',{'scan':get_object_or_404(request.user.attachment_scans,id=scan_id)})
@login_required
def history(request):
    return render(request,'attachment_scans/history.html',{'scans':request.user.attachment_scans.all()[:50]})
