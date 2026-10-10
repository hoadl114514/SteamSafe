"""Read existing Sysmon metadata only. No driver installation or memory/token dump."""
from pathlib import Path
import subprocess,ctypes,xml.etree.ElementTree as ET


def existing_sysmon_evidence(root: Path):
    buffer=ctypes.create_unicode_buffer(32768)
    ctypes.windll.kernel32.GetSystemDirectoryW(buffer,len(buffer))
    executable=Path(buffer.value)/'wevtutil.exe'
    query='*[System[(EventID=11 or EventID=10) and TimeCreated[timediff(@SystemTime)<=300000]]]'
    result=subprocess.run([str(executable),'qe','Microsoft-Windows-Sysmon/Operational','/q:'+query,
        '/f:xml','/c:150','/rd:true'],capture_output=True,text=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        return {'available':False,'note':'没有可读取的 Sysmon 日志；文件通知本身不提供写入进程身份','events':[]}
    content=result.stdout.strip()
    if not content:return {'available':True,'events':[]}
    try:
        document=ET.fromstring(content)
    except ET.ParseError:
        document=ET.fromstring('<Events>'+content+'</Events>')
    events=[];prefix=str(root.resolve()).lower()+'\\'
    for event in document.iter():
        if event.tag.split('}')[-1]!='Event':continue
        fields={n.attrib.get('Name',''):n.text or '' for n in event.iter() if n.tag.split('}')[-1]=='Data'}
        target=fields.get('TargetFilename') or fields.get('TargetImage','')
        if not target.lower().startswith(prefix):continue
        relative=target.lower()[len(prefix):]
        if relative.startswith(('steamapps\\','userdata\\','logs\\','appcache\\')):continue
        actor=fields.get('SourceImage') or fields.get('Image','')
        if actor.lower().startswith(prefix) and not actor.lower().startswith(prefix+'steamapps\\'):continue
        events.append({'target':target,'source_image':actor,'source_pid':fields.get('SourceProcessId') or fields.get('ProcessId',''),
                       'access':fields.get('GrantedAccess',''),'utc':fields.get('UtcTime','')})
    return {'available':True,'note':'来源线索，不等于已确认该进程为恶意软件；不自动删除外部游戏/MOD','events':events[:30]}
