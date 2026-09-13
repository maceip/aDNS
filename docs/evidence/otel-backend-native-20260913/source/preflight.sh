#!/bin/sh
set -eu
python3 - <<'PY'
import hashlib,json,pathlib,subprocess,time,os,socket,struct
c='agentdns-secondary';v=json.loads(subprocess.check_output(['docker','inspect',c],timeout=15))[0]
expected='553c55cd4980182a7e5ca3b56f4cc8ccb582162c57e4c123d5fb367d72cbbb4d';assert v['Id']==expected and v['State']['Running'] and v['RestartCount']==0
pid=v['State']['Pid'];stat=pathlib.Path(f'/proc/{pid}/stat').read_text();ticks=int(stat[stat.rfind(')')+2:].split()[19]);assert ticks==38227
cfg=pathlib.Path('/opt/agentdns-secondary/config/named.conf');sha=hashlib.sha256(cfg.read_bytes()).hexdigest();assert sha=='1ed3e45c29b882fa164dc51d48c310064a4a7ccd15448c5c2bce200b7463e3a6'
ports=v['NetworkSettings']['Ports'];assert '53/tcp' in ports and '53/udp' in ports
listeners=subprocess.check_output(['ss','-H','-lnt'],timeout=10,text=True)
for line in listeners.splitlines():
 address=line.split()[3]
 assert address.rsplit(':',1)[-1] not in ('4318','13000','13200'),address
fs=os.statvfs('/var/lib/docker');free=fs.f_bavail*fs.f_frsize;assert free>=8*1024**3
memory={line.split(':',1)[0]:int(line.split()[1])*1024 for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemAvailable:','MemTotal:'))};assert memory['MemAvailable']>=3*1024**3
def query(tcp):
 ident=os.urandom(2);question=b'\x07example\x04test\x00'+struct.pack('!HH',6,1);packet=ident+struct.pack('!HHHHH',0,1,0,0,0)+question;deadline=time.monotonic()+4
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
  s.settimeout(4);s.connect(('10.71.0.4',53))
  if tcp:
   s.sendall(struct.pack('!H',len(packet))+packet)
   def read(size):
    data=b''
    while len(data)<size:
     remain=deadline-time.monotonic();assert remain>0;s.settimeout(remain);part=s.recv(size-len(data));assert part;data+=part
    return data
   size=struct.unpack('!H',read(2))[0];assert 12<=size<=4096;answer=read(size)
  else:s.send(packet);answer=s.recv(4097);assert len(answer)<=4096
 assert answer[:2]==ident and len(answer)>=12
 _,flags,qd,an,ns,ar=struct.unpack('!HHHHHH',answer[:12]);assert flags&0x8000 and flags&0x0400 and flags&15==0 and qd==1 and an>=1
 assert answer[12:12+len(question)]==question
 def skip(offset):
  for _ in range(128):
   assert offset<len(answer);n=answer[offset];offset+=1
   if n&0xc0==0xc0:assert offset<len(answer);return offset+1
   assert n<=63 and offset+n<=len(answer)
   if n==0:return offset
   offset+=n
  raise RuntimeError('DNS name bound')
 offset=skip(12+len(question));kind,klass,ttl,size=struct.unpack('!HHIH',answer[offset:offset+10]);offset+=10;assert kind==6 and klass==1 and offset+size<=len(answer)
 cursor=skip(skip(offset));assert cursor+20==offset+size;serial=struct.unpack('!I',answer[cursor:cursor+4])[0]
 return {'authoritative':True,'rcode':0,'serial':serial,'ttl':ttl,'answer_bytes':len(answer)}
answers={'udp':query(False),'tcp':query(True)}
assert (answers['tcp']['serial']-answers['udp']['serial'])%(2**32) in (0,1)
compose=subprocess.run(['docker','compose','version','--short'],capture_output=True,text=True,timeout=10)
print(json.dumps({'status':'passed','checked_unix':time.time(),'bind_container_id':v['Id'],'bind_image_id':v['Image'],'bind_pid':pid,'bind_start_ticks':ticks,'bind_restart_count':v['RestartCount'],'bind_started_at':v['State']['StartedAt'],'bind_config_sha256':sha,'bind_ports':ports,'disk_available_bytes':free,'memory_bytes':memory,'port_conflicts':False,'soa':answers,'compose_available':compose.returncode==0,'compose_version':compose.stdout.strip(),'docker_version':subprocess.check_output(['docker','version','--format','{{.Server.Version}}'],timeout=10,text=True).strip()}))
PY
