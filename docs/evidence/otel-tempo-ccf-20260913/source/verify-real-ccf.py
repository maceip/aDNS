from pathlib import Path
import json,urllib.request,concurrent.futures,base64,re,time,hashlib
source=Path('.validation/otel-live-20260913-attempt3/results/proof');out=Path('.validation/otel-stack-20260913/real-ccf-verification-attempt3');out.mkdir()
expected={}
for phase in ['quorum','recovery']:
 for span in json.loads((source/phase/'spans.json').read_text()):expected.setdefault(span['trace_id'],[]).append(span)
assert len(expected)<=100

def ident(x,n):
 if not x:return None
 if re.fullmatch('[0-9a-f]{'+str(n)+'}',x):return x
 value=base64.b64decode(x,validate=True).hex();assert len(value)==n;return value

def attrs(xs):
 result={}
 for x in xs:
  v=x['value']
  if 'stringValue'in v:y=v['stringValue']
  elif 'intValue'in v:y=int(v['intValue'])
  elif 'boolValue'in v:y=v['boolValue']
  else:raise AssertionError(v)
  result[x['key']]=y
 return result

def fetch(trace):
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:13200/api/traces/'+trace,headers={'Accept':'application/json'}),timeout=8) as response:data=response.read(8*1024*1024)
 (out/(trace+'.json')).write_bytes(data);v=json.loads(data);found=[]
 for b in v['batches']:
  resource=attrs(b['resource']['attributes']);assert resource['service.name']=='agentdns-authority' and resource['service.version']=='0.1.0'
  for group in b['scopeSpans']:
   for s in group['spans']:
    assert ident(s['traceId'],32)==trace
    found.append({'trace_id':trace,'span_id':ident(s['spanId'],16),'parent_span_id':ident(s.get('parentSpanId'),16),'name':s['name'],'kind':({'SPAN_KIND_UNSPECIFIED':0,'SPAN_KIND_INTERNAL':1,'SPAN_KIND_SERVER':2,'SPAN_KIND_CLIENT':3,'SPAN_KIND_PRODUCER':4,'SPAN_KIND_CONSUMER':5}.get(s.get('kind'),s.get('kind',0))),'start_unix_ns':int(s['startTimeUnixNano']),'end_unix_ns':int(s['endTimeUnixNano']),'status':({'STATUS_CODE_UNSET':0,'STATUS_CODE_OK':1,'STATUS_CODE_ERROR':2}.get(s.get('status',{}).get('code'),s.get('status',{}).get('code',0))),'attributes':attrs(s.get('attributes',[])),'links':[{'trace_id':ident(link['traceId'],32),'span_id':ident(link['spanId'],16)} for link in s.get('links',[])]})
 byid={s['span_id']:s for s in found};assert len(byid)==len(found)==len(expected[trace]),(trace,len(found),len(expected[trace]))
 for want in expected[trace]:
  want=dict(want);want['parent_span_id']=want['parent_span_id'] or None;want['attributes']={k:v for k,v in want['attributes'].items() if k not in ['dns.zone','error.type']}
  got=byid[want['span_id']];assert got==want,(trace,want,got)
 return {'trace_id':trace,'spans':len(found),'links':sum(len(s['links']) for s in found)}
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(fetch,expected))
record={'status':'passed','claim':'independent Tempo comparison to actual captured Virtual CCF quorum/recovery OTLP; no native hardware trace claim','trace_count':len(results),'span_count':sum(x['spans'] for x in results),'link_count':sum(x['links'] for x in results),'checked_fields':['exact trace/span/parent IDs','exact names/kinds/start/end/status','expected bounded attribute projection','exact original-transaction async links'],'traces':results,'source_sha256':{str(source/phase/'spans.json'):hashlib.sha256((source/phase/'spans.json').read_bytes()).hexdigest() for phase in ['quorum','recovery']},'finished_unix':time.time()}
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k not in ['traces','source_sha256']},indent=2))
