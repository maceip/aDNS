"""Actual VM TLS/auth/backend and unchanged BIND checks; public result only."""
import base64, hashlib, http.client, json, os, pathlib, socket, ssl, subprocess, threading, time
ROOT=pathlib.Path('/opt/agentdns-observability');STATE=pathlib.Path('/var/lib/agentdns-observability');OUT=STATE/'evidence'
def call(port,path,method='GET',body=None,headers=None,tls=False,trust=True):
    retained=[]
    def close():
        for sock in retained:
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
    timer=threading.Timer(5,close);timer.daemon=True;timer.start()
    conn=http.client.HTTPConnection('10.71.0.4' if tls else '127.0.0.1',port,timeout=5)
    version=None
    try:
        sock=socket.create_connection((conn.host,port),timeout=4);retained.append(sock)
        if tls:
            ctx=ssl.create_default_context(cafile=str(ROOT/'exporter-public-ca.pem')) if trust else ssl.create_default_context()
            ctx.minimum_version=ssl.TLSVersion.TLSv1_3
            sock=ctx.wrap_socket(sock,server_hostname='20.166.33.141',do_handshake_on_connect=False);retained.append(sock);sock.do_handshake();version=sock.version()
        conn.sock=sock;conn.request(method,path,body=body,headers=headers or {});response=conn.getresponse();data=response.read(1048577)
        if len(data)>1048576:raise RuntimeError('HTTP response bound')
        return response.status,data,version
    finally: conn.close();close();timer.cancel();timer.join()
def attr(k,v):return {'key':k,'value':{'stringValue':v}}
def main():
    started=time.time();auth=os.environ.pop('AGENTDNS_SMOKE_AUTHORIZATION');deadline=time.monotonic()+70
    while True:
        try:
            c,_,_=call(4318,'/v1/traces','POST',b'{"resourceSpans":[]}',{'Content-Type':'application/json','Authorization':auth},True)
            t,_,_=call(13200,'/ready');g,_,_=call(13000,'/api/health')
            if (c,t,g)==(200,200,200):break
        except (OSError,http.client.HTTPException):pass
        if time.monotonic()>deadline:raise RuntimeError('backend readiness deadline')
        time.sleep(2)
    missing,_,_=call(4318,'/v1/traces','POST',b'{}',{'Content-Type':'application/json'},True)
    wrong,_,_=call(4318,'/v1/traces','POST',b'{}',{'Content-Type':'application/json','Authorization':'Basic '+base64.b64encode(b'agentdns:deliberately-wrong').decode()},True)
    assert missing==wrong==401
    try:call(4318,'/v1/traces','POST',b'{}',{'Content-Type':'application/json','Authorization':auth},True,False)
    except ssl.SSLCertVerificationError:untrusted=True
    else:raise RuntimeError('untrusted CA accepted')
    trace=os.urandom(16).hex();span=os.urandom(8).hex();now=time.time_ns();sentinel='private-canary-'+os.urandom(10).hex()
    payload={'resourceSpans':[{'resource':{'attributes':[attr('service.name','agentdns-otel-smoke'),attr('deployment.environment','native-backend-validation'),attr('service.namespace','agentdns'),attr('service.instance.id','vm-backend-smoke'),attr('password',sentinel)]},'scopeSpans':[{'scope':{'name':sentinel},'spans':[{'traceId':trace,'spanId':span,'name':'agentdns.otel.smoke','kind':1,'startTimeUnixNano':str(now),'endTimeUnixNano':str(now+1000000),'attributes':[attr('evidence',sentinel),attr('authorization',sentinel),{'key':'http.response.status_code','value':{'intValue':'200'}}],'status':{'code':1,'message':sentinel},'events':[{'timeUnixNano':str(now),'name':sentinel}]}]}]}]}
    (OUT/'synthetic-input.json').write_text(json.dumps(payload,indent=2)+'\n')
    code,body,version=call(4318,'/v1/traces','POST',json.dumps(payload).encode(),{'Content-Type':'application/json','Authorization':auth},True);assert code==200 and version=='TLSv1.3'
    (OUT/'otlp-response.json').write_bytes(body);deadline=time.monotonic()+35
    while True:
        code,data,_=call(13200,'/api/traces/'+trace,headers={'Accept':'application/json'})
        if code==200:break
        if time.monotonic()>deadline:raise RuntimeError('trace persistence deadline')
        time.sleep(1)
    (OUT/'tempo-trace.json').write_bytes(data);assert sentinel.encode() not in data
    j=json.loads(data);spans=[s for b in j['batches'] for scope in b['scopeSpans'] for s in scope['spans']];assert len(spans)==1
    found=spans[0];actual=found['traceId'];assert actual==trace or base64.b64decode(actual).hex()==trace
    assert found['name']=='agentdns.otel.smoke'
    resources={a['key']:a['value'] for b in j['batches'] for a in b['resource']['attributes']}
    assert resources['service.version']=={'stringValue':'0.1.0'} and resources['service.instance.id']=={'stringValue':'vm-backend-smoke'}
    password=(STATE/'private'/'grafana-password').read_text().strip();g_auth='Basic '+base64.b64encode(('agentdns:'+password).encode()).decode();del password
    for path,name in [('/api/user','grafana-user.json'),('/api/datasources','grafana-datasources.json'),('/api/dashboards/uid/agentdns-architecture','grafana-dashboard.json'),('/api/datasources/proxy/uid/agentdns-tempo/api/traces/'+trace,'grafana-trace.json')]:
        code,data,_=call(13000,path,headers={'Authorization':g_auth,'Accept':'application/json'});assert code==200,(path,code);assert sentinel.encode() not in data;(OUT/name).write_bytes(data)
    del auth,g_auth
    preflight=(ROOT/'preflight.sh').read_text()
    preflight=preflight.replace("assert address.rsplit(':',1)[-1] not in ('4318','13000','13200'),address","pass # Backend ports are now intentionally occupied; BIND checks remain exact.")
    after=json.loads(subprocess.check_output(['sh','-c',preflight],timeout=30));assert after['status']=='passed'
    actual={}
    for name in ['otel-collector','tempo','loki','grafana']:
        v=json.loads(subprocess.check_output(['docker','inspect',f'agentdns-otel-native-validation-{name}-1'],timeout=10))[0]
        assert v['State']['Running'] and v['RestartCount']==0
        image=json.loads(subprocess.check_output(['docker','image','inspect',v['Image']],timeout=10))[0]
        actual[name]={'container_id':v['Id'],'image_id':v['Image'],'image_reference':v['Config']['Image'],'repo_digests':image['RepoDigests'],'architecture':image['Architecture'],'restart_count':v['RestartCount'],'started_at':v['State']['StartedAt'],'ports':v['NetworkSettings']['Ports'],'memory_limit_bytes':v['HostConfig']['Memory'],'nano_cpus':v['HostConfig']['NanoCpus'],'pids_limit':v['HostConfig']['PidsLimit']}
    print(json.dumps({'status':'passed','claim':'synthetic native-VM backend transport/privacy smoke; no native CCF assertion','started_unix':started,'finished_unix':time.time(),'trace_id':trace,'span_id':span,'tls':version,'missing_authorization_status':missing,'wrong_authorization_status':wrong,'untrusted_ca_rejected':untrusted,'grafana_authenticated_resources':True,'bind_after':after,'containers':actual}))
if __name__=='__main__':main()
