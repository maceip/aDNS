#!/usr/bin/env python3
"""Exercise real CCF governance, transactions and receipts on a local virtual node.

No virtual quote is admitted as hardware evidence. This test uses a governed
operator grant to test the shared transaction boundary and exact signature path.
Run in the pinned CCF toolchain image, with /build writable and /src read-only.
"""
import base64
import datetime
import hashlib
import http.client
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import time
import uuid

import ccf.cose
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.x509.oid import NameOID

ROOT=pathlib.Path("/src")

def b64(data):return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
def jcs(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def cert(key,cn):
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)])
    now=datetime.datetime.now(datetime.timezone.utc)
    return x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1)).sign(key,hashes.SHA384())

class Client:
    def __init__(self,port,ca):
        self.port=port;self.context=ssl.create_default_context(cafile=str(ca));self.context.set_alpn_protocols(["http/1.1"])
    def request(self,method,path,body=None,content_type="application/json"):
        if body is not None and not isinstance(body,bytes):body=json.dumps(body).encode()
        conn=http.client.HTTPSConnection("127.0.0.1",self.port,context=self.context,timeout=15)
        try:
            conn.request(method,path,body,{"content-type":content_type});response=conn.getresponse();raw=response.read();headers=dict(response.getheaders())
            try:data=json.loads(raw)
            except (json.JSONDecodeError,UnicodeDecodeError):data=raw
            return response.status,{k.lower():v for k,v in headers.items()},data
        finally:conn.close()

def main():
    if "--quorum" in sys.argv and "--recovery" in sys.argv:raise ValueError("run quorum and disk recovery scenarios separately")
    work=pathlib.Path("/build/live-smoke-"+uuid.uuid4().hex[:12]);work.mkdir();os.chmod(work,0o700)
    member_key=ec.generate_private_key(ec.SECP384R1());member_cert=cert(member_key,"agentdns test member")
    keypem=member_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    certpem=member_cert.public_bytes(serialization.Encoding.PEM).decode();member_id=member_cert.fingerprint(hashes.SHA256()).hex()
    (work/"member_cert.pem").write_text(certpem)
    encryption=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    (work/"member_enc_pubk.pem").write_bytes(encryption.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    sys.path.insert(0, str(ROOT / "tools"))
    import packaged_constitution
    (work/"constitution.js").write_bytes(packaged_constitution.load(ROOT))
    config=json.loads((ROOT/"ccf/node.example.json").read_text());config["command"]["start"]["constitution_files"]=[str(work/"constitution.js")]
    if "--quorum" in sys.argv:
        config["network"]["rpc_interfaces"]["primary_rpc_interface"]["enabled_operator_features"]=["SnapshotRead","LedgerChunkRead"]
        config["network"]["rpc_interfaces"]["primary_rpc_interface"]["published_address"]="127.0.0.1:8000"
        config["network"]["node_to_node_interface"]["bind_address"]="127.0.0.1:8002"
    config["command"]["start"]["members"]=[{"certificate_file":str(work/"member_cert.pem"),"encryption_public_key_file":str(work/"member_enc_pubk.pem")}]
    config["node_certificate"]["initial_validity_days"]=1;config["command"]["start"]["initial_service_certificate_validity_days"]=1
    (work/"node.json").write_text(json.dumps(config));(work/"member_key.pem").write_text(keypem);os.chmod(work/"member_key.pem",0o600)
    log=open(work/"node.log","wb")
    process=subprocess.Popen(["/build/agentdns","--config",str(work/"node.json")],cwd=work,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,"CCF_PLATFORM_OVERRIDE":"Virtual"})
    try:
        for _ in range(200):
            if process.poll() is not None:raise RuntimeError((work/"node.log").read_text())
            if (work/"service_cert.pem").exists():break
            time.sleep(.1)
        ca=work/"service_cert.pem";public=Client(8000,ca);internal=Client(8001,ca)
        for _ in range(100):
            try:
                if public.request("GET","/node/state")[0]==200:break
            except (OSError,http.client.HTTPException):pass
            time.sleep(.1)
        def gov(path,body,msg_type,proposal=None):
            headers={"ccf.gov.msg.type":msg_type,"ccf.gov.msg.created_at":int(time.time())}
            if proposal:headers["ccf.gov.msg.proposal_id"]=proposal
            signed=ccf.cose.create_cose_sign1(b"" if body is None else json.dumps(body).encode(),keypem,certpem,headers)
            return public.request("POST",path+"?api-version=2024-07-01",signed,"application/cose")
        status,_,digest=gov(f"/gov/members/state-digests/{member_id}:update",None,"state_digest");assert status==200,(status,digest)
        status,_,body=gov(f"/gov/members/state-digests/{member_id}:ack",digest,"ack");assert status==204,(status,body)
        def propose(actions):
            status,_,created=gov("/gov/members/proposals:create",{"actions":actions},"proposal");assert status==200,(status,created)
            proposal=created["proposalId"]
            if created["proposalState"]!="Accepted":
                status,_,voted=gov(f"/gov/members/proposals/{proposal}/ballots/{member_id}:submit",{"ballot":"export function vote(proposal, proposer_id) { return true; }"},"ballot",proposal)
                assert status==200 and voted["proposalState"]=="Accepted",(status,voted)
        propose([{"name":"transition_service_to_open","args":{"next_service_identity":ca.read_text()}}])
        signer=ec.generate_private_key(ec.SECP256R1());spki=signer.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        now=int(time.time())
        grant={"grant_id":"smoke-operator","subject_spki_sha256":hashlib.sha256(spki).hexdigest(),"zones":["example.test."],"mailbox_domains":[],"service_hosts":[],"roles":[],"address_cidrs":[],"ports":[],"allowed_operations":["operator_records"],"acme_names":[],"operator_names":["example.test."],"operator_record_types":["TXT"],"attested_names":[],"attested_record_types":[],"max_lease_seconds":3600,"max_challenge_lifetime_seconds":1800,"valid_from":now-60,"valid_until":now+3600,"revoked":False}
        def rr(name,rtype,data):return {"name":name,"rclass":"In","rtype":rtype,"ttl":300,"rdata":{rtype:data}}
        base=[rr("example.test.","Soa",{"mname":"ns.example.test.","rname":"hostmaster.example.test.","serial":7,"refresh":60,"retry":30,"expire":600,"minimum":60}),rr("example.test.","Ns","ns.example.test."),rr("ns.example.test.","A","192.0.2.1")]
        metadata={"id":1,"origin":"example.test.","serial":7,"base_records":base,"signed_records":[],"signature_validity":600,"refresh_before":300,"last_signed_at":0,"earliest_signature_expiration":0,"maintenance_health":"initializing","ksk_dnskey_rdata":[]}
        propose([{"name":"adns_set_configuration","args":{"audience":"ccf://smoke","epoch":1,"last_time":now}},{"name":"adns_set_owner_grant","args":{"grant":grant}},{"name":"adns_create_zone","args":{"metadata":metadata}}])
        for _ in range(200):
            status,headers,body=internal.request("POST","/app/internal/maintenance",{})
            if status==200:break
            if status not in (404,503):raise AssertionError((status,body))
            time.sleep(.1)
        assert status==200,(status,body)
        assert headers.get("x-agentdns-commit-status")=="committed" and body["status"]=="committed",(headers,body)
        for path in ["maintenance","transfer-key","secondary/requests","secondary/response","axfr","udp"]:
            status,_,body=public.request("POST","/app/internal/"+path,{});assert status==403,(path,status,body)
        action={"operation":"operator_records","request_id":str(uuid.uuid4()),"audience":"ccf://smoke","grant_id":"smoke-operator","zone":"example.test.","signer_spki_der":b64(spki),"parameters":{"expected_serial":7,"mutations":[{"action":"replace","name":"example.test.","type":"TXT","ttl":300,"rdata_strings":["ccf-atomic-smoke"]}]}}
        status,_,nonce=public.request("POST","/app/service/nonce",{"action":action});assert status==200,(status,nonce)
        signed={"action":action,"nonce":nonce["nonce"],"nonce_expires_at":nonce["expires_at"],"intent_hash":nonce["intent_hash"]}
        signature=signer.sign(jcs(signed),ec.ECDSA(hashes.SHA256()));r,s=utils.decode_dss_signature(signature)
        signed["client_signature"]=b64(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
        lookup="/app/service/request?grant_id=smoke-operator&request_id="+action["request_id"]
        status,headers,pending_state=public.request("GET",lookup)
        assert status==200 and pending_state["status"]=="pending" and pending_state["phase"]=="awaiting_committed_result",(status,pending_state)
        assert headers.get("x-agentdns-commit-status")=="committed" and pending_state["observation_status"]=="committed"
        revoked=json.loads(json.dumps(grant));revoked["revoked"]=True
        propose([{"name":"adns_set_owner_grant","args":{"grant":revoked}}])
        status,headers,failure=public.request("POST","/app/zone/operator/records",signed)
        assert status==403 and headers.get("x-agentdns-commit-status")=="committed",(status,headers,failure)
        assert failure["status"]==failure["execution_state"]=="failed" and failure["observation_status"]=="committed"
        assert failure["observation_tx_id"]==failure["tx_id"]==headers["x-agentdns-transaction-id"]
        status,_,failed_state=public.request("GET",lookup)
        assert status==200 and failed_state["status"]=="failed" and failed_state["latest_observation"]["nonce"]==signed["nonce"],(status,failed_state)
        assert failed_state["latest_observation"]["signed_message_digest"]==hashlib.sha256(jcs({k:v for k,v in signed.items() if k!="client_signature"})).hexdigest()
        status,_,unchanged=public.request("GET","/app/zone/status?zone=example.test.")
        assert status==200 and unchanged["committed_state"]["serial"]==7,(status,unchanged)
        (work/"request-observations.json").write_text(json.dumps({"pending":pending_state,"failed_submit":failure,"failed_query":failed_state,"unchanged_serial":7},indent=2)+"\n")
        propose([{"name":"adns_set_owner_grant","args":{"grant":grant}}])
        status,headers,result=public.request("POST","/app/zone/operator/records",signed);assert status==200,(status,result)
        assert headers.get("x-agentdns-commit-status")=="committed" and result["status"]=="committed",(headers,result)
        txid=result["tx_id"]
        status,_,committed=public.request("GET","/app/tx?transaction_id="+txid);assert status==200 and committed["status"]=="Committed",(status,committed)
        status,_,retry=public.request("POST","/app/zone/operator/records",signed);assert status==200 and retry==result,(status,retry,result)
        status,_,reconciled=public.request("GET","/app/service/request?grant_id=smoke-operator&request_id="+action["request_id"]);assert status==200 and reconciled==result,(status,reconciled,result)
        altered=json.loads(json.dumps(signed));altered["action"]["parameters"]["mutations"][0]["rdata_strings"]=["changed"]
        altered["intent_hash"]=hashlib.sha256(jcs(altered["action"])).hexdigest();payload={k:v for k,v in altered.items() if k!="client_signature"}
        r,s=utils.decode_dss_signature(signer.sign(jcs(payload),ec.ECDSA(hashes.SHA256())));altered["client_signature"]=b64(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
        status,_,conflict=public.request("POST","/app/zone/operator/records",altered);assert status==409,(status,conflict)
        status,_,media=public.request("POST","/app/service/nonce",{},"text/plain");assert status==415,(status,media)
        status,headers,receipt=public.request("GET","/app/governance/ksk-receipt?zone=example.test.");assert status==200,(status,receipt)
        assert headers.get("x-agentdns-commit-status")=="committed"; (work/"ksk-receipt.json").write_text(json.dumps(receipt,indent=2))
        sys.path.insert(0,str(ROOT/"tools"));import verify_ksk_receipt
        verify_ksk_receipt.verify(receipt,ca.read_bytes())
        for field in ["owner_name","dnskey_rdata_hex","tx_id","proof"]:
            altered=json.loads(json.dumps(receipt))
            if field=="owner_name":altered[field]="attacker.test."
            elif field=="dnskey_rdata_hex":altered[field]=altered[field][:-2]+("00" if altered[field][-2:]!="00" else "01")
            elif field=="tx_id":altered[field]="9.999999"
            else:altered[field]["signature"]=b64(b"invalid-signature")
            try:verify_ksk_receipt.verify(altered,ca.read_bytes())
            except (ValueError,AssertionError,InvalidSignature):pass
            else:raise AssertionError("receipt tampering accepted: "+field)
        # DNS wire SOA query, exercise both RFC 8484 forms through the commit gate.
        packet=bytes.fromhex("123401000001000000000000")+b"\x07example\x04test\x00\x00\x06\x00\x01"
        for method,path,body in [("POST","/app/dns-query",packet),("GET","/app/dns-query?dns="+b64(packet),None)]:
            status,headers,answer=public.request(method,path,body,"application/dns-message");assert status==200 and isinstance(answer,bytes) and answer[:2]==b"\x12\x34",(status,answer)
            assert headers.get("x-agentdns-commit-status")=="committed"
        summary={"status":"passed","ccf_version":"7.0.15","platform":"Virtual (consensus test only)","request_reconciliation":"committed pending observation; globally committed403 after grant revocation; unchanged zone; exact original nonce succeeds after reauthorization; historical success preserved","operator_tx_id":txid,"receipt_tx_id":receipt["tx_id"],"artifacts":str(work)}
        if "--quorum" in sys.argv:
            from quorum import exercise
            summary["quorum"]=exercise(work,config,public,internal,ca,propose,signer,action,process)
        if "--recovery" in sys.argv:
            from recovery import exercise
            summary["disk_recovery"]=exercise(work,config,public,internal,ca,propose,signer,action,process,keypem,certpem,member_id,encryption,signed,result)
        (work/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
        print(json.dumps(summary,indent=2),flush=True)
    finally:
        process.terminate()
        try:process.wait(timeout=15)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        log.close()

if __name__=="__main__":main()
