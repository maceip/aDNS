"""Exercise CCF disaster recovery from disk using an actual member share."""
import hashlib
import hmac
import json
import os
import pathlib
import struct
import subprocess
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


def exercise(work,config,public,internal,ca,propose,signer,template,primary,member_key_pem,member_cert_pem,member_id,encryption,original_request,original_result):
    from live_smoke import Client,b64,jcs
    import verify_ksk_receipt
    import durable_recovery
    import ccf_control
    secret=bytes([83])*32;key_name="recovery.example.test."
    propose([{"name":"adns_set_transfer","args":{"key_name":key_name,"endpoint":"127.0.0.1:55354","zones":["example.test."],"secret_sha256":hashlib.sha256(secret).hexdigest()}}])
    for _ in range(100):
        status,_,body=internal.request("POST","/app/internal/transfer-key",{"key_name":key_name,"secret_base64url":b64(secret),"zones":["example.test."]})
        if status==200:break
        time.sleep(.05)
    assert status==200,(status,body)
    status,_,before=public.request("GET","/app/governance/ksk-receipt?zone=example.test.");assert status==200
    verify_ksk_receipt.verify(before,ca.read_bytes())
    pending_action=json.loads(json.dumps(template));pending_action["request_id"]=str(uuid.uuid4())
    pending_action["parameters"]["expected_serial"]=8;pending_action["parameters"]["mutations"][0]["rdata_strings"]=["after-disk-recovery"]
    status,_,nonce=public.request("POST","/app/service/nonce",{"action":pending_action});assert status==200
    pending={"action":pending_action,"nonce":nonce["nonce"],"nonce_expires_at":nonce["expires_at"],"intent_hash":nonce["intent_hash"]}
    r,s=utils.decode_dss_signature(signer.sign(jcs(pending),ec.ECDSA(hashes.SHA256())))
    pending["client_signature"]=b64(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
    rejected_action=json.loads(json.dumps(template));rejected_action["request_id"]=str(uuid.uuid4())
    rejected_action["parameters"]["expected_serial"]=999
    status,_,rejected_nonce=public.request("POST","/app/service/nonce",{"action":rejected_action});assert status==200
    rejected={"action":rejected_action,"nonce":rejected_nonce["nonce"],"nonce_expires_at":rejected_nonce["expires_at"],"intent_hash":rejected_nonce["intent_hash"]}
    r,s=utils.decode_dss_signature(signer.sign(jcs(rejected),ec.ECDSA(hashes.SHA256())))
    rejected["client_signature"]=b64(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
    status,headers,failure=public.request("POST","/app/zone/operator/records",rejected)
    assert status==409 and headers.get("x-agentdns-commit-status")=="committed",(status,failure)
    # CCF has confirmed the nonce is globally committed before disk recovery.
    primary.terminate();primary.wait(timeout=15)
    # Exercise the operator helper on the complete stopped ledger, including
    # the unsuffixed current chunk; never recover against the backup itself.
    backup=work.parent/(work.name+"-durable-backup")
    durable_recovery.archive(work,backup,ca.read_bytes(),before,"example.test.",
        {"kind":"stopped-local-CCF-test","returncode":primary.returncode})
    recovered=work/"disk-recovered"
    durable_recovery.restore_copy(backup,recovered)
    cfg=durable_recovery.recovery_config(config,str(backup/"previous-service.pem"),"ledger","snapshots")
    (recovered/"node.json").write_text(json.dumps(cfg));log=open(recovered/"node.log","wb")
    node=subprocess.Popen(["/build/agentdns","--config",str(recovered/"node.json")],cwd=recovered,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,"CCF_PLATFORM_OVERRIDE":"Virtual"})
    try:
        for _ in range(300):
            if node.poll() is not None:raise RuntimeError((recovered/"node.log").read_text()[-8000:])
            if (recovered/"service_cert.pem").is_file():break
            time.sleep(.1)
        current_ca=recovered/"service_cert.pem"
        assert current_ca.read_bytes()!=ca.read_bytes(),"recovery must create a fresh service identity"
        client=Client(8000,current_ca)
        for _ in range(300):
            try:
                status,_,state=client.request("GET","/node/state")
                if status==200 and state["state"]=="PartOfPublicNetwork":break
            except OSError:pass
            time.sleep(.1)
        assert status==200 and state["state"]=="PartOfPublicNetwork",(status,state)
        recovery_client=ccf_control.Client("https://127.0.0.1:8000",None,current_ca)
        recovery_governance=ccf_control.Governance(recovery_client,work/"member_key.pem",work/"member_cert.pem")
        durable_recovery.accept_recovery(recovery_client,recovery_governance,ca.read_bytes(),current_ca.read_bytes())
        submitted=durable_recovery.submit_share(recovery_client,recovery_governance,encryption)
        assert submitted["submittedCount"]==1
        for _ in range(300):
            status,_,state=client.request("GET","/app/zone/status?zone=example.test.")
            if status==200:break
            time.sleep(.1)
        assert status==200 and state["committed_state"]["serial"]==8,(status,state)
        status,headers,recovered_failure=client.request("GET","/app/service/request?grant_id=smoke-operator&request_id="+rejected_action["request_id"])
        assert status==200 and headers.get("x-agentdns-commit-status")=="committed" and recovered_failure["status"]=="failed",(status,recovered_failure)
        assert recovered_failure["latest_observation"]["signed_message_digest"]==failure["signed_message_digest"]
        assert recovered_failure["latest_observation"]["nonce"]==rejected["nonce"] and recovered_failure["latest_observation"]["http_status"]==409
        (work/"recovered-request-observation.json").write_text(json.dumps(recovered_failure,indent=2)+"\n")
        status,_,history=client.request("POST","/app/zone/operator/records",original_request)
        assert status==200 and history==original_result,(status,history,original_result)
        status,_,after=client.request("GET","/app/governance/ksk-receipt?zone=example.test.")
        assert status==200 and after["dnskey_rdata_hex"]==before["dnskey_rdata_hex"],(status,after)
        continuity=durable_recovery.verify_continuity(before,ca.read_bytes(),after,current_ca.read_bytes(),"example.test.")
        assert continuity["exact_dnskey_rdata_preserved"]
        durable_recovery.verify_archive(backup)
        status,headers,result=client.request("POST","/app/zone/operator/records",pending)
        assert status==200 and result["zone_serial"]==9 and headers.get("x-agentdns-commit-status")=="committed",(status,result)
        status,_,retry=client.request("POST","/app/zone/operator/records",pending)
        assert status==200 and retry==result,"recovered nonce retry changed the committed result"
        def wire(name):return b"".join(bytes([len(label)])+label.encode() for label in name.rstrip(".").split("."))+b"\x00"
        query=struct.pack("!6H",401,0,1,0,0,0)+wire("example.test.")+struct.pack("!HH",252,1)
        clock=int(time.time()).to_bytes(6,"big");algorithm=wire("hmac-sha256.");name=wire(key_name)
        variables=name+struct.pack("!HI",255,0)+algorithm+clock+struct.pack("!HHH",300,0,0)
        mac=hmac.new(secret,query+variables,hashlib.sha256).digest()
        rdata=algorithm+clock+struct.pack("!HH",300,len(mac))+mac+struct.pack("!HHH",401,0,0)
        packet=query[:10]+b"\x00\x01"+query[12:]+name+struct.pack("!HHIH",250,255,0,len(rdata))+rdata
        status,headers,frames=Client(8001,current_ca).request("POST","/app/internal/axfr",packet,"application/dns-message")
        assert status==200 and headers.get("x-agentdns-commit-status")=="committed" and isinstance(frames,bytes) and len(frames)>2,"TSIG secret not recovered"
        (work/"recovery-ksk-receipt.json").write_text(json.dumps(after,indent=2)+"\n")
        (work/"recovery-service-cert.pem").write_bytes(current_ca.read_bytes())
        return {"method":"durable_recovery helper: immutable complete ledger/snapshot archive, copied Recover process, actual member acceptance and RSA-decrypted share","ksk":"exact DNSKEY RDATA preserved; new identity receipt verified","tsig":"original private key authenticates AXFR after recovery","history":"original committed result and transaction ID preserved", "failed_observation":"globally committed authenticated rejection and its live nonce survive disk recovery","nonce":"pre-recovery unconsumed nonce commits exactly once after recovery","original_tx_id":original_result["tx_id"],"recovered_receipt_tx_id":after["tx_id"],"post_recovery_tx_id":result["tx_id"]}
    finally:
        node.terminate()
        try:node.wait(timeout=15)
        except subprocess.TimeoutExpired:node.kill();node.wait()
        log.close()
