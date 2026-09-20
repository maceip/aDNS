"""Real three-node CCF failure test. Virtual nodes test consensus, not hardware."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import VALIDATION_DOMAIN
import base64
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import threading
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


def exercise(work, config, public, internal, ca, propose, signer, template, primary):
    from live_smoke import Client, b64, jcs

    processes=[]
    logs=[]
    requests=[]
    relays=[]

    class PeerRelay:
        """Drop links before pausing peers; SIGSTOP alone buffers TCP writes."""
        def __init__(self, listen_port, target_port):
            self.blocked=threading.Event();self.closed=threading.Event()
            self.lock=threading.Lock();self.sockets=set();self.target=target_port
            self.listener=socket.socket();self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            self.listener.bind(("127.0.0.1",listen_port));self.listener.listen(16);self.listener.settimeout(.1)
            threading.Thread(target=self.accept,daemon=True).start()
        def close_socket(self, sock):
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            sock.close()
            with self.lock:self.sockets.discard(sock)
        def pump(self, source, destination):
            try:
                while not self.blocked.is_set() and not self.closed.is_set():
                    data=source.recv(65536)
                    if not data:break
                    destination.sendall(data)
            except OSError:pass
            finally:self.close_socket(source);self.close_socket(destination)
        def accept(self):
            while not self.closed.is_set():
                try:incoming,_=self.listener.accept()
                except (OSError,TimeoutError):continue
                if self.blocked.is_set():incoming.close();continue
                try:outgoing=socket.create_connection(("127.0.0.1",self.target),timeout=1);outgoing.settimeout(None)
                except OSError:incoming.close();continue
                with self.lock:self.sockets.update((incoming,outgoing))
                if self.blocked.is_set():self.close_socket(incoming);self.close_socket(outgoing);continue
                threading.Thread(target=self.pump,args=(incoming,outgoing),daemon=True).start()
                threading.Thread(target=self.pump,args=(outgoing,incoming),daemon=True).start()
        def partition(self):
            self.blocked.set()
            with self.lock:sockets=list(self.sockets)
            for sock in sockets:self.close_socket(sock)
        def restore(self):self.blocked.clear()
        def close(self):self.closed.set();self.partition();self.listener.close()

    class Pending:
        def __init__(self, client, method, path, body=None, content_type="application/json"):
            self.result=None;self.error=None;self.done=threading.Event()
            def run():
                try:self.result=client.request(method,path,body,content_type)
                except Exception as error:self.error=error
                finally:self.done.set()
            self.thread=threading.Thread(target=run,daemon=True);self.thread.start();requests.append(self)
        def committed(self,expected_status=200):
            assert self.done.wait(15),"response remained pending after quorum restored"
            assert self.error is None,self.error
            status,headers,body=self.result
            assert status==expected_status and headers.get("x-agentdns-commit-status")=="committed",self.result
            return body

    def signed_action(serial, text):
        action=json.loads(json.dumps(template));action["request_id"]=str(uuid.uuid4())
        action["parameters"]["expected_serial"]=serial
        action["parameters"]["mutations"][0]["rdata_strings"]=[text]
        status,_,nonce=public.request("POST","/app/service/nonce",{"action":action});assert status==200,(status,nonce)
        request={"action":action,"nonce":nonce["nonce"],"nonce_expires_at":nonce["expires_at"],"intent_hash":nonce["intent_hash"]}
        r,s=utils.decode_dss_signature(signer.sign(jcs(request),ec.ECDSA(hashes.SHA256())))
        request["client_signature"]=b64(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
        return request

    def wire(name):return b"".join(bytes([len(label)])+label.encode() for label in name.rstrip(".").split("."))+b"\x00"

    def tsig_query(qtype):
        packet=struct.pack("!6H",321,0,1,0,0,0)+wire((VALIDATION_DOMAIN + '.'))+struct.pack("!HH",qtype,1)
        clock=int(time.time()).to_bytes(6,"big");algorithm=wire("hmac-sha256.");name=wire(('quorum.' + VALIDATION_DOMAIN + '.'))
        variables=name+struct.pack("!HI",255,0)+algorithm+clock+struct.pack("!HHH",300,0,0)
        mac=hmac.new(bytes([71])*32,packet+variables,hashlib.sha256).digest()
        rdata=algorithm+clock+struct.pack("!HH",300,len(mac))+mac+struct.pack("!HHH",321,0,0)
        return packet[:10]+b"\x00\x01"+packet[12:]+name+struct.pack("!HHIH",250,255,0,len(rdata))+rdata

    try:
        # Admit peers through the actual consortium action; never bypass CCF
        # node authentication or reconfiguration when constructing the test.
        for index in (1,2):
            peer=work/f"peer{index}";peer.mkdir()
            cfg=json.loads(json.dumps(config));base=8000+index*10
            relay=PeerRelay(base+102,base+2);relays.append(relay)
            cfg["network"]["node_to_node_interface"]={"bind_address":f"127.0.0.1:{base+2}","published_address":f"127.0.0.1:{base+102}"}
            cfg["network"]["rpc_interfaces"]["primary_rpc_interface"]["bind_address"]=f"127.0.0.1:{base}"
            cfg["network"]["rpc_interfaces"]["primary_rpc_interface"]["published_address"]=f"127.0.0.1:{base}"
            cfg["network"]["rpc_interfaces"]["agentdns-internal"]["bind_address"]=f"127.0.0.1:{base+1}"
            cfg["command"]={"type":"Join","service_certificate_file":str(ca),"join":{"retry_timeout":"100ms","target_rpc_address":"127.0.0.1:8000"}}
            (peer/"node.json").write_text(json.dumps(cfg));log=open(peer/"node.log","wb");logs.append(log)
            process=subprocess.Popen(["/build/agentdns","--config",str(peer/"node.json")],cwd=peer,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,"CCF_PLATFORM_OVERRIDE":"Virtual"});processes.append(process)
            pending=None
            for _ in range(200):
                if process.poll() is not None:raise RuntimeError((peer/"node.log").read_text())
                status,_,nodes=public.request("GET",f"/node/network/nodes?port={base}")
                if status==200 and nodes["nodes"]:
                    pending=nodes["nodes"][0];break
                time.sleep(.1)
            assert pending is not None,("peer did not join",index)
            propose([{"name":"transition_node_to_trusted","args":{"node_id":pending["node_id"],"valid_from":datetime.datetime.now(datetime.timezone.utc).isoformat(),"validity_period_days":1}}])
            client=Client(base,ca)
            for _ in range(200):
                try:
                    status,_,value=client.request("GET",('/app/zone/status?zone=' + VALIDATION_DOMAIN + '.'))
                    if status==200:break
                except OSError:pass
                time.sleep(.1)
            assert status==200,(status,value)
        assert len(public.request("GET","/node/config")[2])==3
        import importlib.util
        spec=importlib.util.spec_from_file_location("supervisor",pathlib.Path(__file__).resolve().parents[1]/"run.py")
        supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor)
        provision=json.dumps({"key_name":('quorum.' + VALIDATION_DOMAIN + '.'),"secret_base64url":b64(bytes([71])*32),"zones":[(VALIDATION_DOMAIN + '.')]}).encode()
        assert not supervisor.provision_transfer_secret("127.0.0.1:8001",ca,provision)
        propose([{"name":"adns_set_transfer","args":{"key_name":('quorum.' + VALIDATION_DOMAIN + '.'),"endpoint":"127.0.0.1:55353","zones":[(VALIDATION_DOMAIN + '.')],"secret_sha256":hashlib.sha256(bytes([71])*32).hexdigest()}}])
        for _ in range(100):
            status,_,result=internal.request("POST","/app/internal/transfer-key",{"key_name":('quorum.' + VALIDATION_DOMAIN + '.'),"secret_base64url":b64(bytes([71])*32),"zones":[(VALIDATION_DOMAIN + '.')]})
            if status==200:break
            time.sleep(.05)
        assert status==200,(status,result)
        assert supervisor.provision_transfer_secret("127.0.0.1:8001",ca,provision)
        status,_,original_ksk=public.request("GET",('/app/governance/ksk-receipt?zone=' + VALIDATION_DOMAIN + '.'))
        assert status==200
        first=signed_action(8,"quorum-restored")
        rejected=signed_action(999,"authenticated-failure-quorum")
        for relay in relays:relay.partition()
        for process in processes:process.send_signal(signal.SIGSTOP)
        mutation=Pending(public,"POST","/app/zone/operator/records",first)
        rejected_write=Pending(public,"POST","/app/zone/operator/records",rejected)
        time.sleep(.25)
        # All successful snapshots and authenticated failed observations wait
        # for global commitment; no tentative result/diagnostic may escape.
        reads=[
            Pending(public,"GET","/app/service/request?grant_id=smoke-operator&request_id="+first["action"]["request_id"]),
            Pending(public,"GET",('/app/zone/status?zone=' + VALIDATION_DOMAIN + '.')),
            Pending(public,"GET",('/app/governance/ksk-receipt?zone=' + VALIDATION_DOMAIN + '.')),
            Pending(public,"POST","/app/dns-query",tsig_query(6),"application/dns-message"),
            Pending(internal,"POST","/app/internal/axfr",tsig_query(252),"application/dns-message"),
            Pending(internal,"POST","/app/internal/udp",tsig_query(6),"application/dns-message"),
            Pending(internal,"POST","/app/internal/secondary/requests",{}),
            Pending(public,"GET","/app/service/request?grant_id=smoke-operator&request_id="+rejected["action"]["request_id"]),
        ]
        time.sleep(1)
        assert not mutation.done.is_set(),("tentative mutation escaped",mutation.result,mutation.error)
        assert not rejected_write.done.is_set(),("tentative failed metadata escaped",rejected_write.result,rejected_write.error)
        for item in reads:assert not item.done.is_set(),("tentative read/output escaped",item.result,item.error)
        for relay in relays:relay.restore()
        for process in processes:process.send_signal(signal.SIGCONT)
        committed=mutation.committed()
        observations=[item.committed() for item in reads]
        failed=rejected_write.committed(409)
        assert failed["execution_state"]=="failed" and failed["observation_status"]=="committed"
        assert observations[-1]["status"]=="failed" and observations[-1]["observation_status"]=="committed"
        assert committed["zone_serial"]==9
        # Withhold the next write from both peers, then lose the primary. The
        # majority elects a replacement from the committed history alone.
        rolled_back=signed_action(9,"must-never-be-published")
        failed_rollback=signed_action(999,"failed-observation-must-not-publish")
        for relay in relays:relay.partition()
        for process in processes:process.send_signal(signal.SIGSTOP)
        lost=Pending(public,"POST","/app/zone/operator/records",rolled_back)
        lost_failure=Pending(public,"POST","/app/zone/operator/records",failed_rollback)
        time.sleep(.25)
        read_lost=Pending(public,"GET","/app/service/request?grant_id=smoke-operator&request_id="+rolled_back["action"]["request_id"])
        read_lost_failure=Pending(public,"GET","/app/service/request?grant_id=smoke-operator&request_id="+failed_rollback["action"]["request_id"])
        time.sleep(.5)
        assert not lost_failure.done.is_set() and not read_lost_failure.done.is_set(),"tentative failure was exposed"
        assert not lost.done.is_set() and not read_lost.done.is_set(),"rollback candidate was exposed"
        primary.kill();primary.wait(timeout=15)
        for relay in relays:relay.restore()
        for process in processes:process.send_signal(signal.SIGCONT)
        replacement=None
        for _ in range(250):
            for port in (8010,8020):
                client=Client(port,ca)
                try:
                    status,_,info=client.request("GET","/node/network/nodes/self")
                    if status==200 and info["primary"]:replacement=client;break
                except OSError:pass
            if replacement is not None:break
            time.sleep(.1)
        assert replacement is not None,"surviving quorum did not elect primary"
        status,_,missing=replacement.request("GET","/app/service/request?grant_id=smoke-operator&request_id="+rolled_back["action"]["request_id"])
        assert status==200 and missing["status"]=="pending" and missing["phase"]=="awaiting_committed_result",(status,missing)
        status,_,rolled_failure=replacement.request("GET","/app/service/request?grant_id=smoke-operator&request_id="+failed_rollback["action"]["request_id"])
        assert status==200 and rolled_failure["status"]=="pending" and "signed_message_digest" not in rolled_failure["latest_observation"],(status,rolled_failure)
        status,_,state=replacement.request("GET",('/app/zone/status?zone=' + VALIDATION_DOMAIN + '.'))
        assert status==200 and state["committed_state"]["serial"]==9,(status,state)
        # The nonce consumed by the discarded write is still available in the
        # surviving history, and exact retry can commit once on the new leader.
        status,headers,result=replacement.request("POST","/app/zone/operator/records",rolled_back)
        assert status==200 and result["zone_serial"]==10 and headers.get("x-agentdns-commit-status")=="committed",(status,result)
        status,_,recovered_ksk=replacement.request("GET",('/app/governance/ksk-receipt?zone=' + VALIDATION_DOMAIN + '.'))
        assert status==200 and recovered_ksk["dnskey_rdata_hex"]==original_ksk["dnskey_rdata_hex"],"KSK changed across primary loss"
        import verify_ksk_receipt
        verify_ksk_receipt.verify(recovered_ksk,ca.read_bytes())
        status,headers,frames=Client(replacement.port+1,ca).request("POST","/app/internal/axfr",tsig_query(252),"application/dns-message")
        assert status==200 and headers.get("x-agentdns-commit-status")=="committed" and isinstance(frames,bytes) and len(frames)>2,"TSIG private key unavailable after primary loss"
        return {"nodes":3,"stalled_output_paths":10,"transport_partition":"relay links closed before peer pause; no buffered tentative replication","quorum_restore":"committed","primary_loss":"uncommitted success and failed-attempt metadata absent; both committed nonces reconcile pending; consumed nonce rolled back", "failed_observations":"HTTP409 metadata and its GET blocked without quorum; committed failure preserves execution_state; rolled-back diagnostic absent on replacement","replicated_private_keys":"same KSK receipt verified; authenticated AXFR with original TSIG key","retry_tx_id":result["tx_id"]}
    finally:
        for process in processes:
            if process.poll() is None:process.send_signal(signal.SIGCONT);process.terminate()
        for process in processes:
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        for log in logs:log.close()
        for relay in relays:relay.close()
