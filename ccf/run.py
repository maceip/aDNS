#!/usr/bin/env python3
"""Supervise the CCF process and autonomous peering driver inside one SNP image."""
import argparse
import errno
import hashlib
import http.client
import json
import os
import pathlib
import re
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time


def read_regular(path, maximum, reject_other_write=False):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,"rb") as stream:
        metadata=os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or reject_other_write and metadata.st_mode & 0o022:
            raise ValueError("configuration input must be regular and not writable by group or others")
        body=stream.read(maximum+1)
    if not body or len(body)>maximum:raise ValueError("configuration input size")
    return body


def strict_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError("duplicate configuration field")
        result[key]=value
    return result


def pinned_configuration(config_path, manifest_path, expected_digest, state):
    if not re.fullmatch(r"[0-9a-f]{64}",expected_digest):raise ValueError("canonical configuration manifest digest required")
    raw=read_regular(manifest_path,65536)
    if hashlib.sha256(raw).hexdigest()!=expected_digest:raise ValueError("configuration manifest digest mismatch")
    manifest=json.loads(raw,object_pairs_hook=strict_object)
    if not isinstance(manifest,dict) or not 1<=len(manifest)<=128:raise ValueError("configuration manifest entries")
    verified={}
    total=0
    for path,digest in manifest.items():
        if not isinstance(path,str) or not pathlib.Path(path).is_absolute() or str(pathlib.Path(path))!=path or ".." in pathlib.Path(path).parts:
            raise ValueError("canonical absolute manifest path required")
        if not isinstance(digest,str) or not re.fullmatch(r"[0-9a-f]{64}",digest):raise ValueError("canonical manifest file digest required")
        body=read_regular(path,8*1024*1024)
        total+=len(body)
        if total>32*1024*1024:raise ValueError("configuration manifest aggregate size")
        if hashlib.sha256(body).hexdigest()!=digest:raise ValueError("configuration file digest mismatch")
        verified[path]=body
    config_path=str(pathlib.Path(config_path).absolute())
    if config_path not in verified:raise ValueError("node configuration missing from manifest")
    config=json.loads(verified[config_path],object_pairs_hook=strict_object)
    required={config_path}
    command=config["command"]
    if command["type"]=="Start":
        required.update(command["start"]["constitution_files"])
        for member in command["start"]["members"]:
            for field in ("certificate_file","encryption_public_key_file","data_json_file"):
                if field in member:required.add(member[field])
    elif command["type"]=="Join":required.add(command["service_certificate_file"])
    elif command["type"]=="Recover":required.add(command["recover"]["previous_service_identity_file"])
    else:raise ValueError("unknown CCF startup command")
    for field in ("node_data_json_file","service_data_json_file"):
        if field in config:required.add(config[field])
    if not required.issubset(verified):raise ValueError("referenced bootstrap file missing from manifest")
    # Freeze verified bytes before CCF opens them. The confidential writable
    # directory removes a check/use race on externally mounted input files.
    bootstrap=pathlib.Path(tempfile.mkdtemp(prefix="verified-bootstrap-",dir=state))
    paths={}
    for path,body in verified.items():
        copy=bootstrap/(hashlib.sha256(path.encode()).hexdigest()+".data")
        with open(copy,"xb") as stream:os.chmod(copy,0o600);stream.write(body)
        paths[path]=str(copy)
    def substitute(value):
        if isinstance(value,str):return paths.get(value,value)
        if isinstance(value,list):return [substitute(item) for item in value]
        if isinstance(value,dict):return {key:substitute(item) for key,item in value.items()}
        return value
    config=substitute(config)
    frozen=bootstrap/"node.json"
    with open(frozen,"x") as stream:os.chmod(frozen,0o600);json.dump(config,stream)
    return frozen,config


def load_transfer_secret(path):
    # ACI confidential secret volumes can expose read-only 0444 files. Their
    # bytes remain inside the confidential container; reject writable shares.
    body=read_regular(path,65536,reject_other_write=True)
    if not body or len(body)>65536:raise ValueError("TSIG provisioning file size")
    try:value=json.loads(body)
    except (ValueError,UnicodeError):raise ValueError("invalid TSIG provisioning JSON") from None
    if not isinstance(value,dict) or set(value)!={"key_name","secret_base64url","zones"}:
        raise ValueError("invalid TSIG provisioning schema")
    return body


class SocketDeadline:
    """Retain and shut down one TLS socket at the absolute operation deadline."""
    def __init__(self, stream, deadline):
        self.stream=stream;self.deadline=deadline
        self.expired=threading.Event();self.timer=None

    def __enter__(self):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError("CCF HTTP deadline exceeded")
        self.stream.settimeout(remaining)
        def expire():
            self.expired.set()
            try:self.stream.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        self.timer=threading.Timer(remaining,expire);self.timer.daemon=True;self.timer.start()
        return self

    def __exit__(self,*_):
        self.timer.cancel();self.timer.join()
        if self.expired.is_set() or time.monotonic()>=self.deadline:
            raise TimeoutError("CCF HTTP deadline exceeded") from None


def bounded_http(address,certificate,method,path,body=None,*,timeout=10):
    """One bounded CA/name-verified loopback request; no proxy or redirects.

    Main only supplies numeric loopback endpoints. Connect, TLS handshake,
    headers and buffered body share one absolute deadline; response body is
    limited to 64KiB. Retain the TLS socket after HTTPConnection releases it.
    """
    context=ssl.create_default_context(cafile=str(certificate))
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    deadline=time.monotonic()+timeout
    conn=http.client.HTTPSConnection(address,context=context,timeout=timeout)
    raw=None;stream=None
    try:
        raw=socket.create_connection((conn.host,conn.port),timeout=timeout)
        stream=context.wrap_socket(raw,server_hostname=conn.host,do_handshake_on_connect=False)
        with SocketDeadline(stream,deadline):
            stream.do_handshake();conn.sock=stream
            conn.request(method,path,body,{"content-type":"application/json","connection":"close"})
            response=conn.getresponse()
            headers={}
            for key,value in response.getheaders():
                lower=key.lower()
                if lower in ("x-agentdns-commit-status","x-agentdns-transaction-id") and lower in headers:
                    raise RuntimeError("duplicate CCF commitment header")
                headers[lower]=value
            payload=bytearray()
            while len(payload)<=65536:
                if time.monotonic()>=deadline:raise TimeoutError("CCF HTTP deadline exceeded")
                chunk=response.read1(min(65536,65537-len(payload)))
                if not chunk:return response.status,headers,bytes(payload)
                payload.extend(chunk)
            raise RuntimeError("oversized CCF response")
    finally:
        conn.close()
        if stream is not None:stream.close()
        if raw is not None:raw.close()


def provision_transfer_secret(address,certificate,body):
    try:
        status,headers,raw=bounded_http(address,certificate,"POST","/app/internal/transfer-key",body,timeout=10)
        try:result=json.loads(raw,object_pairs_hook=strict_object)
        except (ValueError,UnicodeError):raise RuntimeError("invalid TSIG provisioning response") from None
        if not isinstance(result,dict):raise RuntimeError("invalid TSIG provisioning response")
        if status==200:
            txid=headers.get("x-agentdns-transaction-id")
            canonical_txid=isinstance(txid,str) and re.fullmatch(r"(?:0|[1-9][0-9]{0,19})\.(?:0|[1-9][0-9]{0,19})",txid) and all(int(part)<1<<64 for part in txid.split("."))
            if headers.get("x-agentdns-commit-status")!="committed" or result.get("status")!="committed" or not canonical_txid or result.get("tx_id")!=txid:
                raise RuntimeError("TSIG provisioning did not confirm global commit")
            return True
        error=result.get("error")
        if status==404 and (error=="NOT_FOUND: governed transfer key" or isinstance(error,dict) and error.get("code")=="FrontendNotOpen"):
            return False
        raise RuntimeError(f"TSIG provisioning rejected (HTTP {status})")
    except (OSError,http.client.HTTPException):return False


def runtime_environment():
    return {key:os.environ[key] for key in ("PATH","LANG","LC_ALL","LC_CTYPE","UVM_SECURITY_CONTEXT_DIR") if key in os.environ}


def telemetry_environments(state):
    """Keep OTLP credentials exclusively in the exporter process environment."""
    node=runtime_environment();driver=dict(node)
    # Fixed image-owned dependencies. Never inherit a caller-supplied Python
    # import path into either privileged process.
    driver["PYTHONPATH"]="/opt/agentdns/python"
    for key in ("OTEL_EXPORTER_OTLP_ENDPOINT","OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "OTEL_EXPORTER_OTLP_PROTOCOL","OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
                "OTEL_EXPORTER_OTLP_HEADERS","OTEL_EXPORTER_OTLP_TRACES_HEADERS",
                "OTEL_EXPORTER_OTLP_CERTIFICATE","OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
                "OTEL_SERVICE_NAME","OTEL_RESOURCE_ATTRIBUTES","OTEL_SDK_DISABLED"):
        if key in os.environ:driver[key]=os.environ[key]
    directory=None
    if os.environ.get("OTEL_SDK_DISABLED","").lower()!="true":
        try:
            directory=pathlib.Path(tempfile.mkdtemp(prefix="telemetry-",dir=state))
            path=str(directory.absolute()/"spans.sock")
            # Match telemetry.py's portable AF_UNIX receiver limit.
            if len(os.fsencode(path))>100:
                directory.rmdir();directory=None
            else:
                node["AGENTDNS_TRACE_SOCKET"]=path
                driver["AGENTDNS_TRACE_SOCKET"]=path
        except OSError:
            # Observability cannot prevent authority startup. No path or
            # configuration value is logged here.
            directory=None
    return node,driver,directory


def retire_trace_socket(process, configured_path, directory, parent_identity):
    """Remove only a stale socket belonging to a conclusively reaped driver.

    Keep the original private directory identity across driver replacements.
    A successful datagram connect proves a live listener, which must survive
    even if the retired child is dead. No datagram or private data is sent.
    All uncertain cases leave the path untouched and only disable telemetry.
    """
    if process is None or process.poll() is None or directory is None:
        return False
    directory=pathlib.Path(directory).absolute()
    if configured_path!=str(directory/"spans.sock"):
        return False
    descriptor=None
    try:
        descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        parent=os.fstat(descriptor)
        def private_parent(metadata):
            return (stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==os.getuid()
                    and not metadata.st_mode & 0o077
                    and (metadata.st_dev,metadata.st_ino)==parent_identity)
        if not private_parent(parent) or not private_parent(os.stat(directory,follow_symlinks=False)):
            return False
        try:original=os.stat("spans.sock",dir_fd=descriptor,follow_symlinks=False)
        except FileNotFoundError:return True
        if not stat.S_ISSOCK(original.st_mode) or original.st_uid!=os.getuid():
            return False
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as probe:
            probe.settimeout(.1)
            try:probe.connect(configured_path)
            except OSError as error:
                if error.errno!=errno.ECONNREFUSED:return False
            else:return False
        # Reject replacement/rename between inspection and the liveness probe.
        current=os.stat("spans.sock",dir_fd=descriptor,follow_symlinks=False)
        identity=lambda metadata:(metadata.st_dev,metadata.st_ino,metadata.st_mode,
                                  metadata.st_uid,metadata.st_ctime_ns)
        if identity(current)!=identity(original) or not private_parent(os.stat(directory,follow_symlinks=False)):
            return False
        os.unlink("spans.sock",dir_fd=descriptor)
        return True
    except OSError:return False
    finally:
        if descriptor is not None:os.close(descriptor)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",default="/config/node.json")
    parser.add_argument("--state-dir",default="/state")
    parser.add_argument("--listen",default="0.0.0.0:5353")
    parser.add_argument("--provision-tsig-file",help="confidential regular JSON file without group/other write access, installed after governance approval")
    parser.add_argument("--config-manifest",help="strict absolute-file-path to SHA256 bootstrap manifest")
    parser.add_argument("--config-manifest-sha256",help="exact manifest digest pinned in the confidential deployment command")
    args=parser.parse_args()
    if bool(args.config_manifest)!=bool(args.config_manifest_sha256):parser.error("configuration manifest path and digest must be supplied together")
    state=pathlib.Path(args.state_dir);state.mkdir(parents=True,exist_ok=True)
    config_path=pathlib.Path(args.config).absolute()
    if args.config_manifest:
        config_path,config=pinned_configuration(config_path,args.config_manifest,args.config_manifest_sha256,state)
    else:config=json.loads(read_regular(config_path,1024*1024),object_pairs_hook=strict_object)
    interfaces=config["network"]["rpc_interfaces"]
    internal=interfaces["agentdns-internal"]
    address=internal["bind_address"]
    if not (address.startswith("127.0.0.1:") or address.startswith("[::1]:")):
        parser.error("agentdns-internal must bind loopback")
    if any(interface.get("app_protocol","HTTP1")!="HTTP1" for interface in interfaces.values()):
        parser.error("CCF commitment gate requires HTTP1 on all interfaces")
    certificate=pathlib.Path(config["command"]["service_certificate_file"])
    if not certificate.is_absolute():certificate=state/certificate
    provision_body=load_transfer_secret(args.provision_tsig_file) if args.provision_tsig_file else None
    cmd=config.get("command",{})
    if cmd.get("type")=="Join":
        target=cmd.get("join",{}).get("target_rpc_address","")
        if target.startswith("agentdns.test:"):
            try:
                with open("/etc/hosts","a") as hosts_file:
                    hosts_file.write("128.251.125.64 agentdns.test\n")
            except OSError:pass
    # CCF logs its child environment at startup. Pass only runtime essentials;
    # credentials or deployment secret variables must never enter that log.
    child_env,driver_env,telemetry_directory=telemetry_environments(state)
    telemetry_parent=telemetry_directory.stat() if telemetry_directory is not None else None
    telemetry_identity=(telemetry_parent.st_dev,telemetry_parent.st_ino) if telemetry_parent else None
    node=subprocess.Popen(["/usr/local/bin/agentdns","--config",str(config_path)],cwd=state,env=child_env)
    driver=None;driver_identity=None;stopping=False;provisioned=False;next_provision=0
    def stop(*_):
        nonlocal stopping
        stopping=True
        for process in (driver,node):
            if process is not None and process.poll() is None:process.terminate()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        while node.poll() is None and not stopping:
            if certificate.is_file():
                identity=hashlib.sha256(certificate.read_bytes()).digest()
                if driver is not None and identity!=driver_identity:
                    # Recovery may replace the service identity. Retire the
                    # old pinned client before starting one with the new CA.
                    driver.terminate()
                    try:driver.wait(timeout=15)
                    except subprocess.TimeoutExpired:driver.kill();driver.wait()
                    retire_trace_socket(driver,driver_env.get("AGENTDNS_TRACE_SOCKET"),telemetry_directory,telemetry_identity)
                    driver=None;driver_identity=None;provisioned=False
                if driver is None:
                    # A pre-existing output file is not proof that this node
                    # has started with that identity. Verify the actual TLS
                    # listener before handing the file to the peering driver.
                    try:
                        status,_,_=bounded_http(address,certificate,"GET","/node/state",timeout=1)
                        # Internal interface ACLs may intentionally deny the
                        # node route; its authenticated TLS response suffices.
                        if 200<=status<500:
                            driver=subprocess.Popen(["python3","/opt/agentdns/host_driver.py","--ccf-url",f"https://{address}","--service-cert",str(certificate),"--listen",args.listen],env=driver_env)
                            driver_identity=identity
                    except (OSError,http.client.HTTPException,RuntimeError):pass
                if driver is not None and provision_body is not None and not provisioned and time.monotonic()>=next_provision:
                    provisioned=provision_transfer_secret(address,certificate,provision_body)
                    next_provision=time.monotonic()+1
            if driver is not None and driver.poll() is not None:
                raise RuntimeError("autonomous peering/lifecycle driver exited")
            time.sleep(0.25)
    finally:
        stop()
        for process in (driver,node):
            if process is not None:
                try:process.wait(timeout=15)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        if telemetry_directory is not None:
            retire_trace_socket(driver,driver_env.get("AGENTDNS_TRACE_SOCKET"),telemetry_directory,telemetry_identity)
            # Never recursively remove unexpected files or an active listener.
            try:telemetry_directory.rmdir()
            except OSError:pass
    return node.returncode or 0


if __name__=="__main__":raise SystemExit(main())
