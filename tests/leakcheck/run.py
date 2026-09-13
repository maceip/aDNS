#!/usr/bin/env python3
"""Reproduce the finite Rust core leak check on a native ARM64 Docker host."""
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'docs/evidence/leakcheck-20260913'
IMAGE = 'agentdns-leakcheck:1.95.0'


def main():
    architecture = subprocess.check_output(['docker','info','--format','{{.Architecture}}'], text=True).strip()
    if architecture not in ('aarch64','arm64'):
        raise RuntimeError('This recorded workload requires native ARM64 Docker; do not label QEMU as native.')
    if (OUT/'provenance.json').exists():
        raise RuntimeError('Preserve the prior evidence bundle before running again; refusing to overwrite provenance.')
    OUT.mkdir(parents=True,exist_ok=True)
    runs=ROOT/'.validation/leakcheck-runs'
    runs.mkdir(parents=True,exist_ok=True)
    frozen=Path(tempfile.mkdtemp(prefix='run-',dir=runs))/'source'
    files=[ROOT/'Cargo.toml',ROOT/'Cargo.lock',*sorted((ROOT/'crates').glob('*/Cargo.toml')),
           *sorted((ROOT/'crates').glob('*/build.rs')),*sorted((ROOT/'crates').glob('*/src/**/*')),
           ROOT/'tests/leakcheck/src/main.rs',ROOT/'tests/leakcheck/Cargo.lock',
           ROOT/'tests/leakcheck/Cargo.toml',ROOT/'tests/leakcheck/Dockerfile',Path(__file__).resolve()]
    files=sorted(set(p for p in files if p.is_file()))
    source_hashes={}
    for original in files:
        destination=frozen/original.relative_to(ROOT)
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(original,destination)
        source_hashes[str(original.relative_to(ROOT))]=hashlib.sha256(destination.read_bytes()).hexdigest()
    subprocess.run(['docker','build','--platform','linux/arm64','-f','tests/leakcheck/Dockerfile','-t',IMAGE,'.'],cwd=frozen,check=True,timeout=1200)
    image_id=subprocess.check_output(['docker','image','inspect',IMAGE,'--format','{{.Id}}'],text=True,timeout=30).strip()
    command = ['docker','run','--rm','--platform','linux/arm64','-v',str(frozen)+':/src:ro','-v',str(OUT)+':/out','-v','agentdns-leakcheck-build:/build',image_id]
    started = time.time()
    script = '''set -eu
CARGO_TARGET_DIR=/build CARGO_HOME=/build/cargo-home cargo build --locked --manifest-path tests/leakcheck/Cargo.toml --release
/build/release/agentdns-leakcheck > /out/native-baseline.json 2> /out/native-signing.log
timeout 900 valgrind --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=definite,indirect --error-exitcode=99 --log-file=/out/valgrind.log /build/release/agentdns-leakcheck > /out/workload-result.json 2> /out/valgrind-signing.log
'''
    subprocess.run(command+['bash','-c',script],cwd=ROOT,check=True,timeout=1800)
    versions = subprocess.check_output(command+['bash','-c','rustc -Vv; cargo --version; valgrind --version; ldd --version | head -1; uname -m; sha256sum /build/release/agentdns-leakcheck'],text=True,timeout=30)
    drift=[name for name,digest in source_hashes.items() if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest]
    result={'started_unix_seconds':started,'finished_unix_seconds':time.time(),'exit_code':0,
            'docker_host_architecture':architecture,'versions_and_binary_sha256':versions,
            'image_id':image_id,'source_mode':'read-only copied allowlist, built and executed without live source mounts',
            'live_source_changes_during_run':drift,'source_sha256':source_hashes}
    (OUT/'provenance.json').write_text(json.dumps(result,indent=2)+'\n')
    result_files=sorted(p for p in OUT.iterdir() if p.is_file() and p.name!='SHA256SUMS')
    (OUT/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in result_files))
    print(json.dumps({'exit_code':0,'evidence_directory':str(OUT),'elapsed_seconds':time.time()-started}))


if __name__=='__main__':main()
