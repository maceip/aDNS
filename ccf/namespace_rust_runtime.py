#!/usr/bin/env python3
"""Namespace the SDK's Rust EH personality without changing its implementation.

Two Rust staticlibs each embed std. Most std symbols are version-mangled, but
rust_eh_personality and its DWARF reference are not. Rename BOTH definitions and
ALL relocations in a build-local copy of the SDK archive. This keeps each
runtime's own personality and does not suppress any duplicate-symbol errors.
"""
import pathlib
import subprocess
import sys

source, destination = map(pathlib.Path, sys.argv[1:])
before = subprocess.run(["nm", "-A", str(source)], check=True, capture_output=True, text=True).stdout
if sum(line.endswith(" T rust_eh_personality") for line in before.splitlines()) != 1:
    raise SystemExit("Pinned SDK must contain exactly one Rust EH personality definition")
subprocess.run([
    "objcopy", "--redefine-sym", "rust_eh_personality=adns_ccf_sdk_rust_eh_personality",
    "--redefine-sym", "DW.ref.rust_eh_personality=DW.ref.adns_ccf_sdk_rust_eh_personality",
    str(source), str(destination),
], check=True)
after = subprocess.run(["nm", "-A", str(destination)], check=True, capture_output=True, text=True).stdout
if any(line.split()[-1] in ("rust_eh_personality", "DW.ref.rust_eh_personality") for line in after.splitlines() if line.split()):
    destination.unlink(missing_ok=True)
    raise SystemExit("SDK runtime namespacing left an unrenamed symbol or relocation")
if sum(line.endswith(" T adns_ccf_sdk_rust_eh_personality") for line in after.splitlines()) != 1:
    destination.unlink(missing_ok=True)
    raise SystemExit("SDK runtime namespacing changed the personality definition count")
