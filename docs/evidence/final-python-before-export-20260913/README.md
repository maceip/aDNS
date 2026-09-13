# Final Linux Python regression run

All **76 tests passed**: 52 tools (including 18 capture-worker tests), 12 host-driver tests, nine supervisor tests and three runner guards. The tool suite includes seven focused measurement-client checks and a regression requiring operator records at the exact governed DNS owner rather than accepting a CNAME target.

The run used a copied public-source allowlist, mounted read-only into an isolated Ubuntu 24.04 validation container. `source-sha256.json` identifies the exact tested bytes; `linux-runtime.json` records Python and dependency versions. Public logs and exit codes are included. No cloud deployment, native registration or performance claim follows from these regression tests. The earlier 66-test bundle remains unchanged.

On Linux with Python cbor2, cryptography, dnspython and BIND `named-checkconf` installed, reproduce from the repository root:

```sh
python3 -m unittest discover -s tools/tests -v
python3 -m unittest discover -s ccf -p test_host_driver.py -v
python3 -m unittest discover -s ccf/tests -p test_supervisor.py -v
python3 -m unittest discover -s tests/rust-integration -p test_run_ccf.py -v
```

The SHA256 manifest covers every public file in this bundle.
