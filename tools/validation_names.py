"""Names for executable acceptance harnesses, resolved from the common store.

Static wire/cryptographic test vectors retain their recorded names. These values
are for generated deployments, traffic and validators that must agree at runtime.
"""
from domain_registry import get

VALIDATION_DOMAIN = get("validation_domain")
VALIDATION_ZONE = get("validation_zone")
VALIDATION_NS_HOSTNAME = "ns." + VALIDATION_DOMAIN
CCF_RPC_HOSTNAME = get("ccf_rpc_hostname")
CCF_RPC_URL = get("ccf_rpc_url")
CCF_AUDIENCE = get("ccf_audience")
CAPTURE_TLS_HOSTNAME = get("capture_tls_hostname")
TRANSFER_KEY_NAME = get("transfer_key_name")
CAA_ISSUER = get("caa_primary_domain")
