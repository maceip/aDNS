"""Offline new-genesis safety boundaries; uses retained public keys, creates none."""
import base64
import copy
import json
import re
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import prepare_aci_durable_candidate as candidate
import check_aci_template as preflight


class DurableCandidateTests(unittest.TestCase):
    def fixture(self):
        baseline = json.loads((ROOT / "docs/evidence/startup-repair-20260919/deployment/template.json").read_text())
        public = ROOT / "docs/evidence/azure-native-v5-ready-20260913/bootstrap"
        return candidate.prepare(baseline, (public / "member0_cert.pem").read_bytes(),
                                 (public / "member0_enc_pubk.pem").read_bytes(), "20260921")

    def inspect(self, template):
        properties = template["resources"][0]["properties"]
        containers = {c["name"]: c["properties"] for c in properties["containers"]}
        volumes = {v["name"]: v for v in properties["volumes"]}
        node = json.loads(base64.b64decode(volumes["public-config"]["secret"]["node.json"]))
        return properties, containers, volumes, node

    def test_explicit_new_genesis_reuses_only_original_public_member(self):
        template, parameters, storage, public, summary = self.fixture()
        self.assertEqual(summary["member_id"], "3552372ebdc37ab6ae5eddc694623dbebb8ae40b159250136c47dd29c7ef173d")
        self.assertTrue(summary["new_genesis"])
        self.assertFalse(summary["old_service_identity_retained"])
        self.assertEqual(set(public), {"node.json", "manifest.json", "member0_cert.pem", "member0_enc_pubk.pem"})
        self.assertTrue(all(p["value"].startswith("REQUIRED_AFTER_APPROVAL__") for p in parameters["parameters"].values()))
        self.assertEqual(storage["resources"][0]["name"], "adnsrecovery20260921")
        self.assertNotIn("private", json.dumps(template).lower())

    def test_reject_automatic_start_restart_wrong_paths_and_shared_writers(self):
        for change in ("restart", "local-ledger", "pid-on-share", "secondary-writer", "state-on-share", "wrong-fqdn", "wrong-mode", "old-name", "literal-storage-key", "storage-default", "tfstate"):
            with self.subTest(change=change):
                template = self.fixture()[0]
                properties, containers, volumes, node = self.inspect(template)
                if change == "restart": properties["restartPolicy"] = "Always"
                elif change == "local-ledger": node["ledger"]["directory"] = "ledger"
                elif change == "pid-on-share": node["output_files"]["pid_file"] = "/durable/node.pid"
                elif change == "secondary-writer": containers["secondary"]["volumeMounts"] = [{"name": "durable-state", "mountPath": "/durable"}]
                elif change == "state-on-share": volumes["primary-state"] = copy.deepcopy(volumes["durable-state"])
                elif change == "wrong-fqdn": node["network"]["rpc_interfaces"]["primary_rpc_interface"]["published_address"] = "agentdns.test:8000"
                elif change == "wrong-mode": node["command"]["type"] = "Recover"
                elif change == "old-name": template["resources"][0]["name"] = "agentdns-ccf-joiner"
                elif change == "literal-storage-key": volumes["durable-state"]["azureFile"]["storageAccountKey"] = "secret"
                elif change == "storage-default": template["parameters"][candidate.STORAGE_KEY_PARAMETER]["defaultValue"] = "secret"
                elif change == "tfstate": volumes["durable-state"]["azureFile"]["storageAccountName"] = "ahtfstate"
                with self.assertRaises(ValueError): candidate.validate_durable_candidate(template, containers, volumes, node)

    def test_retained_logging_is_required_and_workspace_secrets_stay_references(self):
        template = self.fixture()[0]
        properties, containers, volumes, node = self.inspect(template)
        self.assertTrue(candidate.validate_retained_logging(template)["configured"])
        policy={"primary":{"env_rules":[preflight.OTEL_DISABLED_RULE]}}
        self.assertEqual(preflight.validate_otel(template, containers, volumes, policy),
                         {"configured":False,"trace_export_enabled":False,"mode":"explicitly_disabled"})
        for change in ("missing", "literal-key", "literal-id", "key-default", "id-default", "key-string", "extra-setting"):
            with self.subTest(change=change):
                invalid = copy.deepcopy(template)
                props, cs, vs, ns = self.inspect(invalid)
                if change == "missing": del props["diagnostics"]
                elif change == "literal-key": props["diagnostics"]["logAnalytics"]["workspaceKey"] = "private-fixture-secret"
                elif change == "literal-id": props["diagnostics"]["logAnalytics"]["workspaceId"] = "unreviewed-workspace"
                elif change == "key-default": invalid["parameters"]["logAnalyticsWorkspaceKey"]["defaultValue"] = "private-fixture-secret"
                elif change == "id-default": invalid["parameters"]["logAnalyticsWorkspaceId"]["defaultValue"] = "unreviewed-workspace"
                elif change == "key-string": invalid["parameters"]["logAnalyticsWorkspaceKey"]["type"] = "string"
                else: props["diagnostics"]["logAnalytics"]["metadata"] = {"unexpected": "value"}
                with self.assertRaises(ValueError) as rejected:
                    candidate.validate_durable_candidate(invalid, cs, vs, ns)
                self.assertNotIn("private-fixture-secret", str(rejected.exception))

    def test_retained_workspace_contract_supports_creation_time_collection(self):
        workspace = candidate.logging_workspace_template("northeurope")["resources"][0]
        self.assertEqual(workspace["name"], "adns-authority-logs")
        self.assertEqual(workspace["location"], "northeurope")
        self.assertEqual(workspace["properties"]["retentionInDays"], 30)
        self.assertFalse(workspace["properties"]["features"]["disableLocalAuth"])
        self.assertEqual(workspace["properties"]["publicNetworkAccessForIngestion"], "Enabled")

    def test_confidential_policy_rejects_new_exec_signal_or_mount_authority(self):
        template = self.fixture()[0]
        _, containers, volumes, node = self.inspect(template)
        policies = {"primary": {"allow_stdio_access": True, "env_rules": copy.deepcopy(candidate.PLATFORM_ENV_RULES), "mounts": [{"destination": "/durable", "options": ["rbind", "rshared", "rw"], "source": "sandbox:///tmp/atlas/azureFileVolume/.+", "type": "bind"}]}, "secondary": {"allow_stdio_access": True, "mounts": []}}
        candidate.validate_durable_candidate(template, containers, volumes, node, policies)
        for field, value in (("exec_processes", [{"command": ["sh"]}]), ("signals", [9]), ("allow_elevated", True), ("allow_stdio_access", False)):
            invalid = copy.deepcopy(policies)
            invalid["primary"][field] = value
            with self.assertRaises(ValueError): candidate.validate_durable_candidate(template, containers, volumes, node, invalid)
        policies["primary"]["mounts"][0]["source"] = ".*"
        with self.assertRaises(ValueError): candidate.validate_durable_candidate(template, containers, volumes, node, policies)

    def test_policy_finalization_rejects_stale_input_and_preserves_generated_authority(self):
        template = self.fixture()[0]
        generated = copy.deepcopy(template)
        for container in generated["resources"][0]["properties"]["containers"]:
            container["properties"]["image"] = container["properties"]["image"].split("@")[0] + ":offline-tag"
        entries = [{"name": name, "layers": [name], "mounts": [], "exec_processes": [], "signals": [], "env_rules": []}
                   for name in ("primary", "secondary", "pause-container")]
        entries[0]["env_rules"]=[{**candidate.OTEL_DISABLED_RULE,"required":False}]
        entries[1]["env_rules"] = [{"pattern": "AGENTDNS_TRANSFER_KEY_B64=.*", "required": False, "strategy": "re2"}]
        raw = "package policy\ncontainers := " + json.dumps(entries) + "\nallow_all := false\n"
        generated["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"] = base64.b64encode(raw.encode()).decode()
        final, review = candidate.finalize_policy(template, generated)
        body = base64.b64decode(final["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"]).decode()
        result = json.JSONDecoder().raw_decode(body[re.search(r"(?m)^containers\s*:=\s*", body).end():])[0]
        self.assertTrue(body.endswith("\nallow_all := false\n"))
        self.assertEqual(result[0]["layers"], entries[0]["layers"])
        self.assertEqual(result[0]["mounts"], entries[0]["mounts"])
        self.assertEqual(result[0]["env_rules"], [candidate.OTEL_DISABLED_RULE]+candidate.PLATFORM_ENV_RULES)
        self.assertNotEqual(review["generated_policy_sha256"], review["final_policy_sha256"])
        generated["resources"][0]["properties"]["restartPolicy"] = "Always"
        with self.assertRaisesRegex(ValueError, "differs beyond"):
            candidate.finalize_policy(template, generated)


if __name__ == "__main__":
    unittest.main()
