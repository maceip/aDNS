"""Exercise the guard on tracked, new, ignored, and live-harness source files."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("domain_literal_guard", HERE / "check_domain_literals.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class DomainLiteralTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        self.registry = self.root / "topology.json"
        self.registry.write_text(json.dumps({"schema_version": 1, "domain": "managed.example", "naming": {"ccf_rpc_hostname": "authority.managed.example"}}))
        (self.root / "tools").mkdir()
        self.config_path = self.root / "tools/domain-literal-exceptions.json"
        self.config = {"schema_version": 1, "path_exclusions": [{"pattern": "fixtures/*", "category": "fixed-fixtures", "reason": "static input vectors"}], "line_exceptions": []}
        self.save_config()

    def save_config(self):
        self.config_path.write_text(json.dumps(self.config))

    def audit(self):
        return guard.audit(self.root, self.registry)

    def test_tracked_and_new_operational_literals_fail_and_ignored_output_does_not(self):
        (self.root / "tracked.py").write_text('host = "managed.example"\n')
        subprocess.run(["git", "-C", str(self.root), "add", "tracked.py"], check=True)
        (self.root / "new.sh").write_text('curl https://authority.managed.example\n')
        (self.root / ".gitignore").write_text("build/\n")
        (self.root / "build").mkdir()
        (self.root / "build/output.js").write_text('host = "managed.example"\n')
        result = self.audit()
        self.assertEqual({item["path"] for item in result["violations"]}, {"tracked.py", "new.sh"})
        cli = subprocess.run(["python3", str(HERE / "check_domain_literals.py"), "--root", str(self.root), "--registry", str(self.registry)], text=True, capture_output=True)
        self.assertEqual(cli.returncode, 1)

    def test_live_harness_is_checked_while_explicit_fixed_fixtures_are_classified(self):
        (self.root / "tests").mkdir()
        (self.root / "tests/live_smoke.py").write_text('endpoint = "https://managed.example"\n')
        (self.root / "fixtures").mkdir()
        (self.root / "fixtures/signed.json").write_text('{"identity":"managed.example"}\n')
        self.assertEqual([item["path"] for item in self.audit()["violations"]], ["tests/live_smoke.py"])

    def test_exception_is_bound_to_exact_file_and_line_bytes(self):
        line = '// Protocol identifier: https://managed.example/claims/v1'
        (self.root / "protocol.js").write_text(line + '\n')
        self.config["line_exceptions"] = [{"path": "protocol.js", "sha256": guard.line_hash(line), "category": "protocol-identifier", "reason": "Versioned identifier in existing signed claims"}]
        self.save_config()
        self.assertEqual(self.audit()["violations"], [])
        (self.root / "protocol.js").write_text(line + '\nconst endpoint = "https://managed.example";\n')
        self.assertEqual(len(self.audit()["violations"]), 1)
        (self.root / "other.js").write_text(line + '\n')
        self.assertEqual(len(self.audit()["violations"]), 2)

    def test_current_needles_follow_registry_and_retired_names_are_explicit(self):
        data = json.loads(self.registry.read_text())
        data["domain"] = "next.example"
        self.registry.write_text(json.dumps(data))
        self.config["additional_domains"] = [{"domain": "retired.example", "reason": "Retired endpoint must not return"}]
        self.save_config()
        (self.root / "run.sh").write_text('curl https://next.example\ncurl https://retired.example\n')
        self.assertEqual([item["domains"] for item in self.audit()["violations"]], [["next.example"], ["retired.example"]])

    def test_own_canonical_registry_is_exempt_with_an_alternate_selected_registry(self):
        production = self.root / "infra/production"
        production.mkdir(parents=True)
        canonical = production / "topology.json"
        canonical.write_bytes(self.registry.read_bytes())
        (production / "other-config.json").write_bytes(self.registry.read_bytes())
        result = self.audit()
        self.assertEqual([item["path"] for item in result["violations"]], ["infra/production/other-config.json"])
        self.assertEqual(result["excluded_files"]["canonical-registry"], 1)

    def test_all_central_ses_and_caa_values_are_checked_in_terraform_source(self):
        keys = ("ses_feedback_host", "ses_spf_host", "ses_dkim_primary_host", "ses_dkim_secondary_host", "ses_dkim_tertiary_host",
                "caa_primary_domain", "caa_secondary_domain")
        data = json.loads(self.registry.read_text())
        values = {key: key.replace("_", "-") + ".example" for key in keys}
        data["naming"].update(values)
        self.registry.write_text(json.dumps(data))
        (self.root / "dns.tf").write_text("\n".join(f'{key} = "{value}"' for key, value in values.items()) + "\n")
        result = self.audit()
        self.assertEqual({item["path"] for item in result["violations"]}, {"dns.tf"})
        self.assertEqual({domain for item in result["violations"] for domain in item["domains"]}, set(values.values()))


if __name__ == "__main__":
    unittest.main()
