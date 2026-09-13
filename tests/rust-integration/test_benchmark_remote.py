import importlib.util
from pathlib import Path
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location("benchmark_remote", Path(__file__).with_name("benchmark_remote.py"))
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class SamplingTests(unittest.TestCase):
    def test_slow_responses_are_concurrent_and_all_slots_accounted_for(self):
        lock = threading.Lock()
        active = 0
        maximum = 0

        def probe(index):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(.03)
            with lock:
                active -= 1
            return "example.test. SOA"

        samples, failures, report = benchmark.sample_window(probe, .3, 100)
        self.assertGreater(maximum, 1)
        self.assertEqual(len(samples) + len(failures), 30)
        self.assertEqual(report["attempted_samples"], len(samples))
        self.assertEqual(report["missed_samples"], len(failures))
        self.assertEqual(sorted(row["sample_index"] for row in samples + failures), list(range(30)))
        self.assertTrue(all(row["latency_ms"] >= 20 for row in samples))
        self.assertTrue(all(not row["attempted"] for row in failures))

    def test_failed_network_probes_do_not_become_successful_latency_samples(self):
        def probe(index):
            raise TimeoutError("simulated bounded network timeout")

        samples, failures, report = benchmark.sample_window(probe, .1, 50)
        self.assertEqual(samples, [])
        self.assertEqual(len(failures), 5)
        self.assertEqual(report["attempted_samples"] + report["missed_samples"], 5)
        self.assertTrue(all(row["error"] == "TimeoutError" for row in failures if row["attempted"]))


if __name__ == "__main__":
    unittest.main()
