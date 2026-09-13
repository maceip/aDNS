import importlib.util
from pathlib import Path
import tempfile
import contextlib
import io
import sys
from unittest.mock import patch
import unittest

spec = importlib.util.spec_from_file_location("observe_native_bind", Path(__file__).with_name("observe_native_bind.py"))
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class NativeBindObserverTests(unittest.TestCase):
    def test_duration_bound_allows_1380_and_rejects_larger_or_off_cadence(self):
        args = ["collector", "--seconds", "1380", "--output", "/unused"]
        with patch.object(sys, "argv", args), patch.object(observer.Path, "mkdir", side_effect=RuntimeError("duration accepted")):
            with self.assertRaisesRegex(RuntimeError, "duration accepted"):
                observer.main()
        for seconds in (1390, 1381, 1371, 29):
            args[2] = str(seconds)
            with patch.object(sys, "argv", args), patch.object(observer.Path, "mkdir") as mkdir, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    observer.main()
                self.assertEqual(error.exception.code, 2)
                mkdir.assert_not_called()

    def test_actual_named_rss_units_and_identity(self):
        raw = "Name:\tnamed\nVmRSS:\t1234 kB\nVmHWM:\t5678 kB\n"
        self.assertEqual(observer.process_status(raw), {"rss_kib": 1234, "high_water_rss_kib": 5678, "comm": "named"})
        for invalid in (raw.replace("named", "python3"), raw.replace(" kB", " MB"), raw.replace("VmRSS:", "NoRSS:")):
            with self.assertRaises(ValueError): observer.process_status(invalid)

    def test_stat_identity_handles_process_name_spaces_and_parentheses(self):
        fields = ["S"] + [str(i) for i in range(4, 53)]
        self.assertEqual(observer.process_start("1 (na) med) " + " ".join(fields)), 22)

    def test_cgroup_counter_rejects_unavailable_or_noninteger_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "memory.current"
            path.write_text("102400\n")
            self.assertEqual(observer.counter(path), 102400)
            for invalid in ("max", "-1", "123 bytes", "１２３"):
                path.write_text(invalid)
                with self.assertRaises(ValueError): observer.counter(path)


if __name__ == "__main__": unittest.main()
