"""The cxx bridge macro and cxx_build must resolve to the same locked version.

cxx embeds a bridge ABI version in every generated symbol
(`...$cxxbridge1$<N>$...`), so when `cxx` and `cxx-build` diverge the Rust
staticlib and the generated C++ shims reference different symbols and the CCF
app link fails with `undefined reference` errors. That is exactly what broke
the ccf-consensus and ccf-secondary jobs on 2026-09-14 (cxx 1.0.149 vs
cxx-build 1.0.202): a ~25-minute failure that this seconds-long check in the
safe-core suite now catches first.
"""
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def locked_versions(lock_text, name):
    return set(re.findall(
        r'\[\[package\]\]\nname = "%s"\nversion = "([^"]+)"' % re.escape(name),
        lock_text))


class CxxLockTests(unittest.TestCase):
    def test_cxx_and_cxx_build_share_one_locked_version(self):
        lock = (ROOT / 'Cargo.lock').read_text()
        cxx = locked_versions(lock, 'cxx')
        build = locked_versions(lock, 'cxx-build')
        self.assertEqual(len(cxx), 1, 'expected exactly one locked cxx, got %r' % (cxx,))
        self.assertEqual(len(build), 1, 'expected exactly one locked cxx-build, got %r' % (build,))
        self.assertEqual(cxx, build,
                         'cxx %r and cxx-build %r must match or the CCF link breaks' % (cxx, build))


if __name__ == '__main__':
    unittest.main()
