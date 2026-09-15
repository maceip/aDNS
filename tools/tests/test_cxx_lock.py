"""The cxx bridge macro and cxx_build must resolve to the same locked version.

cxx embeds a bridge ABI version in every generated symbol
(`...$cxxbridge1$<N>$...`), so when `cxx` and `cxx-build` diverge the Rust
staticlib and the generated C++ shims reference different symbols and the CCF
app link fails with `undefined reference` errors. That is exactly what broke
the ccf-consensus and ccf-secondary jobs on 2026-09-14 (cxx 1.0.149 vs
cxx-build 1.0.202): a ~25-minute failure that this seconds-long check in the
safe-core suite now catches first.

The locked pair is 1.0.202, not merely "any equal pair": 1.0.149's generated
header uses `$` in identifiers, which the CCF build rejects
(`-Werror -Wdollar-in-identifier-extension`), while the 1.0.202-generated
header for the current bridge.rs is proven clean (green CI 2026-09-13). Note
the MSRV asymmetry behind the original drift: safe-core checks with 1.85.1 but
never compiles the optional cxx bridge, while the CCF image builds it with
Rust 1.95 — so resolving under 1.85 can silently downgrade cxx alone. Keep the
pair equal here; change the version deliberately, then watch the CCF jobs.
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
