# SPDX-License-Identifier: Apache-2.0
"""Exercise the native runner's ABI check with real ELF files and stub builds."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NativeSdkAbi(unittest.TestCase):
    def run_case(self, metadata, linked="2620"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk, build, fixtures, commands = (root / name for name in ["sdk", "build", "fixtures", "bin"])
            for path in [sdk, build, fixtures, commands]:
                path.mkdir()
            source = root / "source.c"
            source.write_text("int fixture_symbol(void) { return 0; }\n")
            main = root / "main.c"
            main.write_text("extern int fixture_symbol(void); int main(void) { return fixture_symbol(); }\n")
            for name, soname in [("intel-npu-level-zero-probe", "libze_loader.so.1"),
                                 ("intel-npu-openvino-probe", "libopenvino.so." + linked)]:
                library = root / soname
                subprocess.run(["cc", "-shared", "-fPIC", str(source), "-Wl,-soname," + soname,
                                "-o", str(library)], check=True, capture_output=True)
                subprocess.run(["cc", "-fPIE", "-pie", "-Wl,-z,relro,-z,now", str(main), str(library),
                                "-o", str(fixtures / name)], check=True, capture_output=True)
            cmake = commands / "cmake"
            cmake.write_text("""#!/usr/bin/python3
import os
from pathlib import Path
import shutil
import sys
args = sys.argv[1:]
if args[0] == '--build':
    for name in ['intel-npu-level-zero-probe', 'intel-npu-openvino-probe']:
        shutil.copy2(Path(os.environ['FIXTURES']) / name, Path(args[1]) / name)
else:
    build = Path(args[args.index('-B') + 1])
    if os.environ['ABI_METADATA'] != 'MISSING':
        (build / 'openvino-soname.txt').write_text(os.environ['ABI_METADATA'] + '\\n')
""")
            cmake.chmod(0o755)
            ctest = commands / "ctest"
            ctest.write_text("#!/bin/sh\nexit 0\n")
            ctest.chmod(0o755)
            env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                       FIXTURES=str(fixtures), ABI_METADATA=metadata)
            return subprocess.run(["sh", str(ROOT / "scripts/check-native.sh"), str(sdk), str(build)],
                                  env=env, capture_output=True, text=True, timeout=30)

    def test_accepts_2620_sdk_abi(self):
        result = self.run_case("libopenvino.so.2620")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_2621_sdk_abi(self):
        result = self.run_case("libopenvino.so.2621", linked="2621")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_wrong_linked_abi(self):
        result = self.run_case("libopenvino.so.2621", linked="2620")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required direct dependency", result.stderr)

    def test_rejects_unknown_abi_metadata(self):
        result = self.run_case("libopenvino.so.9999")
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_missing_abi_metadata(self):
        result = self.run_case("MISSING")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
