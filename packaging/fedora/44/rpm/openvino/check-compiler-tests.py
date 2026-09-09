#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Run the compiler's self-contained functional cases with bundled configs."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


binary, config, results = (Path(arg).resolve() for arg in sys.argv[1:])
results.mkdir(parents=True, exist_ok=True)
run = Path(tempfile.mkdtemp(prefix="run-", dir=results))
command = [str(binary), "--gtest_filter=*simple_function*", "--gtest_output=xml:" + str(run / "results.xml")]
with (run / "tests.log").open("x") as log:
    result = subprocess.run(command, cwd=run, env=dict(os.environ, CID_TOOL=str(config)), stdout=log, stderr=subprocess.STDOUT)
print(f"Compiler test evidence: {run}")
report = ET.parse(run / "results.xml").getroot()
summary = {key: int(report.attrib[key]) for key in ("tests", "failures", "disabled", "errors")}
summary["skipped"] = len(report.findall(".//skipped"))
summary["exit_code"] = result.returncode
(run / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary))
valid = (
    report.tag == "testsuites"
    and summary["tests"] == len(report.findall(".//testcase"))
    and summary["tests"] > 0
    and all(summary[key] == 0 for key in ("failures", "disabled", "errors", "skipped", "exit_code"))
)
if not valid:
    sys.exit("FAIL: compiler functional tests must execute a nonempty set with no failures or skips")
print("PASS: self-contained compiler functional tests executed without failures or skips")
