#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Require every generated C/C++ link edge to share one single-job pool.

Run after CMake, before Ninja. This bounds concurrent memory-heavy LTO links
while keeping the separately configured compile job limit.
"""

from pathlib import Path
import re
import sys


build = Path(sys.argv[1]).resolve()
graph = (build / "build.ninja").read_text()
rules = (build / "CMakeFiles/rules.ninja").read_text()
definitions = re.findall(r"^pool (\S+)\n  depth = (\d+)$", rules, re.MULTILINE)
pools = dict(definitions)
if len(pools) != len(definitions):
    sys.exit("FAIL: duplicate pool definitions make the Ninja graph invalid")
links = []
for block in re.split(r"(?=^build )", graph, flags=re.MULTILINE):
    first = block.splitlines()[0] if block else ""
    if re.search(r": C(?:XX)?_(?:SHARED_LIBRARY|MODULE_LIBRARY|EXECUTABLE)_LINKER__", first):
        pool = re.search(r"^  pool = (\S+)$", block, re.MULTILINE)
        links.append((first.split(": ")[0], pool.group(1) if pool else None))
if not links:
    sys.exit("FAIL: no generated C/C++ link edges")
used = {pool for _, pool in links}
if len(used) != 1 or None in used or pools.get(next(iter(used))) != "1":
    sample = "\n".join(f"{target}: pool={pool}" for target, pool in links[:5])
    sys.exit(f"FAIL: link edges must share one pool of depth 1; pools={pools}, used={used}\n{sample}")
print(f"PASS: all {len(links)} C/C++ link edges share single-job pool {next(iter(used))}")
