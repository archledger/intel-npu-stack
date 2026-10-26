# SPDX-License-Identifier: Apache-2.0
"""Prepared-source guard contracts; runtime behavior is tested in OpenVINO."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / 'packaging/fedora/44/rpm/openvino/check-lp-ecore-executor-guard.py'
SOURCE = Path('src/inference/src/dev/threading/istreams_executor.cpp')
MARKERS = [
    'std::vector<int> core_types{MAIN_CORE_PROC, EFFICIENT_CORE_PROC, LP_EFFICIENT_CORE_PROC, HYPER_THREADING_PROC};',
    'core_types = {EFFICIENT_CORE_PROC, LP_EFFICIENT_CORE_PROC};',
    'proc_type_table[0][LP_EFFICIENT_CORE_PROC] > 0 ? LP_EFFICIENT_CORE_PROC',
    'OPENVINO_ASSERT(!_streams_info_table.empty(),',
    'if (mixed_stream) {',
    'if (mixed_stream) {',
    'proc_type_table[0][EFFICIENT_CORE_PROC] + proc_type_table[0][LP_EFFICIENT_CORE_PROC]',
    'proc_type_table[0][EFFICIENT_CORE_PROC] + proc_type_table[0][LP_EFFICIENT_CORE_PROC]',
    'if (proc_type_table[0][LP_EFFICIENT_CORE_PROC] > 0 && homogeneous_streams)',
    '_streams > 1 || (_thread_preferred_core_type == ov::hint::SchedulingCoreType::ECORE_ONLY && !_cpu_pinning);',
    '!homogeneous_streams && _streams == 1 &&',
    'while (_threads_per_stream > 1)',
    'if (proc_type_table[0][LP_EFFICIENT_CORE_PROC] > 0 && homogeneous_streams &&\n'
    '                            _threads_per_stream > proc_type_table[i][j]) {\n'
    '                            continue;\n'
    '                        }',
    'streams_num += proc_type_table[i][type] / _threads_per_stream;',
    'const auto num_cores = proc_type_table[0][MAIN_CORE_PROC] + proc_type_table[0][EFFICIENT_CORE_PROC] +\n'
    '                           proc_type_table[0][LP_EFFICIENT_CORE_PROC];',
    '_streams_info_table[0][PROC_TYPE] = LP_EFFICIENT_CORE_PROC;',
    '_streams_info_table[0][STREAM_NUMA_NODE_ID] = _streams_info_table[1][STREAM_NUMA_NODE_ID];',
    '_streams_info_table[0][STREAM_SOCKET_ID] = _streams_info_table[1][STREAM_SOCKET_ID];',
]
EXTRA_MARKERS = {
    Path('src/inference/src/dev/threading/cpu_streams_executor.cpp'): [
        'const auto proc_types = get_org_proc_type_table();',
        'get_tbb_core_type(core_type, core_types, proc_types);',
    ],
    Path('src/inference/src/dev/threading/cpu_streams_executor_internal.cpp'): [
        'int get_tbb_core_type(int proc_type,',
        'core_types.size() == 2 && !proc_type_table.empty() &&',
        'proc_type_table[0][EFFICIENT_CORE_PROC] > 0 && proc_type_table[0][LP_EFFICIENT_CORE_PROC] > 0 &&',
        'proc_type_table[0][MAIN_CORE_PROC] == 0 && proc_type_table[0][HYPER_THREADING_PROC] == 0',
    ],
    Path('src/inference/dev_api/openvino/runtime/threading/cpu_streams_executor_internal.hpp'): [
        'int get_tbb_core_type(int proc_type,',
        'const std::vector<std::vector<int>>& proc_type_table);',
    ],
}


class LPExecutorGuardTest(unittest.TestCase):
    def run_guard(self, markers, extra_markers=None):
        with tempfile.TemporaryDirectory() as directory:
            for relative, lines in {SOURCE: markers, **(EXTRA_MARKERS if extra_markers is None else extra_markers)}.items():
                source = Path(directory) / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text('\n'.join(lines), encoding='utf-8')
            return subprocess.run(
                [sys.executable, str(GUARD), directory],
                capture_output=True, text=True, timeout=10,
            )

    def test_accepts_complete_prepared_source_markers(self):
        result = self.run_guard(MARKERS)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_each_missing_requirement(self):
        for index, marker in enumerate(MARKERS):
            with self.subTest(marker=marker):
                result = self.run_guard(MARKERS[:index] + MARKERS[index + 1:])
                self.assertNotEqual(result.returncode, 0, marker)
                self.assertIn('check-lp-ecore-executor-guard:', result.stderr)

    def test_rejects_duplicate_requirement(self):
        result = self.run_guard(MARKERS + [MARKERS[0]])
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_legacy_core_list(self):
        result = self.run_guard(MARKERS + [
            'core_types = {MAIN_CORE_PROC, EFFICIENT_CORE_PROC, HYPER_THREADING_PROC};',
        ])
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_unused_small_pool_clamp(self):
        result = self.run_guard(MARKERS + [
            '_threads_per_stream = std::min(_threads_per_stream, proc_type_table[i][type]);',
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unused small pools', result.stderr)

    def test_rejects_each_missing_mapping_requirement(self):
        for path, markers in EXTRA_MARKERS.items():
            for index, marker in enumerate(markers):
                with self.subTest(path=path, marker=marker):
                    sources = dict(EXTRA_MARKERS)
                    sources[path] = markers[:index] + markers[index + 1:]
                    result = self.run_guard(MARKERS, sources)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('check-lp-ecore-executor-guard:', result.stderr)

    def test_rejects_missing_mapping_source(self):
        sources = dict(EXTRA_MARKERS)
        del sources[next(iter(sources))]
        result = self.run_guard(MARKERS, sources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('check-lp-ecore-executor-guard:', result.stderr)


if __name__ == '__main__':
    unittest.main()
