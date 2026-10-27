#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Require LP-efficiency-core scheduling in the prepared OpenVINO source."""
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve(strict=True)
source = root / 'src/inference/src/dev/threading/istreams_executor.cpp'
text = source.read_text(encoding='utf-8')

unguarded = 'core_types = {MAIN_CORE_PROC, EFFICIENT_CORE_PROC, HYPER_THREADING_PROC};'
required = {
    'std::vector<int> core_types{MAIN_CORE_PROC, EFFICIENT_CORE_PROC, LP_EFFICIENT_CORE_PROC, HYPER_THREADING_PROC};': 1,
    'core_types = {EFFICIENT_CORE_PROC, LP_EFFICIENT_CORE_PROC};': 1,
    'proc_type_table[0][LP_EFFICIENT_CORE_PROC] > 0 ? LP_EFFICIENT_CORE_PROC': 1,
    'OPENVINO_ASSERT(!_streams_info_table.empty(),': 1,
    'if (mixed_stream) {': 2,
    'proc_type_table[0][EFFICIENT_CORE_PROC] + proc_type_table[0][LP_EFFICIENT_CORE_PROC]': 2,
    'if (proc_type_table[0][LP_EFFICIENT_CORE_PROC] > 0 && homogeneous_streams)': 1,
    '_streams > 1 || (_thread_preferred_core_type == ov::hint::SchedulingCoreType::ECORE_ONLY && !_cpu_pinning);': 1,
    '!homogeneous_streams && _streams == 1 &&': 1,
    'while (_threads_per_stream > 1)': 1,
    'if (proc_type_table[0][LP_EFFICIENT_CORE_PROC] > 0 && homogeneous_streams &&\n'
    '                            _threads_per_stream > proc_type_table[i][j]) {\n'
    '                            continue;\n'
    '                        }': 1,
    'streams_num += proc_type_table[i][type] / _threads_per_stream;': 1,
    'const auto num_cores = proc_type_table[0][MAIN_CORE_PROC] + proc_type_table[0][EFFICIENT_CORE_PROC] +\n'
    '                           proc_type_table[0][LP_EFFICIENT_CORE_PROC];': 1,
    '_streams_info_table[0][PROC_TYPE] = LP_EFFICIENT_CORE_PROC;': 1,
    '_streams_info_table[0][STREAM_NUMA_NODE_ID] = _streams_info_table[1][STREAM_NUMA_NODE_ID];': 1,
    '_streams_info_table[0][STREAM_SOCKET_ID] = _streams_info_table[1][STREAM_SOCKET_ID];': 1,
}
requirements = {
    'src/inference/src/dev/threading/istreams_executor.cpp': required,
    'src/inference/src/dev/threading/cpu_streams_executor.cpp': {
        'const auto proc_types = get_org_proc_type_table();': 1,
        'get_tbb_core_type(core_type, core_types, proc_types);': 1,
    },
    'src/inference/src/dev/threading/cpu_streams_executor_internal.cpp': {
        'int get_tbb_core_type(int proc_type,': 1,
        'core_types.size() == 2 && !proc_type_table.empty() &&': 1,
        'proc_type_table[0][EFFICIENT_CORE_PROC] > 0 && proc_type_table[0][LP_EFFICIENT_CORE_PROC] > 0 &&': 1,
        'proc_type_table[0][MAIN_CORE_PROC] == 0 && proc_type_table[0][HYPER_THREADING_PROC] == 0': 1,
    },
    'src/inference/dev_api/openvino/runtime/threading/cpu_streams_executor_internal.hpp': {
        'int get_tbb_core_type(int proc_type,': 1,
        'const std::vector<std::vector<int>>& proc_type_table);': 1,
    },
}

if unguarded in text:
    raise SystemExit(f'check-lp-ecore-executor-guard: LP-unaware core-type list present in {source}')
if '_threads_per_stream = std::min(_threads_per_stream, proc_type_table[i][type]);' in text:
    raise SystemExit(f'check-lp-ecore-executor-guard: unused small pools still reduce stream width in {source}')
for relative, markers in requirements.items():
    source = root / relative
    try:
        text = source.read_text(encoding='utf-8')
    except OSError as error:
        raise SystemExit(f'check-lp-ecore-executor-guard: cannot read {source}: {error}') from error
    for spelling, count in markers.items():
        if text.count(spelling) != count:
            raise SystemExit(
                f'check-lp-ecore-executor-guard: expected {count} occurrence(s) of {spelling!r} in {source}, '
                f'found {text.count(spelling)}'
            )
print('check-lp-ecore-executor-guard: ok')
