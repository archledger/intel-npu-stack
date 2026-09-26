# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.25)

project(intel_npu_stack_native LANGUAGES CXX)

include(GNUInstallDirs)
include(CTest)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Hardening)

if(NOT DEFINED INTEL_NPU_SDK_PREFIX OR INTEL_NPU_SDK_PREFIX STREQUAL "")
  message(FATAL_ERROR "INTEL_NPU_SDK_PREFIX is required")
endif()
if(NOT IS_ABSOLUTE "${INTEL_NPU_SDK_PREFIX}")
  message(FATAL_ERROR "INTEL_NPU_SDK_PREFIX must be absolute")
endif()
if(NOT IS_DIRECTORY "${INTEL_NPU_SDK_PREFIX}")
  message(FATAL_ERROR "INTEL_NPU_SDK_PREFIX must name a directory")
endif()

file(REAL_PATH "${INTEL_NPU_SDK_PREFIX}" INTEL_NPU_SDK_PREFIX_REAL)

function(intel_npu_require_in_sdk candidate description)
  file(REAL_PATH "${candidate}" candidate_real)
  string(FIND "${candidate_real}/" "${INTEL_NPU_SDK_PREFIX_REAL}/" prefix_position)
  if(NOT prefix_position EQUAL 0)
    message(FATAL_ERROR "${description} escaped INTEL_NPU_SDK_PREFIX: ${candidate_real}")
  endif()
endfunction()

find_path(
  INTEL_NPU_LEVEL_ZERO_INCLUDE_DIR
  NAMES level_zero/ze_api.h
  PATHS "${INTEL_NPU_SDK_PREFIX_REAL}"
  PATH_SUFFIXES level-zero/usr/include include
  NO_DEFAULT_PATH
  REQUIRED
)
find_library(
  INTEL_NPU_LEVEL_ZERO_LOADER
  NAMES ze_loader
  PATHS "${INTEL_NPU_SDK_PREFIX_REAL}"
  PATH_SUFFIXES level-zero/usr/lib/x86_64-linux-gnu level-zero/usr/lib64 level-zero/usr/lib lib64 lib
  NO_DEFAULT_PATH
  REQUIRED
)
find_file(
  INTEL_NPU_OPENVINO_CONFIG
  NAMES OpenVINOConfig.cmake
  PATHS "${INTEL_NPU_SDK_PREFIX_REAL}"
  PATH_SUFFIXES openvino/runtime/cmake openvino/cmake lib64/cmake/openvino2026.2.0
  NO_DEFAULT_PATH
  REQUIRED
)

intel_npu_require_in_sdk("${INTEL_NPU_LEVEL_ZERO_INCLUDE_DIR}" "Level Zero headers")
intel_npu_require_in_sdk("${INTEL_NPU_LEVEL_ZERO_LOADER}" "Level Zero loader")
intel_npu_require_in_sdk("${INTEL_NPU_OPENVINO_CONFIG}" "OpenVINO package configuration")

get_filename_component(INTEL_NPU_OPENVINO_CONFIG_DIR "${INTEL_NPU_OPENVINO_CONFIG}" DIRECTORY)
find_package(
  OpenVINO 2026.2.0 EXACT
  CONFIG REQUIRED
  PATHS "${INTEL_NPU_OPENVINO_CONFIG_DIR}"
  NO_DEFAULT_PATH
)
get_target_property(
  INTEL_NPU_OPENVINO_RUNTIME
  openvino::runtime
  IMPORTED_LOCATION_RELEASE
)
if(NOT INTEL_NPU_OPENVINO_RUNTIME)
  get_target_property(
    INTEL_NPU_OPENVINO_RUNTIME
    openvino::runtime
    IMPORTED_LOCATION_RELWITHDEBINFO
  )
endif()
if(NOT INTEL_NPU_OPENVINO_RUNTIME)
  message(FATAL_ERROR "OpenVINO runtime has no Release or RelWithDebInfo library")
endif()
intel_npu_require_in_sdk("${INTEL_NPU_OPENVINO_RUNTIME}" "OpenVINO runtime")
get_filename_component(
  INTEL_NPU_OPENVINO_RUNTIME_DIR
  "${INTEL_NPU_OPENVINO_RUNTIME}"
  DIRECTORY
)

set(CMAKE_SKIP_RPATH TRUE)

add_library(intel_npu_json STATIC common/json_writer.cpp)
target_include_directories(intel_npu_json PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
intel_npu_harden_target(intel_npu_json)

add_library(intel_npu_level_zero STATIC level_zero/probe.cpp)
target_include_directories(
  intel_npu_level_zero
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${INTEL_NPU_LEVEL_ZERO_INCLUDE_DIR}"
)
target_link_libraries(
  intel_npu_level_zero
  PUBLIC
    intel_npu_json
    "${INTEL_NPU_LEVEL_ZERO_LOADER}"
)
intel_npu_harden_target(intel_npu_level_zero)

add_library(intel_npu_openvino STATIC openvino/probe.cpp)
target_include_directories(intel_npu_openvino PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(
  intel_npu_openvino
  PUBLIC
    intel_npu_json
    openvino::runtime
)
intel_npu_harden_target(intel_npu_openvino)

add_executable(intel_npu_openvino_probe openvino/main.cpp)
set_target_properties(
  intel_npu_openvino_probe
  PROPERTIES OUTPUT_NAME intel-npu-openvino-probe
)
target_link_libraries(intel_npu_openvino_probe PRIVATE intel_npu_openvino)
intel_npu_harden_target(intel_npu_openvino_probe)

add_executable(intel_npu_level_zero_probe level_zero/main.cpp)
set_target_properties(
  intel_npu_level_zero_probe
  PROPERTIES OUTPUT_NAME intel-npu-level-zero-probe
)
target_link_libraries(intel_npu_level_zero_probe PRIVATE intel_npu_level_zero)
intel_npu_harden_target(intel_npu_level_zero_probe)

install(
  TARGETS
    intel_npu_level_zero_probe
    intel_npu_openvino_probe
  RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/intel-npu-stack"
)

if(BUILD_TESTING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_executable(noisy_openvino_probe openvino/main.cpp tests/noisy_openvino_stub.cpp)
  target_include_directories(noisy_openvino_probe PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  intel_npu_harden_target(noisy_openvino_probe)
  add_test(NAME probe_output COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/probe_output_test.py" "$<TARGET_FILE:noisy_openvino_probe>")

  add_executable(json_writer_test tests/json_writer_test.cpp)
  target_link_libraries(json_writer_test PRIVATE intel_npu_json)
  intel_npu_harden_target(json_writer_test)
  add_test(NAME json_writer COMMAND json_writer_test)

  add_executable(openvino_validation_test tests/openvino_validation_test.cpp)
  target_include_directories(openvino_validation_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(
    openvino_validation_test
    PRIVATE
      intel_npu_openvino
  )
  intel_npu_harden_target(openvino_validation_test)
  add_test(NAME openvino_validation COMMAND openvino_validation_test)
  set_tests_properties(
    openvino_validation
    PROPERTIES
      ENVIRONMENT_MODIFICATION
        "LD_LIBRARY_PATH=path_list_prepend:${INTEL_NPU_OPENVINO_RUNTIME_DIR}"
  )

  # The issue #20 reproducer, run on CPU; its NPU cases are hardware qualification.
  add_executable(npu_reshape_bounds "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/reproducers/npu-reshape-bounds.cpp")
  target_link_libraries(npu_reshape_bounds PRIVATE openvino::runtime)
  intel_npu_harden_target(npu_reshape_bounds)
  add_test(NAME npu_reshape_bounds COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/reproducer_test.py" "$<TARGET_FILE:npu_reshape_bounds>")
  set_tests_properties(
    npu_reshape_bounds
    PROPERTIES
      ENVIRONMENT_MODIFICATION
        "LD_LIBRARY_PATH=path_list_prepend:${INTEL_NPU_OPENVINO_RUNTIME_DIR}"
  )

  add_executable(level_zero_mapping_test tests/level_zero_mapping_test.cpp)
  target_link_libraries(level_zero_mapping_test PRIVATE intel_npu_level_zero)
  intel_npu_harden_target(level_zero_mapping_test)
  add_test(NAME level_zero_mapping COMMAND level_zero_mapping_test)
  get_filename_component(
    INTEL_NPU_LEVEL_ZERO_LOADER_DIR
    "${INTEL_NPU_LEVEL_ZERO_LOADER}"
    DIRECTORY
  )
  set_tests_properties(
    level_zero_mapping
    PROPERTIES
      ENVIRONMENT_MODIFICATION
        "LD_LIBRARY_PATH=path_list_prepend:${INTEL_NPU_LEVEL_ZERO_LOADER_DIR}"
  )
endif()
