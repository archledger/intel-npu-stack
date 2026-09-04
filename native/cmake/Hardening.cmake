# SPDX-License-Identifier: Apache-2.0

function(intel_npu_harden_target target)
  target_compile_features(${target} PRIVATE cxx_std_20)
  set_target_properties(
    ${target}
    PROPERTIES
      CXX_EXTENSIONS OFF
      CXX_VISIBILITY_PRESET hidden
      VISIBILITY_INLINES_HIDDEN YES
      POSITION_INDEPENDENT_CODE YES
  )

  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_options(
      ${target}
      PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Werror
        -fstack-protector-strong
        -fPIE
        -Wformat=2
        -Werror=format-security
        $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=3>
    )
    target_link_options(
      ${target}
      PRIVATE
        -pie
        LINKER:-z,relro,-z,now
        LINKER:--as-needed
    )
  else()
    message(FATAL_ERROR "The native helper hardening profile supports only GCC/Clang on Linux")
  endif()
endfunction()
