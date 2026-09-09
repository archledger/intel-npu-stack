// SPDX-License-Identifier: Apache-2.0
#include "vcl_tests_common.h"
#include <gtest/gtest.h>

class ParameterNames : public testing::TestWithParam<VCLTest::VCLTestsParams> {};
TEST_P(ParameterNames, PreservesParameters) {
    EXPECT_FALSE(std::get<0>(GetParam()).at("network").empty());
}
VCLTest::VCLTestsParams params(const char* network) {
    return std::make_tuple(std::unordered_map<std::string, std::string>{{"network", network}, {"device", "VPUX.4000"}});
}
INSTANTIATE_TEST_SUITE_P(ProductionNames, ParameterNames,
    testing::Values(params("mobilenet-v2"), params("mobilenet.v2"), params("simple_function")),
    VCLTest::VCLTestsCommon::getTestCaseName);
