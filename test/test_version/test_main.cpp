// Host unit tests for the protocol version-drop counter (lib/mesh/version_stats).
//
//   pio test -e native

#include <unity.h>
#include "version_stats.h"

using namespace mesh;

static void test_starts_clean() {
    VersionStats v;
    TEST_ASSERT_FALSE(v.any());
    TEST_ASSERT_EQUAL_UINT32(0, v.drops());
    TEST_ASSERT_EQUAL_UINT8(0xFF, v.last_ver());   // sentinel: none seen
}

static void test_counts_and_records_last() {
    VersionStats v;
    TEST_ASSERT_EQUAL_UINT32(1, v.on_foreign(1));  // saw a v1 frame
    TEST_ASSERT_TRUE(v.any());
    TEST_ASSERT_EQUAL_UINT8(1, v.last_ver());
    TEST_ASSERT_EQUAL_UINT32(2, v.on_foreign(3));  // then a v3 frame
    TEST_ASSERT_EQUAL_UINT8(3, v.last_ver());       // last-seen updates
    TEST_ASSERT_EQUAL_UINT32(2, v.drops());
}

static void test_reset() {
    VersionStats v;
    v.on_foreign(1); v.on_foreign(1);
    v.reset();
    TEST_ASSERT_FALSE(v.any());
    TEST_ASSERT_EQUAL_UINT32(0, v.drops());
    TEST_ASSERT_EQUAL_UINT8(0xFF, v.last_ver());
}

void setUp() {}
void tearDown() {}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_starts_clean);
    RUN_TEST(test_counts_and_records_last);
    RUN_TEST(test_reset);
    return UNITY_END();
}
