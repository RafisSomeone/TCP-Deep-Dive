#include <stdio.h>
#include <sys/socket.h>

#include "packet.h"
#include "unity.h"

void test_valid_conversion(void) {
  unsigned char buffer[] = {0x01, 0x23, 0x45, 0x67};
  TEST_ASSERT_EQUAL_UINT32(9029, range_hex_to_decimal(buffer, 1, 3));
}

void test_single_byte(void) {
  unsigned char buffer[] = {0xAA};
  TEST_ASSERT_EQUAL_UINT32(170, range_hex_to_decimal(buffer, 0, 1));
}

void test_large_value(void) {
  unsigned char buffer[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
  TEST_ASSERT_EQUAL_UINT32(81985529216486895,
                           range_hex_to_decimal(buffer, 0, 8));
}
