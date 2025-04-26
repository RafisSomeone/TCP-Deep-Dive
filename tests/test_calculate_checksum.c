#include <stdio.h>
#include <sys/socket.h>

#include "packet.h"
#include "unity.h"

void test_even_length(void) {
  unsigned short data[] = {0x1234, 0x5678, 0x9ABC, 0xDEF0};
  TEST_ASSERT_EQUAL_UINT16(0x1DA6, calculate_checksum(data, sizeof(data)));
}

void test_odd_length(void) {
  unsigned short data[] = {0x1234, 0x5678, 0x9ABC};
  TEST_ASSERT_EQUAL_UINT16(0xFC96, calculate_checksum(data, sizeof(data)));
}

void test_single_carry(void) {
  unsigned short data[] = {0xFFFF, 0x0001};
  TEST_ASSERT_EQUAL_UINT16(0xFFFE, calculate_checksum(data, sizeof(data)));
}

void test_double_carry(void) {
  unsigned short data[] = {0xFFFF, 0xFFFF, 0xFFFF, 0x0002};
  TEST_ASSERT_EQUAL_UINT16(0xFFFD, calculate_checksum(data, sizeof(data)));
}
