#include "unity.h"

extern void test_packet_parse_valid(void);
extern void test_packet_parse_another_port(void);
extern void test_packet_parse_non_ip_packet(void);
extern void test_packet_parse_non_tcp_packet(void);
extern void test_valid_conversion(void);
extern void test_single_byte(void);
extern void test_large_value(void);
extern void test_even_length(void);
extern void test_odd_length(void);
extern void test_single_carry(void);
extern void test_double_carry(void);

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_packet_parse_valid);
    RUN_TEST(test_packet_parse_another_port);
    RUN_TEST(test_packet_parse_non_ip_packet);
    RUN_TEST(test_packet_parse_non_tcp_packet);

    RUN_TEST(test_valid_conversion);
    RUN_TEST(test_single_byte);
    RUN_TEST(test_large_value);

    RUN_TEST(test_even_length);
    RUN_TEST(test_odd_length);
    RUN_TEST(test_single_carry);
    RUN_TEST(test_double_carry);
}

