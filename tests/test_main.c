#include "unity.h"

extern void test_packet_parse_valid(void);
extern void test_packet_parse_another_port(void);
extern void test_packet_parse_non_ip_packet(void);
extern void test_packet_parse_non_tcp_packet(void);
extern void test_valid_conversion(void);
extern void test_single_byte(void);
extern void test_large_value(void);

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

    return UNITY_END();
}
