/**
 * Unit tests for protocol message structures
 */

#include "protocol.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void name(void); \
    static void run_##name(void) { \
        tests_run++; \
        name(); \
        tests_passed++; \
        printf("."); \
        fflush(stdout); \
    } \
    static void name(void)

#define RUN_TEST(name) run_##name()

/* Test command parsing */
TEST(test_msg_parse_command_valid) {
    /* Test all valid commands */
    assert(msg_parse_command("version") == MSG_VERSION);
    assert(msg_parse_command("verack") == MSG_VERACK);
    assert(msg_parse_command("ping") == MSG_PING);
    assert(msg_parse_command("pong") == MSG_PONG);
    assert(msg_parse_command("inv") == MSG_INV);
    assert(msg_parse_command("getdata") == MSG_GETDATA);
    assert(msg_parse_command("notfound") == MSG_NOTFOUND);
    assert(msg_parse_command("block") == MSG_BLOCK);
    assert(msg_parse_command("tx") == MSG_TX);
    assert(msg_parse_command("addr") == MSG_ADDR);
    assert(msg_parse_command("getaddr") == MSG_GETADDR);
    assert(msg_parse_command("getheaders") == MSG_GETHEADERS);
    assert(msg_parse_command("getblocks") == MSG_GETBLOCKS);
    assert(msg_parse_command("headers") == MSG_HEADERS);
    assert(msg_parse_command("reject") == MSG_REJECT);
    assert(msg_parse_command("sendheaders") == MSG_SENDHEADERS);
    assert(msg_parse_command("feefilter") == MSG_FEEFILTER);
    assert(msg_parse_command("sendcmpct") == MSG_SENDCMPCT);
    assert(msg_parse_command("wtxidrelay") == MSG_WTXIDRELAY);
}

TEST(test_msg_parse_command_invalid) {
    /* Test unknown commands */
    assert(msg_parse_command("unknown") == MSG_UNKNOWN);
    assert(msg_parse_command("xyz") == MSG_UNKNOWN);
    assert(msg_parse_command("") == MSG_UNKNOWN);
}

TEST(test_msg_parse_command_no_null) {
    /* Command without null terminator should be rejected */
    char no_null[COMMAND_LEN];
    memset(no_null, 'x', COMMAND_LEN);
    assert(msg_parse_command(no_null) == MSG_UNKNOWN);
}

TEST(test_msg_parse_command_padded) {
    /* Command with null padding (standard wire format) */
    char padded[COMMAND_LEN];
    memset(padded, 0, COMMAND_LEN);
    strcpy(padded, "version");
    assert(msg_parse_command(padded) == MSG_VERSION);
}

/* Test command string retrieval */
TEST(test_msg_command_string) {
    assert(strcmp(msg_command_string(MSG_VERSION), "version") == 0);
    assert(strcmp(msg_command_string(MSG_VERACK), "verack") == 0);
    assert(strcmp(msg_command_string(MSG_PING), "ping") == 0);
    assert(strcmp(msg_command_string(MSG_PONG), "pong") == 0);
    assert(strcmp(msg_command_string(MSG_INV), "inv") == 0);
    assert(strcmp(msg_command_string(MSG_GETDATA), "getdata") == 0);
    assert(strcmp(msg_command_string(MSG_NOTFOUND), "notfound") == 0);
    assert(strcmp(msg_command_string(MSG_BLOCK), "block") == 0);
    assert(strcmp(msg_command_string(MSG_TX), "tx") == 0);
    assert(strcmp(msg_command_string(MSG_ADDR), "addr") == 0);
    assert(strcmp(msg_command_string(MSG_GETADDR), "getaddr") == 0);
    assert(strcmp(msg_command_string(MSG_GETHEADERS), "getheaders") == 0);
    assert(strcmp(msg_command_string(MSG_GETBLOCKS), "getblocks") == 0);
    assert(strcmp(msg_command_string(MSG_HEADERS), "headers") == 0);
    assert(strcmp(msg_command_string(MSG_REJECT), "reject") == 0);
    assert(strcmp(msg_command_string(MSG_SENDHEADERS), "sendheaders") == 0);
    assert(strcmp(msg_command_string(MSG_FEEFILTER), "feefilter") == 0);
    assert(strcmp(msg_command_string(MSG_SENDCMPCT), "sendcmpct") == 0);
    assert(strcmp(msg_command_string(MSG_WTXIDRELAY), "wtxidrelay") == 0);
}

TEST(test_msg_command_string_unknown) {
    /* Unknown type should return NULL */
    assert(msg_command_string(MSG_UNKNOWN) == NULL);
    assert(msg_command_string((msg_type_t)999) == NULL);
}

/* Test checksum computation */
TEST(test_msg_checksum_empty) {
    /* Empty payload */
    uint32_t checksum = msg_checksum(NULL, 0);

    /* SHA256d of empty string:
     * SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     * SHA256(e3b0c442...) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
     * First 4 bytes (LE): 0xe2e0f65d
     */
    assert(checksum == 0xe2e0f65d);
}

TEST(test_msg_checksum_known) {
    /* Known payload: "hello" */
    uint8_t payload[] = "hello";
    uint32_t checksum = msg_checksum(payload, 5);

    /* SHA256d("hello"):
     * SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
     * SHA256(2cf24dba...) = 9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50
     * First 4 bytes (LE): 0xdfc99595
     */
    assert(checksum == 0xdfc99595);
}

TEST(test_msg_checksum_verack) {
    /* Verack message has empty payload, same as empty test */
    uint32_t checksum = msg_checksum(NULL, 0);
    assert(checksum == 0xe2e0f65d);
}

/* Test header validation */
TEST(test_msg_header_valid_mainnet) {
    msg_header_t header;
    header.magic = MAGIC_MAINNET;
    strcpy(header.command, "version");
    header.length = 100;
    header.checksum = 0x12345678;

    assert(msg_header_valid(&header, MAGIC_MAINNET) == ECHO_TRUE);
}

TEST(test_msg_header_valid_testnet) {
    msg_header_t header;
    header.magic = MAGIC_TESTNET;
    strcpy(header.command, "ping");
    header.length = 8;
    header.checksum = 0x12345678;

    assert(msg_header_valid(&header, MAGIC_TESTNET) == ECHO_TRUE);
}

TEST(test_msg_header_valid_regtest) {
    msg_header_t header;
    header.magic = MAGIC_REGTEST;
    strcpy(header.command, "pong");
    header.length = 8;
    header.checksum = 0x12345678;

    assert(msg_header_valid(&header, MAGIC_REGTEST) == ECHO_TRUE);
}

TEST(test_msg_header_invalid_magic) {
    msg_header_t header;
    header.magic = 0xDEADBEEF;  /* Wrong magic */
    strcpy(header.command, "version");
    header.length = 100;
    header.checksum = 0x12345678;

    assert(msg_header_valid(&header, MAGIC_MAINNET) == ECHO_FALSE);
}

TEST(test_msg_header_no_null_terminator) {
    msg_header_t header;
    header.magic = MAGIC_MAINNET;
    memset(header.command, 'x', COMMAND_LEN);  /* No null terminator */
    header.length = 100;
    header.checksum = 0x12345678;

    assert(msg_header_valid(&header, MAGIC_MAINNET) == ECHO_FALSE);
}

TEST(test_msg_header_oversized_payload) {
    msg_header_t header;
    header.magic = MAGIC_MAINNET;
    strcpy(header.command, "block");
    header.length = MAX_MESSAGE_SIZE + 1;  /* Too large */
    header.checksum = 0x12345678;

    assert(msg_header_valid(&header, MAGIC_MAINNET) == ECHO_FALSE);
}

TEST(test_msg_header_max_size_payload) {
    msg_header_t header;
    header.magic = MAGIC_MAINNET;
    strcpy(header.command, "block");
    header.length = MAX_MESSAGE_SIZE;  /* Exactly at limit */
    header.checksum = 0x12345678;

    assert(msg_header_valid(&header, MAGIC_MAINNET) == ECHO_TRUE);
}

TEST(test_msg_header_zero_length) {
    msg_header_t header;
    header.magic = MAGIC_MAINNET;
    strcpy(header.command, "verack");
    header.length = 0;  /* Empty payload */
    header.checksum = 0xe2e0f65d;

    assert(msg_header_valid(&header, MAGIC_MAINNET) == ECHO_TRUE);
}

/* Test message header size */
TEST(test_msg_header_size) {
    /* Header should be exactly 24 bytes */
    assert(sizeof(msg_header_t) == 24);
}

/* Test command padding */
TEST(test_command_padding) {
    msg_header_t header;
    header.magic = MAGIC_MAINNET;

    /* Clear command buffer */
    memset(header.command, 0, COMMAND_LEN);

    /* Set short command */
    strcpy(header.command, "ping");

    /* Remaining bytes should be zero (null padding) */
    for (size_t i = 5; i < COMMAND_LEN; i++) {
        assert(header.command[i] == 0);
    }

    header.length = 8;
    header.checksum = 0x12345678;

    assert(msg_header_valid(&header, MAGIC_MAINNET) == ECHO_TRUE);
}

/* Test round-trip command conversion */
TEST(test_command_roundtrip) {
    for (msg_type_t type = MSG_VERSION; type < MSG_UNKNOWN; type++) {
        const char *cmd = msg_command_string(type);
        assert(cmd != NULL);

        msg_type_t parsed = msg_parse_command(cmd);
        assert(parsed == type);
    }
}

/* Test inventory type constants */
TEST(test_inv_types) {
    /* Verify standard inventory types */
    assert(INV_ERROR == 0);
    assert(INV_TX == 1);
    assert(INV_BLOCK == 2);
    assert(INV_FILTERED_BLOCK == 3);

    /* Witness types have MSG_WITNESS_FLAG set */
    assert(INV_WITNESS_TX == 0x40000001);
    assert(INV_WITNESS_BLOCK == 0x40000002);
}

/* Test service flags */
TEST(test_service_flags) {
    assert(SERVICE_NODE_NETWORK == (1 << 0));
    assert(SERVICE_NODE_WITNESS == (1 << 3));
    assert(SERVICE_NODE_NETWORK_LIMITED == (1 << 10));
}

/* Test reject codes */
TEST(test_reject_codes) {
    assert(REJECT_MALFORMED == 0x01);
    assert(REJECT_INVALID == 0x10);
    assert(REJECT_OBSOLETE == 0x11);
    assert(REJECT_DUPLICATE == 0x12);
    assert(REJECT_NONSTANDARD == 0x40);
    assert(REJECT_DUST == 0x41);
    assert(REJECT_INSUFFICIENTFEE == 0x42);
    assert(REJECT_CHECKPOINT == 0x43);
}

/* Test network magic bytes */
TEST(test_magic_bytes) {
    assert(MAGIC_MAINNET == 0xD9B4BEF9);
    assert(MAGIC_TESTNET == 0x0709110B);
    assert(MAGIC_REGTEST == 0xDAB5BFFA);
}

/* Test protocol constants */
TEST(test_protocol_constants) {
    assert(PROTOCOL_VERSION == 70016);
    assert(MAX_MESSAGE_SIZE == (32 * 1024 * 1024));
    assert(MAX_INV_ENTRIES == 50000);
    assert(MAX_HEADERS_COUNT == 2000);
    assert(MAX_ADDR_COUNT == 1000);
}

int main(void) {
    printf("Running protocol message tests...\n");

    /* Command parsing tests */
    RUN_TEST(test_msg_parse_command_valid);
    RUN_TEST(test_msg_parse_command_invalid);
    RUN_TEST(test_msg_parse_command_no_null);
    RUN_TEST(test_msg_parse_command_padded);

    /* Command string tests */
    RUN_TEST(test_msg_command_string);
    RUN_TEST(test_msg_command_string_unknown);

    /* Checksum tests */
    RUN_TEST(test_msg_checksum_empty);
    RUN_TEST(test_msg_checksum_known);
    RUN_TEST(test_msg_checksum_verack);

    /* Header validation tests */
    RUN_TEST(test_msg_header_valid_mainnet);
    RUN_TEST(test_msg_header_valid_testnet);
    RUN_TEST(test_msg_header_valid_regtest);
    RUN_TEST(test_msg_header_invalid_magic);
    RUN_TEST(test_msg_header_no_null_terminator);
    RUN_TEST(test_msg_header_oversized_payload);
    RUN_TEST(test_msg_header_max_size_payload);
    RUN_TEST(test_msg_header_zero_length);
    RUN_TEST(test_msg_header_size);
    RUN_TEST(test_command_padding);

    /* Round-trip tests */
    RUN_TEST(test_command_roundtrip);

    /* Constants tests */
    RUN_TEST(test_inv_types);
    RUN_TEST(test_service_flags);
    RUN_TEST(test_reject_codes);
    RUN_TEST(test_magic_bytes);
    RUN_TEST(test_protocol_constants);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
