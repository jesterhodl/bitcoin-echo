/*
 * Bitcoin Echo — RIPEMD-160 Test Vectors
 *
 * Test vectors from:
 *   - Original RIPEMD-160 publication (Dobbertin et al., 1996)
 *   - Bitcoin-specific HASH160 test cases
 *
 * Build once. Build right. Stop.
 */

#include <stdio.h>
#include <string.h>
#include "ripemd160.h"

/* Number of test cases */
static int tests_run = 0;
static int tests_passed = 0;

/*
 * Compare two byte arrays and return 1 if equal, 0 otherwise.
 */
static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

/*
 * Print a byte array as hex.
 */
static void print_hex(const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

/*
 * Run a single RIPEMD-160 test.
 */
static void test_ripemd160(const char *name,
                           const uint8_t *input, size_t input_len,
                           const uint8_t expected[20])
{
    uint8_t result[20];

    tests_run++;

    ripemd160(input, input_len, result);

    if (bytes_equal(result, expected, 20)) {
        tests_passed++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
        printf("    Expected: ");
        print_hex(expected, 20);
        printf("\n");
        printf("    Got:      ");
        print_hex(result, 20);
        printf("\n");
    }
}

/*
 * Run a single HASH160 test.
 */
static void test_hash160(const char *name,
                         const uint8_t *input, size_t input_len,
                         const uint8_t expected[20])
{
    uint8_t result[20];

    tests_run++;

    hash160(input, input_len, result);

    if (bytes_equal(result, expected, 20)) {
        tests_passed++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
        printf("    Expected: ");
        print_hex(expected, 20);
        printf("\n");
        printf("    Got:      ");
        print_hex(result, 20);
        printf("\n");
    }
}

/*
 * Test streaming interface produces same result as one-shot.
 */
static void test_streaming(const char *name,
                           const uint8_t *input, size_t input_len)
{
    uint8_t oneshot[20];
    uint8_t streaming[20];
    ripemd160_ctx_t ctx;
    size_t i;

    tests_run++;

    /* One-shot */
    ripemd160(input, input_len, oneshot);

    /* Streaming: feed one byte at a time */
    ripemd160_init(&ctx);
    for (i = 0; i < input_len; i++) {
        ripemd160_update(&ctx, input + i, 1);
    }
    ripemd160_final(&ctx, streaming);

    if (bytes_equal(oneshot, streaming, 20)) {
        tests_passed++;
        printf("  [PASS] %s (streaming)\n", name);
    } else {
        printf("  [FAIL] %s (streaming)\n", name);
        printf("    One-shot:  ");
        print_hex(oneshot, 20);
        printf("\n");
        printf("    Streaming: ");
        print_hex(streaming, 20);
        printf("\n");
    }
}

int main(void)
{
    printf("RIPEMD-160 Test Suite\n");
    printf("=====================\n\n");

    /*
     * Official RIPEMD-160 test vectors from the original publication.
     * Source: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
     */

    /* Empty string */
    {
        const uint8_t *input = (const uint8_t *)"";
        const uint8_t expected[20] = {
            0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
            0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31
        };
        test_ripemd160("Empty string", input, 0, expected);
    }

    /* "a" */
    {
        const uint8_t input[] = "a";
        const uint8_t expected[20] = {
            0x0b, 0xdc, 0x9d, 0x2d, 0x25, 0x6b, 0x3e, 0xe9, 0xda, 0xae,
            0x34, 0x7b, 0xe6, 0xf4, 0xdc, 0x83, 0x5a, 0x46, 0x7f, 0xfe
        };
        test_ripemd160("Single 'a'", input, 1, expected);
        test_streaming("Single 'a'", input, 1);
    }

    /* "abc" */
    {
        const uint8_t input[] = "abc";
        const uint8_t expected[20] = {
            0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04,
            0x4a, 0x8e, 0x98, 0xc6, 0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc
        };
        test_ripemd160("'abc'", input, 3, expected);
        test_streaming("'abc'", input, 3);
    }

    /* "message digest" */
    {
        const uint8_t input[] = "message digest";
        const uint8_t expected[20] = {
            0x5d, 0x06, 0x89, 0xef, 0x49, 0xd2, 0xfa, 0xe5, 0x72, 0xb8,
            0x81, 0xb1, 0x23, 0xa8, 0x5f, 0xfa, 0x21, 0x59, 0x5f, 0x36
        };
        test_ripemd160("'message digest'", input, 14, expected);
        test_streaming("'message digest'", input, 14);
    }

    /* "abcdefghijklmnopqrstuvwxyz" */
    {
        const uint8_t input[] = "abcdefghijklmnopqrstuvwxyz";
        const uint8_t expected[20] = {
            0xf7, 0x1c, 0x27, 0x10, 0x9c, 0x69, 0x2c, 0x1b, 0x56, 0xbb,
            0xdc, 0xeb, 0x5b, 0x9d, 0x28, 0x65, 0xb3, 0x70, 0x8d, 0xbc
        };
        test_ripemd160("Lowercase alphabet", input, 26, expected);
        test_streaming("Lowercase alphabet", input, 26);
    }

    /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
    {
        const uint8_t input[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        const uint8_t expected[20] = {
            0x12, 0xa0, 0x53, 0x38, 0x4a, 0x9c, 0x0c, 0x88, 0xe4, 0x05,
            0xa0, 0x6c, 0x27, 0xdc, 0xf4, 0x9a, 0xda, 0x62, 0xeb, 0x2b
        };
        test_ripemd160("448 bits", input, 56, expected);
        test_streaming("448 bits", input, 56);
    }

    /* "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" */
    {
        const uint8_t input[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const uint8_t expected[20] = {
            0xb0, 0xe2, 0x0b, 0x6e, 0x31, 0x16, 0x64, 0x02, 0x86, 0xed,
            0x3a, 0x87, 0xa5, 0x71, 0x30, 0x79, 0xb2, 0x1f, 0x51, 0x89
        };
        test_ripemd160("Alphanumeric", input, 62, expected);
        test_streaming("Alphanumeric", input, 62);
    }

    /* 8 copies of "1234567890" */
    {
        const uint8_t input[] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        const uint8_t expected[20] = {
            0x9b, 0x75, 0x2e, 0x45, 0x57, 0x3d, 0x4b, 0x39, 0xf4, 0xdb,
            0xd3, 0x32, 0x3c, 0xab, 0x82, 0xbf, 0x63, 0x32, 0x6b, 0xfb
        };
        test_ripemd160("8x '1234567890'", input, 80, expected);
        test_streaming("8x '1234567890'", input, 80);
    }

    printf("\n");
    printf("HASH160 Tests (RIPEMD160(SHA256(x)))\n");
    printf("====================================\n\n");

    /*
     * HASH160 test: empty string
     * SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     * RIPEMD160(above) = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
     */
    {
        const uint8_t *input = (const uint8_t *)"";
        const uint8_t expected[20] = {
            0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 0x37, 0x06,
            0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f, 0x7c, 0x3b, 0x9f, 0xcb
        };
        test_hash160("HASH160 empty", input, 0, expected);
    }

    /*
     * HASH160 of a compressed public key (typical Bitcoin use case).
     * This is a made-up test key, not a real Bitcoin key.
     * Public key: 02 + 32 bytes of 0x01
     */
    {
        const uint8_t pubkey[33] = {
            0x02,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        };
        /* Computed: HASH160(pubkey) = 9b596d772a3bfe0335f36c38357f026221212c90 */
        const uint8_t expected[20] = {
            0x9b, 0x59, 0x6d, 0x77, 0x2a, 0x3b, 0xfe, 0x03, 0x35, 0xf3,
            0x6c, 0x38, 0x35, 0x7f, 0x02, 0x62, 0x21, 0x21, 0x2c, 0x90
        };
        test_hash160("HASH160 pubkey", pubkey, 33, expected);
    }

    printf("\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
