/*
 * Bitcoin Echo — ECDSA Verification Tests
 *
 * Test vectors from Bitcoin Core and libsecp256k1.
 *
 * Build once. Build right. Stop.
 */

#include <stdio.h>
#include <string.h>
#include "secp256k1.h"

static int tests_run = 0;
static int tests_passed = 0;

static int hex_to_bytes(uint8_t *out, const char *hex, size_t out_len)
{
    size_t i;
    size_t hex_len = strlen(hex);

    if (hex_len != out_len * 2) {
        return 0;
    }

    for (i = 0; i < out_len; i++) {
        unsigned int val;
        if (sscanf(hex + i * 2, "%02x", &val) != 1) {
            return 0;
        }
        out[i] = (uint8_t)val;
    }
    return 1;
}

/*
 * ============================================================================
 * DER Parsing Tests
 * ============================================================================
 */

static void test_der_valid(void)
{
    secp256k1_ecdsa_sig_t sig;

    tests_run++;

    /*
     * Valid DER signature from Bitcoin transaction
     * r = 0x7a...e7, s = 0x7b...6d
     */
    uint8_t der[] = {
        0x30, 0x44,  /* SEQUENCE, 68 bytes */
        0x02, 0x20,  /* INTEGER, 32 bytes (r) */
        0x7a, 0x06, 0x2f, 0x3f, 0xcd, 0x4a, 0xc5, 0xe8,
        0x5c, 0x5b, 0x95, 0x4c, 0x5e, 0x27, 0x50, 0x26,
        0x34, 0x82, 0x8b, 0x92, 0xf2, 0xc9, 0xeb, 0x72,
        0xf6, 0x56, 0x6c, 0xeb, 0xd3, 0x42, 0xb8, 0xe7,
        0x02, 0x20,  /* INTEGER, 32 bytes (s) */
        0x7b, 0xa4, 0x36, 0xd8, 0x58, 0xca, 0x8d, 0xbb,
        0x3d, 0x2c, 0x1e, 0xe0, 0x14, 0x05, 0xf4, 0xe6,
        0xc3, 0x3a, 0x5d, 0x6b, 0x50, 0x3f, 0x0a, 0xa2,
        0xc4, 0x21, 0x7a, 0x42, 0x8d, 0xef, 0x2f, 0x6d
    };

    if (secp256k1_ecdsa_sig_parse_der(&sig, der, sizeof(der))) {
        tests_passed++;
        printf("  [PASS] Valid DER signature (64-byte r,s)\n");
    } else {
        printf("  [FAIL] Valid DER signature (64-byte r,s)\n");
    }
}

static void test_der_with_leading_zero(void)
{
    secp256k1_ecdsa_sig_t sig;

    tests_run++;

    /*
     * Valid signature with leading zero on r (high bit set)
     */
    uint8_t der[] = {
        0x30, 0x45,  /* SEQUENCE, 69 bytes */
        0x02, 0x21,  /* INTEGER, 33 bytes (r with leading zero) */
        0x00,
        0x80, 0x06, 0x2f, 0x3f, 0xcd, 0x4a, 0xc5, 0xe8,
        0x5c, 0x5b, 0x95, 0x4c, 0x5e, 0x27, 0x50, 0x26,
        0x34, 0x82, 0x8b, 0x92, 0xf2, 0xc9, 0xeb, 0x72,
        0xf6, 0x56, 0x6c, 0xeb, 0xd3, 0x42, 0xb8, 0xe7,
        0x02, 0x20,  /* INTEGER, 32 bytes (s) */
        0x7b, 0xa4, 0x36, 0xd8, 0x58, 0xca, 0x8d, 0xbb,
        0x3d, 0x2c, 0x1e, 0xe0, 0x14, 0x05, 0xf4, 0xe6,
        0xc3, 0x3a, 0x5d, 0x6b, 0x50, 0x3f, 0x0a, 0xa2,
        0xc4, 0x21, 0x7a, 0x42, 0x8d, 0xef, 0x2f, 0x6d
    };

    if (secp256k1_ecdsa_sig_parse_der(&sig, der, sizeof(der))) {
        tests_passed++;
        printf("  [PASS] DER with required leading zero\n");
    } else {
        printf("  [FAIL] DER with required leading zero\n");
    }
}

static void test_der_short_r(void)
{
    secp256k1_ecdsa_sig_t sig;

    tests_run++;

    /*
     * Valid signature with short r (< 32 bytes)
     */
    uint8_t der[] = {
        0x30, 0x25,  /* SEQUENCE, 37 bytes */
        0x02, 0x01,  /* INTEGER, 1 byte (r) */
        0x01,        /* r = 1 */
        0x02, 0x20,  /* INTEGER, 32 bytes (s) */
        0x7b, 0xa4, 0x36, 0xd8, 0x58, 0xca, 0x8d, 0xbb,
        0x3d, 0x2c, 0x1e, 0xe0, 0x14, 0x05, 0xf4, 0xe6,
        0xc3, 0x3a, 0x5d, 0x6b, 0x50, 0x3f, 0x0a, 0xa2,
        0xc4, 0x21, 0x7a, 0x42, 0x8d, 0xef, 0x2f, 0x6d
    };

    if (secp256k1_ecdsa_sig_parse_der(&sig, der, sizeof(der))) {
        tests_passed++;
        printf("  [PASS] DER with short r\n");
    } else {
        printf("  [FAIL] DER with short r\n");
    }
}

static void test_der_invalid_tag(void)
{
    secp256k1_ecdsa_sig_t sig;

    tests_run++;

    /* Wrong SEQUENCE tag */
    uint8_t der[] = {
        0x31, 0x06,  /* Wrong tag (should be 0x30) */
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x02
    };

    if (!secp256k1_ecdsa_sig_parse_der(&sig, der, sizeof(der))) {
        tests_passed++;
        printf("  [PASS] Reject invalid SEQUENCE tag\n");
    } else {
        printf("  [FAIL] Reject invalid SEQUENCE tag\n");
    }
}

static void test_der_unnecessary_zero(void)
{
    secp256k1_ecdsa_sig_t sig;

    tests_run++;

    /*
     * Invalid: unnecessary leading zero (high bit not set)
     */
    uint8_t der[] = {
        0x30, 0x08,
        0x02, 0x02,  /* INTEGER, 2 bytes */
        0x00, 0x01,  /* Unnecessary leading zero - 0x01 doesn't have high bit set */
        0x02, 0x02,
        0x00, 0x02
    };

    if (!secp256k1_ecdsa_sig_parse_der(&sig, der, sizeof(der))) {
        tests_passed++;
        printf("  [PASS] Reject unnecessary leading zero\n");
    } else {
        printf("  [FAIL] Reject unnecessary leading zero\n");
    }
}

static void test_der_negative(void)
{
    secp256k1_ecdsa_sig_t sig;

    tests_run++;

    /* Invalid: negative integer (high bit set, no leading zero) */
    uint8_t der[] = {
        0x30, 0x06,
        0x02, 0x01,
        0x80,        /* Negative (high bit set) */
        0x02, 0x01,
        0x02
    };

    if (!secp256k1_ecdsa_sig_parse_der(&sig, der, sizeof(der))) {
        tests_passed++;
        printf("  [PASS] Reject negative integer\n");
    } else {
        printf("  [FAIL] Reject negative integer\n");
    }
}

static void test_der_zero_r(void)
{
    secp256k1_ecdsa_sig_t sig;

    tests_run++;

    /* Invalid: r = 0 */
    uint8_t der[] = {
        0x30, 0x06,
        0x02, 0x01,
        0x00,        /* r = 0 */
        0x02, 0x01,
        0x01
    };

    if (!secp256k1_ecdsa_sig_parse_der(&sig, der, sizeof(der))) {
        tests_passed++;
        printf("  [PASS] Reject r = 0\n");
    } else {
        printf("  [FAIL] Reject r = 0\n");
    }
}

static void test_der_length_mismatch(void)
{
    secp256k1_ecdsa_sig_t sig;

    tests_run++;

    /* Invalid: length byte doesn't match content */
    uint8_t der[] = {
        0x30, 0x07,  /* Claims 7 bytes but only 6 follow */
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x02
    };

    if (!secp256k1_ecdsa_sig_parse_der(&sig, der, sizeof(der))) {
        tests_passed++;
        printf("  [PASS] Reject length mismatch\n");
    } else {
        printf("  [FAIL] Reject length mismatch\n");
    }
}

static void test_der_extra_bytes(void)
{
    secp256k1_ecdsa_sig_t sig;

    tests_run++;

    /* Invalid: extra bytes after signature */
    uint8_t der[] = {
        0x30, 0x06,
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x02,
        0xFF  /* Extra byte */
    };

    if (!secp256k1_ecdsa_sig_parse_der(&sig, der, sizeof(der))) {
        tests_passed++;
        printf("  [PASS] Reject extra bytes\n");
    } else {
        printf("  [FAIL] Reject extra bytes\n");
    }
}

/*
 * ============================================================================
 * Scalar Arithmetic Tests
 * ============================================================================
 */

static void test_scalar_mul_basic(void)
{
    secp256k1_scalar_t a, b, r;
    int i;

    tests_run++;

    /* 2 * 3 = 6 */
    for (i = 0; i < 8; i++) {
        a.limbs[i] = 0;
        b.limbs[i] = 0;
    }
    a.limbs[0] = 2;
    b.limbs[0] = 3;

    secp256k1_scalar_mul(&r, &a, &b);

    if (r.limbs[0] == 6 && r.limbs[1] == 0 && r.limbs[7] == 0) {
        tests_passed++;
        printf("  [PASS] Scalar mul: 2 * 3 = 6\n");
    } else {
        printf("  [FAIL] Scalar mul: 2 * 3 = 6 (got %u)\n", r.limbs[0]);
    }
}

static void test_scalar_inv(void)
{
    secp256k1_scalar_t a, inv, product;
    int i;
    int is_one;

    tests_run++;

    /* inv(7) * 7 should equal 1 */
    for (i = 0; i < 8; i++) {
        a.limbs[i] = 0;
    }
    a.limbs[0] = 7;

    secp256k1_scalar_inv(&inv, &a);
    secp256k1_scalar_mul(&product, &inv, &a);

    is_one = (product.limbs[0] == 1);
    for (i = 1; i < 8; i++) {
        if (product.limbs[i] != 0) is_one = 0;
    }

    if (is_one) {
        tests_passed++;
        printf("  [PASS] Scalar inv: inv(7) * 7 = 1\n");
    } else {
        printf("  [FAIL] Scalar inv: inv(7) * 7 = 1\n");
    }
}

/*
 * ============================================================================
 * ECDSA Verification Tests
 * ============================================================================
 */

/*
 * Test mathematically computed ECDSA signature.
 *
 * For private key d=1, public key P=G, message hash e=1, nonce k=1:
 *   r = (k*G).x mod n = Gx (since Gx < n)
 *   s = k^(-1) * (e + r*d) mod n = 1 * (1 + Gx) = 1 + Gx mod n
 *
 * Gx = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
 * r  = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
 * s  = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81799
 */
static void test_ecdsa_valid_signature(void)
{
    secp256k1_ecdsa_sig_t sig;
    secp256k1_point_t pubkey;
    uint8_t msg_hash[32];
    uint8_t pubkey_bytes[33];

    tests_run++;

    /* Public key = G (compressed format) */
    hex_to_bytes(pubkey_bytes,
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        33);

    if (!secp256k1_pubkey_parse(&pubkey, pubkey_bytes, 33)) {
        printf("  [FAIL] Valid ECDSA sig - pubkey parse failed\n");
        return;
    }

    /* Message hash e = 1 */
    hex_to_bytes(msg_hash,
        "0000000000000000000000000000000000000000000000000000000000000001",
        32);

    /*
     * DER signature with:
     * r = Gx = 79BE667E...F81798 (32 bytes, no leading zero since 0x79 < 0x80)
     * s = Gx + 1 = 79BE667E...F81799 (32 bytes, no leading zero)
     */
    uint8_t der_sig[] = {
        0x30, 0x44,  /* SEQUENCE, 68 bytes */
        0x02, 0x20,  /* INTEGER, 32 bytes (r) */
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        0x02, 0x20,  /* INTEGER, 32 bytes (s) */
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x99
    };

    if (!secp256k1_ecdsa_sig_parse_der(&sig, der_sig, sizeof(der_sig))) {
        printf("  [FAIL] Valid ECDSA sig - DER parse failed\n");
        return;
    }

    if (secp256k1_ecdsa_verify(&sig, msg_hash, &pubkey)) {
        tests_passed++;
        printf("  [PASS] Valid ECDSA signature verification\n");
    } else {
        printf("  [FAIL] Valid ECDSA signature verification\n");
    }
}

/*
 * Test with a different message - should fail
 */
static void test_ecdsa_wrong_message(void)
{
    secp256k1_ecdsa_sig_t sig;
    secp256k1_point_t pubkey;
    uint8_t msg_hash[32];
    uint8_t pubkey_bytes[33];

    tests_run++;

    hex_to_bytes(pubkey_bytes,
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        33);

    secp256k1_pubkey_parse(&pubkey, pubkey_bytes, 33);

    /* Different message hash (e = 2 instead of 1) */
    hex_to_bytes(msg_hash,
        "0000000000000000000000000000000000000000000000000000000000000002",
        32);

    /* Signature for e=1, should fail for e=2 */
    uint8_t der_sig[] = {
        0x30, 0x44,
        0x02, 0x20,
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        0x02, 0x20,
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x99
    };

    secp256k1_ecdsa_sig_parse_der(&sig, der_sig, sizeof(der_sig));

    if (!secp256k1_ecdsa_verify(&sig, msg_hash, &pubkey)) {
        tests_passed++;
        printf("  [PASS] Reject wrong message\n");
    } else {
        printf("  [FAIL] Reject wrong message\n");
    }
}

/*
 * Test with wrong public key - should fail
 */
static void test_ecdsa_wrong_pubkey(void)
{
    secp256k1_ecdsa_sig_t sig;
    secp256k1_point_t pubkey;
    uint8_t msg_hash[32];
    uint8_t pubkey_bytes[33];

    tests_run++;

    /* 2*G instead of G (pubkey for d=2, not d=1) */
    hex_to_bytes(pubkey_bytes,
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        33);

    secp256k1_pubkey_parse(&pubkey, pubkey_bytes, 33);

    hex_to_bytes(msg_hash,
        "0000000000000000000000000000000000000000000000000000000000000001",
        32);

    /* Signature for d=1, should fail for d=2 */
    uint8_t der_sig[] = {
        0x30, 0x44,
        0x02, 0x20,
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        0x02, 0x20,
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x99
    };

    secp256k1_ecdsa_sig_parse_der(&sig, der_sig, sizeof(der_sig));

    if (!secp256k1_ecdsa_verify(&sig, msg_hash, &pubkey)) {
        tests_passed++;
        printf("  [PASS] Reject wrong pubkey\n");
    } else {
        printf("  [FAIL] Reject wrong pubkey\n");
    }
}

/*
 * Test with nonce k=2 for variety.
 *
 * For d=1, e=1, k=2:
 *   R = 2*G
 *   r = (2*G).x = c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
 *   s = k^(-1) * (e + r*d) = 2^(-1) * (1 + r) mod n
 *
 * 2^(-1) mod n = (n+1)/2 since n is odd
 * n+1 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142
 * (n+1)/2 = 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
 */
static void test_ecdsa_different_nonce(void)
{
    secp256k1_ecdsa_sig_t sig;
    secp256k1_point_t pubkey;
    uint8_t msg_hash[32];
    uint8_t pubkey_bytes[33];
    uint8_t r_bytes[32];

    tests_run++;

    /* Public key = G */
    hex_to_bytes(pubkey_bytes,
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        33);

    if (!secp256k1_pubkey_parse(&pubkey, pubkey_bytes, 33)) {
        printf("  [FAIL] Different nonce - pubkey parse failed\n");
        return;
    }

    /* Message hash e = 1 */
    hex_to_bytes(msg_hash,
        "0000000000000000000000000000000000000000000000000000000000000001",
        32);

    /* r = (2*G).x */
    hex_to_bytes(r_bytes,
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        32);

    /*
     * s = 2^(-1) * (1 + r) mod n
     * Computed: we need to compute this value
     * For now, set signature directly
     */
    secp256k1_scalar_set_bytes(&sig.r, r_bytes);

    /* Compute s = inv(2) * (1 + r) mod n */
    secp256k1_scalar_t two, inv_two, one_plus_r, one_scalar;
    int i;

    /* two = 2 */
    two.limbs[0] = 2;
    for (i = 1; i < 8; i++) two.limbs[i] = 0;

    /* one = 1 */
    one_scalar.limbs[0] = 1;
    for (i = 1; i < 8; i++) one_scalar.limbs[i] = 0;

    /* inv_two = 2^(-1) mod n */
    secp256k1_scalar_inv(&inv_two, &two);

    /* one_plus_r = 1 + r */
    secp256k1_scalar_add(&one_plus_r, &one_scalar, &sig.r);

    /* s = inv_two * one_plus_r */
    secp256k1_scalar_mul(&sig.s, &inv_two, &one_plus_r);

    if (secp256k1_ecdsa_verify(&sig, msg_hash, &pubkey)) {
        tests_passed++;
        printf("  [PASS] ECDSA with k=2 nonce\n");
    } else {
        printf("  [FAIL] ECDSA with k=2 nonce\n");
    }
}

/*
 * Test infinity pubkey rejection
 */
static void test_ecdsa_infinity_pubkey(void)
{
    secp256k1_ecdsa_sig_t sig;
    secp256k1_point_t pubkey;
    uint8_t msg_hash[32] = {1};

    tests_run++;

    /* Set pubkey to infinity */
    secp256k1_point_set_infinity(&pubkey);

    /* Any valid-looking signature */
    sig.r.limbs[0] = 1;
    sig.s.limbs[0] = 1;
    int i;
    for (i = 1; i < 8; i++) {
        sig.r.limbs[i] = 0;
        sig.s.limbs[i] = 0;
    }

    if (!secp256k1_ecdsa_verify(&sig, msg_hash, &pubkey)) {
        tests_passed++;
        printf("  [PASS] Reject infinity pubkey\n");
    } else {
        printf("  [FAIL] Reject infinity pubkey\n");
    }
}

/*
 * Additional test: verify with uncompressed pubkey
 */
static void test_ecdsa_uncompressed_pubkey(void)
{
    secp256k1_ecdsa_sig_t sig;
    secp256k1_point_t pubkey;
    uint8_t msg_hash[32];
    uint8_t pubkey_bytes[65];

    tests_run++;

    /* Generator G in uncompressed format */
    hex_to_bytes(pubkey_bytes,
        "04"
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        65);

    if (!secp256k1_pubkey_parse(&pubkey, pubkey_bytes, 65)) {
        printf("  [FAIL] Uncompressed pubkey - parse failed\n");
        return;
    }

    hex_to_bytes(msg_hash,
        "0000000000000000000000000000000000000000000000000000000000000001",
        32);

    /* Same signature as test_ecdsa_valid_signature (d=1, e=1, k=1) */
    uint8_t der_sig[] = {
        0x30, 0x44,
        0x02, 0x20,
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        0x02, 0x20,
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x99
    };

    if (!secp256k1_ecdsa_sig_parse_der(&sig, der_sig, sizeof(der_sig))) {
        printf("  [FAIL] Uncompressed pubkey - DER parse failed\n");
        return;
    }

    if (secp256k1_ecdsa_verify(&sig, msg_hash, &pubkey)) {
        tests_passed++;
        printf("  [PASS] ECDSA with uncompressed pubkey\n");
    } else {
        printf("  [FAIL] ECDSA with uncompressed pubkey\n");
    }
}

int main(void)
{
    printf("ECDSA Verification Tests\n");
    printf("========================\n\n");

    printf("DER Parsing:\n");
    test_der_valid();
    test_der_with_leading_zero();
    test_der_short_r();
    test_der_invalid_tag();
    test_der_unnecessary_zero();
    test_der_negative();
    test_der_zero_r();
    test_der_length_mismatch();
    test_der_extra_bytes();

    printf("\nScalar Arithmetic:\n");
    test_scalar_mul_basic();
    test_scalar_inv();

    printf("\nECDSA Verification:\n");
    test_ecdsa_valid_signature();
    test_ecdsa_wrong_message();
    test_ecdsa_wrong_pubkey();
    test_ecdsa_different_nonce();
    test_ecdsa_infinity_pubkey();
    test_ecdsa_uncompressed_pubkey();

    printf("\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
