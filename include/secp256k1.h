/*
 * Bitcoin Echo — secp256k1 Elliptic Curve Cryptography
 *
 * secp256k1 is the elliptic curve used by Bitcoin for digital signatures.
 * Curve equation: y² = x³ + 7 (mod p)
 *
 * Parameters:
 *   p = 2^256 - 2^32 - 977 (field prime)
 *   a = 0, b = 7 (curve coefficients)
 *   G = generator point (defined in implementation)
 *   n = order of G (number of points on curve)
 *
 * This implementation prioritizes correctness and clarity.
 * Constant-time operations are used where required for security.
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_SECP256K1_H
#define ECHO_SECP256K1_H

#include <stddef.h>
#include <stdint.h>

/*
 * ============================================================================
 * Field Element (mod p)
 * ============================================================================
 *
 * A field element is a 256-bit integer in the range [0, p-1].
 * Represented as 8 x 32-bit limbs in little-endian order.
 * limbs[0] is the least significant.
 */

typedef struct {
  uint32_t limbs[8];
} secp256k1_fe_t;

/*
 * Initialize field element to zero.
 */
void secp256k1_fe_zero(secp256k1_fe_t *r);

/*
 * Initialize field element to one.
 */
void secp256k1_fe_one(secp256k1_fe_t *r);

/*
 * Set field element from 32-byte big-endian array.
 * Returns 1 if valid (< p), 0 otherwise.
 */
int secp256k1_fe_set_bytes(secp256k1_fe_t *r, const uint8_t bytes[32]);

/*
 * Export field element to 32-byte big-endian array.
 */
void secp256k1_fe_get_bytes(uint8_t bytes[32], const secp256k1_fe_t *a);

/*
 * Set field element from a small integer.
 */
void secp256k1_fe_set_int(secp256k1_fe_t *r, uint32_t n);

/*
 * Copy field element.
 */
void secp256k1_fe_copy(secp256k1_fe_t *r, const secp256k1_fe_t *a);

/*
 * Check if field element is zero.
 * Returns 1 if zero, 0 otherwise.
 * Constant-time.
 */
int secp256k1_fe_is_zero(const secp256k1_fe_t *a);

/*
 * Check if two field elements are equal.
 * Returns 1 if equal, 0 otherwise.
 * Constant-time.
 */
int secp256k1_fe_equal(const secp256k1_fe_t *a, const secp256k1_fe_t *b);

/*
 * Compare field elements.
 * Returns -1 if a < b, 0 if a == b, 1 if a > b.
 * NOT constant-time.
 */
int secp256k1_fe_cmp(const secp256k1_fe_t *a, const secp256k1_fe_t *b);

/*
 * Negate field element: r = -a (mod p).
 */
void secp256k1_fe_neg(secp256k1_fe_t *r, const secp256k1_fe_t *a);

/*
 * Add field elements: r = a + b (mod p).
 */
void secp256k1_fe_add(secp256k1_fe_t *r, const secp256k1_fe_t *a,
                      const secp256k1_fe_t *b);

/*
 * Subtract field elements: r = a - b (mod p).
 */
void secp256k1_fe_sub(secp256k1_fe_t *r, const secp256k1_fe_t *a,
                      const secp256k1_fe_t *b);

/*
 * Multiply field elements: r = a * b (mod p).
 */
void secp256k1_fe_mul(secp256k1_fe_t *r, const secp256k1_fe_t *a,
                      const secp256k1_fe_t *b);

/*
 * Square field element: r = a² (mod p).
 * Slightly more efficient than mul(r, a, a).
 */
void secp256k1_fe_sqr(secp256k1_fe_t *r, const secp256k1_fe_t *a);

/*
 * Invert field element: r = a^(-1) (mod p).
 * Uses Fermat's little theorem: a^(-1) = a^(p-2) (mod p).
 * Undefined if a == 0.
 */
void secp256k1_fe_inv(secp256k1_fe_t *r, const secp256k1_fe_t *a);

/*
 * Compute square root: r = sqrt(a) (mod p), if it exists.
 * Returns 1 if square root exists, 0 otherwise.
 * If it exists, returns the "even" square root (least significant bit = 0).
 * Uses the fact that p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4).
 */
int secp256k1_fe_sqrt(secp256k1_fe_t *r, const secp256k1_fe_t *a);

/*
 * Check if field element is odd (least significant bit = 1).
 */
int secp256k1_fe_is_odd(const secp256k1_fe_t *a);

/*
 * ============================================================================
 * Scalar (mod n)
 * ============================================================================
 *
 * A scalar is a 256-bit integer in the range [0, n-1], where n is the
 * order of the generator point G.
 *
 * n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
 */

typedef struct {
  uint32_t limbs[8];
} secp256k1_scalar_t;

/*
 * Set scalar from 32-byte big-endian array.
 * Reduces modulo n if necessary.
 */
void secp256k1_scalar_set_bytes(secp256k1_scalar_t *r, const uint8_t bytes[32]);

/*
 * Export scalar to 32-byte big-endian array.
 */
void secp256k1_scalar_get_bytes(uint8_t bytes[32], const secp256k1_scalar_t *a);

/*
 * Check if scalar is zero.
 */
int secp256k1_scalar_is_zero(const secp256k1_scalar_t *a);

/*
 * ============================================================================
 * Curve Points
 * ============================================================================
 *
 * Points on the secp256k1 curve in Jacobian coordinates.
 * Jacobian: (X, Y, Z) represents affine point (X/Z², Y/Z³).
 * The point at infinity is represented by Z = 0.
 */

typedef struct {
  secp256k1_fe_t x;
  secp256k1_fe_t y;
  secp256k1_fe_t z;
} secp256k1_point_t;

/*
 * Set point to infinity (identity element).
 */
void secp256k1_point_set_infinity(secp256k1_point_t *r);

/*
 * Check if point is at infinity.
 */
int secp256k1_point_is_infinity(const secp256k1_point_t *p);

/*
 * Set point from affine coordinates.
 * Does NOT validate that point is on curve.
 */
void secp256k1_point_set_xy(secp256k1_point_t *r, const secp256k1_fe_t *x,
                            const secp256k1_fe_t *y);

/*
 * Get affine coordinates from point.
 * Requires point is not at infinity.
 */
void secp256k1_point_get_xy(secp256k1_fe_t *x, secp256k1_fe_t *y,
                            const secp256k1_point_t *p);

/*
 * Point doubling: r = 2*p.
 */
void secp256k1_point_double(secp256k1_point_t *r, const secp256k1_point_t *p);

/*
 * Point addition: r = p + q.
 */
void secp256k1_point_add(secp256k1_point_t *r, const secp256k1_point_t *p,
                         const secp256k1_point_t *q);

/*
 * Scalar multiplication: r = k * p.
 * Constant-time with respect to the scalar k.
 */
void secp256k1_point_mul(secp256k1_point_t *r, const secp256k1_point_t *p,
                         const secp256k1_scalar_t *k);

/*
 * Scalar multiplication with generator: r = k * G.
 */
void secp256k1_point_mul_gen(secp256k1_point_t *r, const secp256k1_scalar_t *k);

/*
 * Check if point is on the curve.
 * Returns 1 if valid, 0 otherwise.
 */
int secp256k1_point_is_valid(const secp256k1_point_t *p);

/*
 * Negate point: r = -p.
 */
void secp256k1_point_neg(secp256k1_point_t *r, const secp256k1_point_t *p);

/*
 * ============================================================================
 * Public Key Operations
 * ============================================================================
 */

/*
 * Parse public key from bytes.
 * Supports compressed (33 bytes, prefix 02/03) and uncompressed (65 bytes,
 * prefix 04). Returns 1 on success, 0 on failure.
 */
int secp256k1_pubkey_parse(secp256k1_point_t *p, const uint8_t *data,
                           size_t len);

/*
 * Serialize public key to bytes.
 * If compressed is true, outputs 33 bytes (prefix 02/03).
 * If compressed is false, outputs 65 bytes (prefix 04).
 */
void secp256k1_pubkey_serialize(uint8_t *out, const secp256k1_point_t *p,
                                int compressed);

/*
 * ============================================================================
 * Additional Scalar Operations (for ECDSA)
 * ============================================================================
 */

/*
 * Multiply two scalars: r = a * b (mod n).
 */
void secp256k1_scalar_mul(secp256k1_scalar_t *r, const secp256k1_scalar_t *a,
                          const secp256k1_scalar_t *b);

/*
 * Add two scalars: r = a + b (mod n).
 */
void secp256k1_scalar_add(secp256k1_scalar_t *r, const secp256k1_scalar_t *a,
                          const secp256k1_scalar_t *b);

/*
 * Invert scalar: r = a^(-1) (mod n).
 * Uses Fermat's little theorem: a^(-1) = a^(n-2) (mod n).
 * Undefined if a == 0.
 */
void secp256k1_scalar_inv(secp256k1_scalar_t *r, const secp256k1_scalar_t *a);

/*
 * ============================================================================
 * ECDSA Signatures (Session 2.5)
 * ============================================================================
 */

/*
 * ECDSA signature: (r, s) pair.
 * Both r and s are 256-bit scalars in range [1, n-1].
 */
typedef struct {
  secp256k1_scalar_t r;
  secp256k1_scalar_t s;
} secp256k1_ecdsa_sig_t;

/*
 * Parse DER-encoded ECDSA signature.
 *
 * Implements strict BIP-66 validation:
 *   - Signature must be strict DER with no extra bytes
 *   - r and s must be positive integers
 *   - No leading zero bytes unless required for sign
 *   - r and s must be in range [1, n-1]
 *
 * Returns 1 on success, 0 on failure.
 */
int secp256k1_ecdsa_sig_parse_der(secp256k1_ecdsa_sig_t *sig,
                                  const uint8_t *data, size_t len);

/*
 * Parse DER-encoded ECDSA signature (lax mode for pre-BIP-66 blocks).
 *
 * This is a permissive parser for historical Bitcoin signatures that may have:
 *   - Unnecessary leading zero bytes in r or s
 *   - Non-minimal length encodings
 *
 * Used for blocks before BIP-66 activation (height 363725 on mainnet).
 * For new signatures, use secp256k1_ecdsa_sig_parse_der() which enforces
 * strict BIP-66 encoding rules.
 *
 * Returns 1 on success, 0 on failure.
 */
int secp256k1_ecdsa_sig_parse_der_lax(secp256k1_ecdsa_sig_t *sig,
                                      const uint8_t *data, size_t len);

/*
 * Verify ECDSA signature.
 *
 * Algorithm:
 *   1. Check r, s in range [1, n-1]
 *   2. w = s^(-1) mod n
 *   3. u1 = e * w mod n (e is message hash)
 *   4. u2 = r * w mod n
 *   5. R = u1*G + u2*P
 *   6. If R = infinity, reject
 *   7. Accept if R.x mod n == r
 *
 * Parameters:
 *   sig: The signature (r, s)
 *   msg_hash: 32-byte SHA256d hash of the message
 *   pubkey: The public key point
 *
 * Returns 1 if valid, 0 if invalid.
 */
int echo_ecdsa_verify(const secp256k1_ecdsa_sig_t *sig,
                      const uint8_t msg_hash[32],
                      const secp256k1_point_t *pubkey);

/*
 * ============================================================================
 * Schnorr Signatures — BIP-340 (Session 2.6)
 * ============================================================================
 *
 * BIP-340 defines Schnorr signatures for Bitcoin Taproot.
 * Key differences from ECDSA:
 *   - x-only public keys (32 bytes instead of 33)
 *   - 64-byte signatures (r, s) without DER encoding
 *   - Tagged hashes for domain separation
 */

/*
 * Lift x-only public key to curve point.
 *
 * Given a 32-byte x-coordinate, recovers the point with even y.
 * This is the "lift_x" operation from BIP-340.
 *
 * Returns 1 on success, 0 if x is not a valid x-coordinate.
 */
int echo_xonly_pubkey_parse(secp256k1_point_t *p, const uint8_t xonly[32]);

/*
 * Serialize point to x-only format (32 bytes).
 * Only the x-coordinate is output.
 */
void echo_xonly_pubkey_serialize(uint8_t xonly[32],
                                 const secp256k1_point_t *p);

/*
 * BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
 *
 * Parameters:
 *   out: 32-byte output buffer
 *   tag: UTF-8 tag string (null-terminated)
 *   msg: message bytes
 *   msg_len: length of message
 */
void secp256k1_schnorr_tagged_hash(uint8_t out[32], const char *tag,
                                   const uint8_t *msg, size_t msg_len);

/*
 * Verify BIP-340 Schnorr signature.
 *
 * Algorithm:
 *   1. P = lift_x(pk) — recover point from x-only pubkey
 *   2. r = int(sig[0:32]), s = int(sig[32:64])
 *   3. If r >= p, fail
 *   4. If s >= n, fail
 *   5. e = int(tagged_hash("BIP0340/challenge", r || pk || msg)) mod n
 *   6. R = s*G - e*P
 *   7. If R is infinity or has_even_y(R) is false or x(R) != r, fail
 *   8. Return success
 *
 * Parameters:
 *   sig: 64-byte signature (r || s)
 *   msg: message bytes (any length)
 *   msg_len: length of message
 *   pubkey: 32-byte x-only public key
 *
 * Returns 1 if valid, 0 if invalid.
 */
int echo_schnorr_verify(const uint8_t sig[64], const uint8_t *msg,
                        size_t msg_len, const uint8_t pubkey[32]);

#endif /* ECHO_SECP256K1_H */
