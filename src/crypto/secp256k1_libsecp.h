/*
 * Bitcoin Echo — libsecp256k1 Wrapper Header
 *
 * Exposes simple byte-based cryptographic verification functions that
 * wrap the vendored libsecp256k1 library.
 *
 * These functions are called from our main secp256k1.c implementation
 * to provide optimized signature verification.
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_SECP256K1_LIBSECP_H
#define ECHO_SECP256K1_LIBSECP_H

#include <stddef.h>
#include <stdint.h>

/*
 * ============================================================================
 * ECDSA Verification
 * ============================================================================
 */

/*
 * Verify ECDSA signature using libsecp256k1.
 *
 * Parameters:
 *   sig_compact: 64-byte compact signature (r || s)
 *   msg_hash: 32-byte message hash
 *   pubkey_data: serialized public key (33 or 65 bytes)
 *   pubkey_len: length of pubkey_data
 *
 * Returns 1 if valid, 0 if invalid.
 */
int libsecp_ecdsa_verify(const uint8_t sig_compact[64],
                         const uint8_t msg_hash[32],
                         const uint8_t *pubkey_data,
                         size_t pubkey_len);

/*
 * Verify DER-encoded ECDSA signature using libsecp256k1.
 *
 * Parameters:
 *   sig_der: DER-encoded signature
 *   sig_len: length of signature
 *   msg_hash: 32-byte message hash
 *   pubkey_data: serialized public key (33 or 65 bytes)
 *   pubkey_len: length of pubkey_data
 *
 * Returns 1 if valid, 0 if invalid.
 */
int libsecp_ecdsa_verify_der(const uint8_t *sig_der,
                             size_t sig_len,
                             const uint8_t msg_hash[32],
                             const uint8_t *pubkey_data,
                             size_t pubkey_len);

/*
 * ============================================================================
 * Schnorr Verification (BIP-340)
 * ============================================================================
 */

/*
 * Verify BIP-340 Schnorr signature using libsecp256k1.
 *
 * Parameters:
 *   sig: 64-byte signature
 *   msg: message bytes (any length)
 *   msg_len: length of message
 *   pubkey_xonly: 32-byte x-only public key
 *
 * Returns 1 if valid, 0 if invalid.
 */
int libsecp_schnorr_verify(const uint8_t sig[64],
                           const uint8_t *msg,
                           size_t msg_len,
                           const uint8_t pubkey_xonly[32]);

/*
 * ============================================================================
 * Public Key Parsing
 * ============================================================================
 */

/*
 * Parse a public key and output as uncompressed format.
 *
 * Parameters:
 *   input: serialized public key (33 or 65 bytes)
 *   input_len: length of input
 *   output_uncompressed: 65-byte buffer for uncompressed key
 *
 * Returns 1 on success, 0 on failure.
 */
int libsecp_pubkey_parse(const uint8_t *input,
                         size_t input_len,
                         uint8_t output_uncompressed[65]);

/*
 * Parse an x-only public key (for Schnorr/Taproot).
 *
 * Parameters:
 *   input: 32-byte x-only public key
 *   output_uncompressed: 65-byte buffer (only x is meaningful for Schnorr)
 *
 * Returns 1 if valid point on curve, 0 otherwise.
 */
int libsecp_xonly_pubkey_parse(const uint8_t input[32],
                               uint8_t output_uncompressed[65]);

/*
 * ============================================================================
 * Signature Parsing
 * ============================================================================
 */

/*
 * Parse DER-encoded signature to compact format.
 *
 * Parameters:
 *   input: DER-encoded signature
 *   input_len: length of input
 *   output_compact: 64-byte buffer for compact signature (r || s)
 *
 * Returns 1 on success, 0 on failure.
 */
int libsecp_ecdsa_sig_parse_der(const uint8_t *input,
                                size_t input_len,
                                uint8_t output_compact[64]);

#endif /* ECHO_SECP256K1_LIBSECP_H */
