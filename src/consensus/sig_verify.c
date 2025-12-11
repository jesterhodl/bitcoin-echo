/*
 * Bitcoin Echo — Signature Verification Implementation
 *
 * sig_verify.c — the quantum succession seam implementation
 *
 * This file contains the unified signature verification dispatcher.
 * All signature verification in the consensus engine flows through
 * this single point.
 *
 * SUCCESSION GUIDANCE FOR FUTURE DEVELOPERS:
 *
 * When the Bitcoin network adopts a quantum-resistant signature scheme,
 * modify this file (and only this file for signature changes):
 *
 *   1. Add new value to sig_type_t in sig_verify.h (e.g., SIG_DILITHIUM)
 *   2. Add verification case in sig_verify() below
 *   3. Update sig_type_known() to recognize the new type
 *   4. Add test vectors for the new scheme
 *   5. Verify all existing tests still pass
 *
 * Do not modify other files unless the Bitcoin protocol requires it.
 * The signature verification seam is intentionally narrow.
 *
 * Build once. Build right. Stop.
 */

#include "sig_verify.h"
#include "secp256k1.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Verify a signature against a message hash and public key.
 *
 * Dispatches to the appropriate verification function based on type.
 */
int sig_verify(sig_type_t type, const uint8_t *sig, size_t sig_len,
               const uint8_t *hash, const uint8_t *pubkey, size_t pubkey_len) {
  /* Validate inputs */
  if (sig == NULL || hash == NULL || pubkey == NULL) {
    return 0;
  }

  switch (type) {
  case SIG_ECDSA: {
    /*
     * ECDSA verification (pre-SegWit and SegWit v0)
     *
     * Signature: DER-encoded (typically 70-72 bytes)
     * Public key: compressed (33) or uncompressed (65) bytes
     * Hash: 32-byte sighash
     */
    secp256k1_ecdsa_sig_t ecdsa_sig;
    secp256k1_point_t pk_point;

    /* Validate signature length (DER: min 8, max 73 bytes) */
    if (sig_len < 8 || sig_len > 73) {
      return 0;
    }

    /* Validate public key length */
    if (pubkey_len != 33 && pubkey_len != 65) {
      return 0;
    }

    /* Parse DER-encoded signature */
    if (!secp256k1_ecdsa_sig_parse_der(&ecdsa_sig, sig, sig_len)) {
      return 0;
    }

    /* Parse public key */
    if (!secp256k1_pubkey_parse(&pk_point, pubkey, pubkey_len)) {
      return 0;
    }

    /* Verify signature */
    return secp256k1_ecdsa_verify(&ecdsa_sig, hash, &pk_point);
  }

  case SIG_SCHNORR: {
    /*
     * Schnorr verification (Taproot / SegWit v1)
     *
     * Signature: 64 bytes (r || s)
     * Public key: 32 bytes (x-only)
     * Hash: 32-byte sighash (note: Schnorr uses the raw message,
     *       but in Bitcoin context this is always the sighash)
     */

    /* Validate signature length (exactly 64 bytes) */
    if (sig_len != 64) {
      return 0;
    }

    /* Validate public key length (exactly 32 bytes for x-only) */
    if (pubkey_len != 32) {
      return 0;
    }

    /*
     * Note: For BIP-340 Schnorr, the 'hash' parameter is passed
     * as the message. In Bitcoin's Taproot context, this would
     * be the 32-byte sighash. The secp256k1_schnorr_verify function
     * handles the tagged hash internally.
     */
    return secp256k1_schnorr_verify(sig, hash, 32, pubkey);
  }

  default:
    /* Unknown signature type */
    return 0;
  }
}

/*
 * Check whether a signature type is known.
 *
 * Returns 1 for known types, 0 for unknown.
 */
int sig_type_known(sig_type_t type) {
  switch (type) {
  case SIG_ECDSA:
  case SIG_SCHNORR:
    return 1;
  default:
    return 0;
  }
}
