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
#include "../crypto/secp256k1_libsecp.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Verify a signature against a message hash and public key.
 *
 * Dispatches to the appropriate verification function based on type.
 */
int sig_verify(sig_type_t type, const uint8_t *sig, size_t sig_len,
               const uint8_t *hash, const uint8_t *pubkey, size_t pubkey_len,
               uint32_t flags) {
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

    /* Validate signature length */
    /* Strict DER: max 73 bytes. Lax: allow longer for extra leading zeros */
    if (sig_len < 8) {
      return 0;
    }
    if ((flags & SIG_VERIFY_STRICT_DER) && sig_len > 73) {
      return 0;
    }

    /* Validate public key length */
    if (pubkey_len != 33 && pubkey_len != 65) {
      return 0;
    }

    /*
     * For strict DER (post-BIP-66 blocks), call libsecp256k1 directly
     * with the raw bytes - no intermediate parsing overhead.
     *
     * For lax DER (pre-BIP-66 historical blocks), use our lax parser
     * then convert to compact format for libsecp256k1.
     */
    if (flags & SIG_VERIFY_STRICT_DER) {
      /* Fast path: direct libsecp256k1 call with raw DER bytes */
      return libsecp_ecdsa_verify_der(sig, sig_len, hash, pubkey, pubkey_len);
    } else {
      /* Slow path: lax DER parsing for pre-BIP-66 historical signatures */
      secp256k1_ecdsa_sig_t ecdsa_sig;
      uint8_t sig_compact[64];

      if (!secp256k1_ecdsa_sig_parse_der_lax(&ecdsa_sig, sig, sig_len)) {
        return 0;
      }

      /* Convert to compact format for libsecp256k1 */
      secp256k1_scalar_get_bytes(sig_compact, &ecdsa_sig.r);
      secp256k1_scalar_get_bytes(sig_compact + 32, &ecdsa_sig.s);

      return libsecp_ecdsa_verify(sig_compact, hash, pubkey, pubkey_len);
    }
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
     * Call libsecp256k1 directly with raw bytes.
     * For BIP-340 Schnorr, the 'hash' parameter is the 32-byte sighash.
     */
    return libsecp_schnorr_verify(sig, hash, 32, pubkey);
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
