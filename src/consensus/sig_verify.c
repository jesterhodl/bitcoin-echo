/*
 * Bitcoin Echo — Signature Verification Implementation
 *
 * sig_verify.c — the quantum succession seam implementation
 *
 * This file contains the unified signature verification dispatcher.
 * All signature verification in the consensus engine flows through
 * this single point.
 *
 * IMPLEMENTATION NOTE:
 * We call libsecp256k1 directly for maximum performance. No wrapper
 * layers, no intermediate type conversions. Raw bytes in, boolean out.
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
#include <stddef.h>
#include <stdint.h>

/*
 * libsecp256k1 direct includes - no wrapper layer
 */
#include "../../lib/secp256k1/include/secp256k1.h"
#include "../../lib/secp256k1/include/secp256k1_schnorrsig.h"
#include "../../lib/secp256k1/include/secp256k1_extrakeys.h"
#include "../../lib/secp256k1/contrib/lax_der_parsing.h"

/*
 * Static libsecp256k1 context - lazily initialized, never freed.
 * SECP256K1_CONTEXT_NONE is sufficient for verification-only operations.
 */
static secp256k1_context *g_ctx = NULL;

static secp256k1_context *get_context(void) {
  if (g_ctx == NULL) {
    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  }
  return g_ctx;
}

/*
 * Verify a signature against a message hash and public key.
 *
 * Dispatches to the appropriate verification function based on type.
 * Calls libsecp256k1 directly for maximum performance.
 */
int sig_verify(sig_type_t type, const uint8_t *sig, size_t sig_len,
               const uint8_t *hash, const uint8_t *pubkey, size_t pubkey_len,
               uint32_t flags) {
  /* Validate inputs */
  if (sig == NULL || hash == NULL || pubkey == NULL) {
    return 0;
  }

  secp256k1_context *ctx = get_context();
  if (ctx == NULL) {
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

    /* Parse public key */
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey, pubkey_len)) {
      return 0;
    }

    /* Parse signature - strict or lax depending on flags */
    secp256k1_ecdsa_signature parsed_sig;
    if (flags & SIG_VERIFY_STRICT_DER) {
      /* Post-BIP-66: strict DER parsing */
      if (!secp256k1_ecdsa_signature_parse_der(ctx, &parsed_sig, sig,
                                               sig_len)) {
        return 0;
      }
    } else {
      /* Pre-BIP-66: lax DER parsing for historical signatures */
      if (!ecdsa_signature_parse_der_lax(ctx, &parsed_sig, sig, sig_len)) {
        return 0;
      }
    }

    /* Normalize to lower-S (required for Bitcoin consensus) */
    secp256k1_ecdsa_signature_normalize(ctx, &parsed_sig, &parsed_sig);

    /* Verify */
    return secp256k1_ecdsa_verify(ctx, &parsed_sig, hash, &pk);
  }

  case SIG_SCHNORR: {
    /*
     * Schnorr verification (Taproot / SegWit v1)
     *
     * Signature: 64 bytes (r || s)
     * Public key: 32 bytes (x-only)
     * Hash: 32-byte sighash
     */

    /* Validate signature length (exactly 64 bytes) */
    if (sig_len != 64) {
      return 0;
    }

    /* Validate public key length (exactly 32 bytes for x-only) */
    if (pubkey_len != 32) {
      return 0;
    }

    /* Parse x-only public key */
    secp256k1_xonly_pubkey xonly_pk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pk, pubkey)) {
      return 0;
    }

    /* Verify BIP-340 Schnorr signature */
    return secp256k1_schnorrsig_verify(ctx, sig, hash, 32, &xonly_pk);
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
