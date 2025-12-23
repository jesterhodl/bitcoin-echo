/*
 * Bitcoin Echo — libsecp256k1 Wrapper
 *
 * This file provides a thin wrapper around the vendored libsecp256k1 library.
 * It exposes simple byte-based verification functions that can be called
 * from our main secp256k1 implementation.
 *
 * IMPORTANT: This file directly includes libsecp256k1's source files to
 * avoid symbol conflicts with our own secp256k1 implementation. The libsecp
 * symbols become internal to this translation unit.
 *
 * Build once. Build right. Stop.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "secp256k1_libsecp.h"

/*
 * ============================================================================
 * Include libsecp256k1 Source Directly
 * ============================================================================
 *
 * By including the source files directly with SECP256K1_API defined as static,
 * all libsecp256k1 functions become internal to this translation unit.
 * Our wrapper functions (libsecp_*) are the only externally visible symbols.
 */

/* Include libsecp256k1 headers - we compile it separately */
#include "../../lib/secp256k1/include/secp256k1.h"
#include "../../lib/secp256k1/include/secp256k1_schnorrsig.h"
#include "../../lib/secp256k1/include/secp256k1_extrakeys.h"

/*
 * ============================================================================
 * Global Context
 * ============================================================================
 */

static secp256k1_context *g_libsecp_ctx = NULL;

static secp256k1_context *get_libsecp_context(void) {
  if (g_libsecp_ctx == NULL) {
    g_libsecp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  }
  return g_libsecp_ctx;
}

/*
 * ============================================================================
 * ECDSA Verification
 * ============================================================================
 */

int libsecp_ecdsa_verify(const uint8_t sig_compact[64],
                         const uint8_t msg_hash[32],
                         const uint8_t *pubkey_data,
                         size_t pubkey_len) {
  secp256k1_context *ctx = get_libsecp_context();

  /* Parse the public key */
  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_data, pubkey_len)) {
    return 0;
  }

  /* Parse the compact signature */
  secp256k1_ecdsa_signature sig;
  if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig_compact)) {
    return 0;
  }

  /* Normalize to lower-S (required for Bitcoin) */
  secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

  /* Verify */
  return secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pubkey);
}

int libsecp_ecdsa_verify_der(const uint8_t *sig_der,
                             size_t sig_len,
                             const uint8_t msg_hash[32],
                             const uint8_t *pubkey_data,
                             size_t pubkey_len) {
  secp256k1_context *ctx = get_libsecp_context();

  /* Parse the public key */
  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_data, pubkey_len)) {
    return 0;
  }

  /* Parse the DER signature */
  secp256k1_ecdsa_signature sig;
  if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, sig_der, sig_len)) {
    return 0;
  }

  /* Normalize to lower-S (required for Bitcoin) */
  secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

  /* Verify */
  return secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pubkey);
}

/*
 * ============================================================================
 * Schnorr Verification (BIP-340)
 * ============================================================================
 */

int libsecp_schnorr_verify(const uint8_t sig[64],
                           const uint8_t *msg,
                           size_t msg_len,
                           const uint8_t pubkey_xonly[32]) {
  secp256k1_context *ctx = get_libsecp_context();

  /* Parse x-only public key */
  secp256k1_xonly_pubkey pubkey;
  if (!secp256k1_xonly_pubkey_parse(ctx, &pubkey, pubkey_xonly)) {
    return 0;
  }

  /* Verify BIP-340 Schnorr signature */
  return secp256k1_schnorrsig_verify(ctx, sig, msg, msg_len, &pubkey);
}

/*
 * ============================================================================
 * Public Key Parsing
 * ============================================================================
 */

int libsecp_pubkey_parse(const uint8_t *input,
                         size_t input_len,
                         uint8_t output_uncompressed[65]) {
  secp256k1_context *ctx = get_libsecp_context();

  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, input, input_len)) {
    return 0;
  }

  /* Serialize as uncompressed to get x and y coordinates */
  size_t outlen = 65;
  secp256k1_ec_pubkey_serialize(ctx, output_uncompressed, &outlen, &pubkey,
                                 SECP256K1_EC_UNCOMPRESSED);

  return 1;
}

int libsecp_xonly_pubkey_parse(const uint8_t input[32],
                               uint8_t output_uncompressed[65]) {
  secp256k1_context *ctx = get_libsecp_context();

  secp256k1_xonly_pubkey xonly;
  if (!secp256k1_xonly_pubkey_parse(ctx, &xonly, input)) {
    return 0;
  }

  /* For x-only, the y-coordinate is implicitly even.
   * We construct the compressed form: 0x02 || x (32 bytes) */
  output_uncompressed[0] = 0x02;
  memcpy(output_uncompressed + 1, input, 32);

  return 1;
}

/*
 * ============================================================================
 * Signature Parsing
 * ============================================================================
 */

int libsecp_ecdsa_sig_parse_der(const uint8_t *input,
                                size_t input_len,
                                uint8_t output_compact[64]) {
  secp256k1_context *ctx = get_libsecp_context();

  secp256k1_ecdsa_signature sig;
  if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, input, input_len)) {
    return 0;
  }

  /* Serialize as compact (r || s, 64 bytes) */
  secp256k1_ecdsa_signature_serialize_compact(ctx, output_compact, &sig);

  return 1;
}
