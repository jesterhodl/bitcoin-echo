/*
 * Bitcoin Echo — secp256k1 Tagged Hash Support
 *
 * This file contains only the BIP-340 tagged hash function used for Taproot.
 * All signature verification is now handled directly by libsecp256k1 through
 * sig_verify.c.
 *
 * Build once. Build right. Stop.
 */

#include "secp256k1.h"
#include "sha256.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
 *
 * The double SHA256(tag) prefix provides domain separation and allows
 * optimized implementations to precompute the midstate.
 */
void secp256k1_schnorr_tagged_hash(uint8_t out[32], const char *tag,
                                   const uint8_t *msg, size_t msg_len) {
  sha256_ctx_t ctx;
  uint8_t tag_hash[32];
  size_t tag_len;

  /* Compute SHA256(tag) */
  tag_len = strlen(tag);
  sha256((const uint8_t *)tag, tag_len, tag_hash);

  /* Compute SHA256(tag_hash || tag_hash || msg) */
  sha256_init(&ctx);
  sha256_update(&ctx, tag_hash, 32);
  sha256_update(&ctx, tag_hash, 32);
  sha256_update(&ctx, msg, msg_len);
  sha256_final(&ctx, out);
}
