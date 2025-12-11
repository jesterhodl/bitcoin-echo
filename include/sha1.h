/*
 * Bitcoin Echo — SHA-1 Implementation
 *
 * SHA-1 as specified in FIPS 180-4.
 * Used in Bitcoin Script for the OP_SHA1 opcode.
 *
 * Note: SHA-1 is cryptographically broken and should not be used
 * for new applications. It is included here only for compatibility
 * with the Bitcoin Script instruction set.
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_SHA1_H
#define ECHO_SHA1_H

#include <stddef.h>
#include <stdint.h>

/*
 * SHA-1 produces a 160-bit (20-byte) digest.
 */
#define SHA1_DIGEST_SIZE 20

/*
 * SHA-1 processes data in 512-bit (64-byte) blocks.
 */
#define SHA1_BLOCK_SIZE 64

/*
 * SHA-1 context for incremental hashing.
 */
typedef struct {
  uint32_t state[5];               /* Current hash state (H0-H4) */
  uint64_t count;                  /* Number of bytes processed */
  uint8_t buffer[SHA1_BLOCK_SIZE]; /* Partial block buffer */
} sha1_ctx_t;

/*
 * Initialize SHA-1 context.
 */
void sha1_init(sha1_ctx_t *ctx);

/*
 * Feed data into SHA-1 context.
 */
void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * Finalize SHA-1 and retrieve digest.
 */
void sha1_final(sha1_ctx_t *ctx, uint8_t out[SHA1_DIGEST_SIZE]);

/*
 * Compute SHA-1 of data in one call.
 */
void sha1(const uint8_t *data, size_t len, uint8_t out[SHA1_DIGEST_SIZE]);

#endif /* ECHO_SHA1_H */
