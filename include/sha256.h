/*
 * Bitcoin Echo — SHA-256 Implementation
 *
 * SHA-256 as specified in FIPS 180-4.
 * Used throughout Bitcoin for:
 *   - Block header hashing (SHA256d)
 *   - Transaction ID computation (SHA256d)
 *   - Merkle tree construction (SHA256d)
 *   - Address generation (as part of HASH160)
 *   - Script opcodes (OP_SHA256, OP_HASH256)
 *
 * This implementation prioritizes correctness and clarity over speed.
 * No assembly, no SIMD, no hardware acceleration.
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_SHA256_H
#define ECHO_SHA256_H

#include <stddef.h>
#include <stdint.h>

/*
 * SHA-256 produces a 256-bit (32-byte) digest.
 */
#define SHA256_DIGEST_SIZE 32

/*
 * SHA-256 processes data in 512-bit (64-byte) blocks.
 */
#define SHA256_BLOCK_SIZE 64

/*
 * SHA-256 context for incremental hashing.
 *
 * Use sha256_init() to initialize, sha256_update() to feed data,
 * and sha256_final() to retrieve the digest.
 */
typedef struct {
  uint32_t state[8];                 /* Current hash state (H0-H7) */
  uint64_t count;                    /* Number of bytes processed */
  uint8_t buffer[SHA256_BLOCK_SIZE]; /* Partial block buffer */
} sha256_ctx_t;

/*
 * Initialize SHA-256 context.
 *
 * Must be called before sha256_update().
 */
void sha256_init(sha256_ctx_t *ctx);

/*
 * Feed data into SHA-256 context.
 *
 * Can be called multiple times with arbitrary-sized chunks.
 * Data is buffered internally until a complete block is available.
 */
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * Finalize SHA-256 and retrieve digest.
 *
 * Applies padding and writes the 32-byte digest to `out`.
 * The context should not be used after this call without re-initialization.
 */
void sha256_final(sha256_ctx_t *ctx, uint8_t out[SHA256_DIGEST_SIZE]);

/*
 * Compute SHA-256 of data in one call.
 *
 * Convenience function equivalent to init/update/final sequence.
 */
void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

/*
 * Compute SHA-256d (double SHA-256) of data.
 *
 * SHA256d(x) = SHA256(SHA256(x))
 *
 * This is the standard hash used in Bitcoin for:
 *   - Block header hash
 *   - Transaction ID (txid)
 *   - Merkle tree nodes
 */
void sha256d(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

/*
 * Compute SHA-256 midstate.
 *
 * For mining optimization: pre-compute the hash state after processing
 * the first 64 bytes of an 80-byte block header. The remaining 16 bytes
 * (which contain the nonce) can then be hashed incrementally.
 *
 * Parameters:
 *   data - Exactly 64 bytes (one SHA-256 block)
 *   out  - 32 bytes to receive the midstate (raw state, not finalized)
 */
void sha256_midstate(const uint8_t data[SHA256_BLOCK_SIZE],
                     uint8_t out[SHA256_DIGEST_SIZE]);

#endif /* ECHO_SHA256_H */
