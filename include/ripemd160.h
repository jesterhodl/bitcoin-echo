/*
 * Bitcoin Echo — RIPEMD-160 Hash Function
 *
 * RIPEMD-160 as specified by Dobbertin, Bosselaers, and Preneel (1996).
 *
 * Used in Bitcoin for:
 *   - HASH160 = RIPEMD160(SHA256(x)) for address generation
 *   - OP_RIPEMD160 opcode
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_RIPEMD160_H
#define ECHO_RIPEMD160_H

#include <stddef.h>
#include <stdint.h>

/*
 * RIPEMD-160 produces a 160-bit (20-byte) digest.
 */
#define RIPEMD160_DIGEST_SIZE 20

/*
 * RIPEMD-160 processes data in 512-bit (64-byte) blocks.
 */
#define RIPEMD160_BLOCK_SIZE 64

/*
 * RIPEMD-160 context for streaming interface.
 *
 * Allows hashing data incrementally via init/update/final.
 */
typedef struct {
  uint32_t state[5];                    /* Current hash state */
  uint64_t count;                       /* Total bytes processed */
  uint8_t buffer[RIPEMD160_BLOCK_SIZE]; /* Partial block buffer */
} ripemd160_ctx_t;

/*
 * Initialize RIPEMD-160 context.
 *
 * Must be called before first update.
 */
void ripemd160_init(ripemd160_ctx_t *ctx);

/*
 * Update hash with additional data.
 *
 * May be called multiple times to hash data incrementally.
 * Data is buffered internally until a complete block is available.
 *
 * @param ctx   Initialized context
 * @param data  Data to hash
 * @param len   Length of data in bytes
 */
void ripemd160_update(ripemd160_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * Finalize hash and output digest.
 *
 * Applies padding and outputs the final 20-byte hash.
 * Context should not be used after this call without re-initialization.
 *
 * @param ctx   Context with all data added
 * @param out   Output buffer (must be at least 20 bytes)
 */
void ripemd160_final(ripemd160_ctx_t *ctx, uint8_t out[RIPEMD160_DIGEST_SIZE]);

/*
 * Compute RIPEMD-160 hash in one shot.
 *
 * Convenience function for hashing complete data.
 *
 * @param data  Data to hash
 * @param len   Length of data in bytes
 * @param out   Output buffer (must be at least 20 bytes)
 */
void ripemd160(const uint8_t *data, size_t len,
               uint8_t out[RIPEMD160_DIGEST_SIZE]);

/*
 * Compute HASH160 = RIPEMD160(SHA256(x)).
 *
 * This is the standard Bitcoin hash for addresses.
 * Used for P2PKH and P2SH address generation.
 *
 * @param data  Data to hash
 * @param len   Length of data in bytes
 * @param out   Output buffer (must be at least 20 bytes)
 */
void hash160(const uint8_t *data, size_t len,
             uint8_t out[RIPEMD160_DIGEST_SIZE]);

#endif /* ECHO_RIPEMD160_H */
