/*
 * Bitcoin Echo — Block Data Structures
 *
 * This header defines the structures for Bitcoin blocks, including
 * the 80-byte block header and full block with transactions.
 *
 * Block header structure (80 bytes):
 *   - version (4 bytes, signed)
 *   - previous block hash (32 bytes)
 *   - merkle root (32 bytes)
 *   - timestamp (4 bytes, Unix time)
 *   - bits (4 bytes, compact difficulty target)
 *   - nonce (4 bytes)
 *
 * Full block:
 *   - header (80 bytes)
 *   - transaction count (varint)
 *   - transactions (variable)
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_BLOCK_H
#define ECHO_BLOCK_H

#include "echo_types.h"
#include "tx.h"
#include <stdint.h>

/*
 * Block header size in bytes.
 */
#define BLOCK_HEADER_SIZE 80

/*
 * Block size limits.
 */
#define BLOCK_MAX_SIZE 4000000   /* Max block size in bytes (4MB) */
#define BLOCK_MAX_WEIGHT 4000000 /* Max block weight (4M weight units) */
#define BLOCK_MAX_SIGOPS 80000   /* Max signature operations */

/*
 * Genesis block constants (mainnet).
 */
#define GENESIS_BLOCK_VERSION 1
#define GENESIS_BLOCK_TIMESTAMP 1231006505
#define GENESIS_BLOCK_BITS 0x1d00ffff
#define GENESIS_BLOCK_NONCE 2083236893

/*
 * Difficulty adjustment constants.
 */
#define DIFFICULTY_ADJUSTMENT_INTERVAL 2016 /* Blocks between adjustments */
#define TARGET_TIMESPAN 1209600             /* 2 weeks in seconds */
#define TARGET_SPACING 600                  /* 10 minutes in seconds */

/*
 * Block header structure.
 * Exactly 80 bytes when serialized.
 */
typedef struct {
  int32_t version;       /* Block version (signed per protocol) */
  hash256_t prev_hash;   /* Hash of previous block header */
  hash256_t merkle_root; /* Merkle root of transactions */
  uint32_t timestamp;    /* Unix timestamp */
  uint32_t bits;         /* Compact difficulty target */
  uint32_t nonce;        /* Nonce for proof-of-work */
} block_header_t;

/*
 * Full block structure.
 */
typedef struct {
  block_header_t header; /* 80-byte header */
  tx_t *txs;             /* Array of transactions (owned) */
  size_t tx_count;       /* Number of transactions */
} block_t;

/*
 * Initialize a block structure to empty/safe state.
 *
 * Parameters:
 *   block - Block to initialize
 */
void block_init(block_t *block);

/*
 * Free all memory owned by a block.
 *
 * Parameters:
 *   block - Block to free (structure itself is not freed)
 */
void block_free(block_t *block);

/*
 * Parse a block header from raw bytes.
 *
 * Parameters:
 *   data     - Raw header bytes (must be at least 80 bytes)
 *   data_len - Length of data
 *   header   - Output: parsed header
 *
 * Returns:
 *   ECHO_OK on success
 *   ECHO_ERR_NULL_PARAM if data or header is NULL
 *   ECHO_ERR_TRUNCATED if data_len < 80
 */
echo_result_t block_header_parse(const uint8_t *data, size_t data_len,
                                 block_header_t *header);

/*
 * Serialize a block header to bytes.
 *
 * Parameters:
 *   header  - Header to serialize
 *   buf     - Output buffer (must be at least 80 bytes)
 *   buf_len - Size of output buffer
 *
 * Returns:
 *   ECHO_OK on success
 *   ECHO_ERR_NULL_PARAM if header or buf is NULL
 *   ECHO_ERR_BUFFER_TOO_SMALL if buf_len < 80
 */
echo_result_t block_header_serialize(const block_header_t *header, uint8_t *buf,
                                     size_t buf_len);

/*
 * Compute the block hash (hash of the 80-byte header).
 *
 * The block hash is SHA256d of the serialized header.
 * Note: The hash is stored in little-endian byte order internally,
 * but displayed in big-endian (reversed) format by convention.
 *
 * Parameters:
 *   header - Block header
 *   hash   - Output: 32-byte block hash
 *
 * Returns:
 *   ECHO_OK on success
 *   ECHO_ERR_NULL_PARAM if header or hash is NULL
 */
echo_result_t block_header_hash(const block_header_t *header, hash256_t *hash);

/*
 * Parse a full block from raw bytes.
 *
 * This function allocates memory for transactions.
 * Call block_free() when done.
 *
 * Parameters:
 *   data     - Raw block bytes
 *   data_len - Length of data
 *   block    - Output: parsed block
 *   consumed - Output: bytes consumed (may be NULL)
 *
 * Returns:
 *   ECHO_OK on success
 *   ECHO_ERR_NULL_PARAM if data or block is NULL
 *   ECHO_ERR_TRUNCATED if data too short
 *   ECHO_ERR_INVALID_FORMAT if block malformed
 *   ECHO_ERR_OUT_OF_MEMORY if allocation fails
 */
echo_result_t block_parse(const uint8_t *data, size_t data_len, block_t *block,
                          size_t *consumed);

/*
 * Compute the serialized size of a full block.
 *
 * Parameters:
 *   block - Block to measure
 *
 * Returns:
 *   Serialized size in bytes, or 0 if block is NULL
 */
size_t block_serialize_size(const block_t *block);

/*
 * Serialize a full block to bytes.
 *
 * Parameters:
 *   block   - Block to serialize
 *   buf     - Output buffer
 *   buf_len - Size of output buffer
 *   written - Output: bytes written (may be NULL)
 *
 * Returns:
 *   ECHO_OK on success
 *   ECHO_ERR_NULL_PARAM if block or buf is NULL
 *   ECHO_ERR_BUFFER_TOO_SMALL if buffer insufficient
 */
echo_result_t block_serialize(const block_t *block, uint8_t *buf,
                              size_t buf_len, size_t *written);

/*
 * Compute block weight.
 *
 * Weight = (base_size * 3) + total_size
 * Where base_size excludes witness data from all transactions.
 *
 * Parameters:
 *   block - Block to measure
 *
 * Returns:
 *   Block weight in weight units, or 0 if block is NULL
 */
size_t block_weight(const block_t *block);

/*
 * Convert compact "bits" field to 256-bit target.
 *
 * The bits field encodes the target as:
 *   target = mantissa * 256^(exponent - 3)
 * where exponent is the high byte and mantissa is the low 3 bytes.
 *
 * Parameters:
 *   bits   - Compact target representation
 *   target - Output: 256-bit target (32 bytes, little-endian)
 *
 * Returns:
 *   ECHO_OK on success
 *   ECHO_ERR_NULL_PARAM if target is NULL
 */
echo_result_t block_bits_to_target(uint32_t bits, hash256_t *target);

/*
 * Convert 256-bit target to compact "bits" field.
 *
 * Parameters:
 *   target - 256-bit target (32 bytes, little-endian)
 *   bits   - Output: compact target representation
 *
 * Returns:
 *   ECHO_OK on success
 *   ECHO_ERR_NULL_PARAM if target or bits is NULL
 */
echo_result_t block_target_to_bits(const hash256_t *target, uint32_t *bits);

/*
 * Check if a block hash meets the target difficulty.
 *
 * The hash (interpreted as a little-endian 256-bit number) must be
 * less than or equal to the target.
 *
 * Parameters:
 *   hash   - Block hash
 *   target - Target threshold
 *
 * Returns:
 *   ECHO_TRUE if hash <= target, ECHO_FALSE otherwise
 */
echo_bool_t block_hash_meets_target(const hash256_t *hash,
                                    const hash256_t *target);

/*
 * Get the genesis block header (mainnet).
 *
 * Parameters:
 *   header - Output: genesis block header
 */
void block_genesis_header(block_header_t *header);

#endif /* ECHO_BLOCK_H */
