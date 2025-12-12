/**
 * Bitcoin Echo — Transaction Memory Pool
 *
 * The mempool holds unconfirmed transactions awaiting inclusion in a block.
 * This module implements:
 *
 * - Transaction acceptance policy
 * - Fee-based prioritization
 * - Size limits and eviction
 * - Transaction relay policy
 * - Conflict detection (double-spend)
 *
 * Policy decisions:
 * - Minimum fee rate to accept (anti-spam)
 * - Maximum mempool size (memory limits)
 * - Transaction expiry (remove stale transactions)
 * - Replace-by-fee (RBF) for signaling transactions
 *
 * This is NOT consensus-critical code. Different nodes may have different
 * mempool policies and still agree on the valid chain.
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_MEMPOOL_H
#define ECHO_MEMPOOL_H

#include "block.h"
#include "echo_types.h"
#include "tx.h"
#include "utxo.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * ============================================================================
 * MEMPOOL POLICY CONSTANTS
 * ============================================================================
 *
 * These compile-time constants define mempool policy. They are NOT consensus
 * rules and can be adjusted without affecting chain validity.
 */

/**
 * Default maximum mempool size in bytes.
 * 300 MB is the Bitcoin Core default.
 */
#define MEMPOOL_DEFAULT_MAX_SIZE ((size_t)300 * 1024 * 1024)

/**
 * Default minimum fee rate in satoshis per 1000 virtual bytes.
 * Transactions below this rate are rejected.
 * 1000 sat/kvB = 1 sat/vB (the "dust limit" fee rate)
 */
#define MEMPOOL_DEFAULT_MIN_FEE_RATE 1000ULL

/**
 * Default transaction expiry time in seconds.
 * Transactions older than this are evicted (336 hours = 2 weeks).
 */
#define MEMPOOL_DEFAULT_EXPIRY_TIME ((uint64_t)336 * 60 * 60)

/**
 * Maximum number of transactions in a mempool entry's ancestor set.
 * Limits chain depth for package relay considerations.
 */
#define MEMPOOL_MAX_ANCESTORS ((size_t)25)

/**
 * Maximum number of transactions in a mempool entry's descendant set.
 */
#define MEMPOOL_MAX_DESCENDANTS ((size_t)25)

/**
 * Maximum total size of ancestor transactions (in virtual bytes).
 */
#define MEMPOOL_MAX_ANCESTOR_SIZE ((size_t)101 * 1000)

/**
 * Maximum total size of descendant transactions (in virtual bytes).
 */
#define MEMPOOL_MAX_DESCENDANT_SIZE ((size_t)101 * 1000)

/**
 * RBF (Replace-By-Fee) increment: replacement must pay at least this much
 * more in fee rate (satoshis per 1000 vbytes).
 */
#define MEMPOOL_RBF_INCREMENT 1000

/**
 * Maximum number of transactions that can be replaced by a single RBF.
 */
#define MEMPOOL_MAX_REPLACEMENT_COUNT 100

/*
 * ============================================================================
 * MEMPOOL ENTRY
 * ============================================================================
 */

/**
 * Mempool entry: a transaction plus its mempool-specific metadata.
 */
typedef struct mempool_entry {
  tx_t tx;               /* The transaction (owned by entry) */
  hash256_t txid;        /* Cached txid */
  hash256_t wtxid;       /* Cached wtxid */
  satoshi_t fee;         /* Transaction fee in satoshis */
  size_t vsize;          /* Virtual size in vbytes */
  uint64_t fee_rate;     /* Fee rate in sat/kvB (fee * 1000 / vsize) */
  uint64_t time_added;   /* Unix timestamp when added to mempool */
  uint32_t height_added; /* Block height when added */

  /* Ancestor/descendant tracking */
  size_t ancestor_count;     /* Number of unconfirmed ancestors */
  size_t descendant_count;   /* Number of unconfirmed descendants */
  satoshi_t ancestor_fees;   /* Total fees of ancestors + self */
  size_t ancestor_size;      /* Total vsize of ancestors + self */
  satoshi_t descendant_fees; /* Total fees of descendants + self */
  size_t descendant_size;    /* Total vsize of descendants + self */

  /* RBF signaling */
  bool signals_rbf; /* True if any input has sequence < 0xffffffff-1 */

  /* Internal linkage (implementation detail) */
  struct mempool_entry *next; /* Hash table chain */
  struct mempool_entry *prev; /* For ordered iteration */
} mempool_entry_t;

/*
 * ============================================================================
 * MEMPOOL REJECTION REASONS
 * ============================================================================
 */

/**
 * Reason codes for mempool rejection.
 * More specific than general error codes.
 */
typedef enum {
  MEMPOOL_ACCEPT_OK = 0,

  /* Policy rejections (not invalid, just not accepted) */
  MEMPOOL_REJECT_FEE_TOO_LOW,     /* Fee rate below minimum */
  MEMPOOL_REJECT_MEMPOOL_FULL,    /* Mempool at capacity, won't evict for this */
  MEMPOOL_REJECT_TOO_MANY_ANCESTORS,   /* Ancestor count exceeds limit */
  MEMPOOL_REJECT_TOO_MANY_DESCENDANTS, /* Descendant count exceeds limit */
  MEMPOOL_REJECT_ANCESTOR_SIZE,   /* Ancestor total size exceeds limit */
  MEMPOOL_REJECT_DESCENDANT_SIZE, /* Descendant total size exceeds limit */
  MEMPOOL_REJECT_RBF_INSUFFICIENT_FEE, /* RBF replacement fee too low */
  MEMPOOL_REJECT_RBF_TOO_MANY_REPLACED, /* RBF would replace too many txs */
  MEMPOOL_REJECT_NONSTANDARD,     /* Non-standard transaction */

  /* Conflict rejections */
  MEMPOOL_REJECT_CONFLICT,    /* Conflicts with existing tx (double-spend) */
  MEMPOOL_REJECT_DUPLICATE,   /* Transaction already in mempool */
  MEMPOOL_REJECT_CONFIRMED,   /* Transaction already confirmed */

  /* Validation rejections (actually invalid) */
  MEMPOOL_REJECT_INVALID,         /* Transaction failed validation */
  MEMPOOL_REJECT_MISSING_INPUTS,  /* Some inputs not found (UTXO or mempool) */
  MEMPOOL_REJECT_PREMATURE_SPEND, /* Coinbase not mature */

} mempool_reject_t;

/**
 * Result of mempool acceptance attempt.
 */
typedef struct {
  mempool_reject_t reason;  /* Rejection reason (ACCEPT_OK if accepted) */
  satoshi_t required_fee;   /* Minimum fee required for acceptance */
  size_t conflicts_count;   /* Number of conflicting transactions */
  hash256_t first_conflict; /* Hash of first conflicting tx */
} mempool_accept_result_t;

/*
 * ============================================================================
 * MEMPOOL STRUCTURE
 * ============================================================================
 */

/**
 * The mempool (opaque structure, implementation in mempool.c).
 */
typedef struct mempool mempool_t;

/**
 * Mempool configuration.
 */
typedef struct {
  size_t max_size;         /* Maximum size in bytes */
  uint64_t min_fee_rate;   /* Minimum fee rate in sat/kvB */
  uint64_t expiry_time;    /* Transaction expiry in seconds */
  size_t max_ancestors;    /* Max ancestor count per tx */
  size_t max_descendants;  /* Max descendant count per tx */
  size_t max_ancestor_size;   /* Max total ancestor size */
  size_t max_descendant_size; /* Max total descendant size */
} mempool_config_t;

/**
 * Callbacks for mempool operations.
 *
 * The mempool needs to access the UTXO set and current chain state.
 */
typedef struct {
  /**
   * Look up a UTXO by outpoint.
   *
   * Parameters:
   *   outpoint - The outpoint to look up
   *   entry    - Output: the UTXO entry if found
   *   ctx      - User context
   *
   * Returns:
   *   ECHO_OK if found, ECHO_ERR_NOT_FOUND otherwise.
   */
  echo_result_t (*get_utxo)(const outpoint_t *outpoint, utxo_entry_t *entry,
                            void *ctx);

  /**
   * Get current block height.
   */
  uint32_t (*get_height)(void *ctx);

  /**
   * Get current median time past (for locktime validation).
   */
  uint32_t (*get_median_time)(void *ctx);

  /**
   * Announce new transaction to network.
   * Called when a transaction is accepted into the mempool.
   *
   * Parameters:
   *   txid - Hash of accepted transaction
   *   ctx  - User context
   */
  void (*announce_tx)(const hash256_t *txid, void *ctx);

  /* User context passed to all callbacks */
  void *ctx;
} mempool_callbacks_t;

/*
 * ============================================================================
 * MEMPOOL LIFECYCLE
 * ============================================================================
 */

/**
 * Create a new mempool with default configuration.
 *
 * Returns:
 *   Newly allocated mempool, or NULL on allocation failure.
 */
mempool_t *mempool_create(void);

/**
 * Create a new mempool with custom configuration.
 *
 * Parameters:
 *   config - Mempool configuration
 *
 * Returns:
 *   Newly allocated mempool, or NULL on allocation failure.
 */
mempool_t *mempool_create_with_config(const mempool_config_t *config);

/**
 * Destroy mempool and free all resources.
 *
 * Parameters:
 *   mp - Mempool to destroy (may be NULL)
 */
void mempool_destroy(mempool_t *mp);

/**
 * Set callbacks for UTXO lookup and chain state.
 *
 * Parameters:
 *   mp        - Mempool
 *   callbacks - Callback functions
 */
void mempool_set_callbacks(mempool_t *mp, const mempool_callbacks_t *callbacks);

/*
 * ============================================================================
 * TRANSACTION OPERATIONS
 * ============================================================================
 */

/**
 * Attempt to add a transaction to the mempool.
 *
 * This performs:
 * 1. Duplicate check (already in mempool?)
 * 2. Validation (inputs exist, scripts pass, values valid)
 * 3. Policy checks (fee rate, ancestor limits, etc.)
 * 4. Conflict detection (double-spend check)
 * 5. RBF processing if applicable
 * 6. Eviction if needed to make room
 *
 * Parameters:
 *   mp     - Mempool
 *   tx     - Transaction to add (will be copied)
 *   result - Output: detailed result information
 *
 * Returns:
 *   ECHO_OK if transaction was accepted
 *   ECHO_ERR_DUPLICATE if already in mempool
 *   ECHO_ERR_INVALID if transaction invalid
 *   ECHO_ERR_FULL if mempool full and tx not good enough
 */
echo_result_t mempool_add(mempool_t *mp, const tx_t *tx,
                          mempool_accept_result_t *result);

/**
 * Remove a transaction from the mempool by txid.
 *
 * Also removes any dependent transactions (descendants).
 *
 * Parameters:
 *   mp   - Mempool
 *   txid - Transaction ID to remove
 *
 * Returns:
 *   ECHO_OK if removed
 *   ECHO_ERR_NOT_FOUND if not in mempool
 */
echo_result_t mempool_remove(mempool_t *mp, const hash256_t *txid);

/**
 * Remove transactions that conflict with a confirmed block.
 *
 * Called when a new block is connected. Removes:
 * - Transactions included in the block
 * - Transactions that spend outputs consumed by block transactions
 *
 * Parameters:
 *   mp    - Mempool
 *   block - The confirmed block
 */
void mempool_remove_for_block(mempool_t *mp, const block_t *block);

/**
 * Re-add transactions that were removed due to a disconnected block.
 *
 * Called during chain reorganization.
 *
 * Parameters:
 *   mp    - Mempool
 *   block - The disconnected block
 */
void mempool_readd_for_disconnect(mempool_t *mp, const block_t *block);

/**
 * Look up a transaction in the mempool by txid.
 *
 * Parameters:
 *   mp   - Mempool
 *   txid - Transaction ID to find
 *
 * Returns:
 *   Pointer to mempool entry if found, NULL otherwise.
 *   The returned pointer is valid until the entry is removed.
 */
const mempool_entry_t *mempool_lookup(const mempool_t *mp,
                                      const hash256_t *txid);

/**
 * Look up a transaction in the mempool by wtxid.
 *
 * Parameters:
 *   mp    - Mempool
 *   wtxid - Witness transaction ID to find
 *
 * Returns:
 *   Pointer to mempool entry if found, NULL otherwise.
 */
const mempool_entry_t *mempool_lookup_wtxid(const mempool_t *mp,
                                            const hash256_t *wtxid);

/**
 * Check if a transaction is in the mempool.
 *
 * Parameters:
 *   mp   - Mempool
 *   txid - Transaction ID to check
 *
 * Returns:
 *   true if transaction is in mempool, false otherwise.
 */
bool mempool_exists(const mempool_t *mp, const hash256_t *txid);

/**
 * Check if an outpoint is spent by a mempool transaction.
 *
 * Parameters:
 *   mp       - Mempool
 *   outpoint - Outpoint to check
 *
 * Returns:
 *   true if outpoint is spent by a mempool tx, false otherwise.
 */
bool mempool_is_spent(const mempool_t *mp, const outpoint_t *outpoint);

/**
 * Get the mempool transaction that spends an outpoint.
 *
 * Parameters:
 *   mp       - Mempool
 *   outpoint - Outpoint to check
 *
 * Returns:
 *   Pointer to the mempool entry that spends this outpoint, or NULL.
 */
const mempool_entry_t *mempool_get_spender(const mempool_t *mp,
                                           const outpoint_t *outpoint);

/*
 * ============================================================================
 * MEMPOOL STATISTICS
 * ============================================================================
 */

/**
 * Get number of transactions in mempool.
 */
size_t mempool_size(const mempool_t *mp);

/**
 * Get total size of mempool in bytes.
 */
size_t mempool_bytes(const mempool_t *mp);

/**
 * Get current minimum fee rate for acceptance.
 *
 * This may be higher than the configured minimum if the mempool is full.
 *
 * Parameters:
 *   mp - Mempool
 *
 * Returns:
 *   Minimum fee rate in satoshis per 1000 virtual bytes.
 */
uint64_t mempool_min_fee_rate(const mempool_t *mp);

/**
 * Mempool statistics structure.
 */
typedef struct {
  size_t tx_count;        /* Number of transactions */
  size_t total_bytes;     /* Total size in bytes */
  size_t total_vsize;     /* Total virtual size */
  satoshi_t total_fees;   /* Total fees of all transactions */
  uint64_t min_fee_rate;  /* Current minimum fee rate */
  uint64_t median_fee_rate; /* Median fee rate */
  size_t max_ancestor_count; /* Max ancestor count of any tx */
  size_t max_descendant_count; /* Max descendant count of any tx */
} mempool_stats_t;

/**
 * Get mempool statistics.
 *
 * Parameters:
 *   mp    - Mempool
 *   stats - Output: statistics structure
 */
void mempool_get_stats(const mempool_t *mp, mempool_stats_t *stats);

/*
 * ============================================================================
 * TRANSACTION SELECTION (FOR MINING)
 * ============================================================================
 */

/**
 * Iterator for selecting transactions for block building.
 */
typedef struct mempool_iter mempool_iter_t;

/**
 * Create iterator for selecting transactions by fee rate.
 *
 * Transactions are returned in descending order by fee rate.
 * This is used for building block templates.
 *
 * Parameters:
 *   mp - Mempool
 *
 * Returns:
 *   Iterator, or NULL on allocation failure.
 */
mempool_iter_t *mempool_iter_by_fee(const mempool_t *mp);

/**
 * Get next transaction from iterator.
 *
 * Parameters:
 *   iter - Iterator
 *
 * Returns:
 *   Next mempool entry, or NULL if no more entries.
 */
const mempool_entry_t *mempool_iter_next(mempool_iter_t *iter);

/**
 * Destroy iterator.
 *
 * Parameters:
 *   iter - Iterator to destroy (may be NULL)
 */
void mempool_iter_destroy(mempool_iter_t *iter);

/**
 * Select transactions for a block.
 *
 * Selects transactions in fee-rate order up to the given weight limit.
 * Respects ancestor relationships (won't select child before parent).
 *
 * Parameters:
 *   mp         - Mempool
 *   txs        - Output array for selected transactions
 *   max_txs    - Maximum number of transactions to select
 *   max_weight - Maximum total weight in weight units
 *   selected   - Output: number of transactions selected
 *
 * Returns:
 *   ECHO_OK on success
 */
echo_result_t mempool_select_for_block(const mempool_t *mp,
                                       const mempool_entry_t **txs,
                                       size_t max_txs, size_t max_weight,
                                       size_t *selected);

/*
 * ============================================================================
 * MAINTENANCE
 * ============================================================================
 */

/**
 * Remove expired transactions.
 *
 * Should be called periodically (e.g., once per minute).
 *
 * Parameters:
 *   mp           - Mempool
 *   current_time - Current Unix timestamp
 *
 * Returns:
 *   Number of transactions evicted.
 */
size_t mempool_expire(mempool_t *mp, uint64_t current_time);

/**
 * Trim mempool to size limit.
 *
 * Evicts lowest fee-rate transactions until size is below limit.
 *
 * Parameters:
 *   mp - Mempool
 *
 * Returns:
 *   Number of transactions evicted.
 */
size_t mempool_trim(mempool_t *mp);

/**
 * Clear all transactions from mempool.
 *
 * Parameters:
 *   mp - Mempool
 */
void mempool_clear(mempool_t *mp);

/*
 * ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================
 */

/**
 * Get human-readable string for rejection reason.
 *
 * Parameters:
 *   reason - Rejection reason code
 *
 * Returns:
 *   Static string describing the reason.
 */
const char *mempool_reject_string(mempool_reject_t reason);

/**
 * Initialize accept result to success state.
 *
 * Parameters:
 *   result - Result structure to initialize
 */
void mempool_accept_result_init(mempool_accept_result_t *result);

/**
 * Calculate fee rate from fee and vsize.
 *
 * Parameters:
 *   fee   - Fee in satoshis
 *   vsize - Virtual size in bytes
 *
 * Returns:
 *   Fee rate in satoshis per 1000 virtual bytes.
 */
uint64_t mempool_calc_fee_rate(satoshi_t fee, size_t vsize);

#endif /* ECHO_MEMPOOL_H */
