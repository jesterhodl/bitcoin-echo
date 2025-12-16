/*
 * Bitcoin Echo — Policy Configuration
 *
 * IMPORTANT: This file has NO DEFAULTS.
 *
 * Policy settings control which consensus-valid transactions your node will
 * relay and temporarily store in its mempool. They do NOT affect consensus.
 * All nodes agree on valid blocks regardless of policy settings.
 *
 * Why no defaults?
 * Because policy is a VALUE JUDGMENT. There is no "neutral" setting.
 * Every policy choice reflects beliefs about what Bitcoin should be used for.
 *
 * ALL POLICY CONSTANTS BELOW ARE COMMENTED OUT.
 *
 * If you leave them commented out:
 * - The policy code checks #ifdef POLICY_CONSTANT_NAME
 * - If undefined: accept anything consensus allows (no policy restriction)
 * - If defined: enforce the policy restriction
 *
 * This means: CONSENSUS is the baseline. Policy restricts further.
 * No policy defined = relay anything that's consensus-valid.
 *
 * This is not a "safe default" - it's architectural reality.
 * Consensus defines validity. Policy optionally restricts relay.
 * If you don't define policy, you're choosing maximum permissiveness.
 *
 * Make your choices explicit. Uncomment the constants below and set values
 * that match your operational requirements and philosophical beliefs.
 */

#ifndef ECHO_POLICY_H
#define ECHO_POLICY_H

/*
 * =============================================================================
 * TRANSACTION RELAY POLICY
 * =============================================================================
 */

/*
 * Data carrier (OP_RETURN) policy - POLICY_MAX_DATACARRIER_BYTES
 *
 * OP_RETURN outputs allow embedding arbitrary data in transactions.
 * Consensus permits up to ~10KB per output (limited by max tx size).
 * Policy determines how much data your node will relay.
 *
 * Historical values:
 * - 0 bytes: No OP_RETURN relay (pre-2013)
 * - 40 bytes: Initial OP_RETURN standard (2013-2014)
 * - 80 bytes: Standard relay limit (2014-2024)
 * - 83 bytes: 80 bytes of data + 3 bytes overhead (actual wire format)
 * - 100000 bytes: Effectively unlimited (Bitcoin Core v30+)
 *
 * Your choice reflects belief about Bitcoin's purpose:
 * - 0: No data embedding allowed in relay
 * - 40-83: Minimal data for timestamping/commitments
 * - 100000: All consensus-valid data is legitimate
 *
 * UNCOMMENT ONE:
 */
// #define POLICY_MAX_DATACARRIER_BYTES 0       /* No data relay */
// #define POLICY_MAX_DATACARRIER_BYTES 80      /* Conservative: timestamps/commitments only */
// #define POLICY_MAX_DATACARRIER_BYTES 100000  /* Permissive: accept all consensus-valid data */

/*
 * Witness data filtering - POLICY_FILTER_WITNESS_DATA
 *
 * SegWit witness fields can contain arbitrary data. Some protocols embed
 * images, text, and other non-financial data in witness fields ("inscriptions").
 *
 * 0 = Accept all consensus-valid witness data
 * 1 = Filter transactions with patterns indicating arbitrary data embedding
 *
 * Note: Pattern matching is not perfect. Sophisticated embedding may bypass
 * filters. Filtered transactions may still appear in blocks if miners include them.
 *
 * Your choice reflects belief about witness field purpose:
 * - 0: Witness fields are consensus-valid space, any use is legitimate
 * - 1: Witness fields are for signatures/scripts, not data storage
 *
 * UNCOMMENT ONE:
 */
// #define POLICY_FILTER_WITNESS_DATA 0  /* Accept all witness data */
// #define POLICY_FILTER_WITNESS_DATA 1  /* Filter data-embedding patterns */

/*
 * Bare multisig relay - POLICY_PERMIT_BARE_MULTISIG
 *
 * Multisig outputs can be "bare" (scriptPubKey directly in output) or
 * "wrapped" (behind P2SH or P2WSH). Bare multisig creates larger UTXO entries
 * and has been used for data encoding.
 *
 * 0 = Reject bare multisig, only relay P2SH/P2WSH-wrapped multisig
 * 1 = Accept bare multisig outputs
 *
 * Note: Bare multisig remains consensus-valid. Miners may include these
 * transactions in blocks regardless of your setting.
 *
 * Your choice reflects tradeoff:
 * - 0: Reduce UTXO bloat, discourage data encoding
 * - 1: Maximum compatibility, no filtering
 *
 * UNCOMMENT ONE:
 */
// #define POLICY_PERMIT_BARE_MULTISIG 0  /* Reject bare multisig */
// #define POLICY_PERMIT_BARE_MULTISIG 1  /* Accept bare multisig */

/*
 * =============================================================================
 * FEE AND ECONOMIC POLICY
 * =============================================================================
 */

/*
 * Minimum relay fee - POLICY_MIN_RELAY_FEE_RATE (satoshis per 1000 bytes)
 *
 * Transactions paying less than this fee rate will not be relayed or
 * accepted into mempool. Protects against DoS via free transactions.
 *
 * Note: Miners may mine zero-fee transactions. Blocks containing them
 * are consensus-valid.
 *
 * Typical values:
 * - 0: Accept zero-fee transactions (DoS risk, not recommended)
 * - 1000: Standard minimum (1 sat/byte)
 * - Higher: More selective relay, less spam
 *
 * UNCOMMENT AND SET:
 */
// #define POLICY_MIN_RELAY_FEE_RATE 1000  /* 1 sat/byte minimum */

/*
 * Dust threshold - POLICY_DUST_THRESHOLD (satoshis)
 *
 * Outputs below this value are "dust" - worth less than the fee to spend them.
 * Transactions creating dust outputs are not relayed.
 *
 * Prevents UTXO set bloat from economically unspendable outputs.
 *
 * Standard value: 546 satoshis (cost to spend P2PKH at 3 sat/byte)
 *
 * Note: Dust outputs remain consensus-valid. Miners may include them.
 *
 * UNCOMMENT AND SET:
 */
// #define POLICY_DUST_THRESHOLD 546  /* Standard dust limit */

/*
 * =============================================================================
 * TRANSACTION SIZE AND COMPLEXITY LIMITS
 * =============================================================================
 */

/*
 * Maximum standard transaction weight - POLICY_MAX_STANDARD_TX_WEIGHT
 *
 * Transactions heavier than this are "non-standard" and won't be relayed,
 * even if consensus-valid.
 *
 * Consensus maximum: 400000 weight units (CONSENSUS_MAX_TX_SIZE)
 * Standard: typically 400000 (accept up to consensus limit)
 *
 * Lower values reduce DoS risk from large transactions.
 *
 * UNCOMMENT AND SET:
 */
// #define POLICY_MAX_STANDARD_TX_WEIGHT 400000  /* Accept up to consensus max */

/*
 * Maximum signature operations - POLICY_MAX_STANDARD_TX_SIGOPS
 *
 * Transactions with more signature operations than this limit won't be relayed,
 * even if consensus-valid.
 *
 * Prevents CPU exhaustion from transaction validation.
 *
 * Typical value: 4000 (derived from consensus max / 20)
 *
 * UNCOMMENT AND SET:
 */
// #define POLICY_MAX_STANDARD_TX_SIGOPS 4000  /* Standard sigop limit */

/*
 * =============================================================================
 * MEMPOOL RESOURCE LIMITS
 * =============================================================================
 */

/*
 * Mempool size limit - POLICY_MEMPOOL_MAX_SIZE_MB (megabytes)
 *
 * Maximum memory for unconfirmed transactions. When full, lowest fee-rate
 * transactions are evicted.
 *
 * This is a resource limit, not a consensus parameter.
 *
 * Typical values:
 * - 300 MB: Standard capacity
 * - Lower: Constrained environments (IoT, embedded)
 * - Higher: More relay capacity, better fee estimation
 *
 * UNCOMMENT AND SET:
 */
// #define POLICY_MEMPOOL_MAX_SIZE_MB 300  /* Standard mempool size */

/*
 * Mempool expiry - POLICY_MEMPOOL_EXPIRY_HOURS (hours)
 *
 * Transactions in mempool longer than this are evicted, even if paying fees.
 * Prevents mempool bloat from never-mined transactions.
 *
 * Typical value: 336 hours (2 weeks)
 *
 * UNCOMMENT AND SET:
 */
// #define POLICY_MEMPOOL_EXPIRY_HOURS 336  /* 2 week expiry */

/*
 * =============================================================================
 * REPLACE-BY-FEE (RBF) POLICY
 * =============================================================================
 */

/*
 * RBF policy - POLICY_ENABLE_RBF
 *
 * 0 = Do not relay replacement transactions (first-seen policy)
 * 1 = Relay replacements if they pay higher fee (BIP-125)
 *
 * Note: Both policies are consensus-compatible. This only affects relay
 * and mempool management.
 *
 * Your choice reflects preference:
 * - 0: Faster finality for unconfirmed transactions
 * - 1: Better fee bumping, more user flexibility
 *
 * UNCOMMENT ONE:
 */
// #define POLICY_ENABLE_RBF 0  /* First-seen policy */
// #define POLICY_ENABLE_RBF 1  /* Enable RBF */

/*
 * =============================================================================
 * IMPLEMENTATION PATTERN
 * =============================================================================
 *
 * The policy enforcement code uses this pattern:
 *
 * #ifdef POLICY_MAX_DATACARRIER_BYTES
 *   if (datacarrier_size > POLICY_MAX_DATACARRIER_BYTES) {
 *     reject_transaction();
 *   }
 * #endif
 *
 * If the constant is undefined, the check doesn't exist. The transaction
 * is accepted if it's consensus-valid.
 *
 * This is architectural honesty:
 * - Consensus defines what's valid
 * - Policy optionally restricts what's relayed
 * - No policy = no restriction = relay anything consensus allows
 */

#endif /* ECHO_POLICY_H */
