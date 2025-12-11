/*
 * Bitcoin Echo — Compile-Time Configuration
 *
 * All configuration is compile-time. There are no configuration files,
 * no command-line flags, no runtime policy changes. The node behaves
 * identically on every execution.
 *
 * To build for a different network, define one of:
 *   ECHO_NETWORK_MAINNET  (default)
 *   ECHO_NETWORK_TESTNET
 *   ECHO_NETWORK_REGTEST
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_CONFIG_H
#define ECHO_CONFIG_H

/*
 * Version information.
 */
#define ECHO_VERSION_MAJOR 0
#define ECHO_VERSION_MINOR 0
#define ECHO_VERSION_PATCH 1
#define ECHO_VERSION_STRING "0.0.1"

/* Protocol version we speak */
#define ECHO_PROTOCOL_VERSION 70016

/* User agent string for version messages */
#define ECHO_USER_AGENT "/BitcoinEcho:0.0.1/"

/*
 * Network selection.
 * Default to mainnet if nothing specified.
 */
#if !defined(ECHO_NETWORK_MAINNET) && !defined(ECHO_NETWORK_TESTNET) &&        \
    !defined(ECHO_NETWORK_REGTEST)
#define ECHO_NETWORK_MAINNET
#endif

/*
 * Network magic bytes.
 * Four bytes that prefix every P2P message to identify the network.
 */
#if defined(ECHO_NETWORK_MAINNET)
#define ECHO_NETWORK_MAGIC 0xD9B4BEF9 /* Little-endian: F9 BE B4 D9 */
#define ECHO_NETWORK_NAME "mainnet"
#elif defined(ECHO_NETWORK_TESTNET)
#define ECHO_NETWORK_MAGIC 0x0709110B /* Little-endian: 0B 11 09 07 */
#define ECHO_NETWORK_NAME "testnet3"
#elif defined(ECHO_NETWORK_REGTEST)
#define ECHO_NETWORK_MAGIC 0xDAB5BFFA /* Little-endian: FA BF B5 DA */
#define ECHO_NETWORK_NAME "regtest"
#endif

/*
 * Network ports.
 */
#if defined(ECHO_NETWORK_MAINNET)
#define ECHO_DEFAULT_PORT 8333
#define ECHO_DEFAULT_RPC_PORT 8332
#elif defined(ECHO_NETWORK_TESTNET)
#define ECHO_DEFAULT_PORT 18333
#define ECHO_DEFAULT_RPC_PORT 18332
#elif defined(ECHO_NETWORK_REGTEST)
#define ECHO_DEFAULT_PORT 18444
#define ECHO_DEFAULT_RPC_PORT 18443
#endif

/*
 * Consensus parameters.
 * These values define Bitcoin's rules and must never be changed.
 */

/* Block subsidy halving interval (blocks) */
#define ECHO_HALVING_INTERVAL 210000

/* Initial block subsidy in satoshis (50 BTC) */
#define ECHO_INITIAL_SUBSIDY 5000000000LL

/* Difficulty adjustment interval (blocks) */
#define ECHO_DIFFICULTY_INTERVAL 2016

/* Target time per block (seconds) */
#define ECHO_TARGET_BLOCK_TIME 600

/* Target time per difficulty period (seconds) */
#define ECHO_TARGET_PERIOD_TIME                                                \
  (ECHO_DIFFICULTY_INTERVAL * ECHO_TARGET_BLOCK_TIME)

/* Coinbase maturity (blocks before spendable) */
#define ECHO_COINBASE_MATURITY 100

/* Maximum block weight (weight units) */
#define ECHO_MAX_BLOCK_WEIGHT 4000000

/* Maximum block size for legacy calculations (bytes) */
#define ECHO_MAX_BLOCK_SIZE 1000000

/* Maximum script size (bytes) */
#define ECHO_MAX_SCRIPT_SIZE 10000

/* Maximum script element size (bytes) */
#define ECHO_MAX_SCRIPT_ELEMENT 520

/* Maximum number of operations per script */
#define ECHO_MAX_SCRIPT_OPS 201

/* Maximum stack size during script execution */
#define ECHO_MAX_STACK_SIZE 1000

/* Maximum number of public keys in multisig */
#define ECHO_MAX_MULTISIG_KEYS 20

/* Maximum number of signature operations per block */
#define ECHO_MAX_BLOCK_SIGOPS 80000

/* Maximum transaction size (bytes) */
#define ECHO_MAX_TX_SIZE 400000

/* Locktime threshold: values below are block heights, above are timestamps */
#define ECHO_LOCKTIME_THRESHOLD 500000000

/* Sequence number that disables locktime */
#define ECHO_SEQUENCE_FINAL 0xFFFFFFFF

/* BIP-68 sequence lock flags */
#define ECHO_SEQUENCE_LOCKTIME_DISABLE (1 << 31)
#define ECHO_SEQUENCE_LOCKTIME_TYPE (1 << 22)
#define ECHO_SEQUENCE_LOCKTIME_MASK 0x0000FFFF

/*
 * Soft fork activation heights (mainnet).
 * After these heights, the corresponding rules are enforced.
 */
#if defined(ECHO_NETWORK_MAINNET)
#define ECHO_BIP16_HEIGHT 173805   /* P2SH */
#define ECHO_BIP34_HEIGHT 227931   /* Height in coinbase */
#define ECHO_BIP65_HEIGHT 388381   /* CHECKLOCKTIMEVERIFY */
#define ECHO_BIP66_HEIGHT 363725   /* Strict DER signatures */
#define ECHO_BIP68_HEIGHT 419328   /* Relative lock-time */
#define ECHO_SEGWIT_HEIGHT 481824  /* Segregated Witness */
#define ECHO_TAPROOT_HEIGHT 709632 /* Taproot/Schnorr */
#elif defined(ECHO_NETWORK_TESTNET)
#define ECHO_BIP16_HEIGHT 514
#define ECHO_BIP34_HEIGHT 21111
#define ECHO_BIP65_HEIGHT 581885
#define ECHO_BIP66_HEIGHT 330776
#define ECHO_BIP68_HEIGHT 770112
#define ECHO_SEGWIT_HEIGHT 834624
#define ECHO_TAPROOT_HEIGHT 2000000 /* Approximate */
#elif defined(ECHO_NETWORK_REGTEST)
#define ECHO_BIP16_HEIGHT 0 /* Always active */
#define ECHO_BIP34_HEIGHT 500
#define ECHO_BIP65_HEIGHT 1351
#define ECHO_BIP66_HEIGHT 1251
#define ECHO_BIP68_HEIGHT 432
#define ECHO_SEGWIT_HEIGHT 0  /* Always active */
#define ECHO_TAPROOT_HEIGHT 0 /* Always active */
#endif

/*
 * Peer-to-peer configuration.
 */
#define ECHO_MAX_OUTBOUND_PEERS 8
#define ECHO_MAX_INBOUND_PEERS 117
#define ECHO_MAX_TOTAL_PEERS (ECHO_MAX_OUTBOUND_PEERS + ECHO_MAX_INBOUND_PEERS)

/* Connection timeout (milliseconds) */
#define ECHO_CONNECT_TIMEOUT_MS 5000

/* Ping interval (milliseconds) */
#define ECHO_PING_INTERVAL_MS 120000

/* Inactivity timeout (milliseconds) */
#define ECHO_INACTIVITY_TIMEOUT_MS 600000

/*
 * Data directory structure.
 * Relative to data directory root.
 */
#define ECHO_BLOCKS_DIR "blocks"
#define ECHO_CHAINSTATE_DIR "chainstate"
#define ECHO_DATABASE_FILE "echo.db"

#endif /* ECHO_CONFIG_H */
