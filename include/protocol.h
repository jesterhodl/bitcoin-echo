/**
 * Bitcoin Echo — Protocol Layer
 *
 * P2P protocol message structures and definitions per Bitcoin protocol
 * specification.
 *
 * All multi-byte integers are little-endian unless specified otherwise.
 * Strings are variable-length and use CompactSize encoding for length.
 */

#ifndef ECHO_PROTOCOL_H
#define ECHO_PROTOCOL_H

#include "block.h"
#include "echo_types.h"
#include "tx.h"
#include <stdint.h>

/* Maximum message size (32MB for blocks) */
#define MAX_MESSAGE_SIZE (32 * 1024 * 1024)

/* Maximum protocol version string length */
#define MAX_USER_AGENT_LEN 256

/* Maximum inventory vectors per message */
#define MAX_INV_ENTRIES 50000

/* Maximum headers per message */
#define MAX_HEADERS_COUNT 2000

/* Maximum addresses per message */
#define MAX_ADDR_COUNT 1000

/* Network magic bytes (mainnet) */
#define MAGIC_MAINNET 0xD9B4BEF9
#define MAGIC_TESTNET 0x0709110B
#define MAGIC_REGTEST 0xDAB5BFFA

/* Protocol version */
#define PROTOCOL_VERSION 70016

/* Services flags */
#define SERVICE_NODE_NETWORK (1 << 0) /* Full node, can serve full blocks */
#define SERVICE_NODE_WITNESS (1 << 3) /* SegWit support */
#define SERVICE_NODE_NETWORK_LIMITED                                           \
  (1 << 10) /* Pruned node with limited history */

/* Inventory types */
#define INV_ERROR 0
#define INV_TX 1
#define INV_BLOCK 2
#define INV_FILTERED_BLOCK 3
#define INV_WITNESS_TX 0x40000001
#define INV_WITNESS_BLOCK 0x40000002

/* Command name length (12 bytes, null-padded) */
#define COMMAND_LEN 12

/**
 * Message header (24 bytes)
 *
 * All network messages start with this header.
 */
typedef struct {
  uint32_t magic;            /* Magic bytes identifying network */
  char command[COMMAND_LEN]; /* Command name (null-padded) */
  uint32_t length;           /* Payload length in bytes */
  uint32_t checksum;         /* First 4 bytes of SHA256d(payload) */
} msg_header_t;

/**
 * Network address (with timestamp)
 *
 * Used in addr messages.
 */
typedef struct {
  uint32_t timestamp; /* Unix timestamp */
  uint64_t services;  /* Service flags */
  uint8_t ip[16];     /* IPv6 address (IPv4 mapped to ::ffff:x.x.x.x) */
  uint16_t port;      /* Port number (big-endian) */
} net_addr_t;

/**
 * Network address (without timestamp)
 *
 * Used in version message.
 */
typedef struct {
  uint64_t services; /* Service flags */
  uint8_t ip[16];    /* IPv6 address */
  uint16_t port;     /* Port number (big-endian) */
} net_addr_notime_t;

/**
 * version message
 *
 * First message sent after connection to handshake.
 */
typedef struct {
  int32_t version;             /* Protocol version */
  uint64_t services;           /* Service flags */
  int64_t timestamp;           /* Unix timestamp */
  net_addr_notime_t addr_recv; /* Receiving node address */
  net_addr_notime_t addr_from; /* Sending node address */
  uint64_t nonce;              /* Random nonce for detecting self-connections */
  char user_agent[MAX_USER_AGENT_LEN]; /* Client identification string */
  size_t user_agent_len;               /* Actual length of user_agent */
  int32_t start_height;                /* Last block received by sending node */
  echo_bool_t relay; /* Whether to relay transactions (BIP-37) */
} msg_version_t;

/**
 * verack message (no payload)
 *
 * Sent in response to version message to complete handshake.
 */
typedef struct {
  /* No fields — message is just the header */
  uint8_t _unused;
} msg_verack_t;

/**
 * ping message
 */
typedef struct {
  uint64_t nonce; /* Random nonce */
} msg_ping_t;

/**
 * pong message
 */
typedef struct {
  uint64_t nonce; /* Nonce from ping message */
} msg_pong_t;

/**
 * Inventory vector
 */
typedef struct {
  uint32_t type;  /* INV_TX, INV_BLOCK, etc. */
  hash256_t hash; /* Transaction or block hash */
} inv_vector_t;

/**
 * inv message
 *
 * Advertise knowledge of transactions or blocks.
 */
typedef struct {
  size_t count;            /* Number of inventory entries */
  inv_vector_t *inventory; /* Array of inventory vectors */
} msg_inv_t;

/**
 * getdata message
 *
 * Request transactions or blocks.
 * Same structure as inv message.
 */
typedef msg_inv_t msg_getdata_t;

/**
 * notfound message
 *
 * Response when requested data is not available.
 * Same structure as inv message.
 */
typedef msg_inv_t msg_notfound_t;

/**
 * block message
 *
 * Full block data.
 */
typedef struct {
  block_t block; /* Complete block */
} msg_block_t;

/**
 * tx message
 *
 * Transaction data.
 */
typedef struct {
  tx_t tx; /* Complete transaction */
} msg_tx_t;

/**
 * addr message
 *
 * Advertise peer addresses.
 */
typedef struct {
  size_t count;          /* Number of addresses */
  net_addr_t *addresses; /* Array of network addresses */
} msg_addr_t;

/**
 * getaddr message (no payload)
 *
 * Request peer addresses.
 */
typedef struct {
  uint8_t _unused;
} msg_getaddr_t;

/**
 * getheaders message
 *
 * Request block headers.
 */
typedef struct {
  uint32_t version;         /* Protocol version */
  size_t hash_count;        /* Number of block locator hashes */
  hash256_t *block_locator; /* Block locator hashes (most recent first) */
  hash256_t hash_stop;      /* Hash to stop at (0 for as many as possible) */
} msg_getheaders_t;

/**
 * getblocks message
 *
 * Request block inventory.
 * Same structure as getheaders.
 */
typedef msg_getheaders_t msg_getblocks_t;

/**
 * headers message
 *
 * Block headers response.
 */
typedef struct {
  size_t count;            /* Number of headers */
  block_header_t *headers; /* Array of block headers */
} msg_headers_t;

/**
 * reject message
 *
 * Notification that a message was rejected.
 */
typedef struct {
  char message[COMMAND_LEN]; /* Command that was rejected */
  uint8_t ccode;             /* Reject code */
  char reason[256];          /* Human-readable reason */
  size_t reason_len;         /* Actual length of reason */
  hash256_t data;            /* Extra data (e.g., rejected tx/block hash) */
  echo_bool_t has_data;      /* Whether data field is present */
} msg_reject_t;

/* Reject codes */
#define REJECT_MALFORMED 0x01
#define REJECT_INVALID 0x10
#define REJECT_OBSOLETE 0x11
#define REJECT_DUPLICATE 0x12
#define REJECT_NONSTANDARD 0x40
#define REJECT_DUST 0x41
#define REJECT_INSUFFICIENTFEE 0x42
#define REJECT_CHECKPOINT 0x43

/**
 * sendheaders message (no payload)
 *
 * Request that new blocks be announced via headers instead of inv.
 */
typedef struct {
  uint8_t _unused;
} msg_sendheaders_t;

/**
 * feefilter message
 *
 * Request not to relay transactions below a fee rate.
 */
typedef struct {
  uint64_t feerate; /* Minimum fee rate in satoshis per 1000 bytes */
} msg_feefilter_t;

/**
 * sendcmpct message
 *
 * Request compact block relay (BIP-152).
 */
typedef struct {
  echo_bool_t announce; /* Whether to announce new blocks via cmpctblock */
  uint64_t version;     /* Compact block version */
} msg_sendcmpct_t;

/**
 * wtxidrelay message (no payload)
 *
 * Indicates support for wtxid-based relay (BIP-339).
 */
typedef struct {
  uint8_t _unused;
} msg_wtxidrelay_t;

/**
 * Message type enumeration
 */
typedef enum {
  MSG_VERSION,
  MSG_VERACK,
  MSG_PING,
  MSG_PONG,
  MSG_INV,
  MSG_GETDATA,
  MSG_NOTFOUND,
  MSG_BLOCK,
  MSG_TX,
  MSG_ADDR,
  MSG_GETADDR,
  MSG_GETHEADERS,
  MSG_GETBLOCKS,
  MSG_HEADERS,
  MSG_REJECT,
  MSG_SENDHEADERS,
  MSG_FEEFILTER,
  MSG_SENDCMPCT,
  MSG_WTXIDRELAY,
  MSG_UNKNOWN
} msg_type_t;

/**
 * Generic message container
 *
 * Holds any protocol message type.
 */
typedef struct {
  msg_type_t type;
  union {
    msg_version_t version;
    msg_verack_t verack;
    msg_ping_t ping;
    msg_pong_t pong;
    msg_inv_t inv;
    msg_getdata_t getdata;
    msg_notfound_t notfound;
    msg_block_t block;
    msg_tx_t tx;
    msg_addr_t addr;
    msg_getaddr_t getaddr;
    msg_getheaders_t getheaders;
    msg_getblocks_t getblocks;
    msg_headers_t headers;
    msg_reject_t reject;
    msg_sendheaders_t sendheaders;
    msg_feefilter_t feefilter;
    msg_sendcmpct_t sendcmpct;
    msg_wtxidrelay_t wtxidrelay;
  } payload;
} msg_t;

/**
 * Parse message type from command string.
 *
 * Returns MSG_UNKNOWN if command is not recognized.
 */
msg_type_t msg_parse_command(const char *command);

/**
 * Get command string for message type.
 *
 * Returns command name (null-terminated, not padded).
 */
const char *msg_command_string(msg_type_t type);

/**
 * Compute message checksum.
 *
 * Checksum is first 4 bytes of SHA256d(payload).
 */
uint32_t msg_checksum(const uint8_t *payload, size_t len);

/**
 * Validate message header.
 *
 * Checks:
 * - Magic bytes match expected network
 * - Command is null-terminated
 * - Length is within bounds
 *
 * Returns true if valid, false otherwise.
 */
echo_bool_t msg_header_valid(const msg_header_t *header,
                             uint32_t expected_magic);

#endif /* ECHO_PROTOCOL_H */
