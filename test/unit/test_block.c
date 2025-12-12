/*
 * Bitcoin Echo — Block Test Vectors
 *
 * Test vectors for block parsing, serialization, and hash computation.
 * Includes the Bitcoin genesis block.
 *
 * Build once. Build right. Stop.
 */

#include "block.h"
#include "echo_types.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

/*
 * Convert hex string to bytes.
 */
static size_t hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
  size_t len = strlen(hex);
  size_t i;
  unsigned int byte;

  if (len % 2 != 0)
    return 0;
  if (len / 2 > max_len)
    return 0;

  for (i = 0; i < len / 2; i++) {
    // NOLINTBEGIN(cert-err34-c) - sscanf is correct here: we check return value
    // and need exactly 2 hex chars, not all available hex like strtoul would
    // read
    if (sscanf(hex + i * 2, "%02x", &byte) != 1)
      return 0;
    // NOLINTEND(cert-err34-c)
    out[i] = (uint8_t)byte;
  }

  return len / 2;
}

/*
 * Print bytes as hex.
 */
static void print_hex(const uint8_t *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
}

/*
 * Compare two byte arrays.
 */
static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    if (a[i] != b[i])
      return 0;
  }
  return 1;
}

/*
 * Reverse bytes for display (little-endian to big-endian).
 */
static void reverse_bytes(uint8_t *data, size_t len) {
  size_t i;
  uint8_t tmp;
  for (i = 0; i < len / 2; i++) {
    tmp = data[i];
    data[i] = data[len - 1 - i];
    data[len - 1 - i] = tmp;
  }
}

/*
 * Test genesis block header generation.
 */
static void test_genesis_header(void) {
  block_header_t header;
  hash256_t hash;
  uint8_t display_hash[32];

  /* Expected genesis block hash (displayed in big-endian) */
  static const char *expected_hash_hex =
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
  uint8_t expected_hash[32];

  tests_run++;

  /* Generate genesis header */
  block_genesis_header(&header);

  /* Verify header fields */
  if (header.version != 1 || header.timestamp != 1231006505 ||
      header.bits != 0x1d00ffff || header.nonce != 2083236893) {
    printf("  [FAIL] Genesis header fields incorrect\n");
    return;
  }

  /* Compute hash */
  if (block_header_hash(&header, &hash) != ECHO_OK) {
    printf("  [FAIL] Genesis header hash computation failed\n");
    return;
  }

  /* Convert expected hash from big-endian display format */
  hex_to_bytes(expected_hash_hex, expected_hash, 32);
  reverse_bytes(expected_hash, 32);

  /* Copy and reverse for comparison */
  memcpy(display_hash, hash.bytes, 32);

  if (bytes_equal(hash.bytes, expected_hash, 32)) {
    tests_passed++;
    printf("  [PASS] Genesis block hash correct\n");
  } else {
    reverse_bytes(display_hash, 32);
    printf("  [FAIL] Genesis block hash incorrect\n");
    printf("    Expected: %s\n", expected_hash_hex);
    printf("    Got:      ");
    print_hex(display_hash, 32);
    printf("\n");
  }
}

/*
 * Test block header parsing and serialization roundtrip.
 */
static void test_header_roundtrip(const char *name, const char *hex) {
  uint8_t data[BLOCK_HEADER_SIZE];
  uint8_t serialized[BLOCK_HEADER_SIZE];
  block_header_t header;
  echo_result_t result;

  tests_run++;

  if (hex_to_bytes(hex, data, sizeof(data)) != BLOCK_HEADER_SIZE) {
    printf("  [FAIL] %s (invalid hex)\n", name);
    return;
  }

  /* Parse */
  result = block_header_parse(data, BLOCK_HEADER_SIZE, &header);
  if (result != ECHO_OK) {
    printf("  [FAIL] %s (parse failed: %d)\n", name, result);
    return;
  }

  /* Serialize */
  result = block_header_serialize(&header, serialized, sizeof(serialized));
  if (result != ECHO_OK) {
    printf("  [FAIL] %s (serialize failed: %d)\n", name, result);
    return;
  }

  /* Compare */
  if (bytes_equal(data, serialized, BLOCK_HEADER_SIZE)) {
    tests_passed++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s (roundtrip mismatch)\n", name);
  }
}

/*
 * Test block hash computation.
 */
static void test_block_hash(const char *name, const char *header_hex,
                            const char *expected_hash_hex) {
  uint8_t header_data[BLOCK_HEADER_SIZE];
  block_header_t header;
  hash256_t hash;
  uint8_t expected_hash[32];
  uint8_t display_hash[32];

  tests_run++;

  if (hex_to_bytes(header_hex, header_data, sizeof(header_data)) !=
      BLOCK_HEADER_SIZE) {
    printf("  [FAIL] %s (invalid header hex)\n", name);
    return;
  }

  if (hex_to_bytes(expected_hash_hex, expected_hash, 32) != 32) {
    printf("  [FAIL] %s (invalid expected hash hex)\n", name);
    return;
  }
  /* Expected hash is in big-endian display format, reverse to little-endian */
  reverse_bytes(expected_hash, 32);

  if (block_header_parse(header_data, BLOCK_HEADER_SIZE, &header) != ECHO_OK) {
    printf("  [FAIL] %s (parse failed)\n", name);
    return;
  }

  if (block_header_hash(&header, &hash) != ECHO_OK) {
    printf("  [FAIL] %s (hash computation failed)\n", name);
    return;
  }

  if (bytes_equal(hash.bytes, expected_hash, 32)) {
    tests_passed++;
    printf("  [PASS] %s\n", name);
  } else {
    memcpy(display_hash, hash.bytes, 32);
    reverse_bytes(display_hash, 32);
    printf("  [FAIL] %s\n", name);
    printf("    Expected: %s\n", expected_hash_hex);
    printf("    Got:      ");
    print_hex(display_hash, 32);
    printf("\n");
  }
}

/*
 * Test bits to target conversion.
 */
static void test_bits_to_target(const char *name, uint32_t bits,
                                const char *expected_target_hex) {
  hash256_t target;
  uint8_t expected_target[32];

  tests_run++;

  /* Parse expected target (big-endian display format) */
  memset(expected_target, 0, 32);
  if (strlen(expected_target_hex) > 0) {
    size_t hex_len = strlen(expected_target_hex);
    size_t byte_len = hex_len / 2;
    uint8_t temp[32];

    if (hex_to_bytes(expected_target_hex, temp, byte_len) != byte_len) {
      printf("  [FAIL] %s (invalid expected target hex)\n", name);
      return;
    }

    /* Copy to expected_target, right-aligned (big-endian) */
    /* Then reverse to little-endian */
    memcpy(expected_target + (32 - byte_len), temp, byte_len);
    reverse_bytes(expected_target, 32);
  }

  if (block_bits_to_target(bits, &target) != ECHO_OK) {
    printf("  [FAIL] %s (conversion failed)\n", name);
    return;
  }

  if (bytes_equal(target.bytes, expected_target, 32)) {
    tests_passed++;
    printf("  [PASS] %s\n", name);
  } else {
    uint8_t display_target[32];
    memcpy(display_target, target.bytes, 32);
    reverse_bytes(display_target, 32);

    printf("  [FAIL] %s\n", name);
    printf("    Expected: %s\n", expected_target_hex);
    printf("    Got:      ");
    print_hex(display_target, 32);
    printf("\n");
  }
}

/*
 * Test target to bits conversion.
 */
static void test_target_to_bits(const char *name, const char *target_hex,
                                uint32_t expected_bits) {
  hash256_t target;
  uint32_t bits;
  uint8_t temp[32];
  size_t hex_len;
  size_t byte_len;

  tests_run++;

  /* Parse target (big-endian display format) */
  memset(target.bytes, 0, 32);
  hex_len = strlen(target_hex);
  byte_len = hex_len / 2;

  if (byte_len > 0) {
    if (hex_to_bytes(target_hex, temp, byte_len) != byte_len) {
      printf("  [FAIL] %s (invalid target hex)\n", name);
      return;
    }

    /* Copy right-aligned, then reverse to little-endian */
    memcpy(target.bytes + (32 - byte_len), temp, byte_len);
    reverse_bytes(target.bytes, 32);
  }

  if (block_target_to_bits(&target, &bits) != ECHO_OK) {
    printf("  [FAIL] %s (conversion failed)\n", name);
    return;
  }

  if (bits == expected_bits) {
    tests_passed++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
    printf("    Expected bits: 0x%08x\n", expected_bits);
    printf("    Got bits:      0x%08x\n", bits);
  }
}

/*
 * Test proof-of-work validation.
 */
static void test_pow_check(const char *name, const char *hash_hex,
                           const char *target_hex, echo_bool_t expected) {
  hash256_t hash, target;
  uint8_t temp[32];
  size_t hex_len, byte_len;
  echo_bool_t result;

  tests_run++;

  /* Parse hash (little-endian in storage, but display is big-endian) */
  if (hex_to_bytes(hash_hex, temp, 32) != 32) {
    printf("  [FAIL] %s (invalid hash hex)\n", name);
    return;
  }
  memcpy(hash.bytes, temp, 32);
  reverse_bytes(hash.bytes, 32);

  /* Parse target (big-endian display format) */
  memset(target.bytes, 0, 32);
  hex_len = strlen(target_hex);
  byte_len = hex_len / 2;

  if (byte_len > 0) {
    if (hex_to_bytes(target_hex, temp, byte_len) != byte_len) {
      printf("  [FAIL] %s (invalid target hex)\n", name);
      return;
    }
    memcpy(target.bytes + (32 - byte_len), temp, byte_len);
    reverse_bytes(target.bytes, 32);
  }

  result = block_hash_meets_target(&hash, &target);

  if (result == expected) {
    tests_passed++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
    printf("    Expected: %s\n", expected ? "valid" : "invalid");
    printf("    Got:      %s\n", result ? "valid" : "invalid");
  }
}

/*
 * Test full block parsing.
 */
static void test_block_parse(const char *name, const char *hex,
                             size_t expected_tx_count) {
  uint8_t *data;
  size_t data_len;
  block_t block;
  size_t consumed;
  echo_result_t result;

  tests_run++;

  data_len = strlen(hex) / 2;
  data = malloc(data_len);
  if (data == NULL) {
    printf("  [FAIL] %s (malloc failed)\n", name);
    return;
  }

  if (hex_to_bytes(hex, data, data_len) != data_len) {
    printf("  [FAIL] %s (invalid hex)\n", name);
    free(data);
    return;
  }

  result = block_parse(data, data_len, &block, &consumed);

  if (result == ECHO_OK && consumed == data_len &&
      block.tx_count == expected_tx_count) {
    tests_passed++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
    printf("    Result: %d\n", result);
    if (result == ECHO_OK) {
      printf("    Consumed: %zu/%zu\n", consumed, data_len);
      printf("    TX count: %zu (expected %zu)\n", block.tx_count,
             expected_tx_count);
    }
  }

  block_free(&block);
  free(data);
}

int main(void) {
  printf("Bitcoin Echo — Block Tests\n");
  printf("==========================\n\n");

  /*
   * Genesis block tests
   */
  printf("Genesis block tests:\n");
  test_genesis_header();

  /* Genesis block header hex */
  const char *genesis_header_hex = "0100000000000000000000000000000000000000000"
                                   "000000000000000000000000000003ba3edfd"
                                   "7a7b12b27ac72c3e67768f617fc81bc3888a51323a9"
                                   "fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

  test_header_roundtrip("Genesis header roundtrip", genesis_header_hex);

  test_block_hash(
      "Genesis block hash", genesis_header_hex,
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

  printf("\n");

  /*
   * Block 170 tests (first block with a non-coinbase transaction)
   */
  printf("Block 170 tests:\n");

  const char *block_170_header_hex = "0100000055bd840a78798ad0da853f68974f3d183"
                                     "e2bd1db6a842c1feecf222a00000000ff104ccb"
                                     "05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a31"
                                     "75c8166562cac7d51b96a49ffff001d283e9e70";

  test_header_roundtrip("Block 170 header roundtrip", block_170_header_hex);

  test_block_hash(
      "Block 170 hash", block_170_header_hex,
      "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee");

  printf("\n");

  /*
   * Bits/target conversion tests
   */
  printf("Bits to target tests:\n");

  /* Genesis block difficulty (bits = 0x1d00ffff) */
  test_bits_to_target(
      "Genesis bits (0x1d00ffff)", 0x1d00ffff,
      "00000000ffff0000000000000000000000000000000000000000000000000000");

  /* A higher difficulty example */
  test_bits_to_target(
      "Higher difficulty (0x1b0404cb)", 0x1b0404cb,
      "00000000000404cb000000000000000000000000000000000000000000000000");

  /* Very high difficulty (bits = 0x170b8c8b) */
  /* Target = 0x0b8c8b * 256^(0x17-3) = 0x0b8c8b at byte position 20
   * (little-endian) */
  test_bits_to_target(
      "Very high difficulty (0x170b8c8b)", 0x170b8c8b,
      "0000000000000000000b8c8b0000000000000000000000000000000000000000");

  printf("\n");

  printf("Target to bits tests:\n");
  test_target_to_bits(
      "Genesis target",
      "00000000ffff0000000000000000000000000000000000000000000000000000",
      0x1d00ffff);

  printf("\n");

  /*
   * Proof-of-work validation tests
   */
  printf("Proof-of-work tests:\n");

  /* Genesis block hash should meet genesis target */
  test_pow_check(
      "Genesis block meets target",
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      "00000000ffff0000000000000000000000000000000000000000000000000000",
      ECHO_TRUE);

  /* A hash that doesn't meet target */
  test_pow_check(
      "Invalid PoW (hash too high)",
      "000000010000000000000000000000000000000000000000000000000000000a",
      "00000000ffff0000000000000000000000000000000000000000000000000000",
      ECHO_FALSE);

  printf("\n");

  /*
   * Full block parsing test
   * Genesis block: header + 1 coinbase transaction
   */
  printf("Full block parsing tests:\n");

  /* Genesis block (header + varint(1) + coinbase tx) */
  /* Note: The genesis block coinbase has a 65-byte pubkey */
  const char *genesis_block_hex =
      /* Header (80 bytes) */
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "3ba3edfd"
      "7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d"
      "1dac2b7c"
      /* Transaction count: 1 */
      "01"
      /* Coinbase transaction (version=1, 1 input, 1 output, locktime=0) */
      "01000000" /* version */
      "01"       /* input count */
      "0000000000000000000000000000000000000000000000000000000000000000" /* prev
                                                                            txid
                                                                          */
      "ffffffff" /* prev vout (coinbase marker) */
      "4d"       /* scriptSig length = 77 bytes */
      "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e6365"
      "6c6c6f72"
      "206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b"
      "73"
      "ffffffff"         /* sequence */
      "01"               /* output count */
      "00f2052a01000000" /* value: 50 BTC = 5000000000 satoshis */
      "43"               /* scriptPubKey length = 67 bytes */
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6"
      "bc3f4cef"
      "38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
      "00000000"; /* locktime */

  test_block_parse("Genesis block parse", genesis_block_hex, 1);

  printf("\n");

  /*
   * Error handling tests
   */
  printf("Error handling tests:\n");

  /* Truncated header */
  {
    uint8_t truncated[40];
    block_header_t header;
    echo_result_t result;

    tests_run++;
    memset(truncated, 0, sizeof(truncated));
    result = block_header_parse(truncated, sizeof(truncated), &header);

    if (result == ECHO_ERR_TRUNCATED) {
      tests_passed++;
      printf("  [PASS] Truncated header rejected\n");
    } else {
      printf("  [FAIL] Truncated header not rejected (result: %d)\n", result);
    }
  }

  /* NULL parameters */
  {
    block_header_t header;
    echo_result_t result;

    tests_run++;
    result = block_header_parse(NULL, 80, &header);

    if (result == ECHO_ERR_NULL_PARAM) {
      tests_passed++;
      printf("  [PASS] NULL data rejected\n");
    } else {
      printf("  [FAIL] NULL data not rejected (result: %d)\n", result);
    }
  }

  printf("\n");

  /* Summary */
  printf("==========================\n");
  printf("Tests: %d/%d passed\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
