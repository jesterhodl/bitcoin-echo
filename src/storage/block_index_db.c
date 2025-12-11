/*
 * Bitcoin Echo — Block Index Database Implementation
 *
 * Persistent storage for block headers using SQLite.
 * See block_index_db.h for interface documentation.
 *
 * Build once. Build right. Stop.
 */

#include "block_index_db.h"
#include "block.h"
#include "chainstate.h"
#include "db.h"
#include "echo_types.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ========================================================================
 * Internal Helpers
 * ======================================================================== */

/*
 * Create the block index schema.
 */
static echo_result_t create_schema(db_t *db) {
  echo_result_t result;

  /* Create blocks table per whitepaper §6.3 */
  result = db_exec(
      db, "CREATE TABLE IF NOT EXISTS blocks ("
          "    hash        BLOB PRIMARY KEY," /* 32 bytes */
          "    height      INTEGER NOT NULL,"
          "    header      BLOB NOT NULL,"   /* 80 bytes */
          "    chainwork   BLOB NOT NULL,"   /* 32 bytes, big-endian */
          "    status      INTEGER NOT NULL" /* validation status flags */
          ");");
  if (result != ECHO_OK) {
    return result;
  }

  /* Create height index for sequential chain navigation */
  result =
      db_exec(db, "CREATE INDEX IF NOT EXISTS idx_height ON blocks(height);");
  if (result != ECHO_OK) {
    return result;
  }

  /* Create chainwork index for chain comparison */
  result = db_exec(
      db, "CREATE INDEX IF NOT EXISTS idx_chainwork ON blocks(chainwork);");
  if (result != ECHO_OK) {
    return result;
  }

  return ECHO_OK;
}

/*
 * Prepare commonly-used statements.
 */
static echo_result_t prepare_statements(block_index_db_t *bdb) {
  echo_result_t result;

  /* Lookup by hash */
  result = db_prepare(&bdb->db,
                      "SELECT hash, height, header, chainwork, status FROM "
                      "blocks WHERE hash = ?",
                      &bdb->lookup_hash_stmt);
  if (result != ECHO_OK)
    return result;

  /* Lookup by height */
  result = db_prepare(&bdb->db,
                      "SELECT hash, height, header, chainwork, status FROM "
                      "blocks WHERE height = ? LIMIT 1",
                      &bdb->lookup_height_stmt);
  if (result != ECHO_OK)
    return result;

  /* Insert */
  result = db_prepare(&bdb->db,
                      "INSERT INTO blocks (hash, height, header, chainwork, "
                      "status) VALUES (?, ?, ?, ?, ?)",
                      &bdb->insert_stmt);
  if (result != ECHO_OK)
    return result;

  /* Update status */
  result = db_prepare(&bdb->db, "UPDATE blocks SET status = ? WHERE hash = ?",
                      &bdb->update_status_stmt);
  if (result != ECHO_OK)
    return result;

  /* Best chain (highest chainwork) */
  result =
      db_prepare(&bdb->db,
                 "SELECT hash, height, header, chainwork, status FROM blocks "
                 "ORDER BY chainwork DESC LIMIT 1",
                 &bdb->best_chain_stmt);
  if (result != ECHO_OK)
    return result;

  bdb->stmts_prepared = true;
  return ECHO_OK;
}

/*
 * Finalize all prepared statements.
 */
static void finalize_statements(block_index_db_t *bdb) {
  if (bdb->stmts_prepared) {
    db_stmt_finalize(&bdb->lookup_hash_stmt);
    db_stmt_finalize(&bdb->lookup_height_stmt);
    db_stmt_finalize(&bdb->insert_stmt);
    db_stmt_finalize(&bdb->update_status_stmt);
    db_stmt_finalize(&bdb->best_chain_stmt);
    bdb->stmts_prepared = false;
  }
}

/*
 * Serialize a block header to 80 bytes.
 */
static void serialize_header(const block_header_t *header, uint8_t *buf) {
  size_t pos = 0;

  /* version (4 bytes, little-endian) */
  buf[pos++] = (uint8_t)(header->version);
  buf[pos++] = (uint8_t)(header->version >> 8);
  buf[pos++] = (uint8_t)(header->version >> 16);
  buf[pos++] = (uint8_t)(header->version >> 24);

  /* prev_hash (32 bytes) */
  memcpy(buf + pos, header->prev_hash.bytes, 32);
  pos += 32;

  /* merkle_root (32 bytes) */
  memcpy(buf + pos, header->merkle_root.bytes, 32);
  pos += 32;

  /* timestamp (4 bytes, little-endian) */
  buf[pos++] = (uint8_t)(header->timestamp);
  buf[pos++] = (uint8_t)(header->timestamp >> 8);
  buf[pos++] = (uint8_t)(header->timestamp >> 16);
  buf[pos++] = (uint8_t)(header->timestamp >> 24);

  /* bits (4 bytes, little-endian) */
  buf[pos++] = (uint8_t)(header->bits);
  buf[pos++] = (uint8_t)(header->bits >> 8);
  buf[pos++] = (uint8_t)(header->bits >> 16);
  buf[pos++] = (uint8_t)(header->bits >> 24);

  /* nonce (4 bytes, little-endian) */
  buf[pos++] = (uint8_t)(header->nonce);
  buf[pos++] = (uint8_t)(header->nonce >> 8);
  buf[pos++] = (uint8_t)(header->nonce >> 16);
  buf[pos++] = (uint8_t)(header->nonce >> 24);
}

/*
 * Deserialize a block header from 80 bytes.
 */
static void deserialize_header(const uint8_t *buf, block_header_t *header) {
  size_t pos = 0;

  /* version (4 bytes, little-endian) */
  header->version = (int32_t)(buf[pos] | (buf[pos + 1] << 8) |
                              (buf[pos + 2] << 16) | (buf[pos + 3] << 24));
  pos += 4;

  /* prev_hash (32 bytes) */
  memcpy(header->prev_hash.bytes, buf + pos, 32);
  pos += 32;

  /* merkle_root (32 bytes) */
  memcpy(header->merkle_root.bytes, buf + pos, 32);
  pos += 32;

  /* timestamp (4 bytes, little-endian) */
  header->timestamp = (uint32_t)(buf[pos] | (buf[pos + 1] << 8) |
                                 (buf[pos + 2] << 16) | (buf[pos + 3] << 24));
  pos += 4;

  /* bits (4 bytes, little-endian) */
  header->bits = (uint32_t)(buf[pos] | (buf[pos + 1] << 8) |
                            (buf[pos + 2] << 16) | (buf[pos + 3] << 24));
  pos += 4;

  /* nonce (4 bytes, little-endian) */
  header->nonce = (uint32_t)(buf[pos] | (buf[pos + 1] << 8) |
                             (buf[pos + 2] << 16) | (buf[pos + 3] << 24));
}

/*
 * Populate a block_index_entry_t from a prepared statement row.
 */
static void populate_entry_from_row(db_stmt_t *stmt,
                                    block_index_entry_t *entry) {
  const void *hash_blob;
  const void *header_blob;
  const void *chainwork_blob;

  /* hash (column 0) */
  hash_blob = db_column_blob(stmt, 0);
  memcpy(entry->hash.bytes, hash_blob, 32);

  /* height (column 1) */
  entry->height = (uint32_t)db_column_int(stmt, 1);

  /* header (column 2) */
  header_blob = db_column_blob(stmt, 2);
  deserialize_header((const uint8_t *)header_blob, &entry->header);

  /* chainwork (column 3) */
  chainwork_blob = db_column_blob(stmt, 3);
  memcpy(entry->chainwork.bytes, chainwork_blob, 32);

  /* status (column 4) */
  entry->status = (uint32_t)db_column_int(stmt, 4);
}

/* ========================================================================
 * Database Lifecycle
 * ======================================================================== */

echo_result_t block_index_db_open(block_index_db_t *bdb, const char *path) {
  echo_result_t result;

  /* Initialize structure */
  memset(bdb, 0, sizeof(block_index_db_t));
  bdb->stmts_prepared = false;

  /* Open database */
  result = db_open(&bdb->db, path);
  if (result != ECHO_OK) {
    return result;
  }

  /* Create schema */
  result = create_schema(&bdb->db);
  if (result != ECHO_OK) {
    db_close(&bdb->db);
    return result;
  }

  /* Prepare statements */
  result = prepare_statements(bdb);
  if (result != ECHO_OK) {
    db_close(&bdb->db);
    return result;
  }

  return ECHO_OK;
}

void block_index_db_close(block_index_db_t *bdb) {
  if (bdb) {
    finalize_statements(bdb);
    db_close(&bdb->db);
    memset(bdb, 0, sizeof(block_index_db_t));
  }
}

/* ========================================================================
 * Block Index Operations
 * ======================================================================== */

echo_result_t block_index_db_lookup_by_hash(block_index_db_t *bdb,
                                            const hash256_t *hash,
                                            block_index_entry_t *entry) {
  echo_result_t result;

  /* Reset statement */
  result = db_stmt_reset(&bdb->lookup_hash_stmt);
  if (result != ECHO_OK)
    return result;

  /* Bind hash parameter */
  result = db_bind_blob(&bdb->lookup_hash_stmt, 1, hash->bytes, 32);
  if (result != ECHO_OK)
    return result;

  /* Execute query */
  result = db_step(&bdb->lookup_hash_stmt);
  if (result == ECHO_DONE) {
    return ECHO_ERR_NOT_FOUND;
  }
  if (result != ECHO_OK) {
    return result;
  }

  /* Populate entry from result row */
  populate_entry_from_row(&bdb->lookup_hash_stmt, entry);

  return ECHO_OK;
}

echo_result_t block_index_db_lookup_by_height(block_index_db_t *bdb,
                                              uint32_t height,
                                              block_index_entry_t *entry) {
  echo_result_t result;

  /* Reset statement */
  result = db_stmt_reset(&bdb->lookup_height_stmt);
  if (result != ECHO_OK)
    return result;

  /* Bind height parameter */
  result = db_bind_int(&bdb->lookup_height_stmt, 1, (int)height);
  if (result != ECHO_OK)
    return result;

  /* Execute query */
  result = db_step(&bdb->lookup_height_stmt);
  if (result == ECHO_DONE) {
    return ECHO_ERR_NOT_FOUND;
  }
  if (result != ECHO_OK) {
    return result;
  }

  /* Populate entry from result row */
  populate_entry_from_row(&bdb->lookup_height_stmt, entry);

  return ECHO_OK;
}

echo_result_t block_index_db_exists(block_index_db_t *bdb,
                                    const hash256_t *hash, bool *exists) {
  block_index_entry_t entry;
  echo_result_t result;

  result = block_index_db_lookup_by_hash(bdb, hash, &entry);
  if (result == ECHO_OK) {
    *exists = true;
    return ECHO_OK;
  } else if (result == ECHO_ERR_NOT_FOUND) {
    *exists = false;
    return ECHO_OK;
  } else {
    return result;
  }
}

echo_result_t block_index_db_insert(block_index_db_t *bdb,
                                    const block_index_entry_t *entry) {
  echo_result_t result;
  uint8_t header_buf[80];

  /* Reset statement */
  result = db_stmt_reset(&bdb->insert_stmt);
  if (result != ECHO_OK)
    return result;

  /* Bind hash (parameter 1) */
  result = db_bind_blob(&bdb->insert_stmt, 1, entry->hash.bytes, 32);
  if (result != ECHO_OK)
    return result;

  /* Bind height (parameter 2) */
  result = db_bind_int(&bdb->insert_stmt, 2, (int)entry->height);
  if (result != ECHO_OK)
    return result;

  /* Bind header (parameter 3) */
  serialize_header(&entry->header, header_buf);
  result = db_bind_blob(&bdb->insert_stmt, 3, header_buf, 80);
  if (result != ECHO_OK)
    return result;

  /* Bind chainwork (parameter 4) */
  result = db_bind_blob(&bdb->insert_stmt, 4, entry->chainwork.bytes, 32);
  if (result != ECHO_OK)
    return result;

  /* Bind status (parameter 5) */
  result = db_bind_int(&bdb->insert_stmt, 5, (int)entry->status);
  if (result != ECHO_OK)
    return result;

  /* Execute insert */
  result = db_step(&bdb->insert_stmt);
  if (result == ECHO_DONE) {
    return ECHO_OK;
  }

  return result;
}

echo_result_t block_index_db_update_status(block_index_db_t *bdb,
                                           const hash256_t *hash,
                                           uint32_t status) {
  echo_result_t result;

  /* Reset statement */
  result = db_stmt_reset(&bdb->update_status_stmt);
  if (result != ECHO_OK)
    return result;

  /* Bind status (parameter 1) */
  result = db_bind_int(&bdb->update_status_stmt, 1, (int)status);
  if (result != ECHO_OK)
    return result;

  /* Bind hash (parameter 2) */
  result = db_bind_blob(&bdb->update_status_stmt, 2, hash->bytes, 32);
  if (result != ECHO_OK)
    return result;

  /* Execute update */
  result = db_step(&bdb->update_status_stmt);
  if (result == ECHO_DONE) {
    /* Check if any rows were updated */
    int changes = db_changes(&bdb->db);
    if (changes == 0) {
      return ECHO_ERR_NOT_FOUND;
    }
    return ECHO_OK;
  }

  return result;
}

/* ========================================================================
 * Chain Queries
 * ======================================================================== */

echo_result_t block_index_db_get_best_chain(block_index_db_t *bdb,
                                            block_index_entry_t *entry) {
  echo_result_t result;

  /* Reset statement */
  result = db_stmt_reset(&bdb->best_chain_stmt);
  if (result != ECHO_OK)
    return result;

  /* Execute query */
  result = db_step(&bdb->best_chain_stmt);
  if (result == ECHO_DONE) {
    return ECHO_ERR_NOT_FOUND; /* Database is empty */
  }
  if (result != ECHO_OK) {
    return result;
  }

  /* Populate entry from result row */
  populate_entry_from_row(&bdb->best_chain_stmt, entry);

  return ECHO_OK;
}

echo_result_t block_index_db_get_chain_block(block_index_db_t *bdb,
                                             uint32_t height,
                                             block_index_entry_t *entry) {
  echo_result_t result;
  db_stmt_t stmt;

  /* Prepare query for blocks on best chain at this height */
  result =
      db_prepare(&bdb->db,
                 "SELECT hash, height, header, chainwork, status FROM blocks "
                 "WHERE height = ? AND (status & ?) != 0 LIMIT 1",
                 &stmt);
  if (result != ECHO_OK)
    return result;

  /* Bind height */
  result = db_bind_int(&stmt, 1, (int)height);
  if (result != ECHO_OK) {
    db_stmt_finalize(&stmt);
    return result;
  }

  /* Bind status flag check (BLOCK_STATUS_VALID_CHAIN) */
  result = db_bind_int(&stmt, 2, BLOCK_STATUS_VALID_CHAIN);
  if (result != ECHO_OK) {
    db_stmt_finalize(&stmt);
    return result;
  }

  /* Execute */
  result = db_step(&stmt);
  if (result == ECHO_DONE) {
    db_stmt_finalize(&stmt);
    return ECHO_ERR_NOT_FOUND;
  }
  if (result != ECHO_OK) {
    db_stmt_finalize(&stmt);
    return result;
  }

  /* Populate entry */
  populate_entry_from_row(&stmt, entry);

  db_stmt_finalize(&stmt);
  return ECHO_OK;
}

echo_result_t block_index_db_get_prev(block_index_db_t *bdb,
                                      const hash256_t *hash,
                                      block_index_entry_t *entry) {
  echo_result_t result;
  block_index_entry_t current;

  /* Lookup current block to get prev_hash */
  result = block_index_db_lookup_by_hash(bdb, hash, &current);
  if (result != ECHO_OK)
    return result;

  /* Lookup parent by prev_hash from header */
  result = block_index_db_lookup_by_hash(bdb, &current.header.prev_hash, entry);
  return result;
}

echo_result_t block_index_db_find_common_ancestor(
    block_index_db_t *bdb, const hash256_t *hash_a, const hash256_t *hash_b,
    block_index_entry_t *ancestor) {
  echo_result_t result;
  block_index_entry_t entry_a, entry_b;

  /* Lookup both blocks */
  result = block_index_db_lookup_by_hash(bdb, hash_a, &entry_a);
  if (result != ECHO_OK)
    return result;

  result = block_index_db_lookup_by_hash(bdb, hash_b, &entry_b);
  if (result != ECHO_OK)
    return result;

  /*
   * Walk both chains backward until we find a common block.
   * First, bring both to the same height by walking the higher one backward.
   */
  while (entry_a.height > entry_b.height) {
    result = block_index_db_get_prev(bdb, &entry_a.hash, &entry_a);
    if (result != ECHO_OK)
      return result;
  }

  while (entry_b.height > entry_a.height) {
    result = block_index_db_get_prev(bdb, &entry_b.hash, &entry_b);
    if (result != ECHO_OK)
      return result;
  }

  /* Now both are at the same height, walk backward together */
  while (memcmp(entry_a.hash.bytes, entry_b.hash.bytes, 32) != 0) {
    result = block_index_db_get_prev(bdb, &entry_a.hash, &entry_a);
    if (result != ECHO_OK)
      return result;

    result = block_index_db_get_prev(bdb, &entry_b.hash, &entry_b);
    if (result != ECHO_OK)
      return result;
  }

  /* Found common ancestor */
  *ancestor = entry_a;
  return ECHO_OK;
}

/* ========================================================================
 * Batch Operations
 * ======================================================================== */

echo_result_t block_index_db_mark_best_chain(block_index_db_t *bdb,
                                             const hash256_t *hashes,
                                             size_t count) {
  echo_result_t result;
  db_stmt_t stmt;
  size_t i;

  /* Prepare update statement */
  result = db_prepare(
      &bdb->db, "UPDATE blocks SET status = status | ? WHERE hash = ?", &stmt);
  if (result != ECHO_OK)
    return result;

  /* Update each block */
  for (i = 0; i < count; i++) {
    result = db_stmt_reset(&stmt);
    if (result != ECHO_OK) {
      db_stmt_finalize(&stmt);
      return result;
    }

    /* Bind BLOCK_STATUS_VALID_CHAIN flag */
    result = db_bind_int(&stmt, 1, BLOCK_STATUS_VALID_CHAIN);
    if (result != ECHO_OK) {
      db_stmt_finalize(&stmt);
      return result;
    }

    /* Bind hash */
    result = db_bind_blob(&stmt, 2, hashes[i].bytes, 32);
    if (result != ECHO_OK) {
      db_stmt_finalize(&stmt);
      return result;
    }

    /* Execute */
    result = db_step(&stmt);
    if (result != ECHO_DONE) {
      db_stmt_finalize(&stmt);
      return result;
    }
  }

  db_stmt_finalize(&stmt);
  return ECHO_OK;
}

echo_result_t block_index_db_unmark_best_chain(block_index_db_t *bdb,
                                               const hash256_t *hashes,
                                               size_t count) {
  echo_result_t result;
  db_stmt_t stmt;
  size_t i;

  /* Prepare update statement */
  result = db_prepare(
      &bdb->db, "UPDATE blocks SET status = status & ? WHERE hash = ?", &stmt);
  if (result != ECHO_OK)
    return result;

  /* Compute bitmask to clear BLOCK_STATUS_VALID_CHAIN */
  int clear_mask = ~BLOCK_STATUS_VALID_CHAIN;

  /* Update each block */
  for (i = 0; i < count; i++) {
    result = db_stmt_reset(&stmt);
    if (result != ECHO_OK) {
      db_stmt_finalize(&stmt);
      return result;
    }

    /* Bind clear mask */
    result = db_bind_int(&stmt, 1, clear_mask);
    if (result != ECHO_OK) {
      db_stmt_finalize(&stmt);
      return result;
    }

    /* Bind hash */
    result = db_bind_blob(&stmt, 2, hashes[i].bytes, 32);
    if (result != ECHO_OK) {
      db_stmt_finalize(&stmt);
      return result;
    }

    /* Execute */
    result = db_step(&stmt);
    if (result != ECHO_DONE) {
      db_stmt_finalize(&stmt);
      return result;
    }
  }

  db_stmt_finalize(&stmt);
  return ECHO_OK;
}

/* ========================================================================
 * Statistics and Queries
 * ======================================================================== */

echo_result_t block_index_db_count(block_index_db_t *bdb, size_t *count) {
  echo_result_t result;
  db_stmt_t stmt;

  result = db_prepare(&bdb->db, "SELECT COUNT(*) FROM blocks", &stmt);
  if (result != ECHO_OK)
    return result;

  result = db_step(&stmt);
  if (result != ECHO_OK) {
    db_stmt_finalize(&stmt);
    return result;
  }

  *count = (size_t)db_column_int(&stmt, 0);

  db_stmt_finalize(&stmt);
  return ECHO_OK;
}

echo_result_t block_index_db_get_height(block_index_db_t *bdb,
                                        uint32_t *height) {
  echo_result_t result;
  block_index_entry_t entry;

  result = block_index_db_get_best_chain(bdb, &entry);
  if (result != ECHO_OK)
    return result;

  *height = entry.height;
  return ECHO_OK;
}

echo_result_t block_index_db_get_chainwork(block_index_db_t *bdb,
                                           work256_t *chainwork) {
  echo_result_t result;
  block_index_entry_t entry;

  result = block_index_db_get_best_chain(bdb, &entry);
  if (result != ECHO_OK)
    return result;

  *chainwork = entry.chainwork;
  return ECHO_OK;
}
