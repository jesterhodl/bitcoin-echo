/*
 * Bitcoin Echo — Pruning Tests (Session 9.6.2)
 *
 * Tests for block pruning functionality including:
 * - Block status flags for pruned blocks
 * - Block storage file operations (delete, size)
 * - Block index database pruning operations
 * - Pruning configuration
 */

#include "block_index_db.h"
#include "blocks_storage.h"
#include "echo_types.h"
#include "node.h"
#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "test_utils.h"

#define ASSERT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("\n%s:%d: Assertion failed: %s\n", __FILE__, __LINE__, #cond);    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_EQ(a, b)                                                        \
  do {                                                                         \
    if ((a) != (b)) {                                                          \
      printf("\n%s:%d: Expected %d, got %d\n", __FILE__, __LINE__, (int)(b),   \
             (int)(a));                                                        \
      return;                                                                  \
    }                                                                          \
  } while (0)

/*
 * Test data directory.
 */
#define TEST_DATA_DIR "/tmp/echo_pruning_test"

/*
 * Recursively remove a directory and all its contents.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static void remove_dir_recursive(const char *path) {
  DIR *dir = opendir(path);
  if (dir == NULL) {
    return;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

    struct stat st;
    if (stat(full_path, &st) == 0) {
      if (S_ISDIR(st.st_mode)) {
        remove_dir_recursive(full_path);
      } else {
        unlink(full_path);
      }
    }
  }
  closedir(dir);
  rmdir(path);
}

static void cleanup_test_dir(void) { remove_dir_recursive(TEST_DATA_DIR); }

/*
 * Test: BLOCK_STATUS_PRUNED flag value.
 */
static void test_pruned_flag_value(void) {
  /* Verify flag is defined and has expected value */
  ASSERT_EQ(BLOCK_STATUS_PRUNED, 0x40);

  /* Verify flag doesn't overlap with other status flags */
  ASSERT((BLOCK_STATUS_PRUNED & BLOCK_STATUS_VALID_HEADER) == 0);
  ASSERT((BLOCK_STATUS_PRUNED & BLOCK_STATUS_VALID_TREE) == 0);
  ASSERT((BLOCK_STATUS_PRUNED & BLOCK_STATUS_VALID_SCRIPTS) == 0);
  ASSERT((BLOCK_STATUS_PRUNED & BLOCK_STATUS_VALID_CHAIN) == 0);
  ASSERT((BLOCK_STATUS_PRUNED & BLOCK_STATUS_HAVE_DATA) == 0);
  ASSERT((BLOCK_STATUS_PRUNED & BLOCK_STATUS_FAILED) == 0);
}

/*
 * Test: PRUNE_TARGET_MIN_MB constant.
 */
static void test_prune_target_min(void) {
  /* Verify minimum is 550 MB (for reorg safety) */
  ASSERT_EQ(PRUNE_TARGET_MIN_MB, 550);
}

/*
 * Test: Block storage file existence check.
 */
static void test_block_storage_file_exists(void) {
  cleanup_test_dir();

  block_file_manager_t mgr;
  ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

  /* File 0 should not exist yet */
  bool exists = true;
  ASSERT_EQ(block_storage_file_exists(&mgr, 0, &exists), ECHO_OK);
  ASSERT(exists == false);

  /* Write a block to create the file */
  uint8_t block_data[100] = {0};
  block_file_pos_t pos;
  ASSERT_EQ(block_storage_write(&mgr, block_data, 100, &pos), ECHO_OK);

  /* Now file 0 should exist */
  ASSERT_EQ(block_storage_file_exists(&mgr, 0, &exists), ECHO_OK);
  ASSERT(exists == true);

  /* File 1 should not exist */
  ASSERT_EQ(block_storage_file_exists(&mgr, 1, &exists), ECHO_OK);
  ASSERT(exists == false);

  cleanup_test_dir();
}

/*
 * Test: Block storage file size query.
 */
static void test_block_storage_get_file_size(void) {
  cleanup_test_dir();

  block_file_manager_t mgr;
  ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

  /* Size of non-existent file should be 0 */
  uint64_t size = 999;
  ASSERT_EQ(block_storage_get_file_size(&mgr, 0, &size), ECHO_OK);
  ASSERT_EQ(size, 0);

  /* Write a block */
  uint8_t block_data[100] = {0};
  block_file_pos_t pos;
  ASSERT_EQ(block_storage_write(&mgr, block_data, 100, &pos), ECHO_OK);

  /* File should now have size > 0 */
  ASSERT_EQ(block_storage_get_file_size(&mgr, 0, &size), ECHO_OK);
  ASSERT(size > 0);
  /* Size should include record header */
  ASSERT(size >= 100 + BLOCK_FILE_RECORD_HEADER_SIZE);

  cleanup_test_dir();
}

/*
 * Test: Block storage total size query.
 */
static void test_block_storage_get_total_size(void) {
  cleanup_test_dir();

  block_file_manager_t mgr;
  ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

  /* Empty storage should have size 0 */
  uint64_t total = 999;
  ASSERT_EQ(block_storage_get_total_size(&mgr, &total), ECHO_OK);
  ASSERT_EQ(total, 0);

  /* Write some blocks */
  uint8_t block_data[100] = {0};
  block_file_pos_t pos;
  ASSERT_EQ(block_storage_write(&mgr, block_data, 100, &pos), ECHO_OK);
  ASSERT_EQ(block_storage_write(&mgr, block_data, 100, &pos), ECHO_OK);
  ASSERT_EQ(block_storage_write(&mgr, block_data, 100, &pos), ECHO_OK);

  /* Total should be > 0 */
  ASSERT_EQ(block_storage_get_total_size(&mgr, &total), ECHO_OK);
  ASSERT(total > 0);

  cleanup_test_dir();
}

/*
 * Test: Block storage get current file.
 */
static void test_block_storage_get_current_file(void) {
  cleanup_test_dir();

  block_file_manager_t mgr;
  ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

  /* Initial file should be 0 */
  ASSERT_EQ(block_storage_get_current_file(&mgr), 0);

  cleanup_test_dir();
}

/*
 * Test: Block storage delete file.
 */
static void test_block_storage_delete_file(void) {
  cleanup_test_dir();

  block_file_manager_t mgr;
  ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

  /* Write a block to create file 0 */
  uint8_t block_data[100] = {0};
  block_file_pos_t pos;
  ASSERT_EQ(block_storage_write(&mgr, block_data, 100, &pos), ECHO_OK);

  /* Verify file exists */
  bool exists = false;
  ASSERT_EQ(block_storage_file_exists(&mgr, 0, &exists), ECHO_OK);
  ASSERT(exists == true);

  /* Cannot delete current write file */
  ASSERT_EQ(block_storage_delete_file(&mgr, 0), ECHO_ERR_INVALID_PARAM);

  /* Simulate having moved to file 1 by modifying manager */
  mgr.current_file_index = 1;

  /* Now we should be able to delete file 0 */
  ASSERT_EQ(block_storage_delete_file(&mgr, 0), ECHO_OK);

  /* Verify file is gone */
  ASSERT_EQ(block_storage_file_exists(&mgr, 0, &exists), ECHO_OK);
  ASSERT(exists == false);

  cleanup_test_dir();
}

/*
 * Test: Block index database mark pruned.
 */
static void test_block_index_db_mark_pruned(void) {
  cleanup_test_dir();
  mkdir(TEST_DATA_DIR, 0755);

  char db_path[512];
  snprintf(db_path, sizeof(db_path), "%s/blocks.db", TEST_DATA_DIR);

  block_index_db_t db;
  ASSERT_EQ(block_index_db_open(&db, db_path), ECHO_OK);

  /* Create some test block entries */
  for (uint32_t i = 0; i < 10; i++) {
    block_index_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.height = i;
    entry.hash.bytes[0] = (uint8_t)i; /* Unique hash */
    entry.status = BLOCK_STATUS_VALID_HEADER | BLOCK_STATUS_HAVE_DATA;

    ASSERT_EQ(block_index_db_insert(&db, &entry), ECHO_OK);
  }

  /* Mark blocks 0-4 as pruned */
  ASSERT_EQ(block_index_db_mark_pruned(&db, 0, 5), ECHO_OK);

  /* Verify blocks 0-4 are marked as pruned */
  for (uint32_t i = 0; i < 5; i++) {
    block_index_entry_t entry;
    ASSERT_EQ(block_index_db_lookup_by_height(&db, i, &entry), ECHO_OK);
    ASSERT((entry.status & BLOCK_STATUS_PRUNED) != 0);
    ASSERT((entry.status & BLOCK_STATUS_HAVE_DATA) == 0);
  }

  /* Verify blocks 5-9 are NOT pruned */
  for (uint32_t i = 5; i < 10; i++) {
    block_index_entry_t entry;
    ASSERT_EQ(block_index_db_lookup_by_height(&db, i, &entry), ECHO_OK);
    ASSERT((entry.status & BLOCK_STATUS_PRUNED) == 0);
    ASSERT((entry.status & BLOCK_STATUS_HAVE_DATA) != 0);
  }

  block_index_db_close(&db);
  cleanup_test_dir();
}

/*
 * Test: Block index database get pruned height.
 */
static void test_block_index_db_get_pruned_height(void) {
  cleanup_test_dir();
  mkdir(TEST_DATA_DIR, 0755);

  char db_path[512];
  snprintf(db_path, sizeof(db_path), "%s/blocks.db", TEST_DATA_DIR);

  block_index_db_t db;
  ASSERT_EQ(block_index_db_open(&db, db_path), ECHO_OK);

  /* Create test entries */
  for (uint32_t i = 0; i < 10; i++) {
    block_index_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.height = i;
    entry.hash.bytes[0] = (uint8_t)i;
    entry.status = BLOCK_STATUS_VALID_HEADER | BLOCK_STATUS_HAVE_DATA;

    ASSERT_EQ(block_index_db_insert(&db, &entry), ECHO_OK);
  }

  /* Initially, pruned height should be 0 (genesis has data) */
  uint32_t pruned_height = 999;
  ASSERT_EQ(block_index_db_get_pruned_height(&db, &pruned_height), ECHO_OK);
  ASSERT_EQ(pruned_height, 0);

  /* Prune blocks 0-4 */
  ASSERT_EQ(block_index_db_mark_pruned(&db, 0, 5), ECHO_OK);

  /* Now pruned height should be 5 (first block with data) */
  ASSERT_EQ(block_index_db_get_pruned_height(&db, &pruned_height), ECHO_OK);
  ASSERT_EQ(pruned_height, 5);

  block_index_db_close(&db);
  cleanup_test_dir();
}

/*
 * Test: Block index database is_pruned check.
 */
static void test_block_index_db_is_pruned(void) {
  cleanup_test_dir();
  mkdir(TEST_DATA_DIR, 0755);

  char db_path[512];
  snprintf(db_path, sizeof(db_path), "%s/blocks.db", TEST_DATA_DIR);

  block_index_db_t db;
  ASSERT_EQ(block_index_db_open(&db, db_path), ECHO_OK);

  /* Create a test entry */
  block_index_entry_t entry;
  memset(&entry, 0, sizeof(entry));
  entry.height = 0;
  entry.hash.bytes[0] = 0x42;
  entry.status = BLOCK_STATUS_VALID_HEADER | BLOCK_STATUS_HAVE_DATA;

  ASSERT_EQ(block_index_db_insert(&db, &entry), ECHO_OK);

  /* Check not pruned initially */
  bool is_pruned = true;
  ASSERT_EQ(block_index_db_is_pruned(&db, &entry.hash, &is_pruned), ECHO_OK);
  ASSERT(is_pruned == false);

  /* Mark as pruned */
  ASSERT_EQ(block_index_db_mark_pruned(&db, 0, 1), ECHO_OK);

  /* Now should be pruned */
  ASSERT_EQ(block_index_db_is_pruned(&db, &entry.hash, &is_pruned), ECHO_OK);
  ASSERT(is_pruned == true);

  block_index_db_close(&db);
  cleanup_test_dir();
}

/*
 * Test: Node config prune target initialization.
 */
static void test_node_config_prune_target(void) {
  node_config_t config;
  node_config_init(&config, TEST_DATA_DIR);

  /* Default should be 0 (no pruning) */
  ASSERT_EQ(config.prune_target_mb, 0);
}

/*
 * Test: NULL parameter handling for pruning functions.
 */
static void test_pruning_null_params(void) {
  block_file_manager_t mgr;
  bool exists;
  uint64_t size;

  ASSERT_EQ(block_storage_file_exists(NULL, 0, &exists), ECHO_ERR_NULL_PARAM);
  ASSERT_EQ(block_storage_file_exists(&mgr, 0, NULL), ECHO_ERR_NULL_PARAM);

  ASSERT_EQ(block_storage_get_file_size(NULL, 0, &size), ECHO_ERR_NULL_PARAM);
  ASSERT_EQ(block_storage_get_file_size(&mgr, 0, NULL), ECHO_ERR_NULL_PARAM);

  ASSERT_EQ(block_storage_get_total_size(NULL, &size), ECHO_ERR_NULL_PARAM);
  ASSERT_EQ(block_storage_get_total_size(&mgr, NULL), ECHO_ERR_NULL_PARAM);

  ASSERT_EQ(block_storage_delete_file(NULL, 0), ECHO_ERR_NULL_PARAM);
}

/*
 * Main test runner.
 */
int main(void) {
  test_suite_begin("Pruning Tests");

  test_case("BLOCK_STATUS_PRUNED flag value");
  test_pruned_flag_value();
  test_pass();

  test_case("PRUNE_TARGET_MIN_MB constant");
  test_prune_target_min();
  test_pass();

  test_case("Block storage file exists check");
  test_block_storage_file_exists();
  test_pass();

  test_case("Block storage get file size");
  test_block_storage_get_file_size();
  test_pass();

  test_case("Block storage get total size");
  test_block_storage_get_total_size();
  test_pass();

  test_case("Block storage get current file");
  test_block_storage_get_current_file();
  test_pass();

  test_case("Block storage delete file");
  test_block_storage_delete_file();
  test_pass();

  test_case("Block index DB mark pruned");
  test_block_index_db_mark_pruned();
  test_pass();

  test_case("Block index DB get pruned height");
  test_block_index_db_get_pruned_height();
  test_pass();

  test_case("Block index DB is_pruned check");
  test_block_index_db_is_pruned();
  test_pass();

  test_case("Node config prune target initialization");
  test_node_config_prune_target();
  test_pass();

  test_case("Pruning NULL parameter handling");
  test_pruning_null_params();
  test_pass();

  test_suite_end();
  return test_global_summary();
}
