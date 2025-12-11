/*
 * Bitcoin Echo — Block File Storage Tests
 *
 * Tests for append-only block file storage.
 */

#include "blocks_storage.h"
#include "block.h"
#include "echo_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void name(void); \
    static void run_##name(void) { \
        tests_run++; \
        name(); \
        tests_passed++; \
        printf("."); \
        fflush(stdout); \
    } \
    static void name(void)

#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            printf("\n%s:%d: Assertion failed: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while(0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            printf("\n%s:%d: Expected %d, got %d\n", __FILE__, __LINE__, (int)(b), (int)(a)); \
            exit(1); \
        } \
    } while(0)

/*
 * Test data directory.
 */
#define TEST_DATA_DIR "/tmp/echo_block_storage_test"

/*
 * Remove test directory and all contents.
 */
static void cleanup_test_dir(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_DATA_DIR);
    system(cmd);
}

/*
 * Create a minimal valid block for testing.
 */
static void create_test_block(uint8_t *buf, uint32_t *size_out, uint32_t nonce) {
    /* Block header (80 bytes) */
    uint8_t header[80] = {0};

    /* Version (4 bytes) */
    header[0] = 0x01;
    header[1] = 0x00;
    header[2] = 0x00;
    header[3] = 0x00;

    /* Previous block hash (32 bytes) - all zeros */

    /* Merkle root (32 bytes) - use nonce for uniqueness */
    header[36] = (nonce >> 0) & 0xFF;
    header[37] = (nonce >> 8) & 0xFF;
    header[38] = (nonce >> 16) & 0xFF;
    header[39] = (nonce >> 24) & 0xFF;

    /* Timestamp (4 bytes) */
    header[68] = 0x29;
    header[69] = 0xAB;
    header[70] = 0x5F;
    header[71] = 0x49;

    /* Bits (4 bytes) - max difficulty */
    header[72] = 0xFF;
    header[73] = 0xFF;
    header[74] = 0x00;
    header[75] = 0x1D;

    /* Nonce (4 bytes) */
    header[76] = (nonce >> 0) & 0xFF;
    header[77] = (nonce >> 8) & 0xFF;
    header[78] = (nonce >> 16) & 0xFF;
    header[79] = (nonce >> 24) & 0xFF;

    /* Transaction count (varint: 0) */
    uint8_t tx_count = 0;

    /* Assemble block */
    memcpy(buf, header, 80);
    buf[80] = tx_count;

    *size_out = 81;
}

/*
 * Test: Initialize block storage manager.
 */
TEST(test_init) {
    cleanup_test_dir();

    block_file_manager_t mgr;
    echo_result_t result = block_storage_init(&mgr, TEST_DATA_DIR);

    ASSERT_EQ(result, ECHO_OK);
    ASSERT_EQ(mgr.current_file_index, 0);
    ASSERT_EQ(mgr.current_file_offset, 0);

    /* Verify blocks directory was created */
    char blocks_dir[512];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/%s", TEST_DATA_DIR, ECHO_BLOCKS_DIR);

    struct stat st;
    ASSERT(stat(blocks_dir, &st) == 0);
    ASSERT(S_ISDIR(st.st_mode));

    cleanup_test_dir();
}

/*
 * Test: Write a single block.
 */
TEST(test_write_single_block) {
    cleanup_test_dir();

    block_file_manager_t mgr;
    ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

    /* Create test block */
    uint8_t block_data[256];
    uint32_t block_size;
    create_test_block(block_data, &block_size, 1);

    /* Write block */
    block_file_pos_t pos;
    echo_result_t result = block_storage_write(&mgr, block_data, block_size, &pos);

    ASSERT_EQ(result, ECHO_OK);
    ASSERT_EQ(pos.file_index, 0);
    ASSERT_EQ(pos.file_offset, 0);

    /* Manager should have updated position */
    ASSERT_EQ(mgr.current_file_index, 0);
    ASSERT_EQ(mgr.current_file_offset, BLOCK_FILE_RECORD_HEADER_SIZE + block_size);

    cleanup_test_dir();
}

/*
 * Test: Read a block back.
 */
TEST(test_read_block) {
    cleanup_test_dir();

    block_file_manager_t mgr;
    ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

    /* Create and write test block */
    uint8_t block_data[256];
    uint32_t block_size;
    create_test_block(block_data, &block_size, 1);

    block_file_pos_t pos;
    ASSERT_EQ(block_storage_write(&mgr, block_data, block_size, &pos), ECHO_OK);

    /* Read block back */
    uint8_t *read_data = NULL;
    uint32_t read_size = 0;
    echo_result_t result = block_storage_read(&mgr, pos, &read_data, &read_size);

    ASSERT_EQ(result, ECHO_OK);
    ASSERT(read_data != NULL);
    ASSERT_EQ(read_size, block_size);

    /* Verify data matches */
    ASSERT(memcmp(read_data, block_data, block_size) == 0);

    free(read_data);
    cleanup_test_dir();
}

/*
 * Test: Write multiple blocks.
 */
TEST(test_write_multiple_blocks) {
    cleanup_test_dir();

    block_file_manager_t mgr;
    ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

    block_file_pos_t positions[10];

    /* Write 10 blocks */
    for (uint32_t i = 0; i < 10; i++) {
        uint8_t block_data[256];
        uint32_t block_size;
        create_test_block(block_data, &block_size, i);

        ASSERT_EQ(block_storage_write(&mgr, block_data, block_size, &positions[i]), ECHO_OK);
    }

    /* Read all blocks back and verify */
    for (uint32_t i = 0; i < 10; i++) {
        uint8_t *read_data = NULL;
        uint32_t read_size = 0;
        ASSERT_EQ(block_storage_read(&mgr, positions[i], &read_data, &read_size), ECHO_OK);

        /* Verify nonce in merkle root */
        ASSERT_EQ(read_data[36], (i >> 0) & 0xFF);
        ASSERT_EQ(read_data[37], (i >> 8) & 0xFF);

        free(read_data);
    }

    cleanup_test_dir();
}

/*
 * Test: Resume after restart (scan existing files).
 */
TEST(test_resume_after_restart) {
    cleanup_test_dir();

    block_file_manager_t mgr;
    ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

    /* Write some blocks */
    uint8_t block_data[256];
    uint32_t block_size;
    create_test_block(block_data, &block_size, 1);

    block_file_pos_t pos1, pos2;
    ASSERT_EQ(block_storage_write(&mgr, block_data, block_size, &pos1), ECHO_OK);

    create_test_block(block_data, &block_size, 2);
    ASSERT_EQ(block_storage_write(&mgr, block_data, block_size, &pos2), ECHO_OK);

    uint32_t expected_offset = mgr.current_file_offset;

    /* Reinitialize manager (simulating restart) */
    block_file_manager_t mgr2;
    ASSERT_EQ(block_storage_init(&mgr2, TEST_DATA_DIR), ECHO_OK);

    /* Should resume at same position */
    ASSERT_EQ(mgr2.current_file_index, 0);
    ASSERT_EQ(mgr2.current_file_offset, expected_offset);

    /* Should be able to write more blocks */
    create_test_block(block_data, &block_size, 3);
    block_file_pos_t pos3;
    ASSERT_EQ(block_storage_write(&mgr2, block_data, block_size, &pos3), ECHO_OK);

    cleanup_test_dir();
}

/*
 * Test: Get block file path.
 */
TEST(test_get_path) {
    block_file_manager_t mgr;
    strcpy(mgr.data_dir, TEST_DATA_DIR);

    char path[512];

    block_storage_get_path(&mgr, 0, path);
    ASSERT(strstr(path, "blk00000.dat") != NULL);

    block_storage_get_path(&mgr, 1, path);
    ASSERT(strstr(path, "blk00001.dat") != NULL);

    block_storage_get_path(&mgr, 99999, path);
    ASSERT(strstr(path, "blk99999.dat") != NULL);
}

/*
 * Test: Read non-existent block.
 */
TEST(test_read_nonexistent) {
    cleanup_test_dir();

    block_file_manager_t mgr;
    ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

    block_file_pos_t pos;
    pos.file_index = 99;
    pos.file_offset = 0;

    uint8_t *block_data = NULL;
    uint32_t block_size = 0;

    echo_result_t result = block_storage_read(&mgr, pos, &block_data, &block_size);
    ASSERT_EQ(result, ECHO_ERR_NOT_FOUND);
    ASSERT(block_data == NULL);

    cleanup_test_dir();
}

/*
 * Test: NULL parameter checks.
 */
TEST(test_null_params) {
    block_file_manager_t mgr;
    uint8_t block_data[256];
    uint32_t block_size = 81;
    block_file_pos_t pos;
    uint8_t *read_data = NULL;
    uint32_t read_size = 0;

    ASSERT_EQ(block_storage_init(NULL, TEST_DATA_DIR), ECHO_ERR_NULL_PARAM);
    ASSERT_EQ(block_storage_init(&mgr, NULL), ECHO_ERR_NULL_PARAM);

    ASSERT_EQ(block_storage_write(NULL, block_data, block_size, &pos), ECHO_ERR_NULL_PARAM);
    ASSERT_EQ(block_storage_write(&mgr, NULL, block_size, &pos), ECHO_ERR_NULL_PARAM);
    ASSERT_EQ(block_storage_write(&mgr, block_data, block_size, NULL), ECHO_ERR_NULL_PARAM);

    ASSERT_EQ(block_storage_read(NULL, pos, &read_data, &read_size), ECHO_ERR_NULL_PARAM);
    ASSERT_EQ(block_storage_read(&mgr, pos, NULL, &read_size), ECHO_ERR_NULL_PARAM);
    ASSERT_EQ(block_storage_read(&mgr, pos, &read_data, NULL), ECHO_ERR_NULL_PARAM);
}

/*
 * Test: Large block (near max size).
 */
TEST(test_large_block) {
    cleanup_test_dir();

    block_file_manager_t mgr;
    ASSERT_EQ(block_storage_init(&mgr, TEST_DATA_DIR), ECHO_OK);

    /* Create a large block (1 MB) */
    uint32_t large_size = 1024 * 1024;
    uint8_t *large_block = (uint8_t *)malloc(large_size);
    ASSERT(large_block != NULL);

    /* Fill with pattern */
    for (uint32_t i = 0; i < large_size; i++) {
        large_block[i] = (uint8_t)(i & 0xFF);
    }

    /* Write it */
    block_file_pos_t pos;
    ASSERT_EQ(block_storage_write(&mgr, large_block, large_size, &pos), ECHO_OK);

    /* Read it back */
    uint8_t *read_data = NULL;
    uint32_t read_size = 0;
    ASSERT_EQ(block_storage_read(&mgr, pos, &read_data, &read_size), ECHO_OK);

    ASSERT_EQ(read_size, large_size);
    ASSERT(memcmp(read_data, large_block, large_size) == 0);

    free(large_block);
    free(read_data);
    cleanup_test_dir();
}

/*
 * Main test runner.
 */
int main(void) {
    printf("Running block storage tests...\n");

    run_test_init();
    run_test_write_single_block();
    run_test_read_block();
    run_test_write_multiple_blocks();
    run_test_resume_after_restart();
    run_test_get_path();
    run_test_read_nonexistent();
    run_test_null_params();
    run_test_large_block();

    printf("\n");
    printf("Block storage tests: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
