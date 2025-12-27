/**
 * chaser_validate.h — Parallel block validation chaser
 *
 * Validates blocks concurrently using a threadpool. Based on libbitcoin-node's
 * chaser_validate pattern with atomic backlog control.
 *
 * Key features:
 * - Independent threadpool for validation work
 * - Atomic backlog limits concurrent validations
 * - Responds to CHASE_CHECKED events from download
 * - Emits CHASE_VALID on successful validation
 *
 * Copyright (c) 2024 Bitcoin Echo
 * SPDX-License-Identifier: MIT
 */

#ifndef ECHO_CHASER_VALIDATE_H
#define ECHO_CHASER_VALIDATE_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "chaser.h"
#include "chase.h"

/* Forward declarations */
typedef struct chainstate chainstate_t;

/**
 * Work item for validation queue
 */
typedef struct validate_work {
    uint32_t height;           /* Block height */
    uint8_t block_hash[32];    /* Block hash for lookup */
    bool bypass;               /* Skip validation (checkpoint) */
    struct validate_work *next;
} validate_work_t;

/**
 * Thread-safe work queue
 */
typedef struct {
    validate_work_t *head;
    validate_work_t *tail;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    bool shutdown;
} work_queue_t;

/**
 * Chaser validate - parallel block validation
 *
 * Maintains a threadpool that validates blocks concurrently.
 * Backlog control prevents memory exhaustion.
 */
typedef struct {
    chaser_t base;                    /* Base chaser (must be first) */

    /* Threadpool */
    pthread_t *workers;               /* Worker threads */
    size_t worker_count;              /* Number of workers */
    work_queue_t queue;               /* Work queue */

    /* Backlog control */
    _Atomic size_t backlog;           /* Current pending validations */
    size_t maximum_backlog;           /* Cap (default: 50) */

    /* Dependencies */
    chainstate_t *chainstate;         /* For UTXO lookups (not owned) */

    /* Configuration */
    uint32_t top_checkpoint;          /* Height of top checkpoint */
    bool defer_validation;            /* Skip validation entirely */
} chaser_validate_t;

/**
 * Create a new validation chaser
 *
 * @param node          Parent node
 * @param dispatcher    Event dispatcher
 * @param chainstate    Chainstate for UTXO lookups
 * @param worker_count  Number of worker threads (0 = auto)
 * @param max_backlog   Maximum concurrent validations (0 = default 50)
 * @return New chaser, or NULL on failure
 */
chaser_validate_t *chaser_validate_create(node_t *node,
                                          chase_dispatcher_t *dispatcher,
                                          chainstate_t *chainstate,
                                          size_t worker_count,
                                          size_t max_backlog);

/**
 * Destroy a validation chaser
 *
 * Stops workers and frees resources.
 *
 * @param chaser Chaser to destroy
 */
void chaser_validate_destroy(chaser_validate_t *chaser);

/**
 * Get current backlog count
 *
 * @param chaser Chaser to query
 * @return Number of pending validations
 */
size_t chaser_validate_backlog(chaser_validate_t *chaser);

/**
 * Check if validation is bypassed for a height
 *
 * Checkpoints and milestones bypass validation.
 *
 * @param chaser Chaser to query
 * @param height Block height
 * @return true if validation should be bypassed
 */
bool chaser_validate_is_bypass(chaser_validate_t *chaser, uint32_t height);

/**
 * Submit a block for validation
 *
 * Called when a block is downloaded and checked.
 * Returns immediately; validation happens asynchronously.
 *
 * @param chaser     Chaser to submit to
 * @param height     Block height
 * @param block_hash Block hash for lookup
 * @param bypass     Skip validation (checkpoint)
 * @return 0 on success, -1 if backlog is full
 */
int chaser_validate_submit(chaser_validate_t *chaser, uint32_t height,
                           const uint8_t block_hash[32], bool bypass);

#endif /* ECHO_CHASER_VALIDATE_H */
