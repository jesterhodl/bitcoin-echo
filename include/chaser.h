/**
 * chaser.h — Base chaser interface for chain state management
 *
 * Chasers are components that process chain data in a coordinated way.
 * Each chaser operates with thread safety and communicates via events.
 *
 * Based on libbitcoin-node's chaser pattern.
 *
 * Copyright (c) 2024 Bitcoin Echo
 * SPDX-License-Identifier: MIT
 */

#ifndef ECHO_CHASER_H
#define ECHO_CHASER_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "chase.h"

/* Forward declarations */
typedef struct node node_t;
typedef struct chaser chaser_t;

/**
 * Chaser virtual method table
 *
 * Chasers implement these methods to define their behavior.
 */
typedef struct {
    /** Start the chaser (called from node thread) */
    int (*start)(chaser_t *self);

    /** Handle an event (return false to unsubscribe) */
    bool (*handle_event)(chaser_t *self, chase_event_t event,
                         chase_value_t value);

    /** Stop the chaser (called during shutdown) */
    void (*stop)(chaser_t *self);

    /** Destroy the chaser (free resources) */
    void (*destroy)(chaser_t *self);
} chaser_vtable_t;

/**
 * Base chaser structure
 *
 * Embed this as the first member of derived chaser types:
 *
 *   typedef struct {
 *       chaser_t base;
 *       // ... derived members
 *   } my_chaser_t;
 */
struct chaser {
    const chaser_vtable_t *vtable; /* Virtual method table */
    node_t *node;                  /* Parent node (not owned) */
    chase_dispatcher_t *dispatcher; /* Event dispatcher (not owned) */
    chase_subscription_t *subscription; /* Our event subscription */
    pthread_mutex_t mutex;         /* Protects chaser state */

    /* State protected by mutex */
    uint32_t position;             /* Current processing height */
    bool closed;                   /* True if shutting down */
    bool suspended;                /* True if temporarily paused */
    const char *name;              /* Chaser name for logging */
};

/**
 * Initialize a chaser
 *
 * Must be called by derived types before use.
 *
 * @param self       Chaser to initialize
 * @param vtable     Virtual method table
 * @param node       Parent node
 * @param dispatcher Event dispatcher
 * @param name       Chaser name for logging
 * @return 0 on success, -1 on failure
 */
int chaser_init(chaser_t *self, const chaser_vtable_t *vtable, node_t *node,
                chase_dispatcher_t *dispatcher, const char *name);

/**
 * Cleanup a chaser
 *
 * Must be called by derived types during destruction.
 *
 * @param self Chaser to cleanup
 */
void chaser_cleanup(chaser_t *self);

/**
 * Start the chaser
 *
 * Subscribes to events and calls the derived start method.
 *
 * @param self Chaser to start
 * @return 0 on success, error code on failure
 */
int chaser_start(chaser_t *self);

/**
 * Stop the chaser
 *
 * Marks the chaser as closed and calls the derived stop method.
 *
 * @param self Chaser to stop
 */
void chaser_stop(chaser_t *self);

/**
 * Destroy the chaser
 *
 * Calls the derived destroy method.
 *
 * @param self Chaser to destroy
 */
void chaser_destroy(chaser_t *self);

/**
 * Check if chaser is closed
 *
 * @param self Chaser to check
 * @return true if closed
 */
bool chaser_is_closed(chaser_t *self);

/**
 * Check if chaser is suspended
 *
 * @param self Chaser to check
 * @return true if suspended
 */
bool chaser_is_suspended(chaser_t *self);

/**
 * Suspend the chaser
 *
 * @param self Chaser to suspend
 */
void chaser_suspend(chaser_t *self);

/**
 * Resume the chaser
 *
 * @param self Chaser to resume
 */
void chaser_resume(chaser_t *self);

/**
 * Report a fatal fault
 *
 * Notifies the system of an unrecoverable error.
 *
 * @param self   Chaser reporting the fault
 * @param error  Error code
 */
void chaser_fault(chaser_t *self, int error);

/**
 * Get the chaser's current position (height)
 *
 * @param self Chaser to query
 * @return Current position
 */
uint32_t chaser_position(chaser_t *self);

/**
 * Set the chaser's current position (height)
 *
 * @param self     Chaser to update
 * @param position New position
 */
void chaser_set_position(chaser_t *self, uint32_t position);

/**
 * Notify all chasers of an event
 *
 * Convenience wrapper around chase_notify.
 *
 * @param self  Chaser sending the notification
 * @param event Event type
 * @param value Event value
 */
void chaser_notify(chaser_t *self, chase_event_t event, chase_value_t value);

/**
 * Convenience: notify with height value
 */
static inline void chaser_notify_height(chaser_t *self, chase_event_t event,
                                        uint32_t height) {
    chase_value_t value = {.height = height};
    chaser_notify(self, event, value);
}

/**
 * Lock the chaser mutex
 *
 * Use for protecting multi-step operations on chaser state.
 *
 * @param self Chaser to lock
 */
void chaser_lock(chaser_t *self);

/**
 * Unlock the chaser mutex
 *
 * @param self Chaser to unlock
 */
void chaser_unlock(chaser_t *self);

#endif /* ECHO_CHASER_H */
