/**
 * Bitcoin Echo — PULL-Based Block Download Manager
 *
 * Implements libbitcoin-style work distribution:
 *
 * - Work is organized as BATCHES, not individual items
 * - Peers PULL work when idle, coordinator doesn't push
 * - Starved peers trigger SPLIT from slowest peer
 * - Slow peers are DISCONNECTED, not cooled down
 *
 * See IBD-PULL-MODEL-REWRITE.md for architectural details.
 *
 * Build once. Build right. Stop.
 */

#define LOG_COMPONENT LOG_COMP_SYNC

#include "download_mgr.h"
#include "log.h"
#include "platform.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Internal Structures
 * ============================================================================
 */

/**
 * Batch queue node (doubly-linked list for efficient removal).
 */
typedef struct batch_node {
  work_batch_t batch;
  struct batch_node *next;
  struct batch_node *prev;
} batch_node_t;

/**
 * Download manager internal state.
 *
 * libbitcoin-style: Batch queue + peer performance tracking.
 */
struct download_mgr {
  /* Callbacks for network operations */
  download_callbacks_t callbacks;

  /* Batch queue (doubly-linked list) */
  batch_node_t *queue_head; /* Front of queue (oldest batches) */
  batch_node_t *queue_tail; /* Back of queue (newest batches) */
  size_t queue_count;       /* Number of batches in queue */

  /* Height tracking */
  uint32_t lowest_pending_height;  /* Lowest height in queue/assigned */
  uint32_t highest_queued_height;  /* Highest height added */

  /* Peer performance tracking */
  peer_perf_t peers[DOWNLOAD_MAX_PEERS];
  size_t peer_count;
};

/* ============================================================================
 * Internal Helpers - Batch Queue Operations
 * ============================================================================
 */

/**
 * Allocate a new batch node.
 */
static batch_node_t *batch_node_create(void) {
  batch_node_t *node = calloc(1, sizeof(batch_node_t));
  return node;
}

/**
 * Free a batch node.
 */
static void batch_node_destroy(batch_node_t *node) { free(node); }

/**
 * Add batch to end of queue.
 */
static void queue_push_back(download_mgr_t *mgr, batch_node_t *node) {
  node->next = NULL;
  node->prev = mgr->queue_tail;

  if (mgr->queue_tail != NULL) {
    mgr->queue_tail->next = node;
  } else {
    mgr->queue_head = node;
  }
  mgr->queue_tail = node;
  mgr->queue_count++;
}

/**
 * Add batch to front of queue (for returned work).
 */
static void queue_push_front(download_mgr_t *mgr, batch_node_t *node) {
  node->prev = NULL;
  node->next = mgr->queue_head;

  if (mgr->queue_head != NULL) {
    mgr->queue_head->prev = node;
  } else {
    mgr->queue_tail = node;
  }
  mgr->queue_head = node;
  mgr->queue_count++;
}

/**
 * Remove batch from queue (for assignment to peer).
 * Returns the removed node (caller takes ownership).
 */
static batch_node_t *queue_pop_front(download_mgr_t *mgr) {
  if (mgr->queue_head == NULL) {
    return NULL;
  }

  batch_node_t *node = mgr->queue_head;
  mgr->queue_head = node->next;

  if (mgr->queue_head != NULL) {
    mgr->queue_head->prev = NULL;
  } else {
    mgr->queue_tail = NULL;
  }

  node->next = NULL;
  node->prev = NULL;
  mgr->queue_count--;

  return node;
}

/* ============================================================================
 * Internal Helpers - Peer Operations
 * ============================================================================
 */

/**
 * Find peer_perf slot by peer pointer.
 * Returns NULL if not found.
 */
static peer_perf_t *find_peer_perf(download_mgr_t *mgr, const peer_t *peer) {
  for (size_t i = 0; i < mgr->peer_count; i++) {
    if (mgr->peers[i].peer == peer) {
      return &mgr->peers[i];
    }
  }
  return NULL;
}

/**
 * Find peer_perf slot by peer pointer (const version).
 * Returns NULL if not found.
 */
static const peer_perf_t *find_peer_perf_const(const download_mgr_t *mgr,
                                               const peer_t *peer) {
  for (size_t i = 0; i < mgr->peer_count; i++) {
    if (mgr->peers[i].peer == peer) {
      return &mgr->peers[i];
    }
  }
  return NULL;
}

/**
 * Find the slowest peer that has an assigned batch.
 * Returns NULL if no peers have work.
 */
static peer_perf_t *find_slowest_peer_with_work(download_mgr_t *mgr) {
  peer_perf_t *slowest = NULL;
  float slowest_rate = 1e30f; /* INFINITY equivalent */

  for (size_t i = 0; i < mgr->peer_count; i++) {
    peer_perf_t *perf = &mgr->peers[i];
    if (perf->peer == NULL || perf->batch == NULL) {
      continue; /* No peer or no work */
    }

    /* Peers with 0 rate (unmeasured) are considered slowest */
    float rate = perf->bytes_per_second;
    if (rate < slowest_rate) {
      slowest_rate = rate;
      slowest = perf;
    }
  }

  return slowest;
}

/**
 * Compact the peers array by removing NULL entries.
 */
static void compact_peers(download_mgr_t *mgr) {
  size_t write = 0;
  for (size_t read = 0; read < mgr->peer_count; read++) {
    if (mgr->peers[read].peer != NULL) {
      if (write != read) {
        mgr->peers[write] = mgr->peers[read];
      }
      write++;
    }
  }
  mgr->peer_count = write;
}

/**
 * Update performance window for a peer.
 * Called when recording bytes or on timer.
 */
static void update_peer_window(peer_perf_t *perf, uint64_t now) {
  uint64_t elapsed = now - perf->window_start_time;

  if (elapsed >= DOWNLOAD_PERF_WINDOW_MS) {
    /* Calculate bytes/second for the completed window */
    perf->bytes_per_second =
        (float)perf->bytes_this_window / ((float)elapsed / 1000.0f);

    /* Reset window */
    perf->bytes_this_window = 0;
    perf->window_start_time = now;
  }
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================
 */

download_mgr_t *download_mgr_create(const download_callbacks_t *callbacks) {
  if (callbacks == NULL) {
    return NULL;
  }

  download_mgr_t *mgr = calloc(1, sizeof(download_mgr_t));
  if (mgr == NULL) {
    return NULL;
  }

  mgr->callbacks = *callbacks;
  return mgr;
}

void download_mgr_destroy(download_mgr_t *mgr) {
  if (mgr == NULL) {
    return;
  }

  /* Free all queued batches */
  while (mgr->queue_head != NULL) {
    batch_node_t *node = queue_pop_front(mgr);
    batch_node_destroy(node);
  }

  /* Free all assigned batches (in peer slots) */
  for (size_t i = 0; i < mgr->peer_count; i++) {
    if (mgr->peers[i].batch != NULL) {
      /* batch is first field in batch_node_t, so cast is direct */
      batch_node_t *node = (batch_node_t *)(void *)mgr->peers[i].batch;
      batch_node_destroy(node);
      mgr->peers[i].batch = NULL;
    }
  }

  free(mgr);
}

void download_mgr_add_peer(download_mgr_t *mgr, peer_t *peer) {
  if (mgr == NULL || peer == NULL) {
    return;
  }

  /* Check if already tracked */
  if (find_peer_perf(mgr, peer) != NULL) {
    return;
  }

  /* Find empty slot */
  if (mgr->peer_count >= DOWNLOAD_MAX_PEERS) {
    LOG_WARN("download_mgr: max peers reached, cannot add peer");
    return;
  }

  peer_perf_t *perf = &mgr->peers[mgr->peer_count++];
  memset(perf, 0, sizeof(peer_perf_t));
  perf->peer = peer;
  perf->batch = NULL; /* Idle - will pull work */
  perf->window_start_time = plat_time_ms();
  perf->last_delivery_time = plat_time_ms();

  LOG_DEBUG("download_mgr: added peer, total=%zu", mgr->peer_count);
}

void download_mgr_remove_peer(download_mgr_t *mgr, peer_t *peer) {
  if (mgr == NULL || peer == NULL) {
    return;
  }

  peer_perf_t *perf = find_peer_perf(mgr, peer);
  if (perf == NULL) {
    return;
  }

  /* Return any assigned batch to the queue */
  if (perf->batch != NULL) {
    /* batch is first field in batch_node_t, so cast is direct */
    batch_node_t *node = (batch_node_t *)(void *)perf->batch;
    node->batch.assigned_time = 0; /* Mark as unassigned */
    queue_push_front(mgr, node);   /* Return to front of queue */
    perf->batch = NULL;
    LOG_DEBUG("download_mgr: returned batch to queue from removed peer");
  }

  /* Mark slot as empty */
  perf->peer = NULL;
  compact_peers(mgr);

  LOG_DEBUG("download_mgr: removed peer, total=%zu", mgr->peer_count);
}

size_t download_mgr_add_work(download_mgr_t *mgr, const hash256_t *hashes,
                             const uint32_t *heights, size_t count) {
  if (mgr == NULL || hashes == NULL || heights == NULL || count == 0) {
    return 0;
  }

  /* Check queue capacity */
  if (mgr->queue_count >= DOWNLOAD_MAX_BATCHES) {
    LOG_WARN("download_mgr: batch queue full (%zu batches)", mgr->queue_count);
    return 0;
  }

  size_t added = 0;
  size_t i = 0;

  while (i < count && mgr->queue_count < DOWNLOAD_MAX_BATCHES) {
    /* Create a new batch */
    batch_node_t *node = batch_node_create();
    if (node == NULL) {
      LOG_WARN("download_mgr: failed to allocate batch node");
      break;
    }

    /* Fill the batch with up to DOWNLOAD_BATCH_SIZE blocks */
    size_t batch_count = 0;
    while (batch_count < DOWNLOAD_BATCH_SIZE && i < count) {
      memcpy(&node->batch.hashes[batch_count], &hashes[i], sizeof(hash256_t));
      node->batch.heights[batch_count] = heights[i];
      batch_count++;
      i++;
      added++;
    }

    node->batch.count = batch_count;
    node->batch.remaining = batch_count;
    node->batch.assigned_time = 0; /* Not assigned yet */

    /* Update height tracking */
    if (mgr->lowest_pending_height == 0 ||
        node->batch.heights[0] < mgr->lowest_pending_height) {
      mgr->lowest_pending_height = node->batch.heights[0];
    }
    if (node->batch.heights[batch_count - 1] > mgr->highest_queued_height) {
      mgr->highest_queued_height = node->batch.heights[batch_count - 1];
    }

    /* Add to queue */
    queue_push_back(mgr, node);
  }

  if (added > 0) {
    LOG_DEBUG("download_mgr: added %zu blocks in %zu batches, queue=%zu", added,
              (added + DOWNLOAD_BATCH_SIZE - 1) / DOWNLOAD_BATCH_SIZE,
              mgr->queue_count);
  }

  return added;
}

/* ============================================================================
 * PULL Model API Implementation (libbitcoin-style)
 * ============================================================================
 */

bool download_mgr_peer_request_work(download_mgr_t *mgr, peer_t *peer) {
  if (mgr == NULL || peer == NULL) {
    return false;
  }

  peer_perf_t *perf = find_peer_perf(mgr, peer);
  if (perf == NULL) {
    LOG_WARN("download_mgr: unknown peer requesting work");
    return false;
  }

  /* libbitcoin-style: Peer should be idle when requesting work */
  if (perf->batch != NULL && perf->batch->remaining > 0) {
    LOG_DEBUG("download_mgr: peer still has work, ignoring request");
    return false;
  }

  /* If peer had a completed batch, free it */
  if (perf->batch != NULL) {
    /* batch is first field in batch_node_t, so cast is direct */
    batch_node_t *old_node = (batch_node_t *)(void *)perf->batch;
    batch_node_destroy(old_node);
    perf->batch = NULL;
  }

  /* Try to get a batch from the queue */
  batch_node_t *node = queue_pop_front(mgr);
  if (node == NULL) {
    /* Queue empty - peer is starved */
    LOG_DEBUG("download_mgr: no work available, peer starved");
    return false;
  }

  /* Assign batch to peer */
  node->batch.assigned_time = plat_time_ms();
  perf->batch = &node->batch;
  perf->last_delivery_time = plat_time_ms();

  /* Send getdata for all blocks in batch */
  if (mgr->callbacks.send_getdata != NULL) {
    mgr->callbacks.send_getdata(peer, node->batch.hashes, node->batch.count,
                                mgr->callbacks.ctx);
  }

  LOG_DEBUG("download_mgr: assigned batch of %zu blocks to peer",
            node->batch.count);
  return true;
}

void download_mgr_peer_starved(download_mgr_t *mgr, peer_t *peer) {
  if (mgr == NULL) {
    return;
  }

  (void)peer; /* Starved peer identity used for logging only */

  /* libbitcoin-style: Find slowest peer and trigger split */
  peer_perf_t *slowest = find_slowest_peer_with_work(mgr);

  if (slowest == NULL) {
    /* No peer has work - nothing to split */
    LOG_DEBUG("download_mgr: starved but no peers have work to split");
    return;
  }

  LOG_INFO("download_mgr: starved condition - splitting from slowest peer "
           "(rate=%.0f B/s)",
           (double)slowest->bytes_per_second);

  /* Split (which disconnects the slow peer) */
  download_mgr_peer_split(mgr, slowest->peer);
}

void download_mgr_peer_split(download_mgr_t *mgr, peer_t *peer) {
  if (mgr == NULL || peer == NULL) {
    return;
  }

  peer_perf_t *perf = find_peer_perf(mgr, peer);
  if (perf == NULL || perf->batch == NULL) {
    return; /* Peer not found or has no work */
  }

  /* libbitcoin-style: Return ALL work to queue */
  /* batch is first field in batch_node_t, so cast is direct */
  batch_node_t *node = (batch_node_t *)(void *)perf->batch;
  node->batch.assigned_time = 0; /* Mark as unassigned */
  queue_push_front(mgr, node);   /* Return to FRONT (high priority) */
  perf->batch = NULL;

  LOG_INFO("download_mgr: returned batch to queue, disconnecting slow peer");

  /* libbitcoin-style: DISCONNECT the slow peer (sacrifice) */
  if (mgr->callbacks.disconnect_peer != NULL) {
    mgr->callbacks.disconnect_peer(peer, "slow performance (sacrificed)",
                                   mgr->callbacks.ctx);
  }

  /* Mark peer slot as empty (will be compacted on next removal or query) */
  perf->peer = NULL;
  compact_peers(mgr);
}

bool download_mgr_block_received(download_mgr_t *mgr, peer_t *peer,
                                 const hash256_t *hash, size_t block_size) {
  if (mgr == NULL || peer == NULL || hash == NULL) {
    return false;
  }

  peer_perf_t *perf = find_peer_perf(mgr, peer);
  if (perf == NULL) {
    /* Unknown peer - accept block but can't track */
    LOG_DEBUG("download_mgr: block from unknown peer");
    return true;
  }

  /* Update performance tracking */
  uint64_t now = plat_time_ms();
  perf->bytes_this_window += block_size;
  perf->last_delivery_time = now;
  update_peer_window(perf, now);

  /* Check if block is in peer's batch */
  if (perf->batch == NULL) {
    /* Late delivery - peer has no batch (was split or completed) */
    LOG_DEBUG("download_mgr: late block delivery from idle peer");
    return true;
  }

  /* Find the block in the batch */
  for (size_t i = 0; i < perf->batch->count; i++) {
    if (memcmp(&perf->batch->hashes[i], hash, sizeof(hash256_t)) == 0) {
      /* Found it - decrement remaining */
      if (perf->batch->remaining > 0) {
        perf->batch->remaining--;
      }
      LOG_DEBUG("download_mgr: block received, batch remaining=%zu",
                perf->batch->remaining);
      return true;
    }
  }

  /* Block not in batch - late delivery or unrequested */
  LOG_DEBUG("download_mgr: block not in peer's batch (late delivery)");
  return true;
}

bool download_mgr_peer_is_idle(const download_mgr_t *mgr, const peer_t *peer) {
  if (mgr == NULL || peer == NULL) {
    return true;
  }

  const peer_perf_t *perf = find_peer_perf_const(mgr, peer);
  if (perf == NULL) {
    return true; /* Unknown peer considered idle */
  }

  /* Idle if no batch OR batch is complete (all blocks received) */
  return perf->batch == NULL || perf->batch->remaining == 0;
}

bool download_mgr_update_peer_performance(download_mgr_t *mgr, peer_t *peer) {
  if (mgr == NULL || peer == NULL) {
    return true;
  }

  peer_perf_t *perf = find_peer_perf(mgr, peer);
  if (perf == NULL) {
    return false;
  }

  uint64_t now = plat_time_ms();
  update_peer_window(perf, now);

  /* For now, always return healthy - stall detection handled elsewhere */
  return true;
}

/* ============================================================================
 * Query Functions
 * ============================================================================
 */

size_t download_mgr_queue_count(const download_mgr_t *mgr) {
  return mgr != NULL ? mgr->queue_count : 0;
}

size_t download_mgr_assigned_count(const download_mgr_t *mgr) {
  if (mgr == NULL) {
    return 0;
  }

  size_t count = 0;
  for (size_t i = 0; i < mgr->peer_count; i++) {
    if (mgr->peers[i].peer != NULL && mgr->peers[i].batch != NULL) {
      count++;
    }
  }
  return count;
}

size_t download_mgr_pending_blocks(const download_mgr_t *mgr) {
  if (mgr == NULL) {
    return 0;
  }

  size_t total = 0;

  /* Count blocks in queue */
  for (batch_node_t *node = mgr->queue_head; node != NULL; node = node->next) {
    total += node->batch.remaining;
  }

  /* Count blocks assigned to peers */
  for (size_t i = 0; i < mgr->peer_count; i++) {
    if (mgr->peers[i].batch != NULL) {
      total += mgr->peers[i].batch->remaining;
    }
  }

  return total;
}

size_t download_mgr_active_peer_count(const download_mgr_t *mgr) {
  if (mgr == NULL) {
    return 0;
  }

  size_t count = 0;
  for (size_t i = 0; i < mgr->peer_count; i++) {
    if (mgr->peers[i].peer != NULL && mgr->peers[i].batch != NULL &&
        mgr->peers[i].batch->remaining > 0) {
      count++;
    }
  }
  return count;
}

float download_mgr_aggregate_rate(const download_mgr_t *mgr) {
  if (mgr == NULL) {
    return 0.0f;
  }

  float total = 0.0f;
  for (size_t i = 0; i < mgr->peer_count; i++) {
    if (mgr->peers[i].peer != NULL) {
      total += mgr->peers[i].bytes_per_second;
    }
  }
  return total;
}

bool download_mgr_has_block(const download_mgr_t *mgr, const hash256_t *hash) {
  if (mgr == NULL || hash == NULL) {
    return false;
  }

  /* Check queued batches */
  for (batch_node_t *node = mgr->queue_head; node != NULL; node = node->next) {
    for (size_t i = 0; i < node->batch.count; i++) {
      if (memcmp(&node->batch.hashes[i], hash, sizeof(hash256_t)) == 0) {
        return true;
      }
    }
  }

  /* Check assigned batches */
  for (size_t i = 0; i < mgr->peer_count; i++) {
    if (mgr->peers[i].batch != NULL) {
      for (size_t j = 0; j < mgr->peers[i].batch->count; j++) {
        if (memcmp(&mgr->peers[i].batch->hashes[j], hash, sizeof(hash256_t)) ==
            0) {
          return true;
        }
      }
    }
  }

  return false;
}

bool download_mgr_get_peer_stats(const download_mgr_t *mgr, const peer_t *peer,
                                 float *bytes_per_second,
                                 uint32_t *blocks_remaining) {
  if (mgr == NULL || peer == NULL) {
    return false;
  }

  const peer_perf_t *perf = find_peer_perf_const(mgr, peer);
  if (perf == NULL) {
    return false;
  }

  if (bytes_per_second != NULL) {
    *bytes_per_second = perf->bytes_per_second;
  }
  if (blocks_remaining != NULL) {
    *blocks_remaining =
        (perf->batch != NULL) ? (uint32_t)perf->batch->remaining : 0;
  }
  return true;
}

/* ============================================================================
 * Legacy API Compatibility
 * ============================================================================
 */

size_t download_mgr_pending_count(const download_mgr_t *mgr) {
  if (mgr == NULL) {
    return 0;
  }

  /* Pending = blocks in queue (not yet assigned) */
  size_t total = 0;
  for (batch_node_t *node = mgr->queue_head; node != NULL; node = node->next) {
    total += node->batch.remaining;
  }
  return total;
}

size_t download_mgr_inflight_count(const download_mgr_t *mgr) {
  if (mgr == NULL) {
    return 0;
  }

  /* Inflight = blocks assigned to peers but not yet received */
  size_t total = 0;
  for (size_t i = 0; i < mgr->peer_count; i++) {
    if (mgr->peers[i].batch != NULL) {
      total += mgr->peers[i].batch->remaining;
    }
  }
  return total;
}

void download_mgr_block_complete(download_mgr_t *mgr, const hash256_t *hash,
                                 uint32_t height) {
  /* No-op with batch model - blocks are implicitly complete when received
   * and the batch is freed when peer requests new work.
   */
  (void)mgr;
  (void)hash;
  (void)height;
}

/* ============================================================================
 * Debug/Metrics
 * ============================================================================
 */

void download_mgr_get_metrics(const download_mgr_t *mgr,
                              download_metrics_t *metrics) {
  if (mgr == NULL || metrics == NULL) {
    return;
  }

  memset(metrics, 0, sizeof(download_metrics_t));

  metrics->pending_count = download_mgr_pending_count(mgr);
  metrics->inflight_count = download_mgr_inflight_count(mgr);
  metrics->total_peers = mgr->peer_count;
  metrics->lowest_pending = mgr->lowest_pending_height;
  metrics->highest_assigned = mgr->highest_queued_height;
  metrics->aggregate_rate = download_mgr_aggregate_rate(mgr);
  metrics->active_peers = download_mgr_active_peer_count(mgr);
  metrics->stalled_peers = 0; /* No stall tracking in PULL model */
}
