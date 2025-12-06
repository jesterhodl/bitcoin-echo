/*
 * Bitcoin Echo — POSIX Platform Implementation
 *
 * This file implements the platform abstraction interface for POSIX systems:
 * Linux, macOS, FreeBSD, and other Unix-like operating systems.
 *
 * Session 1.2: Networking
 * Session 1.3: Threading (to be added)
 * Session 1.4: Files, Time, Entropy (to be added)
 *
 * Build once. Build right. Stop.
 */

/* Feature test macros must come before any includes */
#define _POSIX_C_SOURCE 200809L

#include "platform.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Networking */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

/* Threading */
#include <pthread.h>
#include <time.h>

/*
 * ============================================================================
 * Opaque Type Definitions
 * ============================================================================
 *
 * These define the actual contents of the opaque types declared in platform.h.
 * Only this file knows their structure; callers see only pointers.
 */

/*
 * Socket structure.
 * Wraps a file descriptor with state tracking.
 */
struct plat_socket {
    int fd;          /* File descriptor, -1 if not open */
};

/*
 * Thread structure.
 * Wraps pthread_t handle.
 */
struct plat_thread {
    pthread_t handle;
};

/*
 * Mutex structure.
 * Wraps pthread_mutex_t.
 */
struct plat_mutex {
    pthread_mutex_t handle;
};

/*
 * Condition variable structure.
 * Wraps pthread_cond_t.
 */
struct plat_cond {
    pthread_cond_t handle;
};

/*
 * ============================================================================
 * Networking Implementation
 * ============================================================================
 */

int plat_socket_create(plat_socket_t *sock)
{
    int fd;

    if (sock == NULL) {
        return PLAT_ERR;
    }

    /* Create TCP socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        sock->fd = -1;
        return PLAT_ERR;
    }

    sock->fd = fd;
    return PLAT_OK;
}

int plat_socket_connect(plat_socket_t *sock, const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    char port_str[6];
    int ret;

    if (sock == NULL || sock->fd < 0 || host == NULL) {
        return PLAT_ERR;
    }

    /* Convert port to string for getaddrinfo */
    snprintf(port_str, sizeof(port_str), "%u", port);

    /* Set up hints for getaddrinfo */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       /* IPv4 for now */
    hints.ai_socktype = SOCK_STREAM; /* TCP */
    hints.ai_protocol = IPPROTO_TCP;

    /* Resolve hostname */
    ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        return PLAT_ERR;
    }

    /* Try each address until one succeeds */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (connect(sock->fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            freeaddrinfo(result);
            return PLAT_OK;
        }
    }

    freeaddrinfo(result);
    return PLAT_ERR;
}

int plat_socket_listen(plat_socket_t *sock, uint16_t port, int backlog)
{
    struct sockaddr_in addr;
    int optval = 1;

    if (sock == NULL || sock->fd < 0) {
        return PLAT_ERR;
    }

    /* Allow address reuse to avoid "address already in use" on restart */
    if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR,
                   &optval, sizeof(optval)) < 0) {
        return PLAT_ERR;
    }

    /* Bind to all interfaces on specified port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return PLAT_ERR;
    }

    /* Start listening */
    if (listen(sock->fd, backlog) < 0) {
        return PLAT_ERR;
    }

    return PLAT_OK;
}

int plat_socket_accept(plat_socket_t *listener, plat_socket_t *client)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if (listener == NULL || listener->fd < 0 || client == NULL) {
        return PLAT_ERR;
    }

    /* Accept connection (blocks until one arrives) */
    fd = accept(listener->fd, (struct sockaddr *)&addr, &addr_len);
    if (fd < 0) {
        client->fd = -1;
        return PLAT_ERR;
    }

    client->fd = fd;
    return PLAT_OK;
}

int plat_socket_send(plat_socket_t *sock, const void *buf, size_t len)
{
    ssize_t sent;

    if (sock == NULL || sock->fd < 0 || buf == NULL) {
        return PLAT_ERR;
    }

    sent = send(sock->fd, buf, len, 0);
    if (sent < 0) {
        if (errno == EPIPE || errno == ECONNRESET) {
            return PLAT_ERR_CLOSED;
        }
        return PLAT_ERR;
    }

    return (int)sent;
}

int plat_socket_recv(plat_socket_t *sock, void *buf, size_t len)
{
    ssize_t received;

    if (sock == NULL || sock->fd < 0 || buf == NULL) {
        return PLAT_ERR;
    }

    received = recv(sock->fd, buf, len, 0);
    if (received < 0) {
        if (errno == ECONNRESET) {
            return PLAT_ERR_CLOSED;
        }
        return PLAT_ERR;
    }

    /* recv returns 0 on graceful close */
    return (int)received;
}

void plat_socket_close(plat_socket_t *sock)
{
    if (sock == NULL) {
        return;
    }

    if (sock->fd >= 0) {
        close(sock->fd);
        sock->fd = -1;
    }
}

int plat_dns_resolve(const char *host, char *ip_out, size_t ip_len)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct sockaddr_in *addr_in;
    int ret;

    if (host == NULL || ip_out == NULL || ip_len == 0) {
        return PLAT_ERR;
    }

    /* Set up hints for getaddrinfo */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       /* IPv4 */
    hints.ai_socktype = SOCK_STREAM;

    /* Resolve hostname */
    ret = getaddrinfo(host, NULL, &hints, &result);
    if (ret != 0) {
        return PLAT_ERR;
    }

    if (result == NULL) {
        return PLAT_ERR;
    }

    /* Convert first result to string */
    addr_in = (struct sockaddr_in *)result->ai_addr;
    if (inet_ntop(AF_INET, &addr_in->sin_addr, ip_out, ip_len) == NULL) {
        freeaddrinfo(result);
        return PLAT_ERR;
    }

    freeaddrinfo(result);
    return PLAT_OK;
}

/*
 * ============================================================================
 * Threading Implementation
 * ============================================================================
 */

int plat_thread_create(plat_thread_t *thread, void *(*fn)(void *), void *arg)
{
    int ret;

    if (thread == NULL || fn == NULL) {
        return PLAT_ERR;
    }

    ret = pthread_create(&thread->handle, NULL, fn, arg);
    if (ret != 0) {
        return PLAT_ERR;
    }

    return PLAT_OK;
}

int plat_thread_join(plat_thread_t *thread)
{
    int ret;

    if (thread == NULL) {
        return PLAT_ERR;
    }

    ret = pthread_join(thread->handle, NULL);
    if (ret != 0) {
        return PLAT_ERR;
    }

    return PLAT_OK;
}

void plat_mutex_init(plat_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    pthread_mutex_init(&mutex->handle, NULL);
}

void plat_mutex_destroy(plat_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    pthread_mutex_destroy(&mutex->handle);
}

void plat_mutex_lock(plat_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    pthread_mutex_lock(&mutex->handle);
}

void plat_mutex_unlock(plat_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    pthread_mutex_unlock(&mutex->handle);
}

void plat_cond_init(plat_cond_t *cond)
{
    if (cond == NULL) {
        return;
    }

    pthread_cond_init(&cond->handle, NULL);
}

void plat_cond_destroy(plat_cond_t *cond)
{
    if (cond == NULL) {
        return;
    }

    pthread_cond_destroy(&cond->handle);
}

void plat_cond_wait(plat_cond_t *cond, plat_mutex_t *mutex)
{
    if (cond == NULL || mutex == NULL) {
        return;
    }

    pthread_cond_wait(&cond->handle, &mutex->handle);
}

int plat_cond_timedwait(plat_cond_t *cond, plat_mutex_t *mutex, uint32_t ms)
{
    struct timespec ts;
    int ret;

    if (cond == NULL || mutex == NULL) {
        return PLAT_ERR;
    }

    /* Get current time and add timeout */
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000;

    /* Handle nanosecond overflow */
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000;
    }

    ret = pthread_cond_timedwait(&cond->handle, &mutex->handle, &ts);
    if (ret == ETIMEDOUT) {
        return PLAT_ERR_TIMEOUT;
    }
    if (ret != 0) {
        return PLAT_ERR;
    }

    return PLAT_OK;
}

void plat_cond_signal(plat_cond_t *cond)
{
    if (cond == NULL) {
        return;
    }

    pthread_cond_signal(&cond->handle);
}

void plat_cond_broadcast(plat_cond_t *cond)
{
    if (cond == NULL) {
        return;
    }

    pthread_cond_broadcast(&cond->handle);
}

/*
 * ============================================================================
 * File System Implementation (Session 1.4 - placeholder stubs)
 * ============================================================================
 */

int plat_file_read(const char *path, uint8_t **data, size_t *len)
{
    (void)path; (void)data; (void)len;
    return PLAT_ERR; /* Not yet implemented */
}

int plat_file_write(const char *path, const uint8_t *data, size_t len)
{
    (void)path; (void)data; (void)len;
    return PLAT_ERR; /* Not yet implemented */
}

int plat_file_append(const char *path, const uint8_t *data, size_t len)
{
    (void)path; (void)data; (void)len;
    return PLAT_ERR; /* Not yet implemented */
}

int plat_file_rename(const char *old_path, const char *new_path)
{
    (void)old_path; (void)new_path;
    return PLAT_ERR; /* Not yet implemented */
}

int plat_file_delete(const char *path)
{
    (void)path;
    return PLAT_ERR; /* Not yet implemented */
}

int plat_file_exists(const char *path)
{
    (void)path;
    return 0; /* Not yet implemented */
}

int plat_dir_create(const char *path)
{
    (void)path;
    return PLAT_ERR; /* Not yet implemented */
}

/*
 * ============================================================================
 * Time Implementation (Session 1.4 - placeholder stubs)
 * ============================================================================
 */

uint64_t plat_time_ms(void)
{
    return 0; /* Not yet implemented */
}

uint64_t plat_monotonic_ms(void)
{
    return 0; /* Not yet implemented */
}

void plat_sleep_ms(uint32_t ms)
{
    (void)ms;
    /* Not yet implemented */
}

/*
 * ============================================================================
 * Entropy Implementation (Session 1.4 - placeholder stubs)
 * ============================================================================
 */

int plat_random_bytes(uint8_t *buf, size_t len)
{
    (void)buf; (void)len;
    return PLAT_ERR; /* Not yet implemented */
}
