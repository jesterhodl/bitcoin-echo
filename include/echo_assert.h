/*
 * Bitcoin Echo — Debug Assertions
 *
 * Assertions for catching programming errors during development.
 * In release builds (NDEBUG defined), assertions compile to nothing.
 *
 * These assertions are for invariants that should NEVER be violated
 * if the code is correct. They are NOT for validating external input
 * (blocks, transactions, network data) — use proper validation for those.
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_ASSERT_H
#define ECHO_ASSERT_H

#include <stdio.h>
#include <stdlib.h> // IWYU pragma: keep

/*
 * ECHO_ASSERT(condition)
 *
 * Assert that a condition is true. If false in debug builds,
 * prints diagnostic information and aborts.
 *
 * Example:
 *   ECHO_ASSERT(ptr != NULL);
 *   ECHO_ASSERT(index < array_len);
 */
#ifdef NDEBUG
#define ECHO_ASSERT(cond) ((void)0)
#else
#define ECHO_ASSERT(cond)                                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr,                                                          \
              "ECHO_ASSERT failed: %s\n"                                       \
              "  File: %s\n"                                                   \
              "  Line: %d\n"                                                   \
              "  Function: %s\n",                                              \
              #cond, __FILE__, __LINE__, __func__);                            \
      abort();                                                                 \
    }                                                                          \
  } while (0)
#endif

/*
 * ECHO_ASSERT_MSG(condition, message)
 *
 * Assert with a custom message for additional context.
 *
 * Example:
 *   ECHO_ASSERT_MSG(len <= MAX_SIZE, "Buffer length exceeds maximum");
 */
#ifdef NDEBUG
#define ECHO_ASSERT_MSG(cond, msg) ((void)0)
#else
#define ECHO_ASSERT_MSG(cond, msg)                                             \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr,                                                          \
              "ECHO_ASSERT failed: %s\n"                                       \
              "  Message: %s\n"                                                \
              "  File: %s\n"                                                   \
              "  Line: %d\n"                                                   \
              "  Function: %s\n",                                              \
              #cond, (msg), __FILE__, __LINE__, __func__);                     \
      abort();                                                                 \
    }                                                                          \
  } while (0)
#endif

/*
 * ECHO_UNREACHABLE()
 *
 * Mark code paths that should never be reached.
 * If reached in debug builds, prints diagnostic and aborts.
 * In release builds, provides a hint to the compiler for optimization.
 *
 * Example:
 *   switch (type) {
 *       case TYPE_A: return handle_a();
 *       case TYPE_B: return handle_b();
 *       default:
 *           ECHO_UNREACHABLE();
 *   }
 */
#ifdef NDEBUG
#if defined(__GNUC__) || defined(__clang__)
#define ECHO_UNREACHABLE() __builtin_unreachable()
#elif defined(_MSC_VER)
#define ECHO_UNREACHABLE() __assume(0)
#else
#define ECHO_UNREACHABLE() ((void)0)
#endif
#else
#define ECHO_UNREACHABLE()                                                     \
  do {                                                                         \
    fprintf(stderr,                                                            \
            "ECHO_UNREACHABLE reached\n"                                       \
            "  File: %s\n"                                                     \
            "  Line: %d\n"                                                     \
            "  Function: %s\n",                                                \
            __FILE__, __LINE__, __func__);                                     \
    abort();                                                                   \
  } while (0)
#endif

/*
 * ECHO_STATIC_ASSERT(condition, message)
 *
 * Compile-time assertion. Fails at compile time if condition is false.
 * Use for type sizes, struct layout assumptions, etc.
 *
 * Example:
 *   ECHO_STATIC_ASSERT(sizeof(hash256_t) == 32, "hash256_t must be 32 bytes");
 */
#define ECHO_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

#endif /* ECHO_ASSERT_H */
