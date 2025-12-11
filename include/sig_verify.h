/*
 * Bitcoin Echo — Signature Verification Interface
 *
 * sig_verify.h — the quantum succession seam
 *
 * This interface exists to document the succession boundary.
 * All signature verification in the consensus engine flows
 * through this interface. A post-quantum successor would:
 *
 *   1. Fork Bitcoin Echo at its final frozen state
 *   2. Add new signature types to sig_type_t
 *   3. Implement verification for the new scheme
 *   4. Leave all other consensus logic untouched
 *
 * Estimated modification: <500 lines of code.
 *
 * This is not a plugin system. There is no runtime extensibility,
 * no configuration, no abstraction for its own sake. It is a
 * documented seam—the single point where a successor implementation
 * would diverge.
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_SIG_VERIFY_H
#define ECHO_SIG_VERIFY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Signature type enumeration.
 *
 * Current Bitcoin protocol uses:
 *   - ECDSA for pre-SegWit and SegWit v0 (P2PKH, P2WPKH, P2SH-P2WPKH)
 *   - Schnorr for Taproot (SegWit v1)
 *
 * A post-quantum successor would add:
 *   - SIG_DILITHIUM, SIG_SPHINCS, etc.
 */
typedef enum {
  SIG_ECDSA,  /* Pre-SegWit and SegWit v0 */
  SIG_SCHNORR /* Taproot (SegWit v1) */
              /* Successor adds: SIG_DILITHIUM, SIG_SPHINCS, etc. */
} sig_type_t;

/*
 * Verify a signature against a message hash and public key.
 *
 * This is the unified entry point for all signature verification
 * in the consensus engine. Script interpretation, transaction
 * validation, block validation—all cryptographic verification
 * flows through this function.
 *
 * Parameters:
 *   type       - signature scheme identifier
 *   sig        - signature bytes
 *   sig_len    - signature length
 *   hash       - 32-byte message hash (sighash)
 *   pubkey     - public key bytes
 *   pubkey_len - public key length
 *
 * Returns:
 *   1 if signature is valid
 *   0 if signature is invalid
 *
 * This function is pure: no side effects, no I/O, deterministic.
 *
 * For ECDSA (SIG_ECDSA):
 *   - sig: DER-encoded signature (variable length, typically 70-72 bytes)
 *   - pubkey: compressed (33 bytes) or uncompressed (65 bytes)
 *
 * For Schnorr (SIG_SCHNORR):
 *   - sig: 64-byte signature (r || s)
 *   - pubkey: 32-byte x-only public key
 */
int sig_verify(sig_type_t type, const uint8_t *sig, size_t sig_len,
               const uint8_t *hash, const uint8_t *pubkey, size_t pubkey_len);

/*
 * Check whether a signature type is known.
 *
 * Unknown types in consensus-critical paths cause validation failure.
 * This function allows callers to distinguish between "unknown type"
 * and "known type, invalid signature" conditions.
 *
 * Returns:
 *   1 if type is known (SIG_ECDSA or SIG_SCHNORR)
 *   0 if type is unknown
 */
int sig_type_known(sig_type_t type);

#endif /* ECHO_SIG_VERIFY_H */
