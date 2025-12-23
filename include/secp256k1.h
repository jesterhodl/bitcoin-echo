/*
 * Bitcoin Echo — secp256k1 Tagged Hash Support
 *
 * This header declares only the BIP-340 tagged hash function used for Taproot.
 * All signature verification is now handled directly by libsecp256k1 through
 * sig_verify.h.
 *
 * Build once. Build right. Stop.
 */

#ifndef ECHO_SECP256K1_H
#define ECHO_SECP256K1_H

#include <stddef.h>
#include <stdint.h>

/*
 * BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
 *
 * Parameters:
 *   out: 32-byte output buffer
 *   tag: UTF-8 tag string (null-terminated)
 *   msg: message bytes
 *   msg_len: length of message
 */
void secp256k1_schnorr_tagged_hash(uint8_t out[32], const char *tag,
                                   const uint8_t *msg, size_t msg_len);

#endif /* ECHO_SECP256K1_H */
