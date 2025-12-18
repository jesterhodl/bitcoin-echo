#!/usr/bin/env python3
"""
Bitcoin Echo — Regtest Mining Script

A simple CPU miner for regtest testing. This script:
1. Calls getblocktemplate to get mining work
2. Constructs a block with a coinbase transaction
3. Grinds nonces until finding a valid proof-of-work
4. Submits the block via submitblock

Only suitable for regtest where difficulty is trivially low.

Usage:
    python3 regtest_miner.py [--rpcport PORT] [--blocks N]

Session 9.6.4: Regtest Mining implementation.
"""

import argparse
import hashlib
import json
import struct
import sys
import time
import urllib.request
import urllib.error


def sha256d(data: bytes) -> bytes:
    """Double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(n: int) -> bytes:
    """Encode an integer as Bitcoin's CompactSize (varint)."""
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return struct.pack('<BH', 0xfd, n)
    elif n <= 0xffffffff:
        return struct.pack('<BI', 0xfe, n)
    else:
        return struct.pack('<BQ', 0xff, n)


def encode_height(height: int) -> bytes:
    """Encode block height for BIP-34 coinbase scriptsig."""
    if height == 0:
        return b'\x00'  # OP_0

    # Convert height to little-endian bytes
    height_bytes = []
    temp = height
    while temp > 0:
        height_bytes.append(temp & 0xff)
        temp >>= 8

    # Add extra byte if high bit is set (to keep positive)
    if height_bytes and height_bytes[-1] & 0x80:
        height_bytes.append(0)

    # Push opcode (length) + data
    return bytes([len(height_bytes)] + height_bytes)


def create_coinbase_tx(height: int, value: int, extra_nonce: int = 0) -> bytes:
    """
    Create a coinbase transaction.

    Args:
        height: Block height (for BIP-34)
        value: Coinbase value in satoshis
        extra_nonce: Extra nonce for additional randomness

    Returns:
        Serialized coinbase transaction
    """
    # Version
    tx = struct.pack('<I', 1)

    # Input count
    tx += compact_size(1)

    # Coinbase input:
    # - Null outpoint (32 zero bytes + 0xffffffff vout)
    tx += b'\x00' * 32
    tx += struct.pack('<I', 0xffffffff)

    # Scriptsig: BIP-34 height + extra nonce + pool tag
    height_script = encode_height(height)
    extra_nonce_bytes = struct.pack('<Q', extra_nonce)
    pool_tag = b'Bitcoin Echo Regtest Miner'
    scriptsig = height_script + extra_nonce_bytes + pool_tag

    tx += compact_size(len(scriptsig))
    tx += scriptsig

    # Sequence
    tx += struct.pack('<I', 0xffffffff)

    # Output count
    tx += compact_size(1)

    # Output value
    tx += struct.pack('<Q', value)

    # Output script: OP_TRUE (anyone can spend, for testing)
    output_script = b'\x51'  # OP_TRUE
    tx += compact_size(len(output_script))
    tx += output_script

    # Locktime
    tx += struct.pack('<I', 0)

    return tx


def merkle_root(txids: list) -> bytes:
    """Compute Merkle root from list of txids (as bytes, little-endian)."""
    if not txids:
        return b'\x00' * 32

    hashes = list(txids)

    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])  # Duplicate last if odd

        new_hashes = []
        for i in range(0, len(hashes), 2):
            new_hashes.append(sha256d(hashes[i] + hashes[i+1]))
        hashes = new_hashes

    return hashes[0]


def bits_to_target(bits: int) -> int:
    """Convert compact bits to 256-bit target."""
    exponent = bits >> 24
    mantissa = bits & 0x007fffff

    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    else:
        return mantissa << (8 * (exponent - 3))


def serialize_block_header(version: int, prev_hash: bytes, merkle: bytes,
                           timestamp: int, bits: int, nonce: int) -> bytes:
    """Serialize an 80-byte block header."""
    return struct.pack('<I', version) + prev_hash + merkle + \
           struct.pack('<III', timestamp, bits, nonce)


def rpc_call(method: str, params: list, port: int = 18443) -> dict:
    """Make a JSON-RPC call to the node."""
    url = f'http://127.0.0.1:{port}/'
    request_data = json.dumps({
        'id': '1',
        'method': method,
        'params': params
    }).encode('utf-8')

    req = urllib.request.Request(
        url,
        data=request_data,
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result
    except urllib.error.URLError as e:
        print(f"RPC error: {e}")
        return None


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


# Track last used timestamp to ensure strictly increasing
_last_timestamp = 0

def mine_block(template: dict, extra_nonce: int = 0) -> tuple:
    """
    Mine a block from a template.

    Args:
        template: Block template from getblocktemplate
        extra_nonce: Extra nonce for randomness

    Returns:
        (block_hex, block_hash) if successful, (None, None) otherwise
    """
    global _last_timestamp

    version = template['version']
    prev_hash = hex_to_bytes(template['previousblockhash'])[::-1]  # Reverse for internal
    height = template['height']
    bits = int(template['bits'], 16)
    # Use current time but ensure it's at least mintime+1 to satisfy MTP requirement
    # Also ensure strictly increasing timestamps for rapid mining
    mintime = template.get('mintime', 0)
    timestamp = max(int(time.time()), mintime + 1, _last_timestamp + 1)
    _last_timestamp = timestamp
    coinbase_value = template['coinbasevalue']

    # Target for comparison
    target = bits_to_target(bits)

    # Create coinbase transaction
    coinbase_tx = create_coinbase_tx(height, coinbase_value, extra_nonce)
    coinbase_txid = sha256d(coinbase_tx)

    # Collect all txids for merkle tree
    txids = [coinbase_txid]
    block_txs = [coinbase_tx]

    for tx in template.get('transactions', []):
        tx_data = hex_to_bytes(tx['data'])
        block_txs.append(tx_data)
        # txid is hash of non-witness serialization, but for simplicity
        # we use the provided txid
        txid = hex_to_bytes(tx['txid'])[::-1]  # Reverse for internal
        txids.append(txid)

    # Compute merkle root
    merkle = merkle_root(txids)

    # Mine by grinding nonces
    print(f"Mining block {height} (target: {target:064x})")
    start_time = time.time()
    hashes_tried = 0

    for nonce in range(0xffffffff):
        header = serialize_block_header(version, prev_hash, merkle,
                                        timestamp, bits, nonce)
        block_hash = sha256d(header)
        hash_int = int.from_bytes(block_hash, 'little')
        hashes_tried += 1

        if hash_int <= target:
            elapsed = time.time() - start_time
            hashrate = hashes_tried / elapsed if elapsed > 0 else 0
            print(f"Found valid nonce {nonce} after {hashes_tried} hashes "
                  f"({hashrate:.0f} H/s)")

            # Build full block
            block = header
            block += compact_size(len(block_txs))
            for tx in block_txs:
                block += tx

            return bytes_to_hex(block), bytes_to_hex(block_hash[::-1])

        # Progress update every million hashes
        if hashes_tried % 1000000 == 0:
            elapsed = time.time() - start_time
            hashrate = hashes_tried / elapsed if elapsed > 0 else 0
            print(f"  {hashes_tried/1e6:.1f}M hashes ({hashrate:.0f} H/s)...")

    print("Failed to find valid nonce!")
    return None, None


def main():
    parser = argparse.ArgumentParser(description='Bitcoin Echo Regtest Miner')
    parser.add_argument('--rpcport', type=int, default=18443,
                        help='RPC port (default: 18443)')
    parser.add_argument('--blocks', type=int, default=1,
                        help='Number of blocks to mine (default: 1)')
    args = parser.parse_args()

    print("Bitcoin Echo Regtest Miner")
    print("=" * 40)

    for i in range(args.blocks):
        print(f"\n[Block {i+1}/{args.blocks}]")

        # Get block template
        result = rpc_call('getblocktemplate', [], args.rpcport)
        if result is None:
            print("Failed to get block template. Is the node running?")
            return 1

        if 'error' in result and result['error']:
            print(f"RPC error: {result['error']}")
            return 1

        template = result.get('result')
        if template is None:
            print("No result in response")
            return 1

        print(f"  Height: {template['height']}")
        print(f"  Previous: {template['previousblockhash'][:16]}...")
        print(f"  Coinbase value: {template['coinbasevalue']/1e8:.8f} BTC")
        print(f"  Transactions: {len(template.get('transactions', []))}")
        print(f"  Bits: {template['bits']}")

        # Mine the block
        block_hex, block_hash = mine_block(template, extra_nonce=i)
        if block_hex is None:
            print("Mining failed!")
            return 1

        print(f"  Block hash: {block_hash}")

        # Submit the block
        result = rpc_call('submitblock', [block_hex], args.rpcport)
        if result is None:
            print("Failed to submit block")
            return 1

        if result.get('result') is None:
            print("  Block accepted!")
        else:
            print(f"  Block rejected: {result.get('result')}")
            return 1

        # Small delay between blocks
        if i < args.blocks - 1:
            time.sleep(0.1)

    print(f"\nSuccessfully mined {args.blocks} block(s)!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
