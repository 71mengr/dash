# kHeavyHash Proof-of-Work Algorithm

This package implements the **kHeavyHash** proof-of-work algorithm used by Zorkcoin and Kaspa networks. It provides a reference implementation for validating mining work and understanding the algorithm's operation.

## Usage

```go
import "github.com/bcutil/kheavyhash"

// 80-byte work order
var workOrder [80]byte
// ... populate workOrder (PrePowHash || Timestamp || 32B Zeros || Nonce) ...

// Compute kHeavyHash
hash := kheavyhash.KHeavyHash(workOrder[:])
// hash is [32]byte
```

### DebugKHeavyHash

The `DebugKHeavyHash` function helps find the correct endianness of input fields when debugging hash mismatches:

```go
var work [80]byte
var expected [32]byte

result := kheavyhash.DebugKHeavyHash(work, expected)
if result.Found {
    fmt.Printf("PrePowHash reversed: %v\n", result.PrePowHashReversed)
    fmt.Printf("Timestamp reversed: %v\n", result.TimestampReversed)
    fmt.Printf("Nonce reversed: %v\n", result.NonceReversed)
    // Use result.CorrectedInput for the properly formatted input
}
```

## Implementation Notes

### Code Origin

This implementation was originally part of the [kaspad](https://github.com/kaspanet/kaspad) project (Kaspa's full node implementation). The code has been:

1. **Separated**: Extracted from the larger kaspad codebase
2. **Isolated**: Made independent with minimal dependencies (only standard library and `golang.org/x/crypto/sha3`)
3. **Simplified**: Removed Kaspa-specific abstractions and simplified the interface to better match what miners actually do

The simplified API (`KHeavyHash(input []byte) [32]byte`) directly matches the 80-byte input → 32-byte output transformation that mining hardware performs.

### Performance Considerations

⚠️ **This is NOT an optimized implementation** ⚠️

- Matrix rank computation uses Gaussian elimination (O(n³) complexity)
- No SIMD optimizations
- Not intended for actual mining
- Suitable for:
  - Share validation in mining pools
  - Testing and verification
  - Educational purposes
  - Reference implementation

For actual mining, ASIC manufacturers implement highly optimized versions using custom hardware.

## kHeavyHash Proof-of-Work Algorithm

### Overview

kHeavyHash is a memory-hard proof-of-work algorithm that combines:
- **cSHAKE256** (customizable SHAKE256) for initial hashing and finalization
- **xoShiRo256++** (Xoroshiro256++) for pseudorandom number generation
- **Matrix multiplication** over GF(16) for the "heavy" computation

The algorithm takes an 80-byte input (the "kHeavyHash Work Order") and produces a 32-byte hash output.

### kHeavyHash Work Order (80-byte Input)

The input to `KHeavyHash()` must be exactly 80 bytes with the following structure:

```
+----------------+----------+----------------+----------+
| PrePowHash     |Timestamp | Padding        | Nonce    |
| (32 bytes)     |(8 bytes) | (32 bytes)     |(8 bytes) |
+----------------+----------+----------------+----------+
| 0-31           | 32-39    | 40-71          | 72-79    |
+----------------+----------+----------------+----------+
```

Field details:

| Field         | Size      | Offset | Description                                          |
|---------------|-----------|--------|------------------------------------------------------|
| PrePowHash    | 32 bytes  | 0-31   | Pre-computed hash of block header (with timestamp=0, nonce=0) |
| Timestamp     | 8 bytes   | 32-39  | Unix timestamp in little-endian format              |
| Padding       | 32 bytes  | 40-71  | Reserved padding, always zeros                      |
| Nonce         | 8 bytes   | 72-79  | Mining nonce in little-endian format                |

### Algorithm Process

The kHeavyHash algorithm operates in the following steps:

#### Step 1: Initial Hash (cSHAKE256)

The complete 80-byte input is hashed using **cSHAKE256** with the domain string `"ProofOfWorkHash"`.

```
powHash = cSHAKE256("ProofOfWorkHash", 80-byte input)
```

- **Input**: Full 80-byte work order
- **Output**: 32-byte hash
- **Specification**: [NIST SP 800-185 - cSHAKE](https://csrc.nist.gov/publications/detail/sp/800-185/final)

#### Step 2: Matrix Generation

A 64×64 matrix is generated over GF(16) using the **xoShiRo256++** pseudorandom number generator seeded with the PrePowHash (first 32 bytes of input).

```
seed = PrePowHash (bytes 0-31)
generator = xoShiRo256++(seed)
matrix = generate 64×64 matrix using generator
```

The matrix generation process:
1. Initialize xoShiRo256++ PRNG with PrePowHash (split into 4 uint64 values, little-endian)
2. Generate 64×64 matrix where each element is a 4-bit value (nibble, 0-15)
3. Each uint64 from the PRNG provides 16 matrix elements (4 bits each)
4. Continue generating matrices until one with full rank (64) is found

- **PRNG Specification**: [Blackman & Vigna - xoShiRo256++](https://prng.di.unimi.it/xoshiro256plusplus.c)
- **Matrix Properties**: Must have full rank (64) over GF(16)

#### Step 3: Heavy Hash Transformation

The hash from Step 1 is combined with the matrix from Step 2 which is then transformed using
matrix-vector multiplication followed by xor:

```
vector = convert 32-byte powHash to 64 nibbles (4-bit values)
product = matrix × vector (over GF(16))
result = powHash XOR (product converted back to 32 bytes)
```

Detailed process:
1. **Vector Conversion**: Split each byte of powHash into two 4-bit nibbles (high 4 bits, low 4 bits)
   - Creates a 64-element vector, each element is a value 0-15
2. **Matrix Multiplication**: Compute `product[i] = Σ(matrix[i][j] × vector[j])` for each row
   - Each product element is right-shifted by 10 bits (extracting 4 LSBs)
   - All arithmetic is modulo 16
3. **Reconstruction**: Convert 64-element product back to 32 bytes
   - Each pair of nibbles forms one byte: `byte = (nibble1 << 4) | nibble2`
4. **XOR**: XOR the reconstructed bytes with the original powHash

#### Step 4: Final Hash (cSHAKE256)

The result from Step 3 is hashed again using **cSHAKE256** with the domain string `"HeavyHash"`.

```
output = cSHAKE256("HeavyHash", transformed_hash)
```

- **Input**: 32-byte transformed hash from Step 3
- **Output**: 32-byte final proof-of-work hash
- **Specification**: [NIST SP 800-185 - cSHAKE](https://csrc.nist.gov/publications/detail/sp/800-185/final)

### Complete Flow Diagram

```
                    ┌──────────────────┐
                    │     Inputs       │
                    │                  │
                    │  PrePowHash      │
                    │  Timestamp       │
                    │  Nonce           │
                    └────────┬─────────┘
                             │
        ┌────────────────────┴─────────┐
        │ PrePowHash                   │
        │                              │
        │                              │
        │                              │
        │                              │
        ▼                              ▼
┌─────────────────┐  ┌─────────────────────────┐
│ xoShiRo256++    │  │ cSHAKE256               │
│                 │  │ ("ProofOfWorkHash")     │
└────────┬────────┘  └──────────┬──────────────┘
         │                      │
         │                      │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  Matrix Operations   │
         │                      │
         │  (HeavyHash over     │
         │   GF(16))            │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  cSHAKE256           │
         │  ("HeavyHash")       │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │      Output          │
         │                      │
         │  Proof of Work       │
         └──────────────────────┘
```

## Package Structure

```
github.com/bcutil/kheavyhash/
├── kheavyhash.go       # Main KHeavyHash function
├── hash.go             # DomainHash and cSHAKE256 helpers
├── xoshiro.go          # xoShiRo256++ PRNG
├── README.md           # This file
├── LICENSE             # ISC License
├── go.mod
└── kheavyhash_test.go  # Test vectors
```

The package name `bcutil/kheavyhash` follows Go naming conventions:
- `bcutil` = blockchain utilities (common pattern like `btcutil`, `ethutil`)
- `kheavyhash` = clear, descriptive name

## References

### Algorithm Specifications

- **cSHAKE256**: [NIST SP 800-185 - cSHAKE Specification](https://csrc.nist.gov/publications/detail/sp/800-185/final)
- **xoShiRo256++**: [Blackman & Vigna - xoShiRo256++ Source Code and Paper](https://prng.di.unimi.it/xoshiro256plusplus.c)

### Related Projects

- [kaspad](https://github.com/kaspanet/kaspad) - Original Kaspa full node implementation
- [Kaspa Documentation](https://wiki.kaspa.org/) - Kaspa network documentation
- [Zorkcoin](https://github.com/ZorkNetwork/zorkcoin) - Zorkcoin full node implementation
- [Zork Network Documentation](https://docs.zork.network) - Zork Network documentation site

## License

ISC License

Copyright (c) 2025 The Zork Network developers  
Copyright (c) 2018-2019 The kaspanet developers  
Copyright (c) 2013-2018 The btcsuite developers  
Copyright (c) 2015-2016 The Decred developers  
Copyright (c) 2013-2014 Conformal Systems LLC.

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
