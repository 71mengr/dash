package kheavyhash

import (
	"math"
)

const eps float64 = 1e-9

type matrix [64][64]uint16

// generateMatrix generates a 64x64 matrix from a hash seed using xoshiro256++ PRNG
// Continues generating until a matrix with full rank (64) is found
func generateMatrix(hash *domainHash) *matrix {
	var mat matrix
	generator := newxoShiRo256PlusPlus(hash)
	for {
		for i := range mat {
			for j := 0; j < 64; j += 16 {
				val := generator.Uint64()
				for shift := 0; shift < 16; shift++ {
					mat[i][j+shift] = uint16(val >> (4 * shift) & 0x0F)
				}
			}
		}
		if mat.computeRank() == 64 {
			return &mat
		}
	}
}

// computeRank calculates the rank of the matrix using Gaussian elimination
func (mat *matrix) computeRank() int {
	var B [64][64]float64
	for i := range B {
		for j := range B[0] {
			B[i][j] = float64(mat[i][j])
		}
	}
	var rank int
	var rowSelected [64]bool
	for i := 0; i < 64; i++ {
		var j int
		for j = 0; j < 64; j++ {
			if !rowSelected[j] && math.Abs(B[j][i]) > eps {
				break
			}
		}
		if j != 64 {
			rank++
			rowSelected[j] = true
			for p := i + 1; p < 64; p++ {
				B[j][p] /= B[j][i]
			}
			for k := 0; k < 64; k++ {
				if k != j && math.Abs(B[k][i]) > eps {
					for p := i + 1; p < 64; p++ {
						B[k][p] -= B[j][p] * B[k][i]
					}
				}
			}
		}
	}
	return rank
}

// HeavyHash applies the matrix transformation to a hash
func (mat *matrix) HeavyHash(hash *domainHash) *domainHash {
	hashBytes := hash.byteArray()
	var vector [64]uint16
	var product [64]uint16

	// Convert 32-byte hash to 64 nibbles (4-bit values)
	for i := 0; i < 32; i++ {
		vector[2*i] = uint16(hashBytes[i] >> 4)
		vector[2*i+1] = uint16(hashBytes[i] & 0x0F)
	}

	// Matrix-vector multiplication, and convert to 4 bits
	for i := 0; i < 64; i++ {
		var sum uint16
		for j := 0; j < 64; j++ {
			sum += mat[i][j] * vector[j]
		}
		product[i] = sum >> 10
	}

	// Concatenate 4 LSBs back to 8 bit xor with original hash
	var res [32]byte
	for i := range res {
		res[i] = hashBytes[i] ^ (byte(product[2*i]<<4) | byte(product[2*i+1]))
	}

	// Hash again with HeavyHash domain
	writer := newHeavyHashWriter()
	writer.InfallibleWrite(res[:])
	return newDomainHashFromByteArray(writer.Finalize().byteArray())
}

// KHeavyHash implements the complete kHeavyHash proof-of-work algorithm.
//
// The input must be exactly 80 bytes with the following structure:
//   - PrePowHash: bytes 0-31 (32 bytes)
//   - Timestamp: bytes 32-39 (8 bytes, little-endian)
//   - Padding: bytes 40-71 (32 bytes, must be zeros)
//   - Nonce: bytes 72-79 (8 bytes, little-endian)
//
// The function panics if the input length is not exactly 80 bytes.
//
// Returns a 32-byte proof-of-work hash.
//
// Example:
//
//	var workOrder [80]byte // (prePowHash || timestamp || padding || nonce)
//	copy(workOrder[0:32], prePowHash[:])
//	binary.LittleEndian.PutUint64(workOrder[32:40], timestamp)
//	binary.LittleEndian.PutUint64(workOrder[72:80], nonce)
//	hash := KHeavyHash(workOrder[:])  // 32-byte PoW hash
func KHeavyHash(input []byte) [32]byte {
	if len(input) != 80 {
		panic("KHeavyHash input must be exactly 80 bytes")
	}

	// Step 1: Hash input with cSHAKE256 using "ProofOfWorkHash" domain
	writer := newPoWHashWriter()
	writer.InfallibleWrite(input)
	powHash := writer.Finalize()

	// Step 2: Generate matrix from prePowHash (first 32 bytes of input)
	prePowHash := newDomainHashFromByteArray((*[32]byte)(input[:32]))
	mat := generateMatrix(prePowHash)

	// Step 3: Apply matrix transformation
	heavyHash := mat.HeavyHash(powHash)

	// Return as byte array
	return *heavyHash.byteArray()
}

// DebugResult contains the result of DebugKHeavyHash
type DebugResult struct {
	PrePowHashReversed bool     // Whether PrePowHash needs to be reversed
	TimestampReversed  bool     // Whether Timestamp needs to be reversed
	NonceReversed      bool     // Whether Nonce needs to be reversed
	ExpectedReversed   bool     // Whether the expected output hash needs to be reversed
	CorrectedInput     [80]byte // The 80-byte input with correct byte order
	Found              bool     // Whether a matching configuration was found
}

// reverseBytes reverses the byte order of a byte slice
func reverseBytes(data []byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[len(data)-1-i] = b
	}
	return result
}

// DebugKHeavyHash finds the correct endianness of the input fields by trying all permutations
// of byte order for the three fields (PrePowHash, Timestamp, Nonce) and also checks if the
// expected output hash needs to be reversed. This tries 16 total permutations (8 input × 2 expected).
//
// Parameters:
//   - work: 80-byte input work order (may have incorrect byte order for fields)
//   - expected: 32-byte expected output hash (may be in reversed byte order)
//
// Returns:
//   - DebugResult containing the endianness configuration and corrected input
func DebugKHeavyHash(work [80]byte, expected [32]byte) DebugResult {
	// Extract the three fields
	prePowHash := work[0:32]
	timestamp := work[32:40]
	nonce := work[72:80]

	// Try all 16 permutations (2^4): 8 for input fields × 2 for expected (normal/reversed)
	for expectedRev := 0; expectedRev < 2; expectedRev++ {
		var expectedToCheck [32]byte
		if expectedRev == 1 {
			reversed := reverseBytes(expected[:])
			copy(expectedToCheck[:], reversed)
		} else {
			copy(expectedToCheck[:], expected[:])
		}

		// Try all 8 permutations (2^3) of byte order for input fields
		for prePowRev := 0; prePowRev < 2; prePowRev++ {
			for tsRev := 0; tsRev < 2; tsRev++ {
				for nonceRev := 0; nonceRev < 2; nonceRev++ {
					// Build test input with current permutation
					var testInput [80]byte

					// Copy PrePowHash (reversed or not)
					if prePowRev == 1 {
						copy(testInput[0:32], reverseBytes(prePowHash))
					} else {
						copy(testInput[0:32], prePowHash)
					}

					// Copy Timestamp (reversed or not)
					if tsRev == 1 {
						copy(testInput[32:40], reverseBytes(timestamp))
					} else {
						copy(testInput[32:40], timestamp)
					}

					// Padding (already zeroed)
					// testInput[40:72] remains zeros

					// Copy Nonce (reversed or not)
					if nonceRev == 1 {
						copy(testInput[72:80], reverseBytes(nonce))
					} else {
						copy(testInput[72:80], nonce)
					}

					// Test this configuration
					result := KHeavyHash(testInput[:])

					// Check if it matches
					if result == expectedToCheck {
						return DebugResult{
							PrePowHashReversed: prePowRev == 1,
							TimestampReversed:  tsRev == 1,
							NonceReversed:      nonceRev == 1,
							ExpectedReversed:   expectedRev == 1,
							CorrectedInput:     testInput,
							Found:              true,
						}
					}
				}
			}
		}
	}

	// No matching configuration found
	return DebugResult{
		Found: false,
	}
}
