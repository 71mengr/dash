package kheavyhash

import (
	"encoding/hex"
	"testing"
)

// Test vectors provided by user (in reverse byte order)
var testVectors = []struct {
	name       string
	prePowHash string
	timestamp  string
	nonce      string
	expected   string
}{
	{
		name:       "Test Vector 1",
		prePowHash: "0ad86e9bef09726cdc75913e44ec96521391c7ceb2aae3c633f46a94bf4d2546",
		timestamp:  "0000019568d36b3e",
		nonce:      "571506849306fd39",
		expected:   "24e73f15919292c2304e2a4ef7fbdcefd36df82224e231ca0500000000000000",
	},
	{
		name:       "Test Vector 2",
		prePowHash: "b7e1d42013034af294647f2d21f3a3a78d9e71c2e4806fac0d71dda6d4cf387d",
		timestamp:  "0000019568d92dc9",
		nonce:      "900013673a789118",
		expected:   "df9e7136a28836ae27f4105befeda03b2c123be20762e4c50700000000000000",
	},
	{
		name:       "Test Vector 3",
		prePowHash: "0770e18fa1fbcb5c07418759abbfc3f0bcd8d875dd9b2e9d8c49ffb0449f2a5c",
		timestamp:  "000001956920dc46",
		nonce:      "ba001504de87fd14",
		expected:   "19b0bc0c7ff2e9be56a0d10408d61cdcb0db0a70179ee8de0100000000000000",
	},
	{
		name:       "Test Vector 4",
		prePowHash: "2a24f71bf6b01e4191cb3604e93ffd0a3b881acd10afe4a5a6aeccc5299be903",
		timestamp:  "00000195694f73fa",
		nonce:      "c63c04c8ba806a1e",
		expected:   "5ab3b42538a92b352ffe7258bc5cfa7bb2910386521f0c880600000000000000",
	},
	{
		name:       "Test Vector 5",
		prePowHash: "7cd561009913f30bd59ea57830479fc1e64c738e7e39f22baf4567e877042128",
		timestamp:  "00000195698e7d43",
		nonce:      "f4104c741ec69599",
		expected:   "043babd26259ea575d5ddf1fb97d014623f3b6335d656c980000000000000000",
	},
	{
		name:       "Test Vector 6",
		prePowHash: "0741bf4de07012931227ea18b7fb3caf6b587cf9bd1a0ba183fc254d351d3130",
		timestamp:  "00000195699ec7bc",
		nonce:      "ba001a08539b6ec6",
		expected:   "ff009eff2105c95d3d0c5646cef524e8245e37f86d2894ca0300000000000000",
	},
	{
		name:       "Test Vector 7",
		prePowHash: "b38e5d1c36b41c0aad7e4f050d702c76e724200c0a0ce427622c12de90082fd3",
		timestamp:  "000001956a30a608",
		nonce:      "6410f71b4f05a41a",
		expected:   "78598ee69a3163d60fc5ba7072bb15dcc61bffc5fd9d854d0500000000000000",
	},
}

// TestKHeavyHashWithTestVectors validates the kHeavyHash implementation against provided test vectors
func TestKHeavyHashWithTestVectors(t *testing.T) {
	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			// Parse hex strings
			prePowHashBytes, err := hex.DecodeString(tv.prePowHash)
			if err != nil {
				t.Fatalf("Failed to decode prePowHash: %v", err)
			}
			// Reverse prePowHash (it's in reverse byte order)
			//prePowHashBytes = reverseBytes(prePowHashBytes)

			timestampBytes, err := hex.DecodeString(tv.timestamp)
			if err != nil {
				t.Fatalf("Failed to decode timestamp: %v", err)
			}
			// Timestamp is NOT reversed
			timestampBytes = reverseBytes(timestampBytes)

			nonceBytes, err := hex.DecodeString(tv.nonce)
			if err != nil {
				t.Fatalf("Failed to decode nonce: %v", err)
			}
			// Nonce is NOT reversed
			nonceBytes = reverseBytes(nonceBytes)

			expectedBytes, err := hex.DecodeString(tv.expected)
			if err != nil {
				t.Fatalf("Failed to decode expected result: %v", err)
			}
			// Reverse expected result (it's in reverse byte order)
			//expectedBytes = reverseBytes(expectedBytes)

			// Construct 80-byte input: prePowHash (32) || timestamp (8) || padding (32) || nonce (8)
			var input [80]byte
			copy(input[0:32], prePowHashBytes)
			copy(input[32:40], timestampBytes)
			// padding (32 bytes) is already zeroed
			copy(input[72:80], nonceBytes)

			// Calculate kHeavyHash
			result := KHeavyHash(input[:])

			// Compare with expected result
			if !equalBytes(result[:], expectedBytes) {
				t.Errorf("KHeavyHash result mismatch\n"+
					"Expected: %x\n"+
					"Got:      %x\n"+
					"Input:    %x", expectedBytes, result[:], input[:])
			}
		})
	}
}

// TestMatrixGenerationDeterminism verifies that matrix generation is deterministic
func TestMatrixGenerationDeterminism(t *testing.T) {
	// Create a test hash
	testHashBytes := [32]byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}
	testHash := newDomainHashFromByteArray(&testHashBytes)

	// Generate matrix twice
	mat1 := generateMatrix(testHash)
	mat2 := generateMatrix(testHash)

	// Verify they are identical
	if *mat1 != *mat2 {
		t.Error("Matrix generation is not deterministic")
	}

	// Verify matrix has full rank
	if mat1.computeRank() != 64 {
		t.Errorf("Matrix rank is %d, expected 64", mat1.computeRank())
	}
}

// TestMatrixRank verifies that generated matrices always have full rank
func TestMatrixRank(t *testing.T) {
	for i := 0; i < 10; i++ {
		// Create different test hashes
		testHashBytes := [32]byte{}
		for j := range testHashBytes {
			testHashBytes[j] = byte(i*10 + j)
		}
		testHash := newDomainHashFromByteArray(&testHashBytes)

		mat := generateMatrix(testHash)
		rank := mat.computeRank()

		if rank != 64 {
			t.Errorf("Matrix rank is %d, expected 64 for hash %d", rank, i)
		}
	}
}

// TestHeavyHashMatchesKaspadReference tests against the exact Kaspad reference test
func TestHeavyHashMatchesKaspadReference(t *testing.T) {
	// This test matches the exact test from Kaspad's heavyhash_test.go
	expected, err := hex.DecodeString("87689f379943eaf9b7475ca95325687772bfcc68fc7899caeb4409ec4590c325")
	if err != nil {
		t.Fatal(err)
	}

	input := []byte{0xC1, 0xEC, 0xFD, 0xFC}
	writer := newPoWHashWriter()
	writer.InfallibleWrite(input)
	powHash := writer.Finalize()

	// Use the exact test matrix from Kaspad
	testMatrix := matrix{
		{13, 2, 14, 13, 2, 15, 14, 3, 10, 4, 1, 8, 4, 3, 8, 15, 15, 15, 15, 15, 2, 11, 15, 15, 15, 1, 7, 12, 12, 4, 2, 0, 6, 1, 14, 10, 12, 14, 15, 8, 10, 12, 0, 5, 13, 3, 14, 10, 10, 6, 12, 11, 11, 7, 6, 6, 10, 2, 2, 4, 11, 12, 0, 5},
		{4, 13, 0, 2, 1, 15, 13, 13, 11, 2, 5, 12, 15, 7, 0, 10, 7, 2, 6, 3, 12, 0, 12, 0, 2, 6, 7, 7, 7, 7, 10, 12, 11, 14, 12, 12, 4, 11, 10, 0, 10, 11, 2, 10, 1, 7, 7, 12, 15, 9, 5, 14, 9, 12, 3, 0, 12, 13, 4, 13, 8, 15, 11, 6},
		{14, 6, 15, 9, 8, 2, 2, 12, 2, 3, 4, 12, 13, 15, 4, 5, 13, 4, 3, 0, 14, 3, 5, 14, 3, 13, 4, 15, 9, 12, 7, 15, 5, 1, 13, 12, 9, 9, 8, 11, 14, 11, 4, 10, 12, 6, 12, 8, 6, 3, 9, 8, 1, 6, 0, 5, 8, 9, 12, 5, 14, 15, 2, 2},
		{9, 6, 7, 6, 0, 11, 5, 6, 2, 14, 12, 6, 4, 13, 8, 9, 2, 1, 9, 7, 4, 5, 10, 8, 11, 11, 11, 15, 7, 11, 1, 14, 3, 8, 14, 8, 2, 8, 13, 7, 8, 8, 15, 7, 1, 13, 7, 9, 1, 7, 15, 15, 0, 0, 12, 15, 13, 5, 13, 10, 1, 5, 6, 13},
		{4, 0, 12, 10, 6, 11, 14, 2, 2, 15, 4, 1, 2, 4, 2, 12, 13, 1, 9, 10, 8, 0, 2, 10, 13, 8, 9, 7, 5, 3, 8, 2, 6, 6, 1, 12, 3, 0, 1, 4, 2, 8, 3, 13, 6, 15, 0, 13, 14, 4, 15, 0, 7, 3, 7, 8, 5, 14, 14, 5, 5, 0, 1, 2},
		{12, 14, 6, 3, 3, 4, 6, 7, 1, 3, 2, 7, 15, 15, 15, 10, 9, 12, 0, 6, 3, 8, 5, 0, 13, 5, 0, 6, 0, 14, 2, 12, 10, 4, 11, 2, 10, 7, 7, 6, 8, 11, 4, 4, 11, 9, 3, 12, 10, 5, 2, 6, 5, 5, 10, 13, 12, 10, 1, 6, 14, 7, 12, 4},
		{7, 14, 6, 7, 7, 12, 4, 1, 8, 6, 8, 13, 13, 5, 12, 14, 10, 8, 6, 2, 12, 3, 8, 15, 5, 15, 15, 3, 14, 0, 8, 6, 9, 12, 9, 7, 3, 8, 4, 0, 7, 14, 3, 3, 13, 14, 3, 7, 3, 2, 2, 3, 3, 12, 6, 7, 4, 1, 14, 10, 6, 10, 2, 9},
		{14, 11, 15, 5, 7, 10, 1, 11, 4, 2, 6, 2, 9, 7, 4, 0, 9, 12, 11, 2, 3, 13, 1, 5, 4, 10, 5, 6, 6, 12, 8, 1, 1, 15, 4, 2, 12, 12, 0, 4, 14, 3, 11, 1, 7, 5, 9, 4, 3, 15, 7, 3, 15, 9, 8, 3, 8, 3, 3, 6, 7, 6, 9, 2},
		{10, 4, 6, 10, 5, 2, 15, 12, 0, 14, 14, 15, 14, 0, 12, 9, 1, 12, 4, 5, 5, 2, 10, 4, 2, 13, 11, 3, 1, 8, 10, 0, 7, 0, 12, 4, 11, 1, 14, 6, 14, 5, 5, 11, 11, 1, 3, 8, 0, 6, 11, 11, 8, 4, 7, 6, 14, 4, 9, 14, 9, 7, 13, 9},
		{12, 7, 9, 8, 2, 3, 3, 5, 14, 8, 0, 9, 7, 4, 2, 15, 15, 3, 11, 11, 8, 5, 7, 5, 0, 15, 10, 8, 0, 13, 1, 14, 8, 10, 1, 4, 13, 1, 13, 3, 11, 11, 2, 3, 10, 6, 8, 14, 15, 2, 10, 10, 12, 7, 7, 6, 6, 3, 13, 8, 1, 14, 2, 1},
		{2, 11, 6, 9, 13, 3, 12, 6, 0, 4, 6, 13, 8, 14, 6, 9, 10, 2, 10, 8, 4, 13, 6, 5, 0, 13, 15, 4, 2, 2, 1, 7, 5, 3, 3, 13, 7, 3, 5, 9, 15, 14, 14, 6, 0, 15, 11, 2, 4, 15, 6, 9, 8, 9, 15, 2, 6, 9, 15, 8, 4, 4, 11, 1},
		{10, 11, 8, 3, 11, 13, 10, 2, 2, 5, 2, 14, 15, 10, 2, 11, 0, 1, 8, 2, 14, 1, 10, 0, 3, 7, 5, 10, 7, 8, 15, 7, 2, 5, 13, 4, 10, 3, 6, 2, 3, 9, 6, 11, 7, 14, 1, 11, 9, 3, 3, 7, 6, 0, 9, 11, 4, 10, 4, 1, 9, 7, 4, 15},
		{13, 8, 15, 14, 11, 12, 5, 3, 9, 14, 1, 5, 14, 13, 14, 5, 13, 5, 4, 10, 9, 9, 0, 0, 6, 12, 5, 7, 2, 7, 2, 6, 6, 6, 1, 12, 9, 15, 7, 11, 11, 10, 11, 1, 10, 10, 0, 8, 1, 4, 5, 5, 8, 10, 10, 15, 6, 8, 13, 11, 11, 3, 15, 5},
		{8, 11, 5, 10, 1, 10, 9, 1, 12, 7, 6, 11, 1, 1, 4, 1, 2, 8, 4, 4, 7, 7, 8, 2, 7, 1, 14, 1, 8, 15, 15, 12, 10, 4, 15, 11, 3, 6, 10, 7, 4, 0, 10, 9, 11, 7, 1, 14, 4, 14, 3, 14, 10, 4, 13, 12, 5, 3, 12, 7, 10, 8, 0, 3},
		{9, 11, 6, 15, 14, 10, 0, 4, 7, 7, 6, 0, 7, 7, 12, 15, 5, 4, 12, 3, 7, 3, 0, 12, 2, 7, 11, 6, 7, 3, 2, 8, 5, 11, 9, 4, 3, 8, 11, 12, 3, 5, 14, 12, 4, 13, 12, 0, 3, 14, 4, 9, 1, 1, 9, 14, 10, 14, 8, 15, 6, 14, 10, 15},
		{10, 14, 10, 0, 10, 12, 15, 0, 3, 9, 11, 10, 3, 5, 1, 1, 9, 1, 7, 15, 7, 8, 10, 10, 12, 11, 5, 1, 10, 3, 6, 6, 13, 0, 13, 1, 4, 5, 9, 4, 9, 15, 8, 4, 13, 13, 4, 5, 5, 11, 1, 13, 15, 3, 10, 15, 7, 11, 10, 15, 8, 12, 10, 3},
		{8, 5, 11, 3, 8, 13, 15, 15, 3, 12, 1, 13, 1, 7, 1, 5, 6, 13, 7, 8, 5, 1, 12, 3, 10, 7, 12, 6, 14, 12, 15, 5, 3, 12, 2, 15, 11, 13, 1, 13, 8, 5, 8, 0, 13, 15, 7, 13, 6, 13, 10, 1, 11, 0, 8, 9, 5, 11, 2, 9, 9, 10, 4, 15},
		{0, 4, 12, 14, 3, 1, 7, 5, 11, 13, 5, 3, 11, 12, 6, 8, 10, 15, 11, 8, 7, 10, 0, 2, 5, 15, 6, 10, 4, 2, 3, 1, 13, 7, 6, 12, 14, 7, 6, 14, 12, 10, 6, 14, 12, 0, 12, 11, 6, 9, 3, 1, 12, 15, 15, 3, 5, 5, 10, 11, 7, 15, 13, 3},
		{12, 14, 2, 14, 13, 6, 15, 7, 8, 8, 14, 13, 9, 2, 2, 10, 3, 15, 6, 10, 11, 7, 13, 0, 12, 1, 5, 8, 8, 12, 1, 11, 1, 3, 2, 4, 10, 7, 7, 7, 3, 10, 7, 2, 2, 3, 0, 1, 13, 5, 8, 2, 14, 0, 11, 13, 9, 3, 13, 2, 14, 2, 15, 4},
		{0, 0, 13, 6, 9, 12, 15, 7, 8, 0, 7, 4, 12, 15, 3, 2, 7, 1, 14, 4, 9, 3, 13, 12, 11, 12, 9, 9, 3, 7, 10, 9, 1, 9, 10, 2, 10, 14, 11, 0, 14, 4, 15, 12, 12, 9, 9, 8, 14, 1, 9, 14, 0, 6, 1, 0, 13, 9, 7, 6, 13, 2, 3, 9},
		{8, 0, 10, 13, 0, 7, 9, 7, 5, 1, 0, 3, 7, 10, 3, 15, 1, 15, 3, 11, 2, 6, 3, 10, 0, 10, 10, 3, 4, 15, 8, 6, 11, 11, 7, 5, 8, 5, 7, 15, 1, 11, 7, 13, 13, 6, 13, 13, 4, 2, 3, 15, 9, 5, 10, 6, 6, 6, 3, 11, 15, 13, 1, 15},
		{1, 1, 2, 10, 2, 2, 9, 5, 9, 2, 0, 1, 14, 2, 11, 6, 11, 6, 1, 0, 13, 7, 14, 1, 15, 14, 13, 7, 12, 11, 8, 11, 2, 11, 6, 10, 2, 3, 0, 0, 15, 0, 4, 6, 4, 12, 5, 5, 7, 14, 10, 6, 0, 3, 13, 0, 8, 1, 13, 10, 5, 1, 7, 5},
		{0, 5, 2, 12, 10, 2, 5, 1, 14, 0, 1, 4, 15, 11, 8, 7, 11, 14, 15, 6, 4, 1, 6, 6, 7, 13, 12, 5, 13, 2, 1, 6, 2, 13, 5, 15, 0, 8, 8, 6, 5, 5, 2, 0, 3, 13, 14, 2, 10, 5, 7, 6, 14, 5, 1, 4, 11, 2, 11, 1, 8, 15, 2, 4},
		{9, 9, 4, 5, 2, 5, 3, 12, 14, 5, 1, 3, 3, 0, 0, 6, 7, 14, 0, 15, 14, 11, 3, 10, 1, 9, 4, 14, 7, 14, 1, 0, 15, 11, 5, 9, 4, 0, 0, 10, 4, 4, 0, 7, 8, 15, 12, 8, 10, 8, 1, 2, 1, 11, 12, 14, 14, 14, 8, 10, 1, 5, 13, 10},
		{5, 10, 4, 4, 11, 10, 0, 6, 0, 12, 10, 5, 9, 11, 8, 10, 11, 3, 11, 14, 12, 9, 4, 6, 11, 12, 8, 7, 6, 14, 0, 6, 12, 4, 5, 3, 9, 0, 11, 6, 1, 3, 2, 12, 8, 9, 7, 12, 14, 7, 12, 6, 11, 13, 0, 2, 1, 3, 1, 8, 12, 2, 15, 15},
		{10, 11, 2, 3, 11, 10, 1, 7, 1, 10, 10, 14, 5, 13, 10, 3, 11, 15, 9, 14, 11, 11, 3, 15, 11, 6, 15, 13, 13, 1, 1, 10, 5, 1, 5, 11, 10, 3, 9, 12, 12, 1, 5, 6, 3, 3, 1, 1, 12, 8, 3, 15, 6, 2, 8, 14, 3, 4, 10, 9, 7, 13, 2, 6},
		{12, 0, 1, 0, 4, 3, 3, 6, 8, 3, 1, 13, 6, 12, 1, 1, 1, 4, 12, 4, 4, 9, 9, 14, 15, 3, 6, 4, 11, 1, 12, 5, 6, 0, 10, 9, 1, 8, 14, 5, 2, 8, 4, 15, 12, 13, 7, 14, 12, 2, 6, 9, 4, 13, 0, 15, 10, 10, 6, 12, 7, 12, 9, 10},
		{0, 8, 5, 11, 12, 12, 11, 7, 2, 9, 2, 15, 1, 1, 0, 0, 6, 5, 10, 1, 11, 12, 8, 7, 1, 7, 10, 4, 2, 8, 2, 5, 1, 1, 2, 9, 2, 0, 3, 7, 5, 1, 5, 5, 3, 1, 4, 3, 14, 8, 11, 7, 8, 0, 2, 13, 3, 15, 1, 13, 14, 15, 11, 13},
		{8, 13, 5, 14, 2, 9, 9, 13, 15, 8, 2, 14, 4, 2, 6, 0, 1, 13, 10, 13, 6, 12, 15, 11, 6, 11, 9, 9, 2, 9, 6, 14, 2, 9, 12, 1, 13, 9, 5, 11, 10, 4, 4, 5, 8, 9, 13, 10, 9, 0, 5, 15, 4, 12, 7, 10, 6, 5, 5, 15, 8, 8, 11, 14},
		{6, 9, 6, 7, 1, 15, 0, 1, 4, 15, 5, 3, 10, 9, 15, 9, 14, 12, 7, 6, 3, 0, 12, 8, 12, 2, 11, 8, 11, 8, 1, 10, 10, 7, 7, 5, 3, 5, 1, 2, 13, 11, 2, 5, 2, 10, 10, 1, 14, 14, 8, 1, 11, 1, 2, 6, 15, 10, 8, 7, 10, 7, 0, 3},
		{12, 6, 11, 1, 1, 7, 8, 1, 5, 5, 8, 4, 6, 5, 6, 4, 2, 8, 4, 1, 0, 0, 14, 2, 10, 14, 14, 11, 2, 9, 14, 15, 12, 14, 9, 3, 7, 14, 4, 7, 12, 9, 3, 5, 1, 0, 12, 9, 10, 5, 11, 12, 10, 10, 6, 14, 6, 13, 13, 5, 5, 10, 13, 10},
		{12, 6, 13, 0, 8, 0, 10, 6, 15, 15, 7, 3, 0, 10, 13, 14, 10, 13, 5, 13, 15, 14, 3, 4, 10, 10, 9, 6, 6, 15, 2, 7, 0, 10, 6, 14, 2, 9, 11, 7, 5, 5, 13, 14, 11, 15, 9, 4, 2, 0, 15, 5, 4, 14, 14, 1, 3, 4, 5, 8, 1, 1, 10, 12},
		{2, 5, 0, 4, 11, 5, 5, 6, 10, 4, 6, 7, 10, 3, 0, 14, 14, 0, 12, 15, 11, 12, 13, 7, 6, 3, 9, 1, 9, 8, 8, 8, 4, 10, 3, 1, 7, 10, 3, 2, 12, 6, 15, 14, 0, 6, 8, 10, 1, 9, 12, 12, 15, 7, 1, 11, 15, 13, 0, 4, 10, 0, 12, 11},
		{8, 12, 14, 15, 14, 15, 10, 0, 2, 14, 3, 1, 2, 6, 0, 2, 1, 7, 9, 0, 15, 13, 5, 14, 6, 8, 15, 4, 15, 6, 10, 6, 15, 3, 12, 8, 5, 4, 10, 5, 3, 0, 4, 13, 10, 9, 8, 4, 6, 3, 9, 6, 12, 11, 9, 13, 8, 10, 9, 9, 8, 12, 1, 2},
		{11, 10, 15, 15, 5, 14, 15, 7, 5, 9, 14, 14, 7, 11, 6, 6, 3, 8, 2, 3, 4, 14, 11, 1, 12, 15, 11, 6, 0, 0, 13, 7, 14, 3, 12, 14, 0, 15, 6, 1, 11, 2, 11, 8, 3, 13, 4, 12, 10, 13, 7, 14, 9, 13, 3, 10, 2, 14, 13, 4, 12, 13, 14, 10},
		{1, 11, 2, 12, 1, 10, 7, 12, 3, 3, 14, 9, 1, 10, 0, 11, 8, 10, 12, 12, 4, 12, 2, 11, 5, 0, 3, 15, 8, 2, 14, 3, 10, 2, 1, 13, 6, 14, 0, 0, 8, 11, 6, 13, 15, 10, 12, 7, 7, 11, 14, 9, 2, 7, 6, 8, 14, 9, 14, 10, 11, 9, 9, 12},
		{5, 10, 14, 2, 1, 4, 11, 5, 10, 2, 13, 9, 6, 12, 11, 5, 13, 4, 5, 14, 8, 7, 15, 9, 8, 4, 5, 2, 9, 11, 5, 3, 12, 2, 6, 1, 7, 4, 11, 4, 15, 0, 5, 2, 13, 11, 11, 2, 15, 10, 0, 12, 5, 8, 10, 1, 4, 11, 3, 13, 11, 7, 9, 14},
		{9, 8, 10, 5, 0, 2, 5, 8, 7, 3, 3, 6, 11, 1, 13, 15, 4, 4, 11, 6, 2, 6, 13, 11, 2, 6, 9, 4, 5, 13, 12, 2, 8, 7, 7, 12, 14, 15, 5, 12, 7, 0, 15, 15, 0, 5, 15, 0, 3, 9, 10, 15, 9, 11, 10, 10, 5, 3, 9, 3, 12, 13, 0, 13},
		{1, 11, 15, 0, 10, 5, 3, 5, 6, 7, 1, 11, 4, 11, 4, 2, 5, 12, 2, 5, 5, 6, 1, 5, 14, 9, 1, 5, 14, 12, 6, 10, 0, 8, 5, 11, 11, 11, 12, 10, 8, 10, 10, 1, 14, 1, 0, 8, 4, 7, 0, 11, 3, 1, 11, 12, 11, 8, 14, 15, 9, 3, 1, 14},
		{14, 11, 12, 12, 4, 6, 8, 14, 15, 1, 11, 2, 13, 3, 6, 2, 7, 1, 8, 1, 4, 9, 11, 15, 8, 1, 10, 13, 4, 13, 2, 7, 7, 10, 5, 2, 12, 12, 12, 3, 10, 8, 2, 11, 0, 3, 8, 9, 4, 2, 15, 7, 15, 6, 4, 6, 12, 7, 14, 9, 9, 8, 14, 12},
		{15, 4, 8, 12, 11, 11, 9, 5, 0, 0, 7, 6, 10, 5, 8, 2, 5, 6, 14, 11, 13, 0, 13, 15, 5, 4, 9, 15, 13, 12, 14, 15, 10, 2, 3, 6, 10, 14, 1, 8, 6, 7, 10, 1, 14, 9, 12, 13, 7, 2, 12, 10, 6, 11, 15, 1, 15, 11, 13, 0, 6, 13, 7, 15},
		{3, 3, 12, 5, 14, 9, 14, 14, 8, 0, 9, 1, 2, 2, 14, 11, 7, 1, 3, 1, 14, 15, 12, 8, 14, 2, 4, 13, 10, 5, 10, 8, 1, 7, 6, 5, 4, 2, 11, 5, 4, 13, 14, 6, 13, 15, 6, 6, 7, 12, 11, 5, 13, 10, 9, 13, 9, 14, 5, 6, 7, 14, 11, 7},
		{14, 12, 11, 5, 0, 5, 10, 5, 7, 1, 7, 11, 1, 0, 13, 6, 5, 14, 3, 0, 5, 14, 6, 7, 8, 5, 8, 6, 6, 3, 6, 1, 8, 3, 10, 7, 15, 6, 11, 6, 6, 7, 13, 2, 2, 0, 0, 11, 1, 15, 2, 14, 5, 1, 4, 8, 0, 1, 8, 0, 1, 1, 2, 2},
		{10, 13, 13, 3, 15, 14, 9, 12, 15, 15, 8, 5, 8, 10, 5, 9, 6, 6, 7, 15, 1, 0, 14, 9, 1, 11, 6, 11, 13, 4, 6, 14, 9, 12, 13, 8, 14, 6, 14, 2, 3, 15, 4, 4, 14, 4, 9, 12, 8, 0, 9, 11, 13, 10, 8, 14, 3, 5, 7, 11, 6, 7, 15, 2},
		{9, 9, 11, 6, 11, 0, 5, 4, 8, 10, 8, 11, 2, 12, 8, 7, 11, 13, 6, 1, 13, 13, 11, 4, 5, 7, 7, 9, 6, 4, 12, 0, 11, 8, 6, 12, 11, 4, 15, 11, 12, 8, 11, 11, 1, 3, 6, 14, 9, 6, 7, 5, 0, 10, 3, 15, 13, 7, 0, 1, 13, 15, 1, 14},
		{10, 6, 8, 7, 3, 6, 9, 15, 1, 3, 10, 14, 9, 0, 0, 10, 0, 15, 2, 0, 0, 0, 6, 0, 13, 9, 9, 1, 8, 6, 13, 2, 1, 9, 14, 9, 1, 4, 8, 4, 2, 0, 8, 5, 0, 11, 12, 15, 13, 1, 14, 14, 15, 7, 8, 4, 4, 12, 1, 12, 8, 3, 9, 5},
		{12, 11, 1, 4, 10, 14, 8, 12, 2, 4, 15, 2, 9, 7, 7, 11, 15, 12, 10, 11, 7, 4, 13, 0, 8, 6, 8, 8, 10, 5, 5, 13, 3, 7, 9, 13, 13, 14, 6, 8, 1, 5, 7, 12, 4, 4, 6, 9, 13, 1, 6, 1, 6, 14, 5, 8, 2, 10, 4, 10, 1, 9, 6, 15},
		{4, 13, 4, 9, 6, 11, 1, 8, 7, 11, 11, 1, 3, 10, 12, 11, 1, 10, 6, 10, 0, 7, 3, 0, 0, 6, 3, 9, 2, 1, 4, 8, 2, 10, 2, 15, 9, 15, 14, 14, 15, 14, 3, 2, 7, 6, 6, 10, 8, 8, 4, 11, 1, 13, 6, 0, 2, 10, 0, 11, 15, 14, 6, 9},
		{15, 0, 12, 13, 0, 9, 10, 4, 11, 5, 10, 0, 8, 7, 3, 2, 12, 6, 3, 8, 5, 15, 14, 2, 13, 13, 6, 11, 5, 6, 9, 10, 14, 5, 14, 4, 9, 7, 5, 11, 13, 2, 7, 1, 14, 9, 0, 7, 8, 12, 11, 15, 2, 1, 5, 11, 3, 7, 5, 1, 6, 3, 8, 6},
		{0, 3, 8, 1, 4, 6, 3, 1, 3, 8, 2, 0, 15, 15, 14, 15, 13, 10, 11, 9, 2, 11, 5, 12, 3, 3, 0, 1, 5, 3, 11, 6, 10, 11, 8, 5, 7, 15, 4, 12, 8, 8, 12, 12, 12, 1, 9, 4, 11, 6, 10, 11, 1, 12, 8, 12, 5, 6, 1, 14, 2, 10, 3, 0},
		{10, 13, 6, 9, 11, 1, 4, 10, 0, 13, 8, 7, 4, 12, 15, 5, 14, 12, 6, 9, 0, 0, 10, 5, 13, 10, 15, 3, 0, 8, 7, 0, 9, 8, 10, 6, 11, 8, 10, 13, 11, 7, 5, 5, 9, 13, 1, 15, 0, 5, 15, 5, 4, 7, 9, 9, 15, 8, 2, 6, 3, 8, 5, 8},
		{14, 0, 6, 2, 4, 12, 2, 13, 6, 10, 5, 2, 2, 1, 6, 11, 1, 6, 9, 13, 0, 13, 9, 3, 12, 4, 3, 8, 7, 0, 9, 12, 0, 1, 7, 10, 10, 7, 3, 9, 13, 5, 15, 4, 13, 0, 8, 5, 4, 14, 11, 3, 3, 13, 15, 9, 9, 12, 9, 5, 2, 0, 1, 14},
		{4, 14, 13, 0, 14, 15, 11, 10, 11, 1, 3, 3, 9, 1, 12, 8, 6, 5, 15, 11, 1, 7, 5, 3, 8, 13, 0, 13, 11, 5, 8, 1, 8, 6, 13, 4, 13, 7, 12, 6, 5, 5, 7, 0, 12, 1, 1, 8, 1, 6, 4, 2, 8, 8, 15, 11, 11, 11, 4, 4, 4, 7, 13, 12},
		{14, 15, 10, 0, 4, 3, 1, 9, 13, 7, 9, 9, 15, 5, 0, 3, 9, 6, 4, 7, 13, 11, 3, 2, 7, 1, 6, 8, 13, 7, 10, 4, 3, 9, 5, 9, 2, 6, 10, 7, 9, 13, 2, 14, 2, 14, 7, 2, 14, 2, 8, 8, 0, 9, 0, 9, 12, 6, 7, 7, 6, 8, 12, 13},
		{5, 15, 8, 12, 11, 3, 13, 4, 5, 14, 10, 4, 15, 15, 1, 10, 9, 14, 6, 6, 4, 12, 4, 9, 12, 2, 15, 13, 2, 5, 12, 2, 3, 2, 15, 11, 12, 2, 6, 2, 11, 6, 7, 9, 12, 10, 5, 1, 1, 5, 9, 6, 14, 11, 3, 11, 6, 10, 11, 11, 0, 12, 15, 1},
		{12, 6, 8, 10, 2, 5, 7, 9, 8, 14, 15, 15, 13, 10, 15, 3, 10, 10, 6, 10, 14, 10, 7, 5, 3, 7, 6, 12, 11, 12, 8, 9, 12, 9, 15, 15, 15, 7, 8, 3, 15, 14, 1, 12, 0, 0, 4, 0, 9, 10, 8, 7, 14, 10, 8, 14, 6, 2, 8, 1, 11, 10, 0, 1},
		{12, 1, 2, 12, 7, 10, 4, 11, 5, 14, 10, 2, 2, 9, 4, 13, 3, 14, 3, 15, 5, 0, 14, 7, 7, 15, 6, 5, 2, 8, 15, 9, 6, 6, 13, 10, 9, 8, 6, 3, 14, 7, 12, 9, 7, 8, 13, 12, 14, 13, 6, 0, 5, 1, 9, 12, 14, 0, 11, 11, 6, 3, 11, 7},
		{15, 4, 8, 12, 8, 11, 4, 15, 1, 6, 2, 13, 1, 7, 7, 12, 0, 8, 14, 14, 10, 14, 0, 12, 0, 3, 3, 11, 7, 4, 2, 13, 0, 0, 11, 2, 5, 8, 12, 11, 6, 5, 6, 0, 0, 4, 0, 0, 1, 9, 9, 11, 3, 2, 13, 4, 13, 9, 15, 4, 7, 8, 3, 2},
		{3, 13, 8, 8, 12, 10, 5, 4, 7, 13, 10, 13, 14, 3, 2, 12, 11, 0, 9, 5, 6, 4, 14, 4, 6, 9, 2, 5, 10, 3, 9, 10, 5, 0, 12, 5, 15, 5, 15, 15, 2, 12, 3, 11, 0, 15, 9, 14, 1, 5, 6, 6, 14, 5, 8, 0, 5, 9, 3, 7, 7, 12, 15, 1},
		{1, 11, 7, 4, 13, 3, 0, 8, 11, 9, 15, 1, 4, 12, 2, 12, 10, 4, 14, 3, 9, 14, 14, 2, 3, 11, 12, 4, 5, 10, 6, 15, 2, 13, 13, 9, 9, 1, 11, 12, 12, 14, 1, 5, 15, 1, 7, 14, 12, 10, 11, 13, 13, 5, 2, 4, 7, 7, 9, 4, 14, 15, 13, 10},
		{14, 15, 9, 14, 9, 5, 13, 2, 0, 0, 14, 8, 6, 2, 0, 7, 11, 10, 2, 13, 2, 14, 9, 6, 4, 11, 5, 14, 6, 1, 6, 14, 6, 3, 9, 5, 2, 9, 3, 11, 1, 14, 5, 4, 12, 5, 3, 5, 11, 3, 11, 6, 13, 7, 13, 7, 4, 9, 4, 13, 8, 3, 5, 11},
		{13, 12, 12, 13, 8, 2, 4, 2, 10, 6, 3, 5, 7, 7, 6, 13, 8, 6, 15, 4, 12, 7, 15, 4, 3, 9, 8, 15, 0, 3, 12, 1, 9, 8, 13, 10, 15, 4, 14, 1, 6, 15, 0, 4, 8, 9, 3, 1, 3, 15, 5, 5, 1, 11, 11, 10, 11, 10, 8, 8, 5, 4, 13, 0},
		{8, 4, 15, 9, 14, 9, 5, 8, 8, 10, 5, 15, 9, 8, 12, 5, 11, 10, 2, 12, 13, 1, 0, 2, 6, 13, 11, 9, 12, 0, 5, 0, 11, 5, 14, 12, 3, 4, 2, 10, 3, 12, 5, 15, 4, 8, 14, 1, 0, 13, 9, 5, 2, 4, 13, 8, 2, 5, 8, 9, 15, 3, 5, 5},
		{0, 3, 3, 4, 6, 5, 5, 1, 3, 2, 14, 5, 10, 7, 15, 11, 7, 13, 15, 4, 0, 12, 9, 15, 12, 0, 3, 1, 14, 1, 12, 9, 13, 8, 9, 15, 12, 3, 5, 11, 3, 11, 4, 1, 9, 4, 13, 7, 4, 10, 6, 14, 13, 0, 9, 11, 15, 15, 3, 3, 13, 15, 10, 15},
	}

	hashed := testMatrix.HeavyHash(powHash)

	if !equalBytes(expected, hashed.byteSlice()) {
		t.Fatalf("expected: %x == %x", expected, hashed.byteSlice())
	}
}

// TestKHeavyHashInputValidation tests input validation
func TestKHeavyHashInputValidation(t *testing.T) {
	// Test with wrong input size
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for wrong input size")
		}
	}()

	wrongInput := make([]byte, 79) // Wrong size
	KHeavyHash(wrongInput)
}

// TestKHeavyHashConsistency tests that the same input always produces the same output
func TestKHeavyHashConsistency(t *testing.T) {
	// Create test input
	input := make([]byte, 80)
	for i := range input {
		input[i] = byte(i)
	}

	// Run multiple times
	result1 := KHeavyHash(input)
	result2 := KHeavyHash(input)

	if !equalBytes(result1[:], result2[:]) {
		t.Error("KHeavyHash is not consistent for the same input")
	}
}

// Helper function to compare byte slices
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// BenchmarkKHeavyHash benchmarks the kHeavyHash function
func BenchmarkKHeavyHash(b *testing.B) {
	input := make([]byte, 80)
	for i := range input {
		input[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KHeavyHash(input)
	}
}

// BenchmarkMatrixGeneration benchmarks matrix generation
func BenchmarkMatrixGeneration(b *testing.B) {
	testHashBytes := [32]byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}
	testHash := newDomainHashFromByteArray(&testHashBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generateMatrix(testHash)
	}
}

// TestDebugKHeavyHash validates the DebugKHeavyHash function using test vectors with various manipulations
func TestDebugKHeavyHash(t *testing.T) {
	// Use the first test vector as our baseline
	tv := testVectors[0]

	// Parse hex strings to get the correct values
	prePowHashBytes, err := hex.DecodeString(tv.prePowHash)
	if err != nil {
		t.Fatalf("Failed to decode prePowHash: %v", err)
	}

	timestampBytes, err := hex.DecodeString(tv.timestamp)
	if err != nil {
		t.Fatalf("Failed to decode timestamp: %v", err)
	}
	timestampBytes = reverseBytes(timestampBytes) // As used in actual test

	nonceBytes, err := hex.DecodeString(tv.nonce)
	if err != nil {
		t.Fatalf("Failed to decode nonce: %v", err)
	}
	nonceBytes = reverseBytes(nonceBytes) // As used in actual test

	expectedBytes, err := hex.DecodeString(tv.expected)
	if err != nil {
		t.Fatalf("Failed to decode expected result: %v", err)
	}
	var expectedArray [32]byte
	copy(expectedArray[:], expectedBytes)

	// Build the correct input (as used in TestKHeavyHashWithTestVectors)
	var correctInput [80]byte
	copy(correctInput[0:32], prePowHashBytes)
	copy(correctInput[32:40], timestampBytes)
	copy(correctInput[72:80], nonceBytes)

	// Verify the correct input produces the expected output
	correctResult := KHeavyHash(correctInput[:])
	if !equalBytes(correctResult[:], expectedBytes) {
		t.Fatalf("Baseline test failed: correct input does not produce expected output")
	}

	// Test Case 1: All fields and expected are in correct order (should find nothing needs reversing)
	t.Run("AllCorrect", func(t *testing.T) {
		result := DebugKHeavyHash(correctInput, expectedArray)
		if !result.Found {
			t.Error("DebugKHeavyHash should have found a match")
		}
		if result.PrePowHashReversed || result.TimestampReversed || result.NonceReversed || result.ExpectedReversed {
			t.Errorf("Expected no reversals needed, got PrePowHash:%v Timestamp:%v Nonce:%v Expected:%v",
				result.PrePowHashReversed, result.TimestampReversed, result.NonceReversed, result.ExpectedReversed)
		}
		// Verify corrected input matches original
		if result.CorrectedInput != correctInput {
			t.Error("Corrected input should match original when all is correct")
		}
		// Verify corrected input produces correct output
		verifyResult := KHeavyHash(result.CorrectedInput[:])
		if !equalBytes(verifyResult[:], expectedBytes) {
			t.Error("Corrected input should produce expected output")
		}
	})

	// Test Case 2: Reverse PrePowHash
	t.Run("PrePowHashReversed", func(t *testing.T) {
		var testInput [80]byte
		copy(testInput[0:32], reverseBytes(prePowHashBytes))
		copy(testInput[32:40], timestampBytes)
		copy(testInput[72:80], nonceBytes)

		result := DebugKHeavyHash(testInput, expectedArray)
		if !result.Found {
			t.Error("DebugKHeavyHash should have found a match")
		}
		if !result.PrePowHashReversed {
			t.Error("Expected PrePowHashReversed to be true")
		}
		if result.TimestampReversed || result.NonceReversed || result.ExpectedReversed {
			t.Errorf("Expected only PrePowHash reversed, got Timestamp:%v Nonce:%v Expected:%v",
				result.TimestampReversed, result.NonceReversed, result.ExpectedReversed)
		}
		// Verify corrected input produces correct output
		verifyResult := KHeavyHash(result.CorrectedInput[:])
		if !equalBytes(verifyResult[:], expectedArray[:]) {
			t.Error("Corrected input should produce expected output")
		}
	})

	// Test Case 3: Reverse Timestamp
	t.Run("TimestampReversed", func(t *testing.T) {
		var testInput [80]byte
		copy(testInput[0:32], prePowHashBytes)
		copy(testInput[32:40], reverseBytes(timestampBytes))
		copy(testInput[72:80], nonceBytes)

		result := DebugKHeavyHash(testInput, expectedArray)
		if !result.Found {
			t.Error("DebugKHeavyHash should have found a match")
		}
		if !result.TimestampReversed {
			t.Error("Expected TimestampReversed to be true")
		}
		if result.PrePowHashReversed || result.NonceReversed || result.ExpectedReversed {
			t.Errorf("Expected only Timestamp reversed, got PrePowHash:%v Nonce:%v Expected:%v",
				result.PrePowHashReversed, result.NonceReversed, result.ExpectedReversed)
		}
		// Verify corrected input produces correct output
		verifyResult := KHeavyHash(result.CorrectedInput[:])
		if !equalBytes(verifyResult[:], expectedArray[:]) {
			t.Error("Corrected input should produce expected output")
		}
	})

	// Test Case 4: Reverse Nonce
	t.Run("NonceReversed", func(t *testing.T) {
		var testInput [80]byte
		copy(testInput[0:32], prePowHashBytes)
		copy(testInput[32:40], timestampBytes)
		copy(testInput[72:80], reverseBytes(nonceBytes))

		result := DebugKHeavyHash(testInput, expectedArray)
		if !result.Found {
			t.Error("DebugKHeavyHash should have found a match")
		}
		if !result.NonceReversed {
			t.Error("Expected NonceReversed to be true")
		}
		if result.PrePowHashReversed || result.TimestampReversed || result.ExpectedReversed {
			t.Errorf("Expected only Nonce reversed, got PrePowHash:%v Timestamp:%v Expected:%v",
				result.PrePowHashReversed, result.TimestampReversed, result.ExpectedReversed)
		}
		// Verify corrected input produces correct output
		verifyResult := KHeavyHash(result.CorrectedInput[:])
		if !equalBytes(verifyResult[:], expectedArray[:]) {
			t.Error("Corrected input should produce expected output")
		}
	})

	// Test Case 5: Reverse Expected output
	t.Run("ExpectedReversed", func(t *testing.T) {
		reversedExpected := reverseBytes(expectedBytes)
		var reversedExpectedArray [32]byte
		copy(reversedExpectedArray[:], reversedExpected)

		result := DebugKHeavyHash(correctInput, reversedExpectedArray)
		if !result.Found {
			t.Error("DebugKHeavyHash should have found a match")
		}
		if !result.ExpectedReversed {
			t.Error("Expected ExpectedReversed to be true")
		}
		if result.PrePowHashReversed || result.TimestampReversed || result.NonceReversed {
			t.Errorf("Expected only Expected reversed, got PrePowHash:%v Timestamp:%v Nonce:%v",
				result.PrePowHashReversed, result.TimestampReversed, result.NonceReversed)
		}
		// Verify corrected input produces the original expected (not reversed)
		// When ExpectedReversed is true, it means the expected we passed in was reversed,
		// so the corrected input should produce the original (non-reversed) expected value.
		verifyResult := KHeavyHash(result.CorrectedInput[:])
		if !equalBytes(verifyResult[:], expectedArray[:]) {
			t.Error("Corrected input should produce original (non-reversed) expected output")
		}
		// Verify that reversing the output matches the reversed expected we passed in
		reversedOutput := reverseBytes(verifyResult[:])
		if !equalBytes(reversedOutput, reversedExpectedArray[:]) {
			t.Error("Reversing the output should match the reversed expected we passed in")
		}
	})

	// Test Case 6: Reverse all input fields
	t.Run("AllInputFieldsReversed", func(t *testing.T) {
		var testInput [80]byte
		copy(testInput[0:32], reverseBytes(prePowHashBytes))
		copy(testInput[32:40], reverseBytes(timestampBytes))
		copy(testInput[72:80], reverseBytes(nonceBytes))

		result := DebugKHeavyHash(testInput, expectedArray)
		if !result.Found {
			t.Error("DebugKHeavyHash should have found a match")
		}
		if !result.PrePowHashReversed || !result.TimestampReversed || !result.NonceReversed {
			t.Errorf("Expected all input fields reversed, got PrePowHash:%v Timestamp:%v Nonce:%v",
				result.PrePowHashReversed, result.TimestampReversed, result.NonceReversed)
		}
		if result.ExpectedReversed {
			t.Error("Expected should not be reversed in this case")
		}
		// Verify corrected input produces correct output
		verifyResult := KHeavyHash(result.CorrectedInput[:])
		if !equalBytes(verifyResult[:], expectedArray[:]) {
			t.Error("Corrected input should produce expected output")
		}
	})

	// Test Case 7: Reverse all fields including expected
	t.Run("EverythingReversed", func(t *testing.T) {
		var testInput [80]byte
		copy(testInput[0:32], reverseBytes(prePowHashBytes))
		copy(testInput[32:40], reverseBytes(timestampBytes))
		copy(testInput[72:80], reverseBytes(nonceBytes))

		reversedExpected := reverseBytes(expectedBytes)
		var reversedExpectedArray [32]byte
		copy(reversedExpectedArray[:], reversedExpected)

		result := DebugKHeavyHash(testInput, reversedExpectedArray)
		if !result.Found {
			t.Error("DebugKHeavyHash should have found a match")
		}
		if !result.PrePowHashReversed || !result.TimestampReversed || !result.NonceReversed || !result.ExpectedReversed {
			t.Errorf("Expected all fields reversed, got PrePowHash:%v Timestamp:%v Nonce:%v Expected:%v",
				result.PrePowHashReversed, result.TimestampReversed, result.NonceReversed, result.ExpectedReversed)
		}
		// Verify corrected input produces the original expected (not reversed)
		// When ExpectedReversed is true, it means the expected we passed in was reversed,
		// so the corrected input should produce the original (non-reversed) expected value.
		verifyResult := KHeavyHash(result.CorrectedInput[:])
		if !equalBytes(verifyResult[:], expectedArray[:]) {
			t.Error("Corrected input should produce original (non-reversed) expected output")
		}
		// Verify that reversing the output matches the reversed expected we passed in
		reversedOutput := reverseBytes(verifyResult[:])
		if !equalBytes(reversedOutput, reversedExpectedArray[:]) {
			t.Error("Reversing the output should match the reversed expected we passed in")
		}
	})

	// Test Case 8: Random manipulation - reverse PrePowHash and Expected
	t.Run("PrePowHashAndExpectedReversed", func(t *testing.T) {
		var testInput [80]byte
		copy(testInput[0:32], reverseBytes(prePowHashBytes))
		copy(testInput[32:40], timestampBytes)
		copy(testInput[72:80], nonceBytes)

		reversedExpected := reverseBytes(expectedBytes)
		var reversedExpectedArray [32]byte
		copy(reversedExpectedArray[:], reversedExpected)

		result := DebugKHeavyHash(testInput, reversedExpectedArray)
		if !result.Found {
			t.Error("DebugKHeavyHash should have found a match")
		}
		if !result.PrePowHashReversed || !result.ExpectedReversed {
			t.Errorf("Expected PrePowHash and Expected reversed, got PrePowHash:%v Expected:%v",
				result.PrePowHashReversed, result.ExpectedReversed)
		}
		if result.TimestampReversed || result.NonceReversed {
			t.Errorf("Expected Timestamp and Nonce not reversed, got Timestamp:%v Nonce:%v",
				result.TimestampReversed, result.NonceReversed)
		}
		// Verify corrected input produces the original expected (not reversed)
		// When ExpectedReversed is true, it means the expected we passed in was reversed,
		// so the corrected input should produce the original (non-reversed) expected value.
		verifyResult := KHeavyHash(result.CorrectedInput[:])
		if !equalBytes(verifyResult[:], expectedArray[:]) {
			t.Error("Corrected input should produce original (non-reversed) expected output")
		}
		// Verify that reversing the output matches the reversed expected we passed in
		reversedOutput := reverseBytes(verifyResult[:])
		if !equalBytes(reversedOutput, reversedExpectedArray[:]) {
			t.Error("Reversing the output should match the reversed expected we passed in")
		}
	})

	// Test Case 9: Invalid input that shouldn't match
	t.Run("NoMatch", func(t *testing.T) {
		var invalidInput [80]byte
		// Fill with random bytes that definitely won't produce expected
		for i := range invalidInput {
			invalidInput[i] = byte(i ^ 0xFF)
		}
		var invalidExpected [32]byte
		for i := range invalidExpected {
			invalidExpected[i] = byte(i ^ 0xAA)
		}

		result := DebugKHeavyHash(invalidInput, invalidExpected)
		if result.Found {
			t.Error("DebugKHeavyHash should not have found a match for invalid input")
		}
	})

	// Test Case 10: Test with another test vector to ensure it works across different inputs
	t.Run("DifferentTestVector", func(t *testing.T) {
		tv2 := testVectors[1]
		prePowHashBytes2, _ := hex.DecodeString(tv2.prePowHash)
		timestampBytes2, _ := hex.DecodeString(tv2.timestamp)
		timestampBytes2 = reverseBytes(timestampBytes2)
		nonceBytes2, _ := hex.DecodeString(tv2.nonce)
		nonceBytes2 = reverseBytes(nonceBytes2)
		expectedBytes2, _ := hex.DecodeString(tv2.expected)
		var expectedArray2 [32]byte
		copy(expectedArray2[:], expectedBytes2)

		var correctInput2 [80]byte
		copy(correctInput2[0:32], prePowHashBytes2)
		copy(correctInput2[32:40], timestampBytes2)
		copy(correctInput2[72:80], nonceBytes2)

		// Reverse PrePowHash and Timestamp
		var testInput2 [80]byte
		copy(testInput2[0:32], reverseBytes(prePowHashBytes2))
		copy(testInput2[32:40], reverseBytes(timestampBytes2))
		copy(testInput2[72:80], nonceBytes2)

		result := DebugKHeavyHash(testInput2, expectedArray2)
		if !result.Found {
			t.Error("DebugKHeavyHash should have found a match")
		}
		if !result.PrePowHashReversed || !result.TimestampReversed {
			t.Errorf("Expected PrePowHash and Timestamp reversed, got PrePowHash:%v Timestamp:%v",
				result.PrePowHashReversed, result.TimestampReversed)
		}
		if result.NonceReversed || result.ExpectedReversed {
			t.Errorf("Expected Nonce and Expected not reversed, got Nonce:%v Expected:%v",
				result.NonceReversed, result.ExpectedReversed)
		}
		// Verify corrected input produces correct output
		verifyResult := KHeavyHash(result.CorrectedInput[:])
		if !equalBytes(verifyResult[:], expectedArray2[:]) {
			t.Error("Corrected input should produce expected output")
		}
	})
}
