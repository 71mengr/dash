// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_ZERO_KNOWLEDGE_H
#define BITCOIN_UTIL_ZERO_KNOWLEDGE_H

#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#include <string>
#include <vector>
#include <memory>

namespace zkproof {

// Proof version constants
static constexpr uint8_t PROOF_VERSION = 0x01;
static constexpr uint8_t PROOF_VERSION_V2 = 0x02; // Extended version with type info

// Proof types
enum class ProofType : uint8_t {
    BASIC_COMMITMENT = 0x01,   // Simple hash commitment
    RANGE_PROOF = 0x02,        // Prove value in range
    SET_MEMBERSHIP = 0x03,     // Prove value in set
    EQUALITY_PROOF = 0x04,     // Prove two values equal
    COMPOSITE_PROOF = 0x05     // Multiple proofs combined
};

// Convert ProofType to string
inline std::string ProofTypeToString(ProofType type)
{
    switch (type) {
        case ProofType::BASIC_COMMITMENT: return "basic_commitment";
        case ProofType::RANGE_PROOF: return "range_proof";
        case ProofType::SET_MEMBERSHIP: return "set_membership";
        case ProofType::EQUALITY_PROOF: return "equality_proof";
        case ProofType::COMPOSITE_PROOF: return "composite_proof";
        default: return "unknown";
    }
}

/**
 * Basic commitment proof (version 1)
 * Format: [version:1][nonce:32][commitment:32]
 */
std::vector<unsigned char> CreateCommitmentProof(const std::string& claim, const std::string& witness);
bool ExtractProofNonceAndHash(const std::vector<unsigned char>& proof, uint256& nonce, uint256& commitment_hash);
bool VerifyCommitmentProof(const std::vector<unsigned char>& proof, const std::string& claim, const std::string& witness);

/**
 * Extended proof structure (version 2+)
 */
struct ExtendedProof
{
    ProofType type{ProofType::BASIC_COMMITMENT};
    uint8_t version{PROOF_VERSION_V2};
    uint256 challenge_hash;
    std::vector<unsigned char> proof_data;
    int64_t created_at{0};
    
    // Serialization
    SERIALIZE_METHODS(ExtendedProof, obj)
    {
        uint8_t type_byte = static_cast<uint8_t>(obj.type);
        READWRITE(obj.version);
        READWRITE(type_byte);
        READWRITE(obj.challenge_hash);
        READWRITE(obj.proof_data);
        READWRITE(obj.created_at);
        SER_READ(obj, obj.type = static_cast<ProofType>(type_byte));
    }
    
    size_t GetSize() const
    {
        return sizeof(version) + sizeof(uint8_t) + sizeof(challenge_hash) + 
               proof_data.size() + sizeof(created_at);
    }
};

/**
 * Range proof: Prove that a value lies within a certain interval
 * without revealing the actual value.
 * 
 * Example: Prove age >= 18 without revealing exact age.
 */
class RangeProof
{
public:
    RangeProof() = default;
    ~RangeProof() = default;
    
    // Create a range proof
    bool Create(uint64_t value, uint64_t min, uint64_t max);
    
    // Verify the proof
    bool Verify(uint64_t min, uint64_t max) const;
    
    // Get the proof data
    ExtendedProof GetProof() const { return m_proof; }
    
    // Set from proof data
    bool SetProof(const ExtendedProof& proof);
    
    // Helper for age verification
    static bool VerifyAge(const ExtendedProof& proof, int min_age);
    
private:
    ExtendedProof m_proof;
    uint64_t m_committed_value{0};
    
    // Internal proof generation
    std::vector<unsigned char> GenerateRangeProofData(uint64_t value, uint64_t min, uint64_t max);
    bool VerifyRangeProofData(const std::vector<unsigned char>& data, uint64_t min, uint64_t max) const;
};

/**
 * Set membership proof: Prove that a value belongs to a set
 * without revealing which element.
 * 
 * Example: Prove country is in {US, CA, UK, AU} without revealing which.
 */
class SetMembershipProof
{
public:
    SetMembershipProof() = default;
    ~SetMembershipProof() = default;
    
    // Create a set membership proof
    bool Create(const std::string& value, const std::vector<std::string>& set);
    
    // Verify the proof
    bool Verify(const std::vector<std::string>& set) const;
    
    // Get the proof data
    ExtendedProof GetProof() const { return m_proof; }
    
    // Set from proof data
    bool SetProof(const ExtendedProof& proof);
    
    // Helper for country verification
    static bool VerifyCountry(const ExtendedProof& proof, const std::vector<std::string>& allowed_countries);
    
private:
    ExtendedProof m_proof;
    std::string m_committed_value;
    
    // Internal proof generation
    std::vector<unsigned char> GenerateSetProofData(const std::string& value, const std::vector<std::string>& set);
    bool VerifySetProofData(const std::vector<unsigned char>& data, const std::vector<std::string>& set) const;
};

/**
 * Equality proof: Prove that two commitments hide the same value
 */
class EqualityProof
{
public:
    EqualityProof() = default;
    ~EqualityProof() = default;
    
    // Create equality proof between two commitments
    bool Create(const std::vector<unsigned char>& commitment1,
                const std::vector<unsigned char>& commitment2,
                const std::string& witness);
    
    // Verify the proof
    bool Verify(const std::vector<unsigned char>& commitment1,
                const std::vector<unsigned char>& commitment2) const;
    
    // Get the proof data
    ExtendedProof GetProof() const { return m_proof; }
    
    // Set from proof data
    bool SetProof(const ExtendedProof& proof);
    
private:
    ExtendedProof m_proof;
};

/**
 * Composite proof: Combine multiple proofs into one
 */
class CompositeProof
{
public:
    CompositeProof() = default;
    ~CompositeProof() = default;
    
    // Add a proof
    bool AddProof(const ExtendedProof& proof);
    
    // Create the composite
    bool Create();
    
    // Verify all proofs
    bool Verify() const;
    
    // Get the proof data
    ExtendedProof GetProof() const { return m_proof; }
    
    // Set from proof data
    bool SetProof(const ExtendedProof& proof);
    
    // Get individual proofs
    std::vector<ExtendedProof> GetProofs() const { return m_proofs; }
    
private:
    ExtendedProof m_proof;
    std::vector<ExtendedProof> m_proofs;
};

/**
 * Utility functions for common KYC proofs
 */
namespace utils {

// Age proof
ExtendedProof CreateAgeProof(int64_t birth_date, int min_age);
bool VerifyAgeProof(const ExtendedProof& proof, int min_age);

// Country proof
ExtendedProof CreateCountryProof(const std::string& country, const std::vector<std::string>& allowed_countries);
bool VerifyCountryProof(const ExtendedProof& proof, const std::vector<std::string>& allowed_countries);

// Combined KYC proof
ExtendedProof CreateCombinedKYCProof(int64_t birth_date, int min_age,
                                     const std::string& country,
                                     const std::vector<std::string>& allowed_countries);
bool VerifyCombinedKYCProof(const ExtendedProof& proof, int min_age,
                           const std::vector<std::string>& allowed_countries);

// Serialization helpers
std::string ProofToBase64(const ExtendedProof& proof);
ExtendedProof ProofFromBase64(const std::string& base64);

} // namespace utils

} // namespace zkproof

#endif // BITCOIN_UTIL_ZERO_KNOWLEDGE_H
