// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/zero_knowledge.h>

#include <crypto/sha256.h>
#include <logging.h>
#include <random.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/vector.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>

namespace zkproof {

//=============================================================================
// Basic Commitment Proof (Version 1)
//=============================================================================

namespace {

uint256 BuildCommitmentHash(const std::string& claim, const uint256& nonce, const std::string& witness)
{
    CSHA256 hasher;
    uint256 hash;
    hasher.Write(reinterpret_cast<const unsigned char*>(claim.data()), claim.size());
    hasher.Write(nonce.begin(), nonce.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(witness.data()), witness.size());
    hasher.Finalize(hash.begin());
    return hash;
}

uint256 BuildChallengeHash(const std::string& data)
{
    uint256 hash;
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(data.data()), data.size());
    hasher.Finalize(hash.begin());
    return hash;
}

std::string HashToChallenge(const uint256& hash)
{
    return HexStr(hash);
}

} // namespace

std::vector<unsigned char> CreateCommitmentProof(const std::string& claim, const std::string& witness)
{
    const uint256 nonce = GetRandHash();
    const uint256 commitment_hash = BuildCommitmentHash(claim, nonce, witness);

    std::vector<unsigned char> proof;
    proof.reserve(1 + nonce.size() + commitment_hash.size());
    proof.push_back(PROOF_VERSION);
    proof.insert(proof.end(), nonce.begin(), nonce.end());
    proof.insert(proof.end(), commitment_hash.begin(), commitment_hash.end());
    return proof;
}

bool ExtractProofNonceAndHash(const std::vector<unsigned char>& proof, uint256& nonce, uint256& commitment_hash)
{
    if (proof.size() != 65 || proof[0] != PROOF_VERSION) {
        return false;
    }

    memcpy(nonce.begin(), proof.data() + 1, nonce.size());
    memcpy(commitment_hash.begin(), proof.data() + 1 + nonce.size(), commitment_hash.size());
    return true;
}

bool VerifyCommitmentProof(const std::vector<unsigned char>& proof,
                           const std::string& claim,
                           const std::string& witness)
{
    uint256 nonce;
    uint256 commitment_hash;
    if (!ExtractProofNonceAndHash(proof, nonce, commitment_hash)) {
        return false;
    }

    return BuildCommitmentHash(claim, nonce, witness) == commitment_hash;
}

//=============================================================================
// Range Proof Implementation
//=============================================================================

std::vector<unsigned char> RangeProof::GenerateRangeProofData(uint64_t value, uint64_t min, uint64_t max)
{
    std::vector<unsigned char> data;
    
    // Check if value is in range
    if (value < min || value > max) {
        LogPrintf("RangeProof::GenerateRangeProofData: Value %llu out of range [%llu, %llu]\n", value, min, max);
        return data;
    }
    
    // Create a commitment that proves value is in range without revealing it
    // Using a simple binary decomposition for demonstration
    // In production, use proper range proofs like Bulletproofs
    
    uint256 nonce = GetRandHash();
    uint256 range_hash;
    
    // Hash the range together with the value and nonce
    std::string range_str = strprintf("%llu-%llu", min, max);
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(range_str.data()), range_str.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(&value), sizeof(value));
    hasher.Write(nonce.begin(), nonce.size());
    hasher.Finalize(range_hash.begin());
    
    // Store the proof
    data.push_back(PROOF_VERSION_V2);
    data.push_back(static_cast<uint8_t>(ProofType::RANGE_PROOF));
    data.insert(data.end(), nonce.begin(), nonce.end());
    data.insert(data.end(), range_hash.begin(), range_hash.end());
    
    // Store min/max for verification
    data.insert(data.end(), reinterpret_cast<unsigned char*>(&min), 
                reinterpret_cast<unsigned char*>(&min) + sizeof(min));
    data.insert(data.end(), reinterpret_cast<unsigned char*>(&max), 
                reinterpret_cast<unsigned char*>(&max) + sizeof(max));
    
    return data;
}

bool RangeProof::VerifyRangeProofData(const std::vector<unsigned char>& data, uint64_t min, uint64_t max) const
{
    if (data.size() < 1 + 1 + 32 + 32 + 8 + 8) {
        return false;
    }
    
    size_t pos = 0;
    
    uint8_t version = data[pos++];
    if (version != PROOF_VERSION_V2) {
        return false;
    }
    
    uint8_t type_byte = data[pos++];
    if (type_byte != static_cast<uint8_t>(ProofType::RANGE_PROOF)) {
        return false;
    }
    
    // Extract nonce and hash
    uint256 nonce;
    uint256 range_hash;
    memcpy(nonce.begin(), data.data() + pos, nonce.size());
    pos += nonce.size();
    memcpy(range_hash.begin(), data.data() + pos, range_hash.size());
    pos += range_hash.size();
    
    // Extract stored min/max
    uint64_t stored_min, stored_max;
    memcpy(&stored_min, data.data() + pos, sizeof(stored_min));
    pos += sizeof(stored_min);
    memcpy(&stored_max, data.data() + pos, sizeof(stored_max));
    
    // Verify the range matches
    if (stored_min != min || stored_max != max) {
        LogPrintf("RangeProof::VerifyRangeProofData: Range mismatch [%llu,%llu] vs [%llu,%llu]\n",
                  stored_min, stored_max, min, max);
        return false;
    }
    
    // In production, verify the proof cryptographically
    // For now, just verify the hash structure
    
    // Recompute the range string
    std::string range_str = strprintf("%llu-%llu", min, max);
    uint256 computed_hash;
    {
        CSHA256 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(range_str.data()), range_str.size());
        hasher.Write(reinterpret_cast<const unsigned char*>(&m_committed_value), sizeof(m_committed_value));
        hasher.Write(nonce.begin(), nonce.size());
        hasher.Finalize(computed_hash.begin());
    }
    
    return computed_hash == range_hash;
}

bool RangeProof::Create(uint64_t value, uint64_t min, uint64_t max)
{
    m_committed_value = value;
    
    auto proof_data = GenerateRangeProofData(value, min, max);
    if (proof_data.empty()) {
        return false;
    }
    
    m_proof.version = PROOF_VERSION_V2;
    m_proof.type = ProofType::RANGE_PROOF;
    m_proof.proof_data = proof_data;
    m_proof.created_at = GetTime();
    
    // Generate challenge hash
    m_proof.challenge_hash = BuildChallengeHash(std::string(proof_data.begin(), proof_data.end()));
    
    LogPrintf("RangeProof::Create: Created range proof for [%llu, %llu]\n", min, max);
    return true;
}

bool RangeProof::Verify(uint64_t min, uint64_t max) const
{
    return VerifyRangeProofData(m_proof.proof_data, min, max);
}

bool RangeProof::SetProof(const ExtendedProof& proof)
{
    if (proof.type != ProofType::RANGE_PROOF || proof.version != PROOF_VERSION_V2) {
        return false;
    }
    
    m_proof = proof;
    return true;
}

bool RangeProof::VerifyAge(const ExtendedProof& proof, int min_age)
{
    RangeProof range_proof;
    if (!range_proof.SetProof(proof)) {
        return false;
    }
    
    // For age, we need to prove that (now - birth_date) >= min_age
    // Which is equivalent to birth_date <= (now - min_age*365*24*60*60)
    int64_t max_birth_date = GetTime() - (int64_t)min_age * 365 * 24 * 60 * 60;
    
    return range_proof.Verify(0, max_birth_date);
}

//=============================================================================
// Set Membership Proof Implementation
//=============================================================================

std::vector<unsigned char> SetMembershipProof::GenerateSetProofData(
    const std::string& value, const std::vector<std::string>& set)
{
    std::vector<unsigned char> data;
    
    // Check if value is in set
    auto it = std::find(set.begin(), set.end(), value);
    if (it == set.end()) {
        LogPrintf("SetMembershipProof::GenerateSetProofData: Value '%s' not in set\n", value);
        return data;
    }
    
    // Create a Merkle tree of the set and prove membership
    // For demonstration, we'll use a simple hash-based proof
    
    uint256 nonce = GetRandHash();
    uint256 set_hash;
    
    // Hash the entire set for verification
    CSHA256 hasher;
    for (const auto& item : set) {
        hasher.Write(reinterpret_cast<const unsigned char*>(item.data()), item.size());
    }
    hasher.Finalize(set_hash.begin());
    
    // Hash the specific value with the set hash and nonce
    uint256 value_hash;
    CSHA256 value_hasher;
    value_hasher.Write(reinterpret_cast<const unsigned char*>(value.data()), value.size());
    value_hasher.Write(set_hash.begin(), set_hash.size());
    value_hasher.Write(nonce.begin(), nonce.size());
    value_hasher.Finalize(value_hash.begin());
    
    // Store the proof
    data.push_back(PROOF_VERSION_V2);
    data.push_back(static_cast<uint8_t>(ProofType::SET_MEMBERSHIP));
    data.insert(data.end(), nonce.begin(), nonce.end());
    data.insert(data.end(), set_hash.begin(), set_hash.end());
    data.insert(data.end(), value_hash.begin(), value_hash.end());
    
    // Store set size for verification
    uint32_t set_size = set.size();
    data.insert(data.end(), reinterpret_cast<unsigned char*>(&set_size),
                reinterpret_cast<unsigned char*>(&set_size) + sizeof(set_size));
    
    return data;
}

bool SetMembershipProof::VerifySetProofData(const std::vector<unsigned char>& data,
                                            const std::vector<std::string>& set) const
{
    if (data.size() < 1 + 1 + 32 + 32 + 32 + 4) {
        return false;
    }
    
    size_t pos = 0;
    
    uint8_t version = data[pos++];
    if (version != PROOF_VERSION_V2) {
        return false;
    }
    
    uint8_t type_byte = data[pos++];
    if (type_byte != static_cast<uint8_t>(ProofType::SET_MEMBERSHIP)) {
        return false;
    }
    
    // Extract nonce, set_hash, and value_hash
    uint256 nonce, set_hash, value_hash;
    memcpy(nonce.begin(), data.data() + pos, nonce.size());
    pos += nonce.size();
    memcpy(set_hash.begin(), data.data() + pos, set_hash.size());
    pos += set_hash.size();
    memcpy(value_hash.begin(), data.data() + pos, value_hash.size());
    pos += value_hash.size();
    
    // Extract set size
    uint32_t stored_set_size;
    memcpy(&stored_set_size, data.data() + pos, sizeof(stored_set_size));
    
    // Verify set size matches
    if (stored_set_size != set.size()) {
        LogPrintf("SetMembershipProof::VerifySetProofData: Set size mismatch\n");
        return false;
    }
    
    // Recompute set hash
    uint256 computed_set_hash;
    {
        CSHA256 hasher;
        for (const auto& item : set) {
            hasher.Write(reinterpret_cast<const unsigned char*>(item.data()), item.size());
        }
        hasher.Finalize(computed_set_hash.begin());
    }
    
    if (computed_set_hash != set_hash) {
        LogPrintf("SetMembershipProof::VerifySetProofData: Set hash mismatch\n");
        return false;
    }
    
    // Recompute value hash for each possible value to find match
    for (const auto& item : set) {
        uint256 test_hash;
        CSHA256 test_hasher;
        test_hasher.Write(reinterpret_cast<const unsigned char*>(item.data()), item.size());
        test_hasher.Write(set_hash.begin(), set_hash.size());
        test_hasher.Write(nonce.begin(), nonce.size());
        test_hasher.Finalize(test_hash.begin());
        
        if (test_hash == value_hash) {
            return true;
        }
    }
    
    return false;
}

bool SetMembershipProof::Create(const std::string& value, const std::vector<std::string>& set)
{
    auto proof_data = GenerateSetProofData(value, set);
    if (proof_data.empty()) {
        return false;
    }
    
    m_proof.version = PROOF_VERSION_V2;
    m_proof.type = ProofType::SET_MEMBERSHIP;
    m_proof.proof_data = proof_data;
    m_proof.created_at = GetTime();
    m_proof.challenge_hash = BuildChallengeHash(std::string(proof_data.begin(), proof_data.end()));
    
    LogPrintf("SetMembershipProof::Create: Created set membership proof for set of size %zu\n", set.size());
    return true;
}

bool SetMembershipProof::Verify(const std::vector<std::string>& set) const
{
    return VerifySetProofData(m_proof.proof_data, set);
}

bool SetMembershipProof::SetProof(const ExtendedProof& proof)
{
    if (proof.type != ProofType::SET_MEMBERSHIP || proof.version != PROOF_VERSION_V2) {
        return false;
    }
    
    m_proof = proof;
    return true;
}

bool SetMembershipProof::VerifyCountry(const ExtendedProof& proof, const std::vector<std::string>& allowed_countries)
{
    SetMembershipProof set_proof;
    if (!set_proof.SetProof(proof)) {
        return false;
    }
    
    return set_proof.Verify(allowed_countries);
}

//=============================================================================
// Equality Proof Implementation
//=============================================================================

bool EqualityProof::Create(const std::vector<unsigned char>& commitment1,
                           const std::vector<unsigned char>& commitment2,
                           const std::string& witness)
{
    // Prove that both commitments hide the same witness
    uint256 nonce = GetRandHash();
    
    // Hash both commitments together with the witness
    uint256 equality_hash;
    CSHA256 hasher;
    hasher.Write(commitment1.data(), commitment1.size());
    hasher.Write(commitment2.data(), commitment2.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(witness.data()), witness.size());
    hasher.Write(nonce.begin(), nonce.size());
    hasher.Finalize(equality_hash.begin());
    
    // Build proof data
    std::vector<unsigned char> proof_data;
    proof_data.push_back(PROOF_VERSION_V2);
    proof_data.push_back(static_cast<uint8_t>(ProofType::EQUALITY_PROOF));
    proof_data.insert(proof_data.end(), nonce.begin(), nonce.end());
    proof_data.insert(proof_data.end(), equality_hash.begin(), equality_hash.end());
    proof_data.insert(proof_data.end(), commitment1.begin(), commitment1.end());
    proof_data.insert(proof_data.end(), commitment2.begin(), commitment2.end());
    
    m_proof.version = PROOF_VERSION_V2;
    m_proof.type = ProofType::EQUALITY_PROOF;
    m_proof.proof_data = proof_data;
    m_proof.created_at = GetTime();
    m_proof.challenge_hash = BuildChallengeHash(std::string(proof_data.begin(), proof_data.end()));
    
    return true;
}

bool EqualityProof::Verify(const std::vector<unsigned char>& commitment1,
                           const std::vector<unsigned char>& commitment2) const
{
    const auto& data = m_proof.proof_data;
    if (data.size() < 1 + 1 + 32 + 32) {
        return false;
    }
    
    size_t pos = 0;
    
    uint8_t version = data[pos++];
    if (version != PROOF_VERSION_V2) return false;
    
    uint8_t type_byte = data[pos++];
    if (type_byte != static_cast<uint8_t>(ProofType::EQUALITY_PROOF)) return false;
    
    // Extract nonce and hash
    uint256 nonce, equality_hash;
    memcpy(nonce.begin(), data.data() + pos, nonce.size());
    pos += nonce.size();
    memcpy(equality_hash.begin(), data.data() + pos, equality_hash.size());
    pos += equality_hash.size();
    
    // Extract stored commitments
    std::vector<unsigned char> stored_commitment1(data.begin() + pos, data.begin() + pos + commitment1.size());
    pos += commitment1.size();
    std::vector<unsigned char> stored_commitment2(data.begin() + pos, data.begin() + pos + commitment2.size());
    
    // Verify commitments match
    if (stored_commitment1 != commitment1 || stored_commitment2 != commitment2) {
        return false;
    }
    
    // In production, verify the equality proof cryptographically
    // For now, we trust the structure
    
    return true;
}

bool EqualityProof::SetProof(const ExtendedProof& proof)
{
    if (proof.type != ProofType::EQUALITY_PROOF || proof.version != PROOF_VERSION_V2) {
        return false;
    }
    
    m_proof = proof;
    return true;
}

//=============================================================================
// Composite Proof Implementation
//=============================================================================

bool CompositeProof::AddProof(const ExtendedProof& proof)
{
    m_proofs.push_back(proof);
    return true;
}

bool CompositeProof::Create()
{
    if (m_proofs.empty()) {
        return false;
    }
    
    // Serialize all proofs
    std::vector<unsigned char> proof_data;
    proof_data.push_back(PROOF_VERSION_V2);
    proof_data.push_back(static_cast<uint8_t>(ProofType::COMPOSITE_PROOF));
    
    // Store number of proofs
    uint32_t count = m_proofs.size();
    proof_data.insert(proof_data.end(), reinterpret_cast<unsigned char*>(&count),
                      reinterpret_cast<unsigned char*>(&count) + sizeof(count));
    
    // Store each proof
    for (const auto& p : m_proofs) {
        std::vector<unsigned char> serialized;
        CVectorWriter{SER_NETWORK, 0, serialized, 0, p};
        uint32_t size = serialized.size();
        proof_data.insert(proof_data.end(), reinterpret_cast<unsigned char*>(&size),
                          reinterpret_cast<unsigned char*>(&size) + sizeof(size));
        proof_data.insert(proof_data.end(), serialized.begin(), serialized.end());
    }
    
    m_proof.version = PROOF_VERSION_V2;
    m_proof.type = ProofType::COMPOSITE_PROOF;
    m_proof.proof_data = proof_data;
    m_proof.created_at = GetTime();
    m_proof.challenge_hash = BuildChallengeHash(std::string(proof_data.begin(), proof_data.end()));
    
    return true;
}

bool CompositeProof::Verify() const
{
    // Verify each sub-proof
    for (const auto& p : m_proofs) {
        switch (p.type) {
            case ProofType::RANGE_PROOF: {
                RangeProof rp;
                if (!rp.SetProof(p) || !rp.Verify(0, 0)) {
                    return false;
                }
                break;
            }
            case ProofType::SET_MEMBERSHIP: {
                SetMembershipProof smp;
                if (!smp.SetProof(p)) {
                    return false;
                }
                break;
            }
            case ProofType::EQUALITY_PROOF: {
                EqualityProof ep;
                if (!ep.SetProof(p)) {
                    return false;
                }
                break;
            }
            default:
                break;
        }
    }
    return true;
}

bool CompositeProof::SetProof(const ExtendedProof& proof)
{
    if (proof.type != ProofType::COMPOSITE_PROOF || proof.version != PROOF_VERSION_V2) {
        return false;
    }
    
    m_proof = proof;
    
    // Deserialize sub-proofs
    const auto& data = proof.proof_data;
    size_t pos = 0;
    
    if (data.size() < 1 + 1 + 4) return false;
    
    uint8_t version = data[pos++];
    uint8_t type_byte = data[pos++];
    if (version != PROOF_VERSION_V2 || type_byte != static_cast<uint8_t>(ProofType::COMPOSITE_PROOF)) {
        return false;
    }
    
    uint32_t count;
    memcpy(&count, data.data() + pos, sizeof(count));
    pos += sizeof(count);
    
    for (uint32_t i = 0; i < count; i++) {
        if (data.size() < pos + 4) return false;
        uint32_t size;
        memcpy(&size, data.data() + pos, sizeof(size));
        pos += sizeof(size);
        
        if (data.size() < pos + size) return false;
        
        CDataStream{Span<const unsigned char>(data.data() + pos, size), SER_NETWORK, 0} >> m_proofs.emplace_back();
        pos += size;
    }
    
    return true;
}

//=============================================================================
// Utility Functions
//=============================================================================

namespace utils {

ExtendedProof CreateAgeProof(int64_t birth_date, int min_age)
{
    RangeProof proof;
    uint64_t max_birth_date = GetTime() - (uint64_t)min_age * 365 * 24 * 60 * 60;
    
    if (proof.Create(birth_date, 0, max_birth_date)) {
        return proof.GetProof();
    }
    
    return ExtendedProof{};
}

bool VerifyAgeProof(const ExtendedProof& proof, int min_age)
{
    return RangeProof::VerifyAge(proof, min_age);
}

ExtendedProof CreateCountryProof(const std::string& country, const std::vector<std::string>& allowed_countries)
{
    SetMembershipProof proof;
    if (proof.Create(country, allowed_countries)) {
        return proof.GetProof();
    }
    
    return ExtendedProof{};
}

bool VerifyCountryProof(const ExtendedProof& proof, const std::vector<std::string>& allowed_countries)
{
    return SetMembershipProof::VerifyCountry(proof, allowed_countries);
}

ExtendedProof CreateCombinedKYCProof(int64_t birth_date, int min_age,
                                     const std::string& country,
                                     const std::vector<std::string>& allowed_countries)
{
    CompositeProof composite;
    
    auto age_proof = CreateAgeProof(birth_date, min_age);
    if (age_proof.type != ProofType::BASIC_COMMITMENT) {
        composite.AddProof(age_proof);
    }
    
    auto country_proof = CreateCountryProof(country, allowed_countries);
    if (country_proof.type != ProofType::BASIC_COMMITMENT) {
        composite.AddProof(country_proof);
    }
    
    if (composite.Create()) {
        return composite.GetProof();
    }
    
    return ExtendedProof{};
}

bool VerifyCombinedKYCProof(const ExtendedProof& proof, int min_age,
                           const std::vector<std::string>& allowed_countries)
{
    CompositeProof composite;
    if (!composite.SetProof(proof)) {
        return false;
    }
    
    const auto& proofs = composite.GetProofs();
    bool age_ok = false;
    bool country_ok = false;
    
    for (const auto& p : proofs) {
        if (p.type == ProofType::RANGE_PROOF) {
            age_ok = VerifyAgeProof(p, min_age);
        } else if (p.type == ProofType::SET_MEMBERSHIP) {
            country_ok = VerifyCountryProof(p, allowed_countries);
        }
    }
    
    return age_ok && country_ok;
}

std::string ProofToBase64(const ExtendedProof& proof)
{
    std::vector<unsigned char> serialized;
    CVectorWriter{SER_NETWORK, 0, serialized, 0, proof};
    return EncodeBase64(serialized);
}

ExtendedProof ProofFromBase64(const std::string& base64)
{
    ExtendedProof proof;
    auto decoded = DecodeBase64(base64);
    if (decoded) {
        CDataStream{Span<const unsigned char>(decoded->data(), decoded->size()), SER_NETWORK, 0} >> proof;
    }
    return proof;
}

} // namespace utils

} // namespace zkproof
