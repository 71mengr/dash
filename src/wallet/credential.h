// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_CREDENTIAL_H
#define BITCOIN_WALLET_CREDENTIAL_H

#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#include <string>
#include <map>
#include <vector>

namespace wallet {

// Verification status levels
enum class CredentialStatus : uint8_t {
    NONE = 0,           // No verification performed
    PENDING = 1,        // Verification in progress
    VERIFIED_BASIC = 2, // Basic KYC completed
    VERIFIED_FULL = 3,  // Full KYC/AML completed
    EXPIRED = 4,        // Credential expired
    REVOKED = 5         // Credential revoked by issuer
};

// Convert CredentialStatus to string for logging
std::string CredentialStatusToString(CredentialStatus status);

// Credential metadata
class CCredentialMetadata
{
public:
    CCredentialMetadata() = default;
    CCredentialMetadata(int64_t nExpiresAt, const std::string& issuer)
        : nExpiresAt(nExpiresAt), issuer(issuer) {}

    int64_t nExpiresAt{0};           // Timestamp when credential expires
    std::string issuer;                // Issuer DID or identifier
    std::string credentialType;        // "basic_kyc", "full_kyc", etc.
    uint256 credentialHash;            // Hash of the actual credential for verification

    SERIALIZE_METHODS(CCredentialMetadata, obj)
    {
        READWRITE(obj.nExpiresAt);
        READWRITE(obj.issuer);
        READWRITE(obj.credentialType);
        READWRITE(obj.credentialHash);
    }
};

// Main credential storage class
class CWalletCredential
{
public:
    CWalletCredential() = default;

    bool CreateAgeProof(int min_age, std::vector<unsigned char>& proof) const;
    bool CreateCountryProof(const std::string& country_code, std::vector<unsigned char>& proof) const;
    bool VerifyProof(const std::vector<unsigned char>& proof, const std::string& claim_type) const;
    
    // Check if credential contains specific attributes
    bool HasAttribute(const std::string& attr_name) const;
    std::vector<std::string> GetAvailableAttributes() const;

    // Store a verifiable credential (JWT/CWT format)
    bool SetCredential(const std::vector<unsigned char>& credential);

    // Get the raw credential
    std::vector<unsigned char> GetCredential() const { return vchCredential; }

    // Get credential status
    CredentialStatus GetStatus() const { return status; }

    // Update status (called during validation)
    void SetStatus(CredentialStatus newStatus) { status = newStatus; }

    // Check if credential is valid (not expired, not revoked)
    bool IsValid() const;

    // Check if wallet is verified (has valid credential)
    bool IsVerified() const;

    // Get metadata
    CCredentialMetadata GetMetadata() const { return metadata; }

    // Set metadata from parsed credential
    void SetMetadata(const CCredentialMetadata& meta) { metadata = meta; }

    SERIALIZE_METHODS(CWalletCredential, obj)
    {
        uint8_t statusByte = static_cast<uint8_t>(obj.status);
        READWRITE(obj.vchCredential);
        READWRITE(statusByte);
        READWRITE(obj.metadata);
        obj.status = static_cast<CredentialStatus>(statusByte);
    }

    bool CanPerformSensitiveOperations() const;

    std::string GetVerificationFailureReason() const;

    bool ParseJWT(const std::string& jwt);
    bool ParseVC(const std::string& vc_json);
    std::string ToJSON() const;
    // Attribute storage for selective disclosure
    std::map<std::string, std::string> m_attributes;

private:
    std::vector<unsigned char> vchCredential;  // Raw verifiable credential
    CredentialStatus status{CredentialStatus::NONE};
    CCredentialMetadata metadata;

    // Parse credential to extract metadata
    bool ParseMetadata();
};

// Trusted issuer information
class CTrustedIssuer
{
public:
    std::string issuerId;           // Issuer DID
    std::string issuerName;         // Human-readable name (e.g., "Coinfirm")
    std::vector<unsigned char> publicKey;  // Issuer's public key for verification
    bool isTrusted{false};

    SERIALIZE_METHODS(CTrustedIssuer, obj)
    {
        READWRITE(obj.issuerId);
        READWRITE(obj.issuerName);
        READWRITE(obj.publicKey);
        READWRITE(obj.isTrusted);
    }
};

} // namespace wallet

#endif // BITCOIN_WALLET_CREDENTIAL_H
