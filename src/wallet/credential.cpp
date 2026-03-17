// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/credential.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <logging.h>
#include <random.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/vector.h>

#include <univalue.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace wallet {

// Convert CredentialStatus to string
std::string CredentialStatusToString(CredentialStatus status)
{
    switch (status) {
        case CredentialStatus::NONE: return "unverified";
        case CredentialStatus::PENDING: return "verification pending";
        case CredentialStatus::VERIFIED_BASIC: return "basic KYC verified";
        case CredentialStatus::VERIFIED_FULL: return "full KYC verified";
        case CredentialStatus::EXPIRED: return "expired";
        case CredentialStatus::REVOKED: return "revoked";
        default: return "unknown";
    }
}

// Convert string to CredentialStatus
CredentialStatus StringToCredentialStatus(const std::string& status_str)
{
    if (status_str == "none" || status_str == "unverified") return CredentialStatus::NONE;
    if (status_str == "pending") return CredentialStatus::PENDING;
    if (status_str == "basic") return CredentialStatus::VERIFIED_BASIC;
    if (status_str == "full") return CredentialStatus::VERIFIED_FULL;
    if (status_str == "expired") return CredentialStatus::EXPIRED;
    if (status_str == "revoked") return CredentialStatus::REVOKED;
    return CredentialStatus::NONE;
}

// JWT parsing helper - split into parts
static std::vector<std::string> SplitJWT(const std::string& jwt)
{
    std::vector<std::string> parts;
    std::stringstream ss(jwt);
    std::string part;
    
    while (std::getline(ss, part, '.')) {
        parts.push_back(part);
    }
    
    return parts;
}

// Base64URL decode for JWT
static std::string Base64UrlDecode(const std::string& input)
{
    std::string b64 = input;
    // Replace URL-safe characters
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    // Add padding
    while (b64.size() % 4) {
        b64 += '=';
    }
    const auto decoded = DecodeBase64(b64);
    if (!decoded) return "";
    return std::string(decoded->begin(), decoded->end());
}


static int64_t ParseCredentialTimestamp(const UniValue& value)
{
    if (value.isNum()) {
        return value.getInt<int64_t>();
    }
    if (!value.isStr()) {
        return 0;
    }

    const std::string& ts = value.get_str();

    int64_t epoch_seconds{0};
    if (ParseInt64(ts, &epoch_seconds) && epoch_seconds > 0) {
        return epoch_seconds;
    }

    std::tm tm{};
    std::istringstream is(ts);
    is >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (is.fail()) {
        return 0;
    }

#if defined(_WIN32)
    return static_cast<int64_t>(_mkgmtime(&tm));
#else
    return static_cast<int64_t>(timegm(&tm));
#endif
}

// Parse JWT token
bool CWalletCredential::ParseJWT(const std::string& jwt)
{
    try {
        auto parts = SplitJWT(jwt);
        if (parts.size() < 2) {
            LogPrintf("CWalletCredential::ParseJWT: Invalid JWT format\n");
            return false;
        }
        
        // Decode header (not used for now)
        // std::string header = Base64UrlDecode(parts[0]);
        
        // Decode payload
        std::string payload = Base64UrlDecode(parts[1]);
        
        // Parse JSON payload
        UniValue payload_json(UniValue::VOBJ);
        if (!payload_json.read(payload)) {
            LogPrintf("CWalletCredential::ParseJWT: Failed to parse payload JSON\n");
            return false;
        }
        
        // Extract standard JWT claims
        if (payload_json.exists("iss")) {
            metadata.issuer = payload_json["iss"].get_str();
        }
        
        if (payload_json.exists("exp")) {
            metadata.nExpiresAt = payload_json["exp"].getInt<int64_t>();
        }
        
        if (payload_json.exists("sub")) {
            // subject - could be wallet identifier
            m_attributes["subject"] = payload_json["sub"].get_str();
        }
        
        // Extract custom claims for KYC
        if (payload_json.exists("kyc_level")) {
            metadata.credentialType = payload_json["kyc_level"].get_str();
            
            // Set status based on level
            if (metadata.credentialType == "basic") {
                status = CredentialStatus::VERIFIED_BASIC;
            } else if (metadata.credentialType == "full") {
                status = CredentialStatus::VERIFIED_FULL;
            }
        }
        
        // Extract verification attributes
        if (payload_json.exists("attributes") && payload_json["attributes"].isObject()) {
            UniValue attrs = payload_json["attributes"].get_obj();
            std::vector<std::string> keys = attrs.getKeys();
            for (const auto& key : keys) {
                if (attrs[key].isStr()) {
                    m_attributes[key] = attrs[key].get_str();
                } else if (attrs[key].isNum()) {
                    m_attributes[key] = strprintf("%lld", attrs[key].getInt<int64_t>());
                }
            }
        }
        
        // Extract birth date if present
        if (payload_json.exists("birth_date")) {
            m_attributes["birth_date"] = strprintf("%lld", payload_json["birth_date"].getInt<int64_t>());
        }
        
        if (payload_json.exists("country")) {
            m_attributes["country"] = payload_json["country"].get_str();
        }
        
        LogPrintf("CWalletCredential::ParseJWT: Successfully parsed JWT from issuer %s, expires %lld\n",
                  metadata.issuer, metadata.nExpiresAt);
        return true;
        
    } catch (const std::exception& e) {
        LogPrintf("CWalletCredential::ParseJWT: Exception: %s\n", e.what());
        return false;
    }
}

// Parse Verifiable Credential (JSON-LD format)
bool CWalletCredential::ParseVC(const std::string& vc_json)
{
    try {
        UniValue vc(UniValue::VOBJ);
        if (!vc.read(vc_json)) {
            LogPrintf("CWalletCredential::ParseVC: Failed to parse VC JSON\n");
            return false;
        }
        
        // Check for required fields
        if (!vc.exists("issuer")) {
            LogPrintf("CWalletCredential::ParseVC: Missing issuer\n");
            return false;
        }
        
        if (vc["issuer"].isStr()) {
            metadata.issuer = vc["issuer"].get_str();
        } else if (vc["issuer"].isObject() && vc["issuer"].exists("id")) {
            metadata.issuer = vc["issuer"]["id"].get_str();
        }
        
        // Parse issuance/expiration
        if (vc.exists("issuanceDate") && vc["issuanceDate"].isStr()) {
            m_attributes["issuance_date"] = vc["issuanceDate"].get_str();
        }

        if (vc.exists("expirationDate")) {
            const int64_t expires_at = ParseCredentialTimestamp(vc["expirationDate"]);
            if (expires_at > 0) {
                metadata.nExpiresAt = expires_at;
            } else {
                LogPrintf("CWalletCredential::ParseVC: Invalid expirationDate format\n");
                return false;
            }
        }
        
        // Parse credential subject
        if (vc.exists("credentialSubject") && vc["credentialSubject"].isObject()) {
            UniValue subject = vc["credentialSubject"].get_obj();
            std::vector<std::string> keys = subject.getKeys();
            for (const auto& key : keys) {
                if (subject[key].isStr()) {
                    m_attributes[key] = subject[key].get_str();
                } else if (subject[key].isNum()) {
                    m_attributes[key] = strprintf("%lld", subject[key].getInt<int64_t>());
                }
            }
        }
        
        // Parse type to determine KYC level
        if (vc.exists("type") && vc["type"].isArray()) {
            auto types = vc["type"].get_array();
            for (unsigned int i = 0; i < types.size(); i++) {
                std::string type_str = types[i].get_str();
                if (type_str.find("BasicKYC") != std::string::npos) {
                    metadata.credentialType = "basic";
                    status = CredentialStatus::VERIFIED_BASIC;
                } else if (type_str.find("FullKYC") != std::string::npos) {
                    metadata.credentialType = "full";
                    status = CredentialStatus::VERIFIED_FULL;
                }
            }
        }
        
        // Calculate hash of credential for verification
        metadata.credentialHash = Hash(vchCredential);
        
        LogPrintf("CWalletCredential::ParseVC: Successfully parsed VC from issuer %s\n", metadata.issuer);
        return true;
        
    } catch (const std::exception& e) {
        LogPrintf("CWalletCredential::ParseVC: Exception: %s\n", e.what());
        return false;
    }
}

bool CWalletCredential::SetCredential(const std::vector<unsigned char>& credential)
{
    vchCredential = credential;
    
    // Try to determine format and parse
    std::string cred_str(credential.begin(), credential.end());
    
    // Check if it's a JWT (contains dots)
    if (cred_str.find('.') != std::string::npos && 
        cred_str.find('{') == std::string::npos) {
        return ParseJWT(cred_str);
    }
    
    // Check if it's JSON (VC format)
    if (cred_str.find('{') != std::string::npos) {
        return ParseVC(cred_str);
    }
    
    // Fallback parser for plain credential blobs.
    LogPrintf("CWalletCredential::SetCredential: Unknown format, using simple parsing\n");
    return ParseMetadata();
}

bool CWalletCredential::ParseMetadata()
{
    if (vchCredential.empty()) {
        return false;
    }
    
    // Try to extract metadata from credential data
    std::string cred_str(vchCredential.begin(), vchCredential.end());
    
    // Look for JSON-like structure
    size_t json_start = cred_str.find('{');
    if (json_start != std::string::npos) {
        std::string json_part = cred_str.substr(json_start);
        UniValue json(UniValue::VOBJ);
        if (json.read(json_part)) {
            if (json.exists("issuer")) metadata.issuer = json["issuer"].get_str();
            if (json.exists("expiry")) metadata.nExpiresAt = json["expiry"].getInt<int64_t>();
            if (json.exists("type")) metadata.credentialType = json["type"].get_str();
            if (json.exists("status")) {
                status = StringToCredentialStatus(json["status"].get_str());
            }
        }
    }
    
    // If no expiry set, default to 30 days
    if (metadata.nExpiresAt == 0) {
        metadata.nExpiresAt = GetTime() + 30 * 24 * 60 * 60;
    }
    
    // Calculate hash
    metadata.credentialHash = Hash(vchCredential);
    
    return true;
}

bool CWalletCredential::IsValid() const
{
    if (status == CredentialStatus::EXPIRED || status == CredentialStatus::REVOKED) {
        return false;
    }
    
    // Check expiration
    if (metadata.nExpiresAt > 0) {
        int64_t now = GetTime();
        if (now > metadata.nExpiresAt) {
            return false;
        }
    }
    
    return status == CredentialStatus::VERIFIED_BASIC || 
           status == CredentialStatus::VERIFIED_FULL;
}

bool CWalletCredential::IsVerified() const
{
    return IsValid();
}

bool CWalletCredential::CanPerformSensitiveOperations() const
{
    return IsVerified() && status != CredentialStatus::EXPIRED && status != CredentialStatus::REVOKED;
}

std::string CWalletCredential::GetVerificationFailureReason() const
{
    switch (status) {
        case CredentialStatus::NONE:
            return "Wallet is not KYC verified";
        case CredentialStatus::PENDING:
            return "KYC verification is still pending";
        case CredentialStatus::EXPIRED:
            return "KYC credential has expired";
        case CredentialStatus::REVOKED:
            return "KYC credential has been revoked";
        case CredentialStatus::VERIFIED_BASIC:
        case CredentialStatus::VERIFIED_FULL:
            return ""; // No failure
        default:
            return "Unknown verification status";
    }
}

bool CWalletCredential::HasAttribute(const std::string& attr_name) const
{
    return m_attributes.find(attr_name) != m_attributes.end();
}

std::vector<std::string> CWalletCredential::GetAvailableAttributes() const
{
    std::vector<std::string> attrs;
    for (const auto& pair : m_attributes) {
        attrs.push_back(pair.first);
    }
    return attrs;
}

bool CWalletCredential::CreateAgeProof(int min_age, std::vector<unsigned char>& proof) const
{
    // Find birth date attribute
    auto it = m_attributes.find("birth_date");
    if (it == m_attributes.end()) {
        LogPrintf("CWalletCredential::CreateAgeProof: No birth_date attribute found\n");
        return false;
    }
    
    // Parse birth date (timestamp)
    int64_t birth_date{0};
    if (!ParseInt64(it->second, &birth_date) || birth_date <= 0) {
        LogPrintf("CWalletCredential::CreateAgeProof: Invalid birth_date format\n");
        return false;
    }
    
    // Calculate age from birth date
    int64_t now = GetTime();
    int age = (now - birth_date) / (365 * 24 * 60 * 60);
    
    if (age < min_age) {
        LogPrintf("CWalletCredential::CreateAgeProof: Age %d < required %d\n", age, min_age);
        return false; // Can't prove if not old enough
    }
    
    // Build a non-interactive hash-commitment proof over the birth_date claim.
    
    CSHA256 hasher;
    uint256 hash;
    
    // Include the minimum age in the proof
    std::string claim = strprintf("age>=%d", min_age);
    hasher.Write((unsigned char*)claim.data(), claim.size());
    
    // Include a random nonce to prevent replay
    uint256 nonce = GetRandHash();
    hasher.Write(nonce.begin(), nonce.size());
    
    // Include a commitment to the birth date (without revealing it)
    hasher.Write((unsigned char*)it->second.data(), it->second.size());
    
    hasher.Finalize(hash.begin());
    
    // Store proof with format: [min_age][nonce][hash]
    proof.clear();
    proof.push_back(min_age);
    proof.insert(proof.end(), nonce.begin(), nonce.end());
    proof.insert(proof.end(), hash.begin(), hash.end());
    
    LogPrintf("CWalletCredential::CreateAgeProof: Created proof for age >= %d\n", min_age);
    return true;
}

bool CWalletCredential::CreateCountryProof(const std::string& country_code, std::vector<unsigned char>& proof) const
{
    // Find country attribute
    auto it = m_attributes.find("country");
    if (it == m_attributes.end()) {
        LogPrintf("CWalletCredential::CreateCountryProof: No country attribute found\n");
        return false;
    }
    
    // Check if country matches
    if (it->second != country_code) {
        LogPrintf("CWalletCredential::CreateCountryProof: Country %s != required %s\n", 
                  it->second, country_code);
        return false;
    }
    
    // Build a non-interactive hash-commitment proof over the country claim.
    CSHA256 hasher;
    uint256 hash;
    
    std::string claim = strprintf("country=%s", country_code);
    hasher.Write((unsigned char*)claim.data(), claim.size());
    
    // Add nonce
    uint256 nonce = GetRandHash();
    hasher.Write(nonce.begin(), nonce.size());
    
    // Add commitment to actual country
    hasher.Write((unsigned char*)it->second.data(), it->second.size());
    
    hasher.Finalize(hash.begin());
    
    proof.clear();
    proof.insert(proof.end(), nonce.begin(), nonce.end());
    proof.insert(proof.end(), hash.begin(), hash.end());
    
    return true;
}

bool CWalletCredential::VerifyProof(const std::vector<unsigned char>& proof, const std::string& claim_type) const
{
    if (proof.empty()) {
        return false;
    }
    
    if (claim_type.find("age>=") == 0) {
        // Age proof verification
        if (proof.size() < 65) { // 1 byte age + 32 bytes nonce + 32 bytes hash
            return false;
        }
        
        int min_age = proof[0];
        uint256 nonce;
        uint256 claimed_hash;
        
        memcpy(nonce.begin(), proof.data() + 1, 32);
        memcpy(claimed_hash.begin(), proof.data() + 33, 32);
        
        // Recreate the hash using our birth_date
        auto it = m_attributes.find("birth_date");
        if (it == m_attributes.end()) {
            return false;
        }
        
        CSHA256 hasher;
        std::string claim = strprintf("age>=%d", min_age);
        hasher.Write((unsigned char*)claim.data(), claim.size());
        hasher.Write(nonce.begin(), nonce.size());
        hasher.Write((unsigned char*)it->second.data(), it->second.size());
        
        uint256 calculated_hash;
        hasher.Finalize(calculated_hash.begin());
        
        return calculated_hash == claimed_hash;
    }
    
    else if (claim_type.find("country=") == 0) {
        // Country proof verification
        if (proof.size() < 64) { // 32 bytes nonce + 32 bytes hash
            return false;
        }
        
        std::string country_code = claim_type.substr(8);
        uint256 nonce;
        uint256 claimed_hash;
        
        memcpy(nonce.begin(), proof.data(), 32);
        memcpy(claimed_hash.begin(), proof.data() + 32, 32);
        
        auto it = m_attributes.find("country");
        if (it == m_attributes.end()) {
            return false;
        }
        
        CSHA256 hasher;
        std::string claim = strprintf("country=%s", country_code);
        hasher.Write((unsigned char*)claim.data(), claim.size());
        hasher.Write(nonce.begin(), nonce.size());
        hasher.Write((unsigned char*)it->second.data(), it->second.size());
        
        uint256 calculated_hash;
        hasher.Finalize(calculated_hash.begin());
        
        return calculated_hash == claimed_hash;
    }
    
    return false;
}

std::string CWalletCredential::ToJSON() const
{
    UniValue obj(UniValue::VOBJ);
    
    obj.pushKV("status", CredentialStatusToString(status));
    obj.pushKV("is_verified", IsVerified());
    obj.pushKV("is_valid", IsValid());
    
    if (metadata.nExpiresAt > 0) {
        obj.pushKV("expires_at", metadata.nExpiresAt);
    }
    
    if (!metadata.issuer.empty()) {
        obj.pushKV("issuer", metadata.issuer);
    }
    
    if (!metadata.credentialType.empty()) {
        obj.pushKV("credential_type", metadata.credentialType);
    }
    
    if (!metadata.credentialHash.IsNull()) {
        obj.pushKV("credential_hash", metadata.credentialHash.GetHex());
    }
    
    // Add attributes if any
    if (!m_attributes.empty()) {
        UniValue attrs(UniValue::VOBJ);
        for (const auto& pair : m_attributes) {
            // Don't expose sensitive attributes in JSON by default
            if (pair.first == "country" || pair.first == "subject") {
                attrs.pushKV(pair.first, pair.second);
            }
        }
        if (!attrs.empty()) {
            obj.pushKV("attributes", attrs);
        }
    }
    
    return obj.write();
}

// Serialization methods are already in the header using SERIALIZE_METHODS

} // namespace wallet
