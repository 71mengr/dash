// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_KYC_PROVIDER_H
#define BITCOIN_WALLET_KYC_PROVIDER_H

#include <util/translation.h>
#include <wallet/credential.h>
#include <wallet/walletutil.h>

#include <functional>
#include <map>
#include <memory>
#include <string>

namespace wallet {

// KYC verification levels
enum class KYCLevel : uint8_t {
    NONE = 0,
    BASIC_LEVEL = 1,    // Email/phone verification
    ADVANCED_LEVEL = 2, // ID document verification
    FULL_LEVEL = 3,     // Liveness check + address proof
    CORPORATE_LEVEL = 4 // Business verification
};

// KYC session status
struct KYCSession {
    std::string session_id;
    KYCProviderType provider;
    KYCLevel level{KYCLevel::NONE};
    std::string url;                    // URL for user to complete KYC
    int64_t created_at{0};
    int64_t expires_at{0};
    std::string status;                  // "pending", "completed", "failed", "expired"
    std::vector<unsigned char> credential; // Credential after completion
    
    SERIALIZE_METHODS(KYCSession, obj)
    {
        READWRITE(obj.session_id);
        READWRITE(obj.provider);
        READWRITE(obj.level);
        READWRITE(obj.url);
        READWRITE(obj.created_at);
        READWRITE(obj.expires_at);
        READWRITE(obj.status);
        READWRITE(obj.credential);
    }
};

// KYC provider interface
class KYCProvider
{
public:
    virtual ~KYCProvider() = default;
    
    // Provider info
    virtual KYCProviderType GetType() const = 0;
    virtual std::string GetName() const = 0;
    
    // Start a new KYC session
    virtual util::Result<KYCSession> StartSession(KYCLevel level, 
                                                   const std::string& wallet_name,
                                                   const std::string& callback_url) = 0;
    
    // Check session status
    virtual util::Result<KYCSession> CheckSession(const std::string& session_id) = 0;
    
    // Retrieve credential after successful KYC
    virtual util::Result<std::vector<unsigned char>> GetCredential(const std::string& session_id) = 0;
    
    // Verify credential (validate signature, expiration, etc.)
    virtual bool VerifyCredential(const std::vector<unsigned char>& credential, 
                                   CCredentialMetadata& metadata) = 0;
    
    // Check if issuer is trusted
    virtual bool IsIssuerTrusted(const std::string& issuer_did) = 0;
    
    // Get supported levels
    virtual std::vector<KYCLevel> GetSupportedLevels() const = 0;
};

// Coinfirm implementation (Dash's existing partner)
class CoinfirmProvider : public KYCProvider
{
public:
    CoinfirmProvider(const std::string& api_key, const std::string& api_secret);
    ~CoinfirmProvider() override;
    
    KYCProviderType GetType() const override { return KYCProviderType::COINFIRM; }
    std::string GetName() const override { return "Coinfirm"; }
    
    util::Result<KYCSession> StartSession(KYCLevel level, 
                                           const std::string& wallet_name,
                                           const std::string& callback_url) override;
    
    util::Result<KYCSession> CheckSession(const std::string& session_id) override;
    
    util::Result<std::vector<unsigned char>> GetCredential(const std::string& session_id) override;
    
    bool VerifyCredential(const std::vector<unsigned char>& credential, 
                           CCredentialMetadata& metadata) override;
    
    bool IsIssuerTrusted(const std::string& issuer_did) override;
    
    std::vector<KYCLevel> GetSupportedLevels() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// Verifiable Credentials provider (DID-based)
class VerifiableCredentialProvider : public KYCProvider
{
public:
    VerifiableCredentialProvider();
    ~VerifiableCredentialProvider() override;
    
    KYCProviderType GetType() const override { return KYCProviderType::CUSTOM_VC; }
    std::string GetName() const override { return "Verifiable Credentials"; }
    
    util::Result<KYCSession> StartSession(KYCLevel level, 
                                           const std::string& wallet_name,
                                           const std::string& callback_url) override;
    
    util::Result<KYCSession> CheckSession(const std::string& session_id) override;
    
    util::Result<std::vector<unsigned char>> GetCredential(const std::string& session_id) override;
    
    bool VerifyCredential(const std::vector<unsigned char>& credential, 
                           CCredentialMetadata& metadata) override;
    
    bool IsIssuerTrusted(const std::string& issuer_did) override;
    
    std::vector<KYCLevel> GetSupportedLevels() const override;
    
    // Add trusted issuer
    void AddTrustedIssuer(const std::string& did, const std::string& name, 
                          const std::vector<unsigned char>& public_key);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// Factory for creating KYC providers
class KYCProviderFactory
{
public:
    static std::unique_ptr<KYCProvider> CreateProvider(KYCProviderType type, 
                                                       const std::map<std::string, std::string>& config);
    
    static std::vector<KYCProviderType> GetAvailableProviders();
};

} // namespace wallet

#endif // BITCOIN_WALLET_KYC_PROVIDER_H
