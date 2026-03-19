// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/kyc_provider.h>

#include <logging.h>
#include <random.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <iomanip>
#include <optional>
#include <sstream>

namespace wallet {
namespace {

static std::string UrlEncode(const std::string& value)
{
    std::ostringstream encoded;
    encoded << std::hex << std::uppercase;

    for (const unsigned char ch : value) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
            ch == '.' || ch == '~') {
            encoded << static_cast<char>(ch);
        } else {
            encoded << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(ch);
        }
    }

    return encoded.str();
}

static std::string KYCLevelToProviderString(KYCLevel level)
{
    switch (level) {
        case KYCLevel::BASIC_LEVEL:
            return "basic";
        case KYCLevel::ADVANCED_LEVEL:
            return "advanced";
        case KYCLevel::FULL_LEVEL:
            return "full";
        case KYCLevel::CORPORATE_LEVEL:
            return "corporate";
        case KYCLevel::NONE:
            break;
    }
    return "none";
}

} // namespace

struct CoinfirmProvider::Impl {
    std::string api_key;
    std::string api_secret;
    std::string base_url{"https://verify.coinfirm.com"};
    std::string issuer_id{"coinfirm"};
    std::string issuer_name{"Coinfirm"};
    std::optional<CTrustedIssuer> trusted_issuer;
    std::map<std::string, KYCSession> sessions;

    Impl(const std::string& key, const std::string& secret)
        : api_key(key), api_secret(secret) {}

    std::string BuildVerificationUrl(
        const std::string& session_id,
        KYCLevel level,
        const std::string& wallet_name,
        const std::string& callback_url) const
    {
        std::vector<std::pair<std::string, std::string>> params{
            {"session_id", session_id},
            {"level", KYCLevelToProviderString(level)},
            {"wallet", wallet_name},
        };

        if (!callback_url.empty()) {
            params.emplace_back("callback_url", callback_url);
        }

        if (!api_key.empty()) {
            params.emplace_back("api_key", api_key);
        }

        std::string url = base_url;
        if (url.find('?') == std::string::npos) {
            url += '?';
        } else if (!url.empty() && url.back() != '&' && url.back() != '?') {
            url += '&';
        }

        bool first = true;
        for (const auto& [key, value] : params) {
            if (!first) {
                url += '&';
            }
            first = false;
            url += UrlEncode(key);
            url += '=';
            url += UrlEncode(value);
        }

        return url;
    }

    util::Result<KYCSession> StartSession(
        KYCLevel level,
        const std::string& wallet_name,
        const std::string& callback_url)
    {
        KYCSession session;
        session.session_id = "coinfirm_" + GetRandHash().ToString().substr(0, 16);
        session.provider = KYCProviderType::COINFIRM;
        session.level = level;
        session.url = BuildVerificationUrl(session.session_id, level, wallet_name, callback_url);
        session.created_at = GetTime();
        session.expires_at = session.created_at + 24 * 60 * 60;
        session.status = "pending";

        sessions[session.session_id] = session;
        return session;
    }

    util::Result<KYCSession> CheckSession(const std::string& session_id) const
    {
        const auto it = sessions.find(session_id);
        if (it == sessions.end()) {
            return util::Error{_("Session not found")};
        }

        KYCSession session = it->second;
        if (session.status == "pending" && session.expires_at > 0 && GetTime() > session.expires_at) {
            session.status = "expired";
        }
        return session;
    }
};

struct VerifiableCredentialProvider::Impl {
    std::map<std::string, KYCSession> sessions;
    std::map<std::string, CTrustedIssuer> trusted_issuers;

    util::Result<KYCSession> StartSession(KYCLevel level, const std::string& wallet_name)
    {
        KYCSession session;
        session.session_id = "vc_" + GetRandHash().ToString().substr(0, 16);
        session.provider = KYCProviderType::CUSTOM_VC;
        session.level = level;
        session.url = "vc://credential-request/" + session.session_id + "?wallet=" + UrlEncode(wallet_name) + "&level=" + KYCLevelToProviderString(level);
        session.created_at = GetTime();
        session.expires_at = session.created_at + 24 * 60 * 60;
        session.status = "pending";

        sessions[session.session_id] = session;
        return session;
    }

    util::Result<KYCSession> CheckSession(const std::string& session_id) const
    {
        const auto it = sessions.find(session_id);
        if (it == sessions.end()) {
            return util::Error{_("Session not found")};
        }

        KYCSession session = it->second;
        if (session.status == "pending" && session.expires_at > 0 && GetTime() > session.expires_at) {
            session.status = "expired";
        }
        return session;
    }
};

CoinfirmProvider::CoinfirmProvider(const std::string& api_key, const std::string& api_secret)
    : m_impl(std::make_unique<Impl>(api_key, api_secret)) {}

CoinfirmProvider::~CoinfirmProvider() = default;

util::Result<KYCSession> CoinfirmProvider::StartSession(KYCLevel level,
                                                         const std::string& wallet_name,
                                                         const std::string& callback_url)
{
    LogPrintf("CoinfirmProvider::StartSession - level=%d, wallet=%s\n",
              static_cast<int>(level), wallet_name);

    return m_impl->StartSession(level, wallet_name, callback_url);
}

util::Result<KYCSession> CoinfirmProvider::CheckSession(const std::string& session_id)
{
    LogPrintf("CoinfirmProvider::CheckSession - session=%s\n", session_id);
    return m_impl->CheckSession(session_id);
}

util::Result<std::vector<unsigned char>> CoinfirmProvider::GetCredential(const std::string& session_id)
{
    auto session_res = CheckSession(session_id);
    if (!session_res) {
        return util::Error{util::ErrorString(session_res)};
    }

    const auto& session = *session_res;
    if (session.status != "completed" || session.credential.empty()) {
        return util::Error{_("Credential not available for session")};
    }

    return session.credential;
}

bool CoinfirmProvider::VerifyCredential(const std::vector<unsigned char>& credential,
                                         CCredentialMetadata& metadata)
{
    CWalletCredential parsed_credential;
    if (!parsed_credential.SetCredential(credential)) {
        LogPrintf("CoinfirmProvider::VerifyCredential: credential parsing failed\n");
        return false;
    }

    metadata = parsed_credential.GetMetadata();
    if (metadata.credentialHash.IsNull()) {
        metadata.credentialHash = Hash(credential);
    }

    if (metadata.issuer.empty()) {
        LogPrintf("CoinfirmProvider::VerifyCredential: issuer missing\n");
        return false;
    }

    if (!IsIssuerTrusted(metadata.issuer)) {
        LogPrintf("CoinfirmProvider::VerifyCredential: untrusted issuer %s\n", metadata.issuer);
        return false;
    }

    if (metadata.nExpiresAt > 0 && GetTime() > metadata.nExpiresAt) {
        LogPrintf("CoinfirmProvider::VerifyCredential: credential expired at %lld\n", metadata.nExpiresAt);
        return false;
    }

    return true;
}

bool CoinfirmProvider::IsIssuerTrusted(const std::string& issuer_did)
{
    return issuer_did == m_impl->issuer_id || issuer_did == "coinfirm" || issuer_did.find("did:coinfirm:") == 0;
}

std::vector<KYCLevel> CoinfirmProvider::GetSupportedLevels() const
{
    return {KYCLevel::BASIC_LEVEL, KYCLevel::ADVANCED_LEVEL, KYCLevel::FULL_LEVEL};
}

VerifiableCredentialProvider::VerifiableCredentialProvider()
    : m_impl(std::make_unique<Impl>())
{
    AddTrustedIssuer("did:dash:trusted-issuer", "Dash Trusted Issuer", {});
}

VerifiableCredentialProvider::~VerifiableCredentialProvider() = default;

util::Result<KYCSession> VerifiableCredentialProvider::StartSession(
    KYCLevel level,
    const std::string& wallet_name,
    const std::string& callback_url)
{
    LogPrintf("VerifiableCredentialProvider::StartSession - level=%d, wallet=%s, callback=%s\n",
              static_cast<int>(level), wallet_name, callback_url);
    return m_impl->StartSession(level, wallet_name);
}

util::Result<KYCSession> VerifiableCredentialProvider::CheckSession(const std::string& session_id)
{
    LogPrintf("VerifiableCredentialProvider::CheckSession - session=%s\n", session_id);
    return m_impl->CheckSession(session_id);
}

util::Result<std::vector<unsigned char>> VerifiableCredentialProvider::GetCredential(const std::string& session_id)
{
    auto session_res = CheckSession(session_id);
    if (!session_res) {
        return util::Error{util::ErrorString(session_res)};
    }

    const auto& session = *session_res;
    if (session.status != "completed" || session.credential.empty()) {
        return util::Error{_("Credential not available for session")};
    }

    return session.credential;
}

bool VerifiableCredentialProvider::VerifyCredential(
    const std::vector<unsigned char>& credential,
    CCredentialMetadata& metadata)
{
    CWalletCredential parsed_credential;
    if (!parsed_credential.SetCredential(credential)) {
        return false;
    }

    metadata = parsed_credential.GetMetadata();
    if (metadata.credentialHash.IsNull()) {
        metadata.credentialHash = Hash(credential);
    }

    if (metadata.nExpiresAt > 0 && GetTime() > metadata.nExpiresAt) {
        return false;
    }

    return IsIssuerTrusted(metadata.issuer);
}

bool VerifiableCredentialProvider::IsIssuerTrusted(const std::string& issuer_did)
{
    return m_impl->trusted_issuers.count(issuer_did) > 0;
}

std::vector<KYCLevel> VerifiableCredentialProvider::GetSupportedLevels() const
{
    return {
        KYCLevel::BASIC_LEVEL,
        KYCLevel::ADVANCED_LEVEL,
        KYCLevel::FULL_LEVEL,
        KYCLevel::CORPORATE_LEVEL,
    };
}

void VerifiableCredentialProvider::AddTrustedIssuer(
    const std::string& did,
    const std::string& name,
    const std::vector<unsigned char>& public_key)
{
    CTrustedIssuer issuer;
    issuer.issuerId = did;
    issuer.issuerName = name;
    issuer.publicKey = public_key;
    issuer.isTrusted = true;
    m_impl->trusted_issuers[did] = std::move(issuer);
}

// Factory implementation
std::unique_ptr<KYCProvider> KYCProviderFactory::CreateProvider(
    KYCProviderType type,
    const std::map<std::string, std::string>& config)
{
    switch (type) {
        case KYCProviderType::COINFIRM: {
            auto api_key = config.find("api_key");
            auto api_secret = config.find("api_secret");
            if (api_key == config.end() || api_secret == config.end()) {
                return nullptr;
            }
            return std::make_unique<CoinfirmProvider>(api_key->second, api_secret->second);
        }
        case KYCProviderType::CUSTOM_VC:
            return std::make_unique<VerifiableCredentialProvider>();
        default:
            return nullptr;
    }
}

std::vector<KYCProviderType> KYCProviderFactory::GetAvailableProviders()
{
    return {
        KYCProviderType::COINFIRM,
        KYCProviderType::CUSTOM_VC
    };
}

} // namespace wallet
