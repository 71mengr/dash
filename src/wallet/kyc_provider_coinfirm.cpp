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

#include <univalue.h>

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


static std::string DiditDecisionToSessionStatus(const std::string& decision)
{
    if (decision == "approved" || decision == "completed") return "completed";
    if (decision == "declined" || decision == "rejected") return "failed";
    if (decision == "expired") return "expired";
    return "pending";
}

static std::string MapKYCLevelToDiditFlow(KYCLevel level)
{
    switch (level) {
        case KYCLevel::BASIC_LEVEL:
            return "basic-kyc";
        case KYCLevel::ADVANCED_LEVEL:
            return "document-check";
        case KYCLevel::FULL_LEVEL:
            return "document-liveness";
        case KYCLevel::CORPORATE_LEVEL:
            return "business-verification";
        case KYCLevel::NONE:
            break;
    }
    return "unknown";
}


static std::string HashAttributeHex(const std::string& value)
{
    if (value.empty()) {
        return {};
    }
    const auto hash = Hash(value);
    return hash.GetHex();
}

static util::Result<UniValue> ParseCredentialObject(const std::vector<unsigned char>& credential)
{
    UniValue json(UniValue::VOBJ);
    const std::string credential_str(credential.begin(), credential.end());
    if (!json.read(credential_str)) {
        return util::Error{_("Credential must be valid JSON")};
    }
    return json;
}

static bool ExtractCredentialSubjectField(const UniValue& subject,
                                          const std::string& key,
                                          std::string& value_out)
{
    if (!subject.exists(key) || !subject[key].isStr()) {
        return false;
    }
    value_out = subject[key].get_str();
    return !value_out.empty();
}

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


struct DiditProvider::Impl {
    std::string api_key;
    std::string workflow_id;
    std::string webhook_secret;
    std::string base_url{"https://verification.didit.me"};
    std::map<std::string, KYCSession> sessions;

    Impl(const std::string& key,
         const std::string& workflow,
         const std::string& webhook,
         const std::string& url)
        : api_key(key), workflow_id(workflow), webhook_secret(webhook)
    {
        if (!url.empty()) {
            base_url = url;
        }
    }

    std::string BuildVerificationUrl(const KYCSession& session,
                                     const std::string& wallet_name,
                                     const std::string& callback_url) const
    {
        std::vector<std::pair<std::string, std::string>> params{
            {"session_id", session.session_id},
            {"workflow_id", workflow_id},
            {"vendor_data", wallet_name},
            {"kyc_level", KYCLevelToProviderString(session.level)},
            {"flow", MapKYCLevelToDiditFlow(session.level)},
        };

        if (!callback_url.empty()) {
            params.emplace_back("callback", callback_url);
        }

        std::string url = base_url + "/v3/session/";
        url += '?';

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
        session.session_id = "didit_" + GetRandHash().ToString().substr(0, 16);
        session.provider = KYCProviderType::DIDIT;
        session.level = level;
        session.created_at = GetTime();
        session.expires_at = session.created_at + 24 * 60 * 60;
        session.status = "pending";
        session.url = BuildVerificationUrl(session, wallet_name, callback_url);

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
        session.status = DiditDecisionToSessionStatus(session.status);
        if (session.status == "pending" && session.expires_at > 0 && GetTime() > session.expires_at) {
            session.status = "expired";
        }
        if (session.status == "completed" && session.credential.empty()) {
            const std::string credential_json = strprintf(
                "{\"issuer\":\"didit\",\"session_id\":\"%s\",\"decision\":\"approved\"}",
                session.session_id.c_str());
            session.credential.assign(credential_json.begin(), credential_json.end());
        }
        return session;
    }
};

struct LocalVerificationProvider::Impl {
    std::string issuer_id{"local-verification"};
    std::string issuer_name{"Local Verification"};
    std::string base_url{"local-verification://start"};
    std::map<std::string, KYCSession> sessions;

    std::string BuildVerificationUrl(const KYCSession& session,
                                     const std::string& wallet_name,
                                     const std::string& callback_url) const
    {
        std::vector<std::pair<std::string, std::string>> params{
            {"session_id", session.session_id},
            {"wallet", wallet_name},
            {"level", KYCLevelToProviderString(session.level)},
            {"required_fields", "full_name,email,country,age,owner_name"},
            {"auto_hash_fields", "full_name,email"},
            {"auto_verify_fields", "owner_name"},
        };

        if (!callback_url.empty()) {
            params.emplace_back("callback_url", callback_url);
        }

        std::string url = base_url + "?";
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

    util::Result<KYCSession> StartSession(KYCLevel level,
                                          const std::string& wallet_name,
                                          const std::string& callback_url)
    {
        KYCSession session;
        session.session_id = "local_" + GetRandHash().ToString().substr(0, 16);
        session.provider = KYCProviderType::INTERNAL;
        session.level = level;
        session.created_at = GetTime();
        session.expires_at = session.created_at + 24 * 60 * 60;
        session.status = "pending";
        session.url = BuildVerificationUrl(session, wallet_name, callback_url);

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


DiditProvider::DiditProvider(const std::string& api_key,
                             const std::string& workflow_id,
                             const std::string& webhook_secret,
                             const std::string& base_url)
    : m_impl(std::make_unique<Impl>(api_key, workflow_id, webhook_secret, base_url)) {}

DiditProvider::~DiditProvider() = default;

util::Result<KYCSession> DiditProvider::StartSession(KYCLevel level,
                                                     const std::string& wallet_name,
                                                     const std::string& callback_url)
{
    LogPrintf("DiditProvider::StartSession - level=%d, wallet=%s, callback=%s\n",
              static_cast<int>(level), wallet_name, callback_url);
    return m_impl->StartSession(level, wallet_name, callback_url);
}

util::Result<KYCSession> DiditProvider::CheckSession(const std::string& session_id)
{
    LogPrintf("DiditProvider::CheckSession - session=%s\n", session_id);
    return m_impl->CheckSession(session_id);
}

util::Result<std::vector<unsigned char>> DiditProvider::GetCredential(const std::string& session_id)
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

bool DiditProvider::VerifyCredential(const std::vector<unsigned char>& credential,
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

bool DiditProvider::IsIssuerTrusted(const std::string& issuer_did)
{
    return issuer_did == "didit" || issuer_did.find("did:didit:") == 0;
}

std::vector<KYCLevel> DiditProvider::GetSupportedLevels() const
{
    return {
        KYCLevel::BASIC_LEVEL,
        KYCLevel::ADVANCED_LEVEL,
        KYCLevel::FULL_LEVEL,
        KYCLevel::CORPORATE_LEVEL,
    };
}

LocalVerificationProvider::LocalVerificationProvider()
    : m_impl(std::make_unique<Impl>()) {}

LocalVerificationProvider::~LocalVerificationProvider() = default;

util::Result<KYCSession> LocalVerificationProvider::StartSession(KYCLevel level,
                                                                 const std::string& wallet_name,
                                                                 const std::string& callback_url)
{
    LogPrintf("LocalVerificationProvider::StartSession - level=%d, wallet=%s, callback=%s\n",
              static_cast<int>(level), wallet_name, callback_url);
    return m_impl->StartSession(level, wallet_name, callback_url);
}

util::Result<KYCSession> LocalVerificationProvider::CheckSession(const std::string& session_id)
{
    LogPrintf("LocalVerificationProvider::CheckSession - session=%s\n", session_id);
    return m_impl->CheckSession(session_id);
}

util::Result<std::vector<unsigned char>> LocalVerificationProvider::GetCredential(const std::string& session_id)
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

bool LocalVerificationProvider::VerifyCredential(const std::vector<unsigned char>& credential,
                                                 CCredentialMetadata& metadata)
{
    auto credential_json_res = ParseCredentialObject(credential);
    if (!credential_json_res) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: invalid JSON credential\n");
        return false;
    }

    const UniValue& credential_json = *credential_json_res;
    if (!credential_json.exists("issuer") || !credential_json["issuer"].isStr()) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: missing issuer\n");
        return false;
    }

    const std::string issuer = credential_json["issuer"].get_str();
    if (!IsIssuerTrusted(issuer)) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: untrusted issuer %s\n", issuer);
        return false;
    }

    if (!credential_json.exists("credentialSubject") || !credential_json["credentialSubject"].isObject()) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: missing credentialSubject\n");
        return false;
    }

    const UniValue subject = credential_json["credentialSubject"].get_obj();
    std::string full_name;
    std::string email;
    std::string country;
    std::string owner_name;
    if (!ExtractCredentialSubjectField(subject, "full_name", full_name) ||
        !ExtractCredentialSubjectField(subject, "email", email) ||
        !ExtractCredentialSubjectField(subject, "country", country) ||
        !ExtractCredentialSubjectField(subject, "owner_name", owner_name)) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: missing required subject fields\n");
        return false;
    }

    if (!subject.exists("age") || !subject["age"].isNum()) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: missing numeric age\n");
        return false;
    }

    const int age = subject["age"].getInt<int>();
    if (age < 18) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: age %d below minimum\n", age);
        return false;
    }

    const std::string expected_name_hash = HashAttributeHex(full_name);
    const std::string expected_email_hash = HashAttributeHex(email);
    if (subject.exists("full_name_hash") && subject["full_name_hash"].isStr() &&
        subject["full_name_hash"].get_str() != expected_name_hash) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: full_name_hash mismatch\n");
        return false;
    }
    if (subject.exists("email_hash") && subject["email_hash"].isStr() &&
        subject["email_hash"].get_str() != expected_email_hash) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: email_hash mismatch\n");
        return false;
    }

    bool owner_name_verified = false;
    if (subject.exists("owner_name_verified")) {
        if (subject["owner_name_verified"].isBool()) {
            owner_name_verified = subject["owner_name_verified"].get_bool();
        } else if (subject["owner_name_verified"].isStr()) {
            owner_name_verified = subject["owner_name_verified"].get_str() == "true";
        }
    }
    if (!owner_name_verified) {
        owner_name_verified = owner_name == full_name;
    }
    if (!owner_name_verified) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: owner name could not be verified\n");
        return false;
    }

    CWalletCredential parsed_credential;
    if (!parsed_credential.SetCredential(credential)) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: credential parsing failed\n");
        return false;
    }

    metadata = parsed_credential.GetMetadata();
    metadata.issuer = issuer;
    metadata.credentialType = "local_verification";
    metadata.credentialHash = Hash(credential);
    if (metadata.nExpiresAt > 0 && GetTime() > metadata.nExpiresAt) {
        LogPrintf("LocalVerificationProvider::VerifyCredential: credential expired at %lld\n", metadata.nExpiresAt);
        return false;
    }

    return true;
}

bool LocalVerificationProvider::IsIssuerTrusted(const std::string& issuer_did)
{
    return issuer_did == m_impl->issuer_id || issuer_did == "local" || issuer_did == "internal";
}

std::vector<KYCLevel> LocalVerificationProvider::GetSupportedLevels() const
{
    return {
        KYCLevel::BASIC_LEVEL,
        KYCLevel::ADVANCED_LEVEL,
        KYCLevel::FULL_LEVEL,
    };
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
        case KYCProviderType::INTERNAL:
            return std::make_unique<LocalVerificationProvider>();
        case KYCProviderType::DIDIT: {
            auto api_key = config.find("api_key");
            auto workflow_id = config.find("workflow_id");
            if (api_key == config.end() || workflow_id == config.end()) {
                return nullptr;
            }
            const auto webhook_secret = config.find("webhook_secret");
            const auto base_url = config.find("base_url");
            return std::make_unique<DiditProvider>(
                api_key->second,
                workflow_id->second,
                webhook_secret == config.end() ? std::string{} : webhook_secret->second,
                base_url == config.end() ? std::string{} : base_url->second);
        }
        default:
            return nullptr;
    }
}

std::vector<KYCProviderType> KYCProviderFactory::GetAvailableProviders()
{
    return {
        KYCProviderType::INTERNAL,
        KYCProviderType::COINFIRM,
        KYCProviderType::CUSTOM_VC,
        KYCProviderType::DIDIT,
    };
}

} // namespace wallet
