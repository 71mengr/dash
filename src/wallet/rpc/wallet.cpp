// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <core_io.h>
#include <httpserver.h>
#include <policy/policy.h>
#include <rpc/blockchain.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <util/bip32.h>
#include <util/fees.h>
#include <util/message.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <util/url.h>
#include <util/vector.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/rpc/wallet.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <key_io.h>

#include <coinjoin/client.h>
#include <coinjoin/options.h>

#include <algorithm>
#include <cctype>
#include <optional>
#include <set>

#include <univalue.h>

namespace wallet {
/** Checks if a CKey is in the given CWallet compressed or otherwise*/
bool HaveKey(const SigningProvider& wallet, const CKey& key)
{
    CKey key2;
    key2.Set(key.begin(), key.end(), !key.IsCompressed());
    return wallet.HaveKey(key.GetPubKey().GetID()) || wallet.HaveKey(key2.GetPubKey().GetID());
}

static bool IsCredentialTestingChain()
{
    return Params().IsMockableChain();
}

static void EnsureCredentialTestingChain(const std::string& rpc_name)
{
    if (!IsCredentialTestingChain()) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf(
            "%s is only available on mockable test chains. Use importcredential with a real credential in production.",
            rpc_name));
    }
}

static bool IsTrustedCredentialIssuer(const std::string& issuer)
{
    return issuer == "coinfirm" || issuer == "did:dash:trusted-issuer" || issuer.rfind("did:coinfirm:", 0) == 0;
}

static const std::set<std::string>& ValidLocalVerificationCountries()
{
    static const std::set<std::string> countries{
        "AFGHANISTAN", "ALBANIA", "ALGERIA", "ANDORRA", "ANGOLA",
        "ANTIGUA AND BARBUDA", "ARGENTINA", "ARMENIA", "AUSTRALIA", "AUSTRIA",
        "AZERBAIJAN", "BAHAMAS", "BAHRAIN", "BANGLADESH", "BARBADOS",
        "BELARUS", "BELGIUM", "BELIZE", "BENIN", "BHUTAN",
        "BOLIVIA", "BOSNIA AND HERZEGOVINA", "BOTSWANA", "BRAZIL", "BRUNEI",
        "BULGARIA", "BURKINA FASO", "BURUNDI", "CABO VERDE", "CAMBODIA",
        "CAMEROON", "CANADA", "CENTRAL AFRICAN REPUBLIC", "CHAD", "CHILE",
        "CHINA", "COLOMBIA", "COMOROS", "CONGO", "COSTA RICA",
        "COTE DIVOIRE", "CROATIA", "CUBA", "CYPRUS", "CZECHIA",
        "DEMOCRATIC REPUBLIC OF THE CONGO", "DENMARK", "DJIBOUTI", "DOMINICA", "DOMINICAN REPUBLIC",
        "ECUADOR", "EGYPT", "EL SALVADOR", "EQUATORIAL GUINEA", "ERITREA",
        "ESTONIA", "ESWATINI", "ETHIOPIA", "FIJI", "FINLAND",
        "FRANCE", "GABON", "GAMBIA", "GEORGIA", "GERMANY",
        "GHANA", "GREECE", "GRENADA", "GUATEMALA", "GUINEA",
        "GUINEA-BISSAU", "GUYANA", "HAITI", "HONDURAS", "HUNGARY",
        "ICELAND", "INDIA", "INDONESIA", "IRAN", "IRAQ",
        "IRELAND", "ISRAEL", "ITALY", "JAMAICA", "JAPAN",
        "JORDAN", "KAZAKHSTAN", "KENYA", "KIRIBATI", "KUWAIT",
        "KYRGYZSTAN", "LAOS", "LATVIA", "LEBANON", "LESOTHO",
        "LIBERIA", "LIBYA", "LIECHTENSTEIN", "LITHUANIA", "LUXEMBOURG",
        "MADAGASCAR", "MALAWI", "MALAYSIA", "MALDIVES", "MALI",
        "MALTA", "MARSHALL ISLANDS", "MAURITANIA", "MAURITIUS", "MEXICO",
        "MICRONESIA", "MOLDOVA", "MONACO", "MONGOLIA", "MONTENEGRO",
        "MOROCCO", "MOZAMBIQUE", "MYANMAR", "NAMIBIA", "NAURU",
        "NEPAL", "NETHERLANDS", "NEW ZEALAND", "NICARAGUA", "NIGER",
        "NIGERIA", "NORTH KOREA", "NORTH MACEDONIA", "NORWAY", "OMAN",
        "PAKISTAN", "PALAU", "PALESTINE", "PANAMA", "PAPUA NEW GUINEA",
        "PARAGUAY", "PERU", "PHILIPPINES", "POLAND", "PORTUGAL",
        "QATAR", "ROMANIA", "RUSSIA", "RWANDA", "SAINT KITTS AND NEVIS",
        "SAINT LUCIA", "SAINT VINCENT AND THE GRENADINES", "SAMOA", "SAN MARINO", "SAO TOME AND PRINCIPE",
        "SAUDI ARABIA", "SENEGAL", "SERBIA", "SEYCHELLES", "SIERRA LEONE",
        "SINGAPORE", "SLOVAKIA", "SLOVENIA", "SOLOMON ISLANDS", "SOMALIA",
        "SOUTH AFRICA", "SOUTH KOREA", "SOUTH SUDAN", "SPAIN", "SRI LANKA",
        "SUDAN", "SURINAME", "SWEDEN", "SWITZERLAND", "SYRIA",
        "TAIWAN", "TAJIKISTAN", "TANZANIA", "THAILAND", "TIMOR-LESTE",
        "TOGO", "TONGA", "TRINIDAD AND TOBAGO", "TUNISIA", "TURKEY",
        "TURKMENISTAN", "TUVALU", "UGANDA", "UKRAINE", "UNITED ARAB EMIRATES",
        "UNITED KINGDOM", "UNITED STATES", "URUGUAY", "UZBEKISTAN", "VANUATU",
        "VATICAN CITY", "VENEZUELA", "VIETNAM", "YEMEN", "ZAMBIA", "ZIMBABWE",
    };
    return countries;
}

static std::string NormalizeLocalVerificationValue(std::string value)
{
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

static std::string NormalizeLocalVerificationCountry(std::string country)
{
    country = NormalizeLocalVerificationValue(std::move(country));
    std::transform(country.begin(), country.end(), country.begin(), [](unsigned char ch) {
        return ch == '_' ? ' ' : static_cast<char>(std::toupper(ch));
    });
    return country;
}

static RPCHelpMan listaddressbalances()
{
    return RPCHelpMan{"listaddressbalances",
        "\nLists addresses of this wallet and their balances\n",
        {
            {"minamount", RPCArg::Type::NUM, RPCArg::Default{0}, "Minimum balance in " + CURRENCY_UNIT + " an address should have to be shown in the list"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "amount", "The Dash address and the amount in " + CURRENCY_UNIT},
            }
        },
        RPCExamples{
            HelpExampleCli("listaddressbalances", "")
    + HelpExampleCli("listaddressbalances", "10")
    + HelpExampleRpc("listaddressbalances", "")
    + HelpExampleRpc("listaddressbalances", "10")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    CAmount nMinAmount = 0;
    if (!request.params[0].isNull())
        nMinAmount = AmountFromValue(request.params[0]);

    if (nMinAmount < 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");

    UniValue jsonBalances(UniValue::VOBJ);
    std::map<CTxDestination, CAmount> balances = GetAddressBalances(*pwallet);
    for (auto& balance : balances)
        if (balance.second >= nMinAmount)
            jsonBalances.pushKV(EncodeDestination(balance.first), ValueFromAmount(balance.second));

    return jsonBalances;
},
    };
}


static RPCHelpMan setkycprovider()
{
    return RPCHelpMan{"setkycprovider",
        "\nConfigure the KYC provider for this wallet.\n",
        {
            {"provider", RPCArg::Type::STR, RPCArg::Optional::NO, "Provider name (local-verification, coinfirm, vc, didit)"},
            {"api_key", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "API key for provider"},
            {"provider_arg", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Provider-specific second argument: Coinfirm API secret or Didit workflow ID"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "provider", "Configured provider"},
                {RPCResult::Type::BOOL, "success", "Whether configuration succeeded"},
            }
        },
        RPCExamples{
            HelpExampleCli("setkycprovider", "didit my_api_key my_workflow_id")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    std::string provider_str = request.params[0].get_str();
    std::string error;
    KYCProviderType type = ParseKYCProvider(provider_str, error);
    if (type == KYCProviderType::NONE && provider_str != "none") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error.empty() ? "Unknown provider" : error);
    }

    std::map<std::string, std::string> config;
    if (!request.params[1].isNull()) {
        config["api_key"] = request.params[1].get_str();
    }
    if (!request.params[2].isNull()) {
        if (type == KYCProviderType::COINFIRM) {
            config["api_secret"] = request.params[2].get_str();
        } else if (type == KYCProviderType::DIDIT) {
            config["workflow_id"] = request.params[2].get_str();
        }
    }
    
    bool success = pwallet->SetKYCProvider(type, config);
    
    UniValue result(UniValue::VOBJ);
    result.pushKV("provider", provider_str);
    result.pushKV("success", success);
    
    return result;
},
    };
}

static RPCHelpMan startkyc()
{
    return RPCHelpMan{"startkyc",
        "\nStart KYC verification process.\n",
        {
            {"level", RPCArg::Type::STR, RPCArg::Optional::NO, "Verification level (basic, advanced, full)"},
            {"callback_url", RPCArg::Type::STR, RPCArg::Default{""}, "URL for KYC provider to call back"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "session_id", "KYC session ID"},
                {RPCResult::Type::STR, "verification_url", "URL to complete KYC"},
                {RPCResult::Type::STR, "status", "Session status"},
                {RPCResult::Type::NUM, "expires_at", "Expiration timestamp"},
            }
        },
        RPCExamples{
            HelpExampleCli("startkyc", "basic")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    std::string level_str = request.params[0].get_str();
    KYCLevel level;
    
    if (level_str == "basic") {
        level = KYCLevel::BASIC_LEVEL;
    } else if (level_str == "advanced") {
        level = KYCLevel::ADVANCED_LEVEL;
    } else if (level_str == "full") {
        level = KYCLevel::FULL_LEVEL;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid level. Use 'basic', 'advanced', or 'full'");
    }
    
    std::string callback_url = request.params[1].isNull() ? "" : request.params[1].get_str();
    
    auto session_res = pwallet->StartKYCVerification(level, callback_url);
    if (!session_res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(session_res).original);
    }
    
    const auto& session = *session_res;
    
    UniValue result(UniValue::VOBJ);
    result.pushKV("session_id", session.session_id);
    result.pushKV("verification_url", session.url);
    result.pushKV("status", session.status);
    result.pushKV("expires_at", session.expires_at);
    
    return result;
},
    };
}

static RPCHelpMan checkkyc()
{
    return RPCHelpMan{"checkkyc",
        "\nCheck status of KYC verification.\n",
        {
            {"session_id", RPCArg::Type::STR, RPCArg::Optional::NO, "KYC session ID"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "session_id", "KYC session ID"},
                {RPCResult::Type::STR, "status", "Session status"},
                {RPCResult::Type::BOOL, "completed", "Whether verification is complete"},
                {RPCResult::Type::BOOL, "wallet_verified", "Whether wallet is now verified"},
            }
        },
        RPCExamples{
            HelpExampleCli("checkkyc", "coinfirm_abc123")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    std::string session_id = request.params[0].get_str();
    
    auto session_res = pwallet->CheckKYCStatus(session_id);
    if (!session_res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(session_res).original);
    }
    
    const auto& session = *session_res;
    
    UniValue result(UniValue::VOBJ);
    result.pushKV("session_id", session.session_id);
    result.pushKV("status", session.status);
    result.pushKV("completed", session.status == "completed");
    result.pushKV("wallet_verified", pwallet->IsVerified());
    
    return result;
},
    };
}

static RPCHelpMan completekyc()
{
    return RPCHelpMan{"completekyc",
        "\nComplete KYC verification and import credential.\n",
        {
            {"session_id", RPCArg::Type::STR, RPCArg::Optional::NO, "KYC session ID"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether verification was completed"},
                {RPCResult::Type::BOOL, "wallet_verified", "Whether wallet is now verified"},
            }
        },
        RPCExamples{
            HelpExampleCli("completekyc", "coinfirm_abc123")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    std::string session_id = request.params[0].get_str();
    
    bool success = pwallet->CompleteKYCVerification(session_id);
    
    UniValue result(UniValue::VOBJ);
    result.pushKV("success", success);
    result.pushKV("wallet_verified", pwallet->IsVerified());
    
    return result;
},
    };
}

static RPCHelpMan importkyccredential()
{
    return RPCHelpMan{"importkyccredential",
        "\nImport a provider-issued verifiable credential into the wallet and mark the session complete.\n",
        {
            {"credential", RPCArg::Type::STR, RPCArg::Optional::NO, "Raw JWT or VC JSON credential issued by the configured KYC provider"},
            {"session_id", RPCArg::Type::STR, RPCArg::Default{""}, "Optional KYC session ID to attach the credential to"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether the credential was accepted"},
                {RPCResult::Type::BOOL, "wallet_verified", "Whether the wallet is now verified"},
            }
        },
        RPCExamples{
            HelpExampleCli("importkyccredential", "\"<jwt-or-vc-json>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    const std::string credential_str = request.params[0].get_str();
    const std::string session_id = request.params[1].isNull() ? "" : request.params[1].get_str();

    std::vector<unsigned char> credential_data(credential_str.begin(), credential_str.end());
    const bool success = pwallet->ImportKYCCredential(session_id, credential_data);

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", success);
    result.pushKV("wallet_verified", pwallet->IsVerified());
    return result;
},
    };
}

static RPCHelpMan localverify()
{
    return RPCHelpMan{"local-verify",
        "\nRun local verification for the wallet using the provided identity fields.\n"
        "\nThis is the built-in production verification flow. After the checks pass, the wallet is marked verified and a primary wallet address is created.\n",
        {
            {"full_name", RPCArg::Type::STR, RPCArg::Optional::NO, "Full legal name. Must contain at least two words and only letters, spaces, apostrophes, periods, or hyphens."},
            {"age", RPCArg::Type::NUM, RPCArg::Optional::NO, "Age in years. Must be between 18 and 120."},
            {"country", RPCArg::Type::STR, RPCArg::Optional::NO, "Country name. Must match a supported real country name."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether local verification succeeded"},
                {RPCResult::Type::BOOL, "wallet_verified", "Whether the wallet is now verified"},
                {RPCResult::Type::STR, "full_name", "Normalized full name"},
                {RPCResult::Type::NUM, "age", "Validated age"},
                {RPCResult::Type::STR, "country", "Normalized country"},
                {RPCResult::Type::STR, "wallet_name", "Wallet name that was verified"},
                {RPCResult::Type::STR, "wallet_address", "Primary wallet address generated after successful verification"},
                {RPCResult::Type::ARR, "allowed_countries", "Supported countries for the country check",
                    {
                        {RPCResult::Type::STR, "", "Country name"},
                    }},
            }
        },
        RPCExamples{
            HelpExampleCli("local-verify", "\"Ada Lovelace\" 36 \"United Kingdom\"")
            + HelpExampleRpc("local-verify", "\"Ada Lovelace\", 36, \"United Kingdom\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    const std::string full_name = NormalizeLocalVerificationValue(request.params[0].get_str());
    if (full_name.size() < 5) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Full name must be at least 5 characters long");
    }
    if (full_name.find(' ') == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Full name must include at least first name and last name");
    }
    for (const char ch : full_name) {
        if (!(std::isalpha(static_cast<unsigned char>(ch)) || ch == ' ' || ch == '\'' || ch == '-' || ch == '.')) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Full name contains unsupported characters");
        }
    }

    const int age = request.params[1].getInt<int>();
    if (age < 18 || age > 120) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Age must be between 18 and 120");
    }

    const std::string country = NormalizeLocalVerificationCountry(request.params[2].get_str());
    const auto& valid_countries = ValidLocalVerificationCountries();
    if (!valid_countries.count(country)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Country must be a supported real country name");
    }

    const auto destination = pwallet->GetNewDestination("");
    if (!destination) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(destination).original);
    }
    const std::string wallet_address = EncodeDestination(*destination);
    const std::string full_name_hash = Hash(full_name).GetHex();
    const std::string wallet_name = pwallet->GetName();
    const std::string wallet_name_hash = Hash(wallet_name).GetHex();
    const std::string credential_str = strprintf(
        "{\"issuer\":\"local-verification\",\"type\":[\"VerifiableCredential\",\"FullKYC\"],"
        "\"credentialSubject\":{\"full_name\":\"%s\",\"full_name_hash\":\"%s\",\"email\":\"%s\",\"email_hash\":\"%s\","
        "\"country\":\"%s\",\"age\":%d,\"owner_name\":\"%s\",\"owner_name_verified\":true,\"wallet\":\"%s\",\"wallet_address\":\"%s\"}}",
        full_name,
        full_name_hash,
        wallet_name,
        wallet_name_hash,
        country,
        age,
        full_name,
        wallet_name,
        wallet_address);

    std::vector<unsigned char> credential_data(credential_str.begin(), credential_str.end());
    LocalVerificationProvider provider;
    CCredentialMetadata metadata;
    if (!provider.VerifyCredential(credential_data, metadata)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Local verification failed");
    }

    CWalletCredential cred;
    if (!cred.SetCredential(credential_data)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create local verification credential");
    }
    cred.SetMetadata(metadata);

    {
        LOCK(pwallet->cs_wallet);
        WalletBatch batch(pwallet->GetDatabase());
        if (!batch.WriteCredential(cred)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to write credential to database");
        }
        if (!batch.WriteCredentialMetadata(metadata) || !batch.WriteCredentialStatus(cred.GetStatus())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist credential metadata");
        }
        pwallet->SetCredential(cred);
    }

    UniValue allowed_countries(UniValue::VARR);
    for (const auto& valid_country : valid_countries) {
        allowed_countries.push_back(valid_country);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", true);
    result.pushKV("wallet_verified", pwallet->IsVerified());
    result.pushKV("full_name", full_name);
    result.pushKV("age", age);
    result.pushKV("country", country);
    result.pushKV("wallet_name", pwallet->GetName());
    result.pushKV("wallet_address", wallet_address);
    result.pushKV("allowed_countries", std::move(allowed_countries));
    return result;
},
    };
}

static RPCHelpMan setcoinjoinrounds()
{
    return RPCHelpMan{"setcoinjoinrounds",
        "\nSet the number of rounds for CoinJoin.\n",
        {
            {"rounds", RPCArg::Type::NUM, RPCArg::Optional::NO,
                "The default number of rounds is " + ToString(DEFAULT_COINJOIN_ROUNDS) +
                " Cannot be more than " + ToString(MAX_COINJOIN_ROUNDS) + " nor less than " + ToString(MIN_COINJOIN_ROUNDS)},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("setcoinjoinrounds", "4")
    + HelpExampleRpc("setcoinjoinrounds", "16")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;

    int nRounds = request.params[0].getInt<int>();

    if (nRounds > MAX_COINJOIN_ROUNDS || nRounds < MIN_COINJOIN_ROUNDS)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid number of rounds");

    CCoinJoinClientOptions::SetRounds(nRounds);

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan setcoinjoinamount()
{
    return RPCHelpMan{"setcoinjoinamount",
        "\nSet the goal amount in " + CURRENCY_UNIT + " for CoinJoin.\n",
        {
            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO,
                "The default amount is " + ToString(DEFAULT_COINJOIN_AMOUNT) +
                " Cannot be more than " + ToString(MAX_COINJOIN_AMOUNT) + " nor less than " + ToString(MIN_COINJOIN_AMOUNT)},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("setcoinjoinamount", "500")
    + HelpExampleRpc("setcoinjoinamount", "208")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;

    int nAmount = request.params[0].getInt<int>();

    if (nAmount > MAX_COINJOIN_AMOUNT || nAmount < MIN_COINJOIN_AMOUNT)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount of " + CURRENCY_UNIT + " as mixing goal amount");

    CCoinJoinClientOptions::SetAmount(nAmount);

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getwalletinfo()
{
    return RPCHelpMan{"getwalletinfo",
                "Returns an object containing various wallet state info.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                        {RPCResult::Type::NUM, "walletversion", "the wallet version"},
                        {RPCResult::Type::STR, "format", "the database format (bdb or sqlite)"},
                        {RPCResult::Type::NUM, "balance", "DEPRECATED. Identical to getbalances().mine.trusted"},
                        {RPCResult::Type::NUM, "coinjoin_balance", "DEPRECATED. Identical to getbalances().mine.coinjoin"},
                        {RPCResult::Type::NUM, "unconfirmed_balance", "DEPRECATED. Identical to getbalances().mine.untrusted_pending"},
                        {RPCResult::Type::NUM, "immature_balance", "DEPRECATED. Identical to getbalances().mine.immature"},
                        {RPCResult::Type::NUM, "txcount", "the total number of transactions in the wallet"},
                        {RPCResult::Type::NUM_TIME, "timefirstkey", "the " + UNIX_EPOCH_TIME + " of the oldest known key in the wallet"},
                        {RPCResult::Type::NUM_TIME, "keypoololdest", /*optional=*/true, "the " + UNIX_EPOCH_TIME + " of the oldest pre-generated key in the key pool. Legacy wallets only"},
                        {RPCResult::Type::NUM, "keypoolsize", "how many new keys are pre-generated (only counts external keys)"},
                        {RPCResult::Type::NUM, "keypoolsize_hd_internal", /*optional=*/ true, "how many new keys are pre-generated for internal use (used for change outputs and mobile coinjoin, only appears if the wallet is using this feature, otherwise external keys are used)"},
                        {RPCResult::Type::NUM, "keys_left", "how many new keys are left since last automatic backup"},
                        {RPCResult::Type::NUM_TIME, "unlocked_until", /*optional=*/true, "the " + UNIX_EPOCH_TIME + " until which the wallet is unlocked for transfers, or 0 if the wallet is locked (only present for passphrase-encrypted wallets)"},
                        {RPCResult::Type::STR_AMOUNT, "paytxfee", "the transaction fee configuration, set in " + CURRENCY_UNIT + "/kB"},
                        {RPCResult::Type::STR_HEX, "hdchainid", "the ID of the HD chain"},
                        {RPCResult::Type::NUM, "hdaccountcount", "how many accounts of the HD chain are in this wallet"},
                        {RPCResult::Type::ARR, "hdaccounts", "",
                            {
                            {RPCResult::Type::OBJ, "", "",
                                {
                                    {RPCResult::Type::NUM, "hdaccountindex", "the index of the account"},
                                    {RPCResult::Type::NUM, "hdexternalkeyindex", "current external childkey index"},
                                    {RPCResult::Type::NUM, "hdinternalkeyindex", "current internal childkey index"},
                            }},
                        }},
                        {RPCResult::Type::OBJ, "verification", "Wallet verification status",
                        {
                            {RPCResult::Type::BOOL, "is_verified", "Whether wallet is KYC verified"},
                            {RPCResult::Type::STR, "status", "Verification status (none, pending, basic, full, expired, revoked)"},
                            {RPCResult::Type::BOOL, "can_generate_addresses", "Whether wallet can generate new addresses"},
                            {RPCResult::Type::STR, "issuer", /*optional=*/true, "Credential issuer"},
                            {RPCResult::Type::NUM_TIME, "expires_at", /*optional=*/true, "Expiration timestamp"},
                        }},
                        {RPCResult::Type::BOOL, "private_keys_enabled", "false if privatekeys are disabled for this wallet (enforced watch-only wallet)"},
                        {RPCResult::Type::BOOL, "avoid_reuse", "whether this wallet tracks clean/dirty coins in terms of reuse"},
                        {RPCResult::Type::OBJ, "scanning", "current scanning details, or false if no scan is in progress",
                        {
                            {RPCResult::Type::NUM, "duration", "elapsed seconds since scan start"},
                            {RPCResult::Type::NUM, "progress", "scanning progress percentage [0.0, 1.0]"},
                        }},
                        {RPCResult::Type::BOOL, "descriptors", "whether this wallet uses descriptors for scriptPubKey management"},
                        {RPCResult::Type::BOOL, "external_signer", "whether this wallet is configured to use an external signer such as a hardware wallet"},
                        RESULT_LAST_PROCESSED_BLOCK,
                    },
                },
                RPCExamples{
                    HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    CHDChain hdChainCurrent;
    bool fHDEnabled = spk_man && spk_man->GetHDChain(hdChainCurrent);
    UniValue obj(UniValue::VOBJ);

    const auto bal = GetBalance(*pwallet);
    obj.pushKV("walletname", pwallet->GetName());
    obj.pushKV("walletversion", pwallet->GetVersion());
    obj.pushKV("format", pwallet->GetDatabase().Format());
    obj.pushKV("balance", ValueFromAmount(bal.m_mine_trusted));
    obj.pushKV("coinjoin_balance",       ValueFromAmount(bal.m_anonymized));
    obj.pushKV("unconfirmed_balance", ValueFromAmount(bal.m_mine_untrusted_pending));
    obj.pushKV("immature_balance", ValueFromAmount(bal.m_mine_immature));
    obj.pushKV("txcount",       (int)pwallet->mapWallet.size());
    // TODO: implement timefirstkey for Descriptor KeyMan or explain why it's not provided
    if (spk_man) {
        obj.pushKV("timefirstkey", spk_man->GetTimeFirstKey());
    }
    const auto kp_oldest = pwallet->GetOldestKeyPoolTime();
    if (kp_oldest.has_value()) {
        obj.pushKV("keypoololdest", kp_oldest.value());
    }
    size_t kpExternalSize = pwallet->KeypoolCountExternalKeys();
    obj.pushKV("keypoolsize", kpExternalSize);
    obj.pushKV("keypoolsize_hd_internal", pwallet->GetKeyPoolSize() - kpExternalSize);
    obj.pushKV("keys_left", pwallet->nKeysLeftSinceAutoBackup);
    if (pwallet->IsCrypted()) {
        obj.pushKV("unlocked_until", pwallet->nRelockTime);
    }
    obj.pushKV("paytxfee", ValueFromAmount(pwallet->m_pay_tx_fee.GetFeePerK()));
    if (fHDEnabled) {
        obj.pushKV("hdchainid", hdChainCurrent.GetID().GetHex());
        obj.pushKV("hdaccountcount", hdChainCurrent.CountAccounts());
        UniValue accounts(UniValue::VARR);
        for (size_t i = 0; i < hdChainCurrent.CountAccounts(); ++i)
        {
            CHDAccount acc;
            UniValue account(UniValue::VOBJ);
            account.pushKV("hdaccountindex", i);
            if(hdChainCurrent.GetAccount(i, acc)) {
                account.pushKV("hdexternalkeyindex", acc.nExternalChainCounter);
                account.pushKV("hdinternalkeyindex", acc.nInternalChainCounter);
            } else {
                account.pushKV("error", strprintf("account %d is missing", i));
            }
            accounts.push_back(account);
        }
        obj.pushKV("hdaccounts", accounts);
    }
    obj.pushKV("private_keys_enabled", !pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    obj.pushKV("avoid_reuse", pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE));
    if (pwallet->IsScanning()) {
        UniValue scanning(UniValue::VOBJ);
        scanning.pushKV("duration", pwallet->ScanningDuration() / 1000);
        scanning.pushKV("progress", pwallet->ScanningProgress());
        obj.pushKV("scanning", scanning);
    } else {
        obj.pushKV("scanning", false);
    }
    obj.pushKV("descriptors", pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    obj.pushKV("external_signer", pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));

UniValue verification(UniValue::VOBJ);
verification.pushKV("is_verified", pwallet->IsVerified());
verification.pushKV("can_generate_addresses", pwallet->CanGenerateAddresses());

std::string statusStr;
switch (pwallet->GetVerificationStatus()) {
    case CredentialStatus::NONE: statusStr = "none"; break;
    case CredentialStatus::PENDING: statusStr = "pending"; break;
    case CredentialStatus::VERIFIED_BASIC: statusStr = "basic"; break;
    case CredentialStatus::VERIFIED_FULL: statusStr = "full"; break;
    case CredentialStatus::EXPIRED: statusStr = "expired"; break;
    case CredentialStatus::REVOKED: statusStr = "revoked"; break;
    default: statusStr = "unknown";
}
verification.pushKV("status", statusStr);

CWalletCredential cred = pwallet->GetCredential();
CCredentialMetadata metadata = cred.GetMetadata();
if (metadata.nExpiresAt > 0) {
    verification.pushKV("issuer", metadata.issuer);
    verification.pushKV("expires_at", metadata.nExpiresAt);
    verification.pushKV("credential_type", metadata.credentialType);
}

obj.pushKV("verification", verification);

    AppendLastProcessedBlock(obj, *pwallet);
    return obj;
},
    };
}

static RPCHelpMan listwalletdir()
{
    return RPCHelpMan{"listwalletdir",
                "Returns a list of wallets in the wallet directory.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "wallets", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "name", "The wallet name"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwalletdir", "")
            + HelpExampleRpc("listwalletdir", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue wallets(UniValue::VARR);
    for (const auto& path : ListDatabases(GetWalletDir())) {
        UniValue wallet(UniValue::VOBJ);
        wallet.pushKV("name", path.utf8string());
        wallets.push_back(wallet);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("wallets", wallets);
    return result;
},
    };
}

static RPCHelpMan listwallets()
{
    return RPCHelpMan{"listwallets",
                "Returns a list of currently loaded wallets.\n"
                "For full information on the wallet, use \"getwalletinfo\"\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwallets", "")
            + HelpExampleRpc("listwallets", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue obj(UniValue::VARR);

    WalletContext& context = EnsureWalletContext(request.context);
    for (const std::shared_ptr<CWallet>& wallet : GetWallets(context)) {
        LOCK(wallet->cs_wallet);
        obj.push_back(wallet->GetName());
    }

    return obj;
},
    };
}

static RPCHelpMan upgradetohd()
{
    return RPCHelpMan{"upgradetohd",
        "\nUpgrades non-HD wallets to HD.\n"
        "\nIf your wallet is encrypted, the wallet passphrase must be supplied. Supplying an incorrect"
        "\npassphrase may result in your wallet getting locked.\n"
        "\nWarning: You will need to make a new backup of your wallet after setting the HD wallet mnemonic.\n",
        {
            {"mnemonic", RPCArg::Type::STR, RPCArg::Default{""}, "Mnemonic as defined in BIP39 to use for the new HD wallet. Use an empty string \"\" to generate a new random mnemonic."},
            {"mnemonicpassphrase", RPCArg::Type::STR, RPCArg::Default{""}, "Optional mnemonic passphrase as defined in BIP39"},
            {"walletpassphrase", RPCArg::Type::STR, RPCArg::Default{""}, "If your wallet is encrypted you must have your wallet passphrase here. If your wallet is not encrypted, specifying wallet passphrase will trigger wallet encryption."},
            {"rescan", RPCArg::Type::BOOL, RPCArg::DefaultHint{"false if mnemonic is empty"}, "Whether to rescan the blockchain for missing transactions or not"},
        },
        RPCResult{RPCResult::Type::STR, "", "A string with further instructions"},
        RPCExamples{
            HelpExampleCli("upgradetohd", "")
    + HelpExampleCli("upgradetohd", "\"mnemonicword1 ... mnemonicwordN\"")
    + HelpExampleCli("upgradetohd", "\"mnemonicword1 ... mnemonicwordN\" \"mnemonicpassphrase\"")
    + HelpExampleCli("upgradetohd", "\"mnemonicword1 ... mnemonicwordN\" \"\" \"walletpassphrase\"")
    + HelpExampleCli("upgradetohd", "\"mnemonicword1 ... mnemonicwordN\" \"mnemonicpassphrase\" \"walletpassphrase\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    bool generate_mnemonic = request.params[0].isNull() || request.params[0].get_str().empty();
    bool mnemonic_passphrase_has_null{false};
    {
        LOCK(pwallet->cs_wallet);

        SecureString wallet_passphrase;
        wallet_passphrase.reserve(100);

        if (request.params[2].isNull()) {
            if (pwallet->IsCrypted()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Wallet encrypted but passphrase not supplied to RPC.");
            }
        } else {
            wallet_passphrase = std::string_view{request.params[2].get_str()};
        }

        SecureString mnemonic;
        mnemonic.reserve(256);
        if (!generate_mnemonic) {
            mnemonic = std::string_view{request.params[0].get_str()};
        }

        SecureString mnemonic_passphrase;
        mnemonic_passphrase.reserve(256);
        if (!request.params[1].isNull()) {
            mnemonic_passphrase = std::string_view{request.params[1].get_str()};
            mnemonic_passphrase_has_null = (mnemonic_passphrase.find('\0') != std::string::npos);
        }

        // Do not do anything to HD wallets
        if (pwallet->IsHDEnabled()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot upgrade a wallet to HD if it is already upgraded to HD");
        }

        if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Private keys are disabled for this wallet");
        }

        pwallet->WalletLogPrintf("Upgrading wallet to HD\n");
        pwallet->SetMinVersion(FEATURE_HD);

        if (pwallet->IsCrypted()) {
            if (wallet_passphrase.empty()) {
                throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: Wallet encrypted but supplied empty wallet passphrase");
            }

            // We are intentionally re-locking the wallet so we can validate passphrase
            // by verifying if it can unlock the wallet
            pwallet->Lock();

            // Unlock the wallet
            if (!pwallet->Unlock(wallet_passphrase)) {
                // Check if the passphrase has a null character (see bitcoin#27067 for details)
                if (wallet_passphrase.find('\0') == std::string::npos) {
                    throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
                } else {
                    throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered is incorrect. "
                                                                        "It contains a null character (ie - a zero byte). "
                                                                        "If the passphrase was set with a version of this software prior to 23.0, "
                                                                        "please try again with only the characters up to — but not including — "
                                                                        "the first null character. If this is successful, please set a new "
                                                                        "passphrase to avoid this issue in the future.");
                }
            }
        }

        if (pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            pwallet->SetupDescriptorScriptPubKeyMans(mnemonic, mnemonic_passphrase);
        } else {
            auto spk_man = pwallet->GetLegacyScriptPubKeyMan();
            if (!spk_man) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error: Legacy ScriptPubKeyMan is not available");
            }

            if (pwallet->IsCrypted()) {
                pwallet->WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                        spk_man->GenerateNewHDChain(mnemonic, mnemonic_passphrase, encryption_key);
                        return true;
                    });
            } else {
                spk_man->GenerateNewHDChain(mnemonic, mnemonic_passphrase);
            }
        }

        if (pwallet->IsCrypted()) {
            // Relock encrypted wallet
            pwallet->Lock();
        } else if (!wallet_passphrase.empty()) {
            // Encrypt non-encrypted wallet
            if (!pwallet->EncryptWallet(wallet_passphrase)) {
                throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Failed to encrypt HD wallet");
            }
        }
    } // pwallet->cs_wallet

    // If you are generating new mnemonic it is assumed that the addresses have never gotten a transaction before, so you don't need to rescan for transactions
    bool rescan = request.params[3].isNull() ? !generate_mnemonic : request.params[3].get_bool();
    if (rescan) {
        WalletRescanReserver reserver(*pwallet);
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
        }
        CWallet::ScanResult result = pwallet->ScanForWalletTransactions(pwallet->chain().getBlockHash(0), 0, {}, reserver, /*fUpdate=*/true, /*save_progress=*/false);
        switch (result.status) {
        case CWallet::ScanResult::SUCCESS:
            break;
        case CWallet::ScanResult::FAILURE:
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan failed. Potentially corrupted data files.");
        case CWallet::ScanResult::USER_ABORT:
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted.");
            // no default case, so the compiler can warn about missing cases
        }
    }

    // Check if the passphrase has a null character (see #27067 for details)
    if (!mnemonic_passphrase_has_null) {
        return "Make sure that you have backup of your mnemonic.";
    } else {
        return "Make sure that you have backup of your mnemonic. "
               "Your mnemonic passphrase contains a null character (ie - a zero byte). "
               "If the passphrase was created with a version of this software prior to 23.0, "
               "please try again with only the characters up to — but not including — "
               "the first null character. If this is successful, please set a new "
               "passphrase to avoid this issue in the future.";
    }
},
    };
}

static RPCHelpMan loadwallet()
{
    return RPCHelpMan{"loadwallet",
                "\nLoads a wallet from a wallet file or directory."
                "\nNote that all wallet command-line options used when starting dashd will be"
                "\napplied to the new wallet (eg, rescan, etc).\n",
                {
                    {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet directory or .dat file."},
                    {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED_NAMED_ARG, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "name", "The wallet name if loaded successfully."},
                        {RPCResult::Type::STR, "warning", "Warning message if wallet was not loaded cleanly."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("loadwallet", "\"test.dat\"")
            + HelpExampleRpc("loadwallet", "\"test.dat\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    const std::string name(request.params[0].get_str());

    DatabaseOptions options;
    DatabaseStatus status;
    ReadDatabaseArgs(*context.args, options);
    options.require_existing = true;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    std::optional<bool> load_on_start = request.params[1].isNull() ? std::nullopt : std::optional<bool>(request.params[1].get_bool());

    {
        LOCK(context.wallets_mutex);
        if (std::any_of(context.wallets.begin(), context.wallets.end(), [&name](const auto& wallet) { return wallet->GetName() == name; })) {
            throw JSONRPCError(RPC_WALLET_ALREADY_LOADED, "Wallet \"" + name + "\" is already loaded.");
        }
    }

    std::shared_ptr<CWallet> const wallet = LoadWallet(context, name, load_on_start, options, status, error, warnings);

    HandleWalletError(wallet, status, error);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    obj.pushKV("warning", Join(warnings, Untranslated("\n")).original);

    return obj;
},
    };
}

static RPCHelpMan setwalletflag()
{
            std::string flags;
            for (auto& it : WALLET_FLAG_MAP)
                if (it.second & MUTABLE_WALLET_FLAGS)
                    flags += (flags == "" ? "" : ", ") + it.first;

    return RPCHelpMan{"setwalletflag",
                "\nChange the state of the given wallet flag for a wallet.\n",
                {
                    {"flag", RPCArg::Type::STR, RPCArg::Optional::NO, "The name of the flag to change. Current available flags: " + flags},
                    {"value", RPCArg::Type::BOOL, RPCArg::Default{true}, "The new state."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "flag_name", "The name of the flag that was modified"},
                        {RPCResult::Type::BOOL, "flag_state", "The new state of the flag"},
                        {RPCResult::Type::STR, "warnings", /*optional=*/true, "Any warnings associated with the change"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("setwalletflag", "avoid_reuse")
                  + HelpExampleRpc("setwalletflag", "\"avoid_reuse\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;


    std::string flag_str = request.params[0].get_str();
    bool value = request.params[1].isNull() || request.params[1].get_bool();

    if (!WALLET_FLAG_MAP.count(flag_str)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unknown wallet flag: %s", flag_str));
    }

    auto flag = WALLET_FLAG_MAP.at(flag_str);

    if (!(flag & MUTABLE_WALLET_FLAGS)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is immutable: %s", flag_str));
    }

    UniValue res(UniValue::VOBJ);

    if (pwallet->IsWalletFlagSet(flag) == value) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is already set to %s: %s", value ? "true" : "false", flag_str));
    }

    res.pushKV("flag_name", flag_str);
    res.pushKV("flag_state", value);

    if (value) {
        pwallet->SetWalletFlag(flag);
    } else {
        pwallet->UnsetWalletFlag(flag);
    }

    if (flag && value && WALLET_FLAG_CAVEATS.count(flag)) {
        res.pushKV("warnings", WALLET_FLAG_CAVEATS.at(flag));
    }

    return res;
},
    };
}

static RPCHelpMan createwallet()
{
    return RPCHelpMan{
        "createwallet",
        "\nCreates and loads a new wallet.\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name for the new wallet. If this is a path, the wallet will be created at the path location."},
            {"disable_private_keys", RPCArg::Type::BOOL, RPCArg::Default{false}, "Disable the possibility of private keys (only watchonlys are possible in this mode)."},
            {"blank", RPCArg::Type::BOOL, RPCArg::Default{false}, "Create a blank wallet. A blank wallet has no keys or HD seed. One can be set using upgradetohd (by mnemonic) or sethdseed (WIF private key)."},
            {"passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "Encrypt the wallet with this passphrase."},
            {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{false}, "Keep track of coin reuse, and treat dirty and clean coins differently with privacy considerations in mind."},
            {"descriptors", RPCArg::Type::BOOL, RPCArg::Default{false}, "Create a native descriptor wallet. The wallet will use descriptors internally to handle address creation."},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED_NAMED_ARG, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
            {"external_signer", RPCArg::Type::BOOL, RPCArg::Default{false}, "Use an external signer such as a hardware wallet. Requires -signer to be configured. Wallet creation will fail if keys cannot be fetched. Requires disable_private_keys and descriptors set to true."},
            {"require_verification", RPCArg::Type::BOOL, RPCArg::Default{false}, "Require KYC verification before allowing address generation."},
            {"kyc_level", RPCArg::Type::STR, RPCArg::Default{""}, "Optional KYC level to start immediately after wallet creation when require_verification is true. One of: \"basic\", \"advanced\", \"full\"."},
            {"kyc_callback_url", RPCArg::Type::STR, RPCArg::Default{""}, "Optional callback URL to use when starting KYC immediately after wallet creation."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if created successfully. If the wallet was created using a full path, the wallet_name will be the full path."},
                {RPCResult::Type::STR, "warning", "Warning message if wallet was not loaded cleanly."},
                {RPCResult::Type::OBJ, "verification_session", /*optional=*/true, "KYC session details if a verification flow was started automatically after wallet creation.",
                {
                    {RPCResult::Type::STR, "session_id", "KYC session ID"},
                    {RPCResult::Type::STR, "verification_url", "URL to complete KYC"},
                    {RPCResult::Type::STR, "status", "Session status"},
                    {RPCResult::Type::NUM_TIME, "expires_at", "Expiration timestamp"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("createwallet", "\"testwallet\"")
            + HelpExampleRpc("createwallet", "\"testwallet\"")
            + HelpExampleCliNamed("createwallet", {{"wallet_name", "descriptors"}, {"avoid_reuse", true}, {"descriptors", true}, {"load_on_startup", true}})
            + HelpExampleRpcNamed("createwallet", {{"wallet_name", "descriptors"}, {"avoid_reuse", true}, {"descriptors", true}, {"load_on_startup", true}})
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    uint64_t flags = 0;
    if (!request.params[1].isNull() && request.params[1].get_bool()) {
        flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        flags |= WALLET_FLAG_BLANK_WALLET;
    }
    SecureString passphrase;
    passphrase.reserve(100);
    std::vector<bilingual_str> warnings;
    if (!request.params[3].isNull()) {
        passphrase = std::string_view{request.params[3].get_str()};
        if (passphrase.empty()) {
            // Empty string means unencrypted
            warnings.emplace_back(Untranslated("Empty string given as passphrase, wallet will not be encrypted."));
        }
    }


    if (!request.params[4].isNull() && request.params[4].get_bool()) {
        flags |= WALLET_FLAG_AVOID_REUSE;
    }
    if (!request.params[5].isNull() && request.params[5].get_bool()) {
#ifndef USE_SQLITE
        throw JSONRPCError(RPC_WALLET_ERROR, "Compiled without sqlite support (required for descriptor wallets)");
#endif
        if (request.params[6].isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "The createwallet RPC requires specifying the 'load_on_startup' flag when creating descriptor wallets. Dash Core v21 introduced this requirement due to breaking changes in the createwallet RPC.");
        }
        flags |= WALLET_FLAG_DESCRIPTORS;
    }
    if (!request.params[7].isNull() && request.params[7].get_bool()) {
#ifdef ENABLE_EXTERNAL_SIGNER
        flags |= WALLET_FLAG_EXTERNAL_SIGNER;
#else
        throw JSONRPCError(RPC_WALLET_ERROR, "Compiled without external signing support (required for external signing)");
#endif
    }

    bool require_verification = !request.params[8].isNull() && request.params[8].get_bool();
    if (require_verification) {
        flags |= WALLET_FLAG_REQUIRE_VERIFICATION;
    }

    const std::string kyc_level = request.params[9].isNull() ? "" : request.params[9].get_str();
    const std::string kyc_callback_url = request.params[10].isNull() ? "" : request.params[10].get_str();
    if (!kyc_level.empty() && !require_verification) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The createwallet RPC requires require_verification=true when kyc_level is provided.");
    }
#ifndef USE_BDB
    if (!(flags & WALLET_FLAG_DESCRIPTORS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Compiled without bdb support (required for legacy wallets)");
    }
#endif
    DatabaseOptions options;
    DatabaseStatus status;
    ReadDatabaseArgs(*context.args, options);
    options.require_create = true;
    options.create_flags = flags;
    options.create_passphrase = passphrase;
    bilingual_str error;
    std::optional<bool> load_on_start = request.params[6].isNull() ? std::nullopt : std::optional<bool>(request.params[6].get_bool());
    const std::shared_ptr<CWallet> wallet = CreateWallet(context, request.params[0].get_str(), load_on_start, options, status, error, warnings);
    if (!wallet) {
        RPCErrorCode code = status == DatabaseStatus::FAILED_ENCRYPT ? RPC_WALLET_ENCRYPTION_FAILED : RPC_WALLET_ERROR;
        throw JSONRPCError(code, error.original);
    }
    wallet->SetupLegacyScriptPubKeyMan();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    obj.pushKV("warning", Join(warnings, Untranslated("\n")).original);

    if (!kyc_level.empty()) {
        KYCLevel level;
        if (kyc_level == "basic") {
            level = KYCLevel::BASIC_LEVEL;
        } else if (kyc_level == "advanced") {
            level = KYCLevel::ADVANCED_LEVEL;
        } else if (kyc_level == "full") {
            level = KYCLevel::FULL_LEVEL;
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid kyc_level. Use 'basic', 'advanced', or 'full'");
        }

        auto session_res = wallet->StartKYCVerification(level, kyc_callback_url);
        if (!session_res) {
            throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(session_res).original);
        }

        UniValue verification_session(UniValue::VOBJ);
        verification_session.pushKV("session_id", session_res->session_id);
        verification_session.pushKV("verification_url", session_res->url);
        verification_session.pushKV("status", session_res->status);
        verification_session.pushKV("expires_at", session_res->expires_at);
        obj.pushKV("verification_session", verification_session);
    }

    return obj;
},
    };
}

static RPCHelpMan unloadwallet()
{
    return RPCHelpMan{"unloadwallet",
                "Unloads the wallet referenced by the request endpoint otherwise unloads the wallet specified in the argument.\n"
                "Specifying the wallet name on a wallet endpoint is invalid.",
                {
                    {"wallet_name", RPCArg::Type::STR, RPCArg::DefaultHint{"the wallet name from the RPC endpoint"}, "The name of the wallet to unload. If provided both here and in the RPC endpoint, the two must be identical."},
                    {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED_NAMED_ARG, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "warning", "Warning message if wallet was not unloaded cleanly."},
                }},
                RPCExamples{
                    HelpExampleCli("unloadwallet", "wallet_name")
            + HelpExampleRpc("unloadwallet", "wallet_name")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string wallet_name;
    if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
        if (!(request.params[0].isNull() || request.params[0].get_str() == wallet_name)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "RPC endpoint wallet and wallet_name parameter specify different wallets");
        }
    } else {
        wallet_name = request.params[0].get_str();
    }

    WalletContext& context = EnsureWalletContext(request.context);
    std::shared_ptr<CWallet> wallet = GetWallet(context, wallet_name);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
    }

    std::vector<bilingual_str> warnings;
    {
        WalletRescanReserver reserver(*wallet);
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
        }

        // Release the "main" shared pointer and prevent further notifications.
        // Note that any attempt to load the same wallet would fail until the wallet
        // is destroyed (see CheckUniqueFileid).
        std::optional<bool> load_on_start = request.params[1].isNull() ? std::nullopt : std::optional<bool>(request.params[1].get_bool());
        if (!RemoveWallet(context, wallet, load_on_start, warnings)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Requested wallet already unloaded");
        }
    }

    UnloadWallet(std::move(wallet));

    UniValue result(UniValue::VOBJ);
    result.pushKV("warning", Join(warnings, Untranslated("\n")).original);
    return result;
},
    };
}

static RPCHelpMan wipewallettxes()
{
    return RPCHelpMan{"wipewallettxes",
        "\nWipe wallet transactions.\n"
        "Note: Use \"rescanblockchain\" to initiate the scanning progress and recover wallet transactions.\n",
        {
            {"keep_confirmed", RPCArg::Type::BOOL, RPCArg::Default{false}, "Do not wipe confirmed transactions"},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("wipewallettxes", "")
    + HelpExampleRpc("wipewallettxes", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return UniValue::VNULL;
    CWallet* const pwallet = wallet.get();

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort rescan or wait.");
    }

    LOCK(pwallet->cs_wallet);

    bool keep_confirmed{false};
    if (!request.params[0].isNull()) {
        keep_confirmed = request.params[0].get_bool();
    }

    const size_t WALLET_SIZE{pwallet->mapWallet.size()};
    const size_t STEPS{20};
    const size_t BATCH_SIZE = std::max(WALLET_SIZE / STEPS, size_t(1000));

    pwallet->ShowProgress(strprintf("%s " + _("Wiping wallet transactions…").translated, pwallet->GetDisplayName()), 0);

    for (size_t progress = 0; progress < STEPS; ++progress) {
        std::vector<uint256> vHashIn;
        std::vector<uint256> vHashOut;
        size_t count{0};

        for (auto& [txid, wtx] : pwallet->mapWallet) {
            if (progress < STEPS - 1 && ++count > BATCH_SIZE) break;
            if (keep_confirmed && wtx.isConfirmed()) continue;
            vHashIn.push_back(txid);
        }

        if (vHashIn.size() > 0 && pwallet->ZapSelectTx(vHashIn, vHashOut) != DBErrors::LOAD_OK) {
            pwallet->ShowProgress(strprintf("%s " + _("Wiping wallet transactions…").translated, pwallet->GetDisplayName()), 100);
            throw JSONRPCError(RPC_WALLET_ERROR, "Could not properly delete transactions.");
        }

        CHECK_NONFATAL(vHashOut.size() == vHashIn.size());

        if (pwallet->IsAbortingRescan() || pwallet->chain().shutdownRequested()) {
            pwallet->ShowProgress(strprintf("%s " + _("Wiping wallet transactions…").translated, pwallet->GetDisplayName()), 100);
            throw JSONRPCError(RPC_MISC_ERROR, "Wiping was aborted by user.");
        }

        pwallet->ShowProgress(strprintf("%s " + _("Wiping wallet transactions…").translated, pwallet->GetDisplayName()), std::max(1, std::min(99, int(progress * 100 / STEPS))));
    }

    pwallet->ShowProgress(strprintf("%s " + _("Wiping wallet transactions…").translated, pwallet->GetDisplayName()), 100);

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan sethdseed()
{
    return RPCHelpMan{"sethdseed",
                "\nSet or generate a new HD wallet seed. Non-HD wallets will not be upgraded to being a HD wallet. Wallets that are already\n"
                "HD can not be updated to a new HD seed.\n"
                "\nNote that you will need to MAKE A NEW BACKUP of your wallet after setting the HD wallet seed." + HELP_REQUIRING_PASSPHRASE +
                "Note: This command is only compatible with legacy wallets.\n",
                {
                    {"newkeypool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to flush old unused addresses, including change addresses, from the keypool and regenerate it.\n"
                                         "If true, the next address from getnewaddress and change address from getrawchangeaddress will be from this new seed.\n"
                                         "If false, addresses from the existing keypool will be used until it has been depleted."},
                    {"seed", RPCArg::Type::STR, RPCArg::DefaultHint{"random seed"}, "The WIF private key to use as the new HD seed.\n"
                                         "The seed value can be retrieved using the dumpwallet command. It is the private key marked hdseed=1"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("sethdseed", "")
            + HelpExampleCli("sethdseed", "false")
            + HelpExampleCli("sethdseed", "true \"wifkey\"")
            + HelpExampleRpc("sethdseed", "true, \"wifkey\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LegacyScriptPubKeyMan& spk_man = EnsureLegacyScriptPubKeyMan(*pwallet, true);

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set a HD seed to a wallet with private keys disabled");
    }

    LOCK2(pwallet->cs_wallet, spk_man.cs_KeyStore);

    // Do not do anything to non-HD wallets
    if (!pwallet->CanSupportFeature(FEATURE_HD)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set a HD seed on a non-HD wallet. Use the upgradewallet RPC in order to upgrade a non-HD wallet to HD");
    }
    if (pwallet->IsHDEnabled()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set a HD seed. The wallet already has a seed");
    }

    EnsureWalletIsUnlocked(*pwallet);

    bool flush_key_pool = true;
    if (!request.params[0].isNull()) {
        flush_key_pool = request.params[0].get_bool();
    }

    if (request.params[1].isNull()) {
        spk_man.GenerateNewHDChain("", "");
    } else {
        CKey key = DecodeSecret(request.params[1].get_str());
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }
        if (HaveKey(spk_man, key)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Already have this key (either as an HD seed or as a loose private key)");
        }
        CHDChain newHdChain;
        if (!newHdChain.SetSeed(SecureVector(key.begin(), key.end()), true)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key: SetSeed failed");
        }
        if (!spk_man.AddHDChainSingle(newHdChain)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key: AddHDChainSingle failed");
        }
        // add default account
        newHdChain.AddAccount();
    }

    if (flush_key_pool) spk_man.NewKeyPool();

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan upgradewallet()
{
    return RPCHelpMan{"upgradewallet",
        "\nUpgrade the wallet. Upgrades to the latest version if no version number is specified.\n"
        "New keys may be generated and a new wallet backup will need to be made.\n"
        "Consider using RPC upgradetohd instead upgradewallet if you have BIP39 mnemonic or want to set a wallet passphrase also (encrypt wallet).",
        {
            {"version", RPCArg::Type::NUM, RPCArg::Default{int{FEATURE_LATEST}}, "The version number to upgrade to. Default is the latest wallet version."}
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "wallet_name", "Name of wallet this operation was performed on"},
                {RPCResult::Type::NUM, "previous_version", "Version of wallet before this operation"},
                {RPCResult::Type::NUM, "current_version", "Version of wallet after this operation"},
                {RPCResult::Type::STR, "result", /*optional=*/true, "Description of result, if no error"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error message (if there is one)"}
            },
        },
        RPCExamples{
            HelpExampleCli("upgradewallet", "120200")
            + HelpExampleRpc("upgradewallet", "120200")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    RPCTypeCheck(request.params, {UniValue::VNUM}, true);

    EnsureWalletIsUnlocked(*pwallet);

    int version = 0;
    if (!request.params[0].isNull()) {
        version = request.params[0].getInt<int>();
    }
    bilingual_str error;
    const int previous_version{pwallet->GetVersion()};
    const bool wallet_upgraded{pwallet->UpgradeWallet(version, error)};
    const int current_version{pwallet->GetVersion()};
    std::string result;

    if (wallet_upgraded) {
        if (previous_version == current_version) {
            result = "Already at latest version. Wallet version unchanged.";
        } else {
            result = strprintf("Wallet upgraded successfully from version %i to version %i.", previous_version, current_version);
        }
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("wallet_name", pwallet->GetName());
    obj.pushKV("previous_version", previous_version);
    obj.pushKV("current_version", current_version);
    if (!result.empty()) {
        obj.pushKV("result", result);
    } else {
        CHECK_NONFATAL(!error.empty());
        obj.pushKV("error", error.original);
    }
    return obj;
},
    };
}

static RPCHelpMan setwalletcredential()
{
    return RPCHelpMan{"setwalletcredential",
        "\nSets a test credential for development.\n"
        "\nThis RPC is only available on mockable test chains and must not be used in production.\n",
        {
            {"status", RPCArg::Type::STR, RPCArg::Optional::NO, "Verification status (basic, full, none)"},
            {"issuer", RPCArg::Type::STR, RPCArg::Default{"test-issuer"}, "Issuer name"},
            {"expiry_days", RPCArg::Type::NUM, RPCArg::Default{30}, "Days until credential expires"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "status", "Status set"},
                {RPCResult::Type::STR, "message", "Success message"},
                {RPCResult::Type::BOOL, "is_verified", "Whether wallet is now considered verified"},
            }
        },
        RPCExamples{
            HelpExampleCli("setwalletcredential", "basic")
            + HelpExampleCli("setwalletcredential", "full \"coinfirm\" 90")
            + HelpExampleRpc("setwalletcredential", "\"basic\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    EnsureCredentialTestingChain("setwalletcredential");

    // Parse status
    std::string statusStr = request.params[0].get_str();
    CredentialStatus status;
    if (statusStr == "basic") {
        status = CredentialStatus::VERIFIED_BASIC;
    } else if (statusStr == "full") {
        status = CredentialStatus::VERIFIED_FULL;
    } else if (statusStr == "none") {
        status = CredentialStatus::NONE;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid status. Use 'basic', 'full', or 'none'");
    }

    // Parse optional issuer
    std::string issuer = "test-issuer";
    if (!request.params[1].isNull()) {
        issuer = request.params[1].get_str();
    }

    // Parse optional expiry days
    int expiry_days = 30;
    if (!request.params[2].isNull()) {
        expiry_days = request.params[2].getInt<int>();
        if (expiry_days < 1 || expiry_days > 365) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Expiry days must be between 1 and 365");
        }
    }

    // Create credential data
    // In a real implementation, this would be a proper JWT/CWT
    // For testing, we'll create a simple structured credential
    std::string credential_str = strprintf(
        "{\"issuer\":\"%s\",\"status\":\"%s\",\"expiry\":%d,\"wallet\":\"%s\"}",
        issuer, statusStr, GetTime() + (expiry_days * 24 * 60 * 60), pwallet->GetName()
    );
    
    std::vector<unsigned char> credential_data(credential_str.begin(), credential_str.end());

    // Create credential object
    CWalletCredential cred;
    cred.SetCredential(credential_data);
    cred.SetStatus(status);

    // Set metadata
    CCredentialMetadata metadata;
    metadata.nExpiresAt = GetTime() + (expiry_days * 24 * 60 * 60);
    metadata.issuer = issuer;
    metadata.credentialType = statusStr;
    metadata.credentialHash = Hash(credential_data);
    cred.SetMetadata(metadata);

    // Save to database
    {
        LOCK(pwallet->cs_wallet);
        WalletBatch batch(pwallet->GetDatabase());
        if (!batch.WriteCredential(cred)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to write credential to database");
        }
        
        // Also write metadata separately for backup
        batch.WriteCredentialMetadata(metadata);
        batch.WriteCredentialStatus(status);

        // Update wallet
        pwallet->SetCredential(cred);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("status", statusStr);
    result.pushKV("message", strprintf("Credential set successfully. Expires in %d days.", expiry_days));
    result.pushKV("is_verified", cred.IsVerified());
    result.pushKV("wallet_name", pwallet->GetName());

    return result;
},
    };
}


static std::string NormalizeOwnershipClaim(std::string claim)
{
    std::transform(claim.begin(), claim.end(), claim.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return claim;
}

static bool IsSupportedOwnershipClaim(const std::string& claim)
{
    static const std::set<std::string> supported{"full_name", "country", "age", "age_over_18", "age_band", "wallet_address"};
    return supported.count(claim) != 0;
}

static UniValue BuildOwnershipProofClaims(const CWalletCredential& cred, const std::vector<std::string>& requested_claims)
{
    UniValue claims(UniValue::VOBJ);
    for (const std::string& claim : requested_claims) {
        if (claim == "full_name") {
            if (!cred.HasAttribute("full_name")) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Credential does not contain requested claim: full_name");
            }
            claims.pushKV("full_name", cred.m_attributes.at("full_name"));
            continue;
        }
        if (claim == "country") {
            if (!cred.HasAttribute("country")) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Credential does not contain requested claim: country");
            }
            claims.pushKV("country", cred.m_attributes.at("country"));
            continue;
        }
        if (claim == "wallet_address") {
            if (!cred.HasAttribute("wallet_address")) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Credential does not contain requested claim: wallet_address");
            }
            claims.pushKV("wallet_address", cred.m_attributes.at("wallet_address"));
            continue;
        }
        if (!cred.HasAttribute("age")) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Credential does not contain requested claim: %s", claim));
        }

        int64_t age{0};
        if (!ParseInt64(cred.m_attributes.at("age"), &age)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Credential age claim is malformed");
        }

        if (claim == "age") {
            claims.pushKV("age", age);
        } else if (claim == "age_over_18") {
            claims.pushKV("age_over_18", age >= 18);
        } else if (claim == "age_band") {
            std::string band;
            if (age < 18) band = "under_18";
            else if (age < 25) band = "18_24";
            else if (age < 35) band = "25_34";
            else if (age < 50) band = "35_49";
            else if (age < 65) band = "50_64";
            else band = "65_plus";
            claims.pushKV("age_band", band);
        }
    }
    return claims;
}

static UniValue BuildOwnershipProofPayload(const CWalletCredential& cred, const CCredentialMetadata& metadata, const std::string& subject_address, const std::string& challenge, const std::vector<std::string>& requested_claims, const std::string& recipient_pubkey)
{
    const int64_t issued_at = GetTime();
    const int64_t expires_at = metadata.nExpiresAt > 0 ? std::min(metadata.nExpiresAt, issued_at + 300) : issued_at + 300;

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("v", 1);
    payload.pushKV("subject_address", subject_address);
    payload.pushKV("claims", BuildOwnershipProofClaims(cred, requested_claims));
    if (!metadata.issuer.empty()) {
        payload.pushKV("issuer", metadata.issuer);
    }
    if (!metadata.credentialHash.IsNull()) {
        payload.pushKV("credential_hash", metadata.credentialHash.GetHex());
        payload.pushKV("credential_id", metadata.credentialHash.GetHex());
    }
    payload.pushKV("challenge", challenge);
    payload.pushKV("issued_at", issued_at);
    payload.pushKV("expires_at", expires_at);
    if (!recipient_pubkey.empty()) {
        payload.pushKV("recipient_pubkey", recipient_pubkey);
    }
    return payload;
}

static RPCHelpMan getwalletcredential()
{
    return RPCHelpMan{"getwalletcredential",
        "\nReturns the current wallet credential information.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "status", "Verification status (none, pending, basic, full, expired, revoked)"},
                {RPCResult::Type::BOOL, "is_verified", "Whether wallet is verified"},
                {RPCResult::Type::BOOL, "is_valid", "Whether credential is valid (not expired/revoked)"},
                {RPCResult::Type::STR, "issuer", /*optional=*/true, "Credential issuer"},
                {RPCResult::Type::NUM_TIME, "expires_at", /*optional=*/true, "Expiration timestamp"},
                {RPCResult::Type::STR, "credential_type", /*optional=*/true, "Type of credential"},
                {RPCResult::Type::STR_HEX, "credential_hash", /*optional=*/true, "Hash of credential data"},
            }
        },
        RPCExamples{
            HelpExampleCli("getwalletcredential", "")
            + HelpExampleRpc("getwalletcredential", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    CWalletCredential cred = pwallet->GetCredential();
    CCredentialMetadata metadata = cred.GetMetadata();

    UniValue result(UniValue::VOBJ);
    
    // Convert status to string
    std::string statusStr;
    switch (cred.GetStatus()) {
        case CredentialStatus::NONE: statusStr = "none"; break;
        case CredentialStatus::PENDING: statusStr = "pending"; break;
        case CredentialStatus::VERIFIED_BASIC: statusStr = "basic"; break;
        case CredentialStatus::VERIFIED_FULL: statusStr = "full"; break;
        case CredentialStatus::EXPIRED: statusStr = "expired"; break;
        case CredentialStatus::REVOKED: statusStr = "revoked"; break;
        default: statusStr = "unknown";
    }
    
    result.pushKV("status", statusStr);
    result.pushKV("is_verified", cred.IsVerified());
    result.pushKV("is_valid", cred.IsValid());
    
    // Add metadata if available
    if (metadata.nExpiresAt > 0) {
        result.pushKV("expires_at", metadata.nExpiresAt);
        result.pushKV("issuer", metadata.issuer);
        result.pushKV("credential_type", metadata.credentialType);
        if (!metadata.credentialHash.IsNull()) {
            result.pushKV("credential_hash", metadata.credentialHash.GetHex());
        }
    }

    return result;
},
    };
}

static RPCHelpMan confirmownership()
{
    return RPCHelpMan{"confirmownership",
        "\nConfirm that the loaded wallet owns a local verification credential hash and return the claimed identity details.\n"
        "\nThis is intended for local-verification credentials stored in the wallet. The caller must be using the wallet that owns the credential.\n"
        "\nFor third-party checks, prefer signed, challenge-bound, verifier-specific ownership proofs instead of public hash lookups.\n",
        {
            {"credential_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Credential hash returned by getwalletcredential or getwalletinfo"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "matches", "Whether the provided hash matches this wallet's credential"},
                {RPCResult::Type::BOOL, "is_verified", "Whether the wallet credential is currently verified and valid"},
                {RPCResult::Type::STR, "wallet_name", "Wallet name"},
                {RPCResult::Type::STR, "issuer", /*optional=*/true, "Credential issuer"},
                {RPCResult::Type::STR, "credential_type", /*optional=*/true, "Credential type"},
                {RPCResult::Type::STR_HEX, "credential_hash", /*optional=*/true, "Normalized credential hash"},
                {RPCResult::Type::STR, "full_name", /*optional=*/true, "Credential subject full name"},
                {RPCResult::Type::NUM, "age", /*optional=*/true, "Credential subject age"},
                {RPCResult::Type::STR, "country", /*optional=*/true, "Credential subject country"},
                {RPCResult::Type::STR, "wallet_address", /*optional=*/true, "Wallet address embedded in the local verification credential"},
            }
        },
        RPCExamples{
            HelpExampleCli("confirmownership", "\"<credential-hash>\"")
            + HelpExampleRpc("confirmownership", "\"<credential-hash>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    auto normalize_hash = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        return value;
    };

    LOCK(pwallet->cs_wallet);

    const CWalletCredential cred = pwallet->GetCredential();
    const CCredentialMetadata metadata = cred.GetMetadata();
    if (metadata.credentialHash.IsNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not have a credential hash to confirm");
    }

    const std::string requested_hash = normalize_hash(request.params[0].get_str());
    const std::string stored_hash = normalize_hash(metadata.credentialHash.GetHex());
    if (requested_hash != stored_hash) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Credential hash does not belong to this wallet");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("matches", true);
    result.pushKV("is_verified", cred.IsVerified());
    result.pushKV("wallet_name", pwallet->GetName());
    result.pushKV("credential_hash", metadata.credentialHash.GetHex());
    if (!metadata.issuer.empty()) {
        result.pushKV("issuer", metadata.issuer);
    }
    if (!metadata.credentialType.empty()) {
        result.pushKV("credential_type", metadata.credentialType);
    }
    if (cred.HasAttribute("full_name")) {
        result.pushKV("full_name", cred.m_attributes.at("full_name"));
    }
    if (cred.HasAttribute("country")) {
        result.pushKV("country", cred.m_attributes.at("country"));
    }
    if (cred.HasAttribute("age")) {
        int64_t age{0};
        if (ParseInt64(cred.m_attributes.at("age"), &age)) {
            result.pushKV("age", age);
        }
    }
    if (cred.HasAttribute("wallet_address")) {
        result.pushKV("wallet_address", cred.m_attributes.at("wallet_address"));
    }

    return result;
},
    };
}


static RPCHelpMan generateownershipproof()
{
    return RPCHelpMan{"generateownershipproof",
        "\nGenerate a challenge-bound ownership proof for selective external disclosure.\n"
        "\nThis is intended for proof exchange with a verifier. Use confirmownership only for local wallet inspection.\n",
        {
            {"request", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Proof request object",
                {
                    {"challenge", RPCArg::Type::STR, RPCArg::Optional::NO, "Verifier-provided challenge nonce"},
                    {"requested_claims", RPCArg::Type::ARR, RPCArg::Optional::NO, "Claims to disclose",
                        {{"claim", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Claim name (full_name, country, age, age_over_18, age_band, wallet_address)"}}},
                    {"subject_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet address that is presenting the credential"},
                    {"recipient_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional recipient public key hint for encrypted transport workflows"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "proof", "Serialized proof blob"},
                {RPCResult::Type::OBJ, "payload", "Canonical proof payload"},
                {RPCResult::Type::STR, "signature", "Wallet signature over the payload"},
                {RPCResult::Type::NUM_TIME, "expires_at", "Proof expiration time"},
            }
        },
        RPCExamples{
            HelpExampleCli("generateownershipproof", "'{\"challenge\":\"nonce-123\",\"requested_claims\":[\"full_name\",\"country\",\"age_over_18\"],\"subject_address\":\"yX...\"}'")
            + HelpExampleRpc("generateownershipproof", "{\"challenge\":\"nonce-123\",\"requested_claims\":[\"full_name\",\"country\",\"age_over_18\"],\"subject_address\":\"yX...\"}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const UniValue proof_request = request.params[0].get_obj();
    const std::string challenge = proof_request["challenge"].get_str();
    if (challenge.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "challenge must not be empty");
    }

    const std::string subject_address = proof_request["subject_address"].get_str();
    if (!IsValidDestinationString(subject_address)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid subject_address");
    }

    std::vector<std::string> requested_claims;
    std::set<std::string> seen_claims;
    for (const UniValue& claim_value : proof_request["requested_claims"].getValues()) {
        const std::string claim = NormalizeOwnershipClaim(claim_value.get_str());
        if (!IsSupportedOwnershipClaim(claim)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unsupported requested claim: %s", claim));
        }
        if (seen_claims.insert(claim).second) {
            requested_claims.push_back(claim);
        }
    }
    if (requested_claims.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "requested_claims must contain at least one supported claim");
    }

    const std::string recipient_pubkey = proof_request.exists("recipient_pubkey") ? proof_request["recipient_pubkey"].get_str() : "";

    LOCK(pwallet->cs_wallet);

    const CWalletCredential cred = pwallet->GetCredential();
    const CCredentialMetadata metadata = cred.GetMetadata();
    if (!cred.IsValid()) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Wallet credential is not valid: %s", cred.GetVerificationFailureReason()));
    }
    const auto dest = DecodeDestination(subject_address);
    const PKHash* pkhash = std::get_if<PKHash>(&dest);
    if (!pkhash) {
        throw JSONRPCError(RPC_TYPE_ERROR, "subject_address does not refer to a key");
    }
    if (!IsMine(*pwallet, dest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "subject_address does not belong to this wallet");
    }
    if (cred.HasAttribute("wallet_address") && cred.m_attributes.at("wallet_address") != subject_address) {
        throw JSONRPCError(RPC_WALLET_ERROR, "subject_address does not match the verified wallet address in the credential");
    }

    const UniValue payload = BuildOwnershipProofPayload(cred, metadata, subject_address, challenge, requested_claims, recipient_pubkey);
    const std::string payload_str = payload.write();

    std::string signature;
    const SigningResult err = pwallet->SignMessage(payload_str, *pkhash, signature);
    if (err != SigningResult::OK) {
        throw JSONRPCError(RPC_WALLET_ERROR, SigningResultString(err));
    }

    UniValue proof(UniValue::VOBJ);
    proof.pushKV("payload", payload);
    proof.pushKV("subject_address", subject_address);
    proof.pushKV("signature", signature);
    proof.pushKV("signature_type", "wallet-message");

    UniValue result(UniValue::VOBJ);
    result.pushKV("proof", proof.write());
    result.pushKV("payload", payload);
    result.pushKV("signature", signature);
    result.pushKV("expires_at", payload["expires_at"].getInt<int64_t>());
    return result;
},
    };
}

static RPCHelpMan verifyownershipproof()
{
    return RPCHelpMan{"verifyownershipproof",
        "\nVerify an ownership proof blob produced by generateownershipproof.\n",
        {
            {"proof", RPCArg::Type::STR, RPCArg::Optional::NO, "Proof blob"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "Whether the proof is currently valid"},
                {RPCResult::Type::STR, "reason", /*optional=*/true, "Failure reason when valid is false"},
                {RPCResult::Type::OBJ, "claims", /*optional=*/true, "Disclosed claims"},
                {RPCResult::Type::STR, "issuer", /*optional=*/true, "Credential issuer"},
                {RPCResult::Type::NUM_TIME, "expires_at", /*optional=*/true, "Proof expiration time"},
                {RPCResult::Type::STR, "challenge", /*optional=*/true, "Challenge bound into the proof"},
                {RPCResult::Type::STR, "subject_address", /*optional=*/true, "Wallet address that signed the proof"},
            }
        },
        RPCExamples{
            HelpExampleCli("verifyownershipproof", "\"<proof-blob>\"")
            + HelpExampleRpc("verifyownershipproof", "\"<proof-blob>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue proof(UniValue::VOBJ);
    if (!proof.read(request.params[0].get_str()) || !proof.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof must be a valid JSON object serialized as a string");
    }
    if (!proof.exists("payload") || !proof["payload"].isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof is missing payload");
    }
    if (!proof.exists("subject_address") || !proof["subject_address"].isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof is missing subject_address");
    }
    if (!proof.exists("signature") || !proof["signature"].isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof is missing signature");
    }

    const UniValue payload = proof["payload"].get_obj();
    const std::string subject_address = proof["subject_address"].get_str();
    const std::string signature = proof["signature"].get_str();
    const std::string payload_str = payload.write();

    auto invalid = [&](const std::string& reason) {
        UniValue result(UniValue::VOBJ);
        result.pushKV("valid", false);
        result.pushKV("reason", reason);
        return result;
    };

    switch (MessageVerify(subject_address, signature, payload_str)) {
    case MessageVerificationResult::OK:
        break;
    case MessageVerificationResult::ERR_INVALID_ADDRESS:
        return invalid("invalid_address");
    case MessageVerificationResult::ERR_ADDRESS_NO_KEY:
        return invalid("address_no_key");
    case MessageVerificationResult::ERR_MALFORMED_SIGNATURE:
        return invalid("malformed_signature");
    case MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED:
    case MessageVerificationResult::ERR_NOT_SIGNED:
        return invalid("invalid_signature");
    }

    if (!payload.exists("expires_at") || !payload["expires_at"].isNum()) {
        return invalid("missing_expiry");
    }
    if (!payload.exists("challenge") || !payload["challenge"].isStr() || payload["challenge"].get_str().empty()) {
        return invalid("challenge_mismatch");
    }
    if (!payload.exists("subject_address") || !payload["subject_address"].isStr() || payload["subject_address"].get_str() != subject_address) {
        return invalid("subject_address_mismatch");
    }
    const int64_t expires_at = payload["expires_at"].getInt<int64_t>();
    if (GetTime() > expires_at) {
        return invalid("expired");
    }
    if (payload.exists("revoked") && payload["revoked"].isBool() && payload["revoked"].get_bool()) {
        return invalid("revoked");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("valid", true);
    if (payload.exists("claims") && payload["claims"].isObject()) {
        result.pushKV("claims", payload["claims"].get_obj());
    }
    if (payload.exists("issuer") && payload["issuer"].isStr()) {
        result.pushKV("issuer", payload["issuer"].get_str());
    }
    result.pushKV("expires_at", expires_at);
    result.pushKV("challenge", payload["challenge"].get_str());
    result.pushKV("subject_address", subject_address);
    if (payload.exists("credential_id") && payload["credential_id"].isStr()) {
        result.pushKV("credential_id", payload["credential_id"].get_str());
    }
    if (payload.exists("credential_hash") && payload["credential_hash"].isStr()) {
        result.pushKV("credential_hash", payload["credential_hash"].get_str());
    }
    return result;
},
    };
}

static RPCHelpMan importcredential()
{
    return RPCHelpMan{"importcredential",
        "\nImport a KYC verification credential into the wallet.\n"
        "After successful import, the wallet will be able to generate addresses.\n",
        {
            {"credential", RPCArg::Type::STR, RPCArg::Optional::NO, "The verification credential (JWT format)"},
            {"issuer", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Issuer name (if not embedded in credential)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "status", "Result status"},
                {RPCResult::Type::BOOL, "is_verified", "Whether wallet is now verified"},
            }
        },
        RPCExamples{
            HelpExampleCli("importcredential", "\"eyJhbGciOiJIUzI1NiIs...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    std::string credential_str = request.params[0].get_str();
    std::vector<unsigned char> credential_data(credential_str.begin(), credential_str.end());
    const std::optional<std::string> requested_issuer{
        request.params[1].isNull() ? std::nullopt : std::make_optional(request.params[1].get_str())};

    CWalletCredential cred;
    if (!cred.SetCredential(credential_data)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid credential format");
    }

    CCredentialMetadata metadata = cred.GetMetadata();
    if (requested_issuer.has_value()) {
        if (!metadata.issuer.empty() && metadata.issuer != *requested_issuer) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Issuer does not match credential contents");
        }
        if (metadata.issuer.empty()) {
            metadata.issuer = *requested_issuer;
        }
    }

    if (metadata.issuer.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Credential issuer is required");
    }
    if (!IsTrustedCredentialIssuer(metadata.issuer)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Credential issuer is not trusted");
    }

    if (metadata.credentialHash.IsNull()) {
        metadata.credentialHash = Hash(credential_data);
    }

    if (metadata.nExpiresAt > 0 && metadata.nExpiresAt <= GetTime()) {
        cred.SetStatus(CredentialStatus::EXPIRED);
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Credential has expired");
    }

    const auto wallet_attr = cred.m_attributes.find("wallet");
    if (wallet_attr != cred.m_attributes.end() && wallet_attr->second != pwallet->GetName()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Credential does not belong to this wallet");
    }
    const auto subject_attr = cred.m_attributes.find("subject");
    if (subject_attr != cred.m_attributes.end() && subject_attr->second != pwallet->GetName()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Credential subject does not match this wallet");
    }

    if (!cred.IsVerified()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Credential is not in a verified state");
    }
    cred.SetMetadata(metadata);

    // Save to database
    {
        LOCK(pwallet->cs_wallet);
        WalletBatch batch(pwallet->GetDatabase());
        if (!batch.WriteCredential(cred)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to write credential to database");
        }
        if (!batch.WriteCredentialMetadata(metadata) || !batch.WriteCredentialStatus(cred.GetStatus())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist credential metadata");
        }
        pwallet->SetCredential(cred);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("status", CredentialStatusToString(cred.GetStatus()));
    result.pushKV("is_verified", cred.IsVerified());

    return result;
},
    };
}

static UniValue ChatMessageToJSON(const CWallet& wallet, const CWalletChatMessage& message, bool include_body)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("id", static_cast<uint64_t>(message.id));
    obj.pushKV("address", message.peer_address);
    obj.pushKV("direction", message.direction == ChatMessageDirection::OUTBOUND ? "outbound" : "inbound");
    obj.pushKV("created_at", message.created_at);
    obj.pushKV("encrypted", message.encrypted);
    if (include_body) {
        auto body = wallet.DecryptChatMessage(message);
        if (body) {
            obj.pushKV("message", *body);
        } else {
            obj.pushKV("message", "[locked]");
            obj.pushKV("message_error", util::ErrorString(body).original);
        }
    }
    return obj;
}

static RPCHelpMan chat()
{
    return RPCHelpMan{"chat",
        "\nWallet chat storage and sync helpers.\n",
        {
            {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "One of \"message\", \"list\", \"syncstatus\", \"syncexport\", or \"syncimport\"."},
            {"arg1", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Command-specific first argument"},
            {"arg2", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Command-specific second argument"},
        },
        RPCResult{
            RPCResult::Type::ANY, "", "Command-specific result",
        },
        RPCExamples{
            HelpExampleCli("chat", "message XyZAddress \"hello\"")
            + HelpExampleCli("chat", "list XyZAddress")
            + HelpExampleCli("chat", "syncexport")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const std::string command = request.params[0].get_str();

    if (command == "message") {
        if (request.params.size() < 3) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "chat message requires <address> and <message>");
        }
        const std::string address = request.params[1].get_str();
        const CTxDestination dest = DecodeDestination(address);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Dash address");
        }
        auto saved = pwallet->AddChatMessage(address, ChatMessageDirection::OUTBOUND, request.params[2].get_str());
        if (!saved) {
            throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(saved).original);
        }
        return ChatMessageToJSON(*pwallet, *saved, /*include_body=*/true);
    }

    if (command == "list") {
        const std::optional<std::string> address = request.params.size() > 1 && !request.params[1].isNull()
            ? std::make_optional(request.params[1].get_str())
            : std::nullopt;
        UniValue result(UniValue::VARR);
        for (const auto& message : pwallet->GetChatMessages(address)) {
            result.push_back(ChatMessageToJSON(*pwallet, message, /*include_body=*/true));
        }
        return result;
    }

    if (command == "syncstatus") {
        const auto state = pwallet->GetChatSyncState();
        UniValue result(UniValue::VOBJ);
        result.pushKV("last_message_id", static_cast<uint64_t>(state.last_message_id));
        result.pushKV("last_sync_time", state.last_sync_time);
        result.pushKV("message_count", static_cast<uint64_t>(pwallet->GetChatMessages().size()));
        return result;
    }

    if (command == "syncexport") {
        auto sync_blob = pwallet->ExportChatSync();
        if (!sync_blob) {
            throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(sync_blob).original);
        }
        UniValue result(UniValue::VOBJ);
        result.pushKV("sync_blob", *sync_blob);
        result.pushKV("encoding", "hex");
        return result;
    }

    if (command == "syncimport") {
        if (request.params.size() < 2) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "chat syncimport requires a sync blob");
        }
        auto imported = pwallet->ImportChatSync(request.params[1].get_str());
        if (!imported) {
            throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(imported).original);
        }
        UniValue result(UniValue::VOBJ);
        result.pushKV("imported", static_cast<uint64_t>(*imported));
        return result;
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown chat command");
},
    };
}

RPCHelpMan simulaterawtransaction()
{
    return RPCHelpMan{"simulaterawtransaction",
        "\nCalculate the balance change resulting in the signing and broadcasting of the given transaction(s).\n",
        {
            {"rawtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "An array of hex strings of raw transactions.\n",
                {
                    {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                },
            },
            {"options", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED_NAMED_ARG, "Options",
                {
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Whether to include watch-only addresses (see RPC importaddress)"},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "balance_change", "The wallet balance change (negative means decrease)."},
            }
        },
        RPCExamples{
            HelpExampleCli("simulaterawtransaction", "[\"myhex\"]")
            + HelpExampleRpc("simulaterawtransaction", "[\"myhex\"]")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> rpc_wallet = GetWalletForJSONRPCRequest(request);
    if (!rpc_wallet) return UniValue::VNULL;
    const CWallet& wallet = *rpc_wallet;

    RPCTypeCheck(request.params, {UniValue::VARR, UniValue::VOBJ}, true);

    LOCK(wallet.cs_wallet);

    UniValue include_watchonly(UniValue::VNULL);
    if (request.params[1].isObject()) {
        UniValue options = request.params[1];
        RPCTypeCheckObj(options,
            {
                {"include_watchonly", UniValueType(UniValue::VBOOL)},
            },
            true, true);

        include_watchonly = options["include_watchonly"];
    }

    isminefilter filter = ISMINE_SPENDABLE;
    if (ParseIncludeWatchonly(include_watchonly, wallet)) {
        filter |= ISMINE_WATCH_ONLY;
    }

    const auto& txs = request.params[0].get_array();
    CAmount changes{0};
    std::map<COutPoint, CAmount> new_utxos; // UTXO:s that were made available in transaction array
    std::set<COutPoint> spent;

    for (size_t i = 0; i < txs.size(); ++i) {
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, txs[i].get_str())) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction hex string decoding failure.");
        }

        // Fetch previous transactions (inputs)
        std::map<COutPoint, Coin> coins;
        for (const CTxIn& txin : mtx.vin) {
            coins[txin.prevout]; // Create empty map entry keyed by prevout.
        }
        wallet.chain().findCoins(coins);

        // Fetch debit; we are *spending* these; if the transaction is signed and
        // broadcast, we will lose everything in these
        for (const auto& txin : mtx.vin) {
            const auto& outpoint = txin.prevout;
            if (spent.count(outpoint)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction(s) are spending the same output more than once");
            }
            if (new_utxos.count(outpoint)) {
                changes -= new_utxos.at(outpoint);
                new_utxos.erase(outpoint);
            } else {
                if (coins.at(outpoint).IsSpent()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "One or more transaction inputs are missing or have been spent already");
                }
                changes -= wallet.GetDebit(txin, filter);
            }
            spent.insert(outpoint);
        }

        // Iterate over outputs; we are *receiving* these, if the wallet considers
        // them "mine"; if the transaction is signed and broadcast, we will receive
        // everything in these
        // Also populate new_utxos in case these are spent in later transactions

        const auto& hash = mtx.GetHash();
        for (size_t i = 0; i < mtx.vout.size(); ++i) {
            const auto& txout = mtx.vout[i];
            bool is_mine = 0 < (wallet.IsMine(txout) & filter);
            changes += new_utxos[COutPoint(hash, i)] = is_mine ? txout.nValue : 0;
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("balance_change", ValueFromAmount(changes));

    return result;
}
    };
}

// addresses
RPCHelpMan getaddressinfo();
RPCHelpMan getnewaddress();
RPCHelpMan getrawchangeaddress();
RPCHelpMan setlabel();
RPCHelpMan listaddressgroupings();
RPCHelpMan addmultisigaddress();
RPCHelpMan keypoolrefill();
RPCHelpMan newkeypool();
RPCHelpMan getaddressesbylabel();
RPCHelpMan listlabels();
#ifdef ENABLE_EXTERNAL_SIGNER
RPCHelpMan walletdisplayaddress();
#endif // ENABLE_EXTERNAL_SIGNER

// backup
RPCHelpMan dumpprivkey();
RPCHelpMan importprivkey();
RPCHelpMan importaddress();
RPCHelpMan importpubkey();
RPCHelpMan dumpwallet();
RPCHelpMan importwallet();
RPCHelpMan importprunedfunds();
RPCHelpMan removeprunedfunds();
RPCHelpMan importmulti();
RPCHelpMan importdescriptors();
RPCHelpMan listdescriptors();
RPCHelpMan backupwallet();
RPCHelpMan restorewallet();
RPCHelpMan dumphdinfo();
RPCHelpMan importelectrumwallet();

// coins
RPCHelpMan getreceivedbyaddress();
RPCHelpMan getreceivedbylabel();
RPCHelpMan getbalance();
RPCHelpMan getunconfirmedbalance();
RPCHelpMan lockunspent();
RPCHelpMan listlockunspent();
RPCHelpMan getbalances();
RPCHelpMan listunspent();

// encryption
RPCHelpMan walletpassphrase();
RPCHelpMan walletpassphrasechange();
RPCHelpMan walletlock();
RPCHelpMan encryptwallet();

// spend
RPCHelpMan sendtoaddress();
RPCHelpMan sendmany();
RPCHelpMan settxfee();
RPCHelpMan fundrawtransaction();
RPCHelpMan send();
RPCHelpMan walletprocesspsbt();
RPCHelpMan walletcreatefundedpsbt();
RPCHelpMan signrawtransactionwithwallet();

// signmessage
RPCHelpMan signmessage();

// transactions
RPCHelpMan listreceivedbyaddress();
RPCHelpMan listreceivedbylabel();
RPCHelpMan listtransactions();
RPCHelpMan listsinceblock();
RPCHelpMan gettransaction();
RPCHelpMan abandontransaction();
RPCHelpMan rescanblockchain();
RPCHelpMan abortrescan();

Span<const CRPCCommand> GetWalletRPCCommands()
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &fundrawtransaction},
        {"wallet", &abandontransaction},
        {"wallet", &abortrescan},
        {"wallet", &addmultisigaddress},
        {"wallet", &backupwallet},
        {"wallet", &createwallet},
        {"wallet", &restorewallet},
        {"wallet", &dumphdinfo},
        {"wallet", &dumpprivkey},
        {"wallet", &dumpwallet},
        {"wallet", &encryptwallet},
        {"wallet", &getaddressesbylabel},
        {"wallet", &getaddressinfo},
        {"wallet", &getbalance},
        {"wallet", &getnewaddress},
        {"wallet", &getrawchangeaddress},
        {"wallet", &getreceivedbyaddress},
        {"wallet", &getreceivedbylabel},
        {"wallet", &gettransaction},
        {"wallet", &getunconfirmedbalance},
        {"wallet", &getbalances},
        {"wallet", &getwalletinfo},
        {"wallet", &importaddress},
        {"wallet", &importelectrumwallet},
        {"wallet", &importdescriptors},
        {"wallet", &importmulti},
        {"wallet", &importprivkey},
        {"wallet", &importprunedfunds},
        {"wallet", &importpubkey},
        {"wallet", &importwallet},
        {"wallet", &keypoolrefill},
        {"wallet", &listaddressbalances},
        {"wallet", &listaddressgroupings},
        {"wallet", &listdescriptors},
        {"wallet", &listlabels},
        {"wallet", &listlockunspent},
        {"wallet", &listreceivedbyaddress},
        {"wallet", &listreceivedbylabel},
        {"wallet", &listsinceblock},
        {"wallet", &listtransactions},
        {"wallet", &listunspent},
        {"wallet", &listwalletdir},
        {"wallet", &listwallets},
        {"wallet", &loadwallet},
        {"wallet", &lockunspent},
        {"wallet", &newkeypool},
        {"wallet", &removeprunedfunds},
        {"wallet", &rescanblockchain},
        {"wallet", &send},
        {"wallet", &sendmany},
        {"wallet", &sendtoaddress},
        {"wallet", &sethdseed},
        {"wallet", &setcoinjoinrounds},
        {"wallet", &setcoinjoinamount},
        {"wallet", &setlabel},
        {"wallet", &settxfee},
        {"wallet", &setwalletflag},
        {"wallet", &signmessage},
        {"wallet", &signrawtransactionwithwallet},
        {"wallet", &simulaterawtransaction},
        {"wallet", &unloadwallet},
        {"wallet", &upgradewallet},
        {"wallet", &upgradetohd},
#ifdef ENABLE_EXTERNAL_SIGNER
        {"wallet", &walletdisplayaddress},
#endif // ENABLE_EXTERNAL_SIGNER
        {"wallet", &walletlock},
        {"wallet", &walletpassphrasechange},
        {"wallet", &walletpassphrase},
        {"wallet", &walletprocesspsbt},
        {"wallet", &walletcreatefundedpsbt},
        {"wallet", &wipewallettxes},
        {"wallet", &setwalletcredential},
        {"wallet", &getwalletcredential},
        {"wallet", &confirmownership},
        {"wallet", &generateownershipproof},
        {"wallet", &verifyownershipproof},
        {"wallet", &importcredential},
        {"wallet", &localverify},
        {"wallet", &chat},
        {"wallet", &setkycprovider},
        {"wallet", &startkyc},
        {"wallet", &completekyc},
        {"wallet", &importkyccredential},
        {"wallet", &checkkyc},
    };
    return commands;
}
} // namespace wallet
