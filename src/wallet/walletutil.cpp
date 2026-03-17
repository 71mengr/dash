// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletutil.h>

#include <logging.h>
#include <util/system.h>

namespace wallet {
fs::path GetWalletDir()
{
    fs::path path;

    if (gArgs.IsArgSet("-walletdir")) {
        path = gArgs.GetPathArg("-walletdir");
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = gArgs.GetDataDirNet();
        // If a wallets directory exists, use that, otherwise default to GetDataDir
        if (fs::is_directory(path / "wallets")) {
            path /= "wallets";
        }
    }

    return path;
}

bool IsFeatureSupported(int wallet_version, int feature_version)
{
    return wallet_version >= feature_version;
}

WalletFeature GetClosestWalletFeature(int version)
{
    static constexpr std::array wallet_features{
        FEATURE_LATEST,
        FEATURE_KYC_ZKPROOF,      // NEW
        FEATURE_KYC_FULL,         // NEW
        FEATURE_KYC_BASIC,        // NEW
        FEATURE_HD,
        FEATURE_COMPRPUBKEY,
        FEATURE_WALLETCRYPT,
        FEATURE_BASE
    };
    for (const WalletFeature& wf : wallet_features) {
        if (version >= wf) return wf;
    }
    return static_cast<WalletFeature>(0);
}

// NEW: Helper function to check if wallet supports KYC features
bool IsKYCFeatureSupported(int wallet_version, KYCFeatureLevel level)
{
    switch (level) {
        case KYCFeatureLevel::BASIC:
            return IsFeatureSupported(wallet_version, FEATURE_KYC_BASIC);
        case KYCFeatureLevel::FULL:
            return IsFeatureSupported(wallet_version, FEATURE_KYC_FULL);
        case KYCFeatureLevel::ZKPROOF:
            return IsFeatureSupported(wallet_version, FEATURE_KYC_ZKPROOF);
        default:
            return false;
    }
}

// NEW: Get minimum wallet version for KYC features
WalletFeature GetMinimumKYCVersion(KYCFeatureLevel level)
{
    switch (level) {
        case KYCFeatureLevel::BASIC:
            return FEATURE_KYC_BASIC;
        case KYCFeatureLevel::FULL:
            return FEATURE_KYC_FULL;
        case KYCFeatureLevel::ZKPROOF:
            return FEATURE_KYC_ZKPROOF;
        default:
            return FEATURE_BASE;
    }
}

// NEW: Parse KYC provider from string with validation
KYCProviderType ParseKYCProvider(const std::string& provider_str, std::string& error)
{
    KYCProviderType type = StringToKYCProviderType(provider_str);
    
    if (type == KYCProviderType::NONE && provider_str != "none") {
        error = strprintf("Unknown KYC provider: %s", provider_str);
    }
    
    // Check if provider is available in this build
    if (type == KYCProviderType::COINFIRM) {
        // Coinfirm is always available as it's Dash's partner
        return type;
    }
    
    // Add checks for other providers based on build configuration
#ifdef ENABLE_ONFIDO
    if (type == KYCProviderType::ONFIDO) return type;
#endif
    
#ifdef ENABLE_JUMIO
    if (type == KYCProviderType::JUMIO) return type;
#endif
    
    if (type == KYCProviderType::CUSTOM_VC) {
        // Verifiable Credentials support is always available
        return type;
    }
    
    if (type == KYCProviderType::INTERNAL) {
        // Internal test provider only available in debug builds
#ifdef DEBUG
        return type;
#else
        error = "Internal test provider only available in debug builds";
        return KYCProviderType::NONE;
#endif
    }
    
    if (type != KYCProviderType::NONE) {
        error = strprintf("KYC provider %s not supported in this build", provider_str);
    }
    
    return type;
}

// NEW: Get list of available KYC providers
std::vector<KYCProviderType> GetAvailableKYCProviders()
{
    std::vector<KYCProviderType> providers;
    
    // Always available
    providers.push_back(KYCProviderType::COINFIRM);
    providers.push_back(KYCProviderType::CUSTOM_VC);
    
    // Optional providers based on build flags
#ifdef ENABLE_ONFIDO
    providers.push_back(KYCProviderType::ONFIDO);
#endif
    
#ifdef ENABLE_JUMIO
    providers.push_back(KYCProviderType::JUMIO);
#endif
    
#ifdef DEBUG
    providers.push_back(KYCProviderType::INTERNAL);
#endif
    
    return providers;
}

// NEW: Get default KYC provider configuration
std::map<std::string, std::string> GetDefaultKYCConfig(KYCProviderType type)
{
    std::map<std::string, std::string> config;
    
    switch (type) {
        case KYCProviderType::COINFIRM:
            // Default Coinfirm configuration
            config["api_url"] = "https://api.coinfirm.com";
            config["timeout"] = "30";
            break;
            
        case KYCProviderType::ONFIDO:
            config["api_url"] = "https://api.onfido.com";
            config["timeout"] = "30";
            break;
            
        case KYCProviderType::JUMIO:
            config["api_url"] = "https://api.jumio.com";
            config["timeout"] = "30";
            break;
            
        case KYCProviderType::CUSTOM_VC:
            config["trusted_issuers"] = "";
            break;
            
        case KYCProviderType::INTERNAL:
            config["mock_mode"] = "true";
            break;
            
        default:
            break;
    }
    
    return config;
}

} // namespace wallet
