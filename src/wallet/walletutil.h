// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETUTIL_H
#define BITCOIN_WALLET_WALLETUTIL_H

#include <fs.h>
#include <script/descriptor.h>

#include <vector>
#include <map>
#include <string>

namespace wallet {
/** (client) version numbers for particular wallet features */
enum WalletFeature
{
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getwalletinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys
    FEATURE_HD = 120200,    // Hierarchical key derivation after BIP32 (HD Wallet), BIP44 (multi-coin), BIP39 (mnemonic)
                            // which uses on-the-fly private key derivation

    // NEW: KYC/credential features
    FEATURE_KYC_BASIC = 130000,   // Basic KYC support (credential storage)
    FEATURE_KYC_FULL = 130100,    // Full KYC with provider integration
    FEATURE_KYC_ZKPROOF = 130200, // Zero-knowledge proof support

    FEATURE_LATEST = FEATURE_KYC_ZKPROOF
};

bool IsFeatureSupported(int wallet_version, int feature_version);
WalletFeature GetClosestWalletFeature(int version);

enum WalletFlags : uint64_t {
    // wallet flags in the upper section (> 1 << 31) will lead to not opening the wallet if flag is unknown
    // unknown wallet flags in the lower section <= (1 << 31) will be tolerated

    // will categorize coins as clean (not reused) and dirty (reused), and handle
    // them with privacy considerations in mind
    WALLET_FLAG_AVOID_REUSE = (1ULL << 0),

    // Indicates that the metadata has been upgraded to contain key origins
    WALLET_FLAG_KEY_ORIGIN_METADATA = (1ULL << 1),

    // Indicates that the descriptor cache has been upgraded to cache last hardened xpubs
    WALLET_FLAG_LAST_HARDENED_XPUB_CACHED = (1ULL << 2),

    // will enforce the rule that the wallet can't contain any private keys (only watch-only/pubkeys)
    WALLET_FLAG_DISABLE_PRIVATE_KEYS = (1ULL << 32),

    //! Flag set when a wallet contains no HD seed and no private keys, scripts,
    //! addresses, and other watch only things, and is therefore "blank."
    //!
    //! The only function this flag serves is to distinguish a blank wallet from
    //! a newly created wallet when the wallet database is loaded, to avoid
    //! initialization that should only happen on first run.
    //!
    //! This flag is also a mandatory flag to prevent previous versions of
    //! bitcoin from opening the wallet, thinking it was newly created, and
    //! then improperly reinitializing it.
    WALLET_FLAG_BLANK_WALLET = (1ULL << 33),

    //! Indicate that this wallet supports DescriptorScriptPubKeyMan
    WALLET_FLAG_DESCRIPTORS = (1ULL << 34),

    //! Indicates that the wallet needs an external signer
    WALLET_FLAG_EXTERNAL_SIGNER = (1ULL << 35),

    // NEW: KYC-related flags
    //! Wallet requires KYC verification for operations
    WALLET_FLAG_REQUIRE_VERIFICATION = (1ULL << 36),

    //! Wallet has KYC auto-renewal enabled
    WALLET_FLAG_KYC_AUTO_RENEW = (1ULL << 37),

    //! Wallet supports selective disclosure (ZK-proofs)
    WALLET_FLAG_KYC_ZKPROOF = (1ULL << 38),
};

// KYC provider types (moved from kyc_provider.h to keep flags in one place)
enum class KYCProviderType : uint8_t {
    NONE = 0,
    COINFIRM = 1,      // Dash's existing partner
    ONFIDO = 2,        // Popular KYC provider
    JUMIO = 3,         // Another major provider
    CUSTOM_VC = 4,     // Verifiable Credentials (DID)
    INTERNAL = 5,      // Built-in local verification provider
    DIDIT = 6          // Didit identity verification
};

// Convert KYCProviderType to string
inline std::string KYCProviderTypeToString(KYCProviderType type)
{
    switch (type) {
        case KYCProviderType::NONE: return "none";
        case KYCProviderType::COINFIRM: return "coinfirm";
        case KYCProviderType::ONFIDO: return "onfido";
        case KYCProviderType::JUMIO: return "jumio";
        case KYCProviderType::CUSTOM_VC: return "verifiable-credentials";
        case KYCProviderType::INTERNAL: return "local-verification";
        case KYCProviderType::DIDIT: return "didit";
        default: return "unknown";
    }
}

// Convert string to KYCProviderType
inline KYCProviderType StringToKYCProviderType(const std::string& str)
{
    if (str == "coinfirm") return KYCProviderType::COINFIRM;
    if (str == "onfido") return KYCProviderType::ONFIDO;
    if (str == "jumio") return KYCProviderType::JUMIO;
    if (str == "verifiable-credentials" || str == "vc") return KYCProviderType::CUSTOM_VC;
    if (str == "internal" || str == "local" || str == "local-verification") return KYCProviderType::INTERNAL;
    if (str == "didit") return KYCProviderType::DIDIT;
    return KYCProviderType::NONE;
}

// KYC feature levels.
enum class KYCFeatureLevel : uint8_t {
    NONE = 0,
    BASIC_LEVEL = 1, // Basic credential storage
    FULL_LEVEL = 2,  // Provider integration
    ZKPROOF_LEVEL = 3 // Zero-knowledge proofs
};

bool IsKYCFeatureSupported(int wallet_version, KYCFeatureLevel level);
WalletFeature GetMinimumKYCVersion(KYCFeatureLevel level);
KYCProviderType ParseKYCProvider(const std::string& provider_str, std::string& error);
std::vector<KYCProviderType> GetAvailableKYCProviders();
std::map<std::string, std::string> GetDefaultKYCConfig(KYCProviderType type);

// Update known flags to include new KYC flags
static constexpr uint64_t KNOWN_WALLET_FLAGS =
        WALLET_FLAG_AVOID_REUSE
    |   WALLET_FLAG_BLANK_WALLET
    |   WALLET_FLAG_KEY_ORIGIN_METADATA
    |   WALLET_FLAG_LAST_HARDENED_XPUB_CACHED
    |   WALLET_FLAG_DISABLE_PRIVATE_KEYS
    |   WALLET_FLAG_DESCRIPTORS
    |   WALLET_FLAG_EXTERNAL_SIGNER
    |   WALLET_FLAG_REQUIRE_VERIFICATION      // NEW
    |   WALLET_FLAG_KYC_AUTO_RENEW            // NEW
    |   WALLET_FLAG_KYC_ZKPROOF;              // NEW


static const std::map<std::string, WalletFlags> WALLET_FLAG_MAP{
    {"avoid_reuse", WALLET_FLAG_AVOID_REUSE},
    {"blank", WALLET_FLAG_BLANK_WALLET},
    {"key_origin_metadata", WALLET_FLAG_KEY_ORIGIN_METADATA},
    {"last_hardened_xpub_cached", WALLET_FLAG_LAST_HARDENED_XPUB_CACHED},
    {"disable_private_keys", WALLET_FLAG_DISABLE_PRIVATE_KEYS},
    {"descriptor_wallet", WALLET_FLAG_DESCRIPTORS},
    {"external_signer", WALLET_FLAG_EXTERNAL_SIGNER},
    {"require_verification", WALLET_FLAG_REQUIRE_VERIFICATION},
    {"kyc_auto_renew", WALLET_FLAG_KYC_AUTO_RENEW},
    {"kyc_zkproof", WALLET_FLAG_KYC_ZKPROOF},
};

// Mutable flags (can be changed after wallet creation)
static constexpr uint64_t MUTABLE_WALLET_FLAGS =
        WALLET_FLAG_AVOID_REUSE
    |   WALLET_FLAG_KYC_AUTO_RENEW;            // NEW - can toggle auto-renewal

//! Get the path of the wallet directory.
fs::path GetWalletDir();

/** Descriptor with some wallet metadata */
class WalletDescriptor
{
public:
    std::shared_ptr<Descriptor> descriptor;
    uint256 id; // Descriptor ID (calculated once at descriptor initialization/deserialization)
    uint64_t creation_time = 0;
    int32_t range_start = 0; // First item in range; start of range, inclusive, i.e. [range_start, range_end). This never changes.
    int32_t range_end = 0; // Item after the last; end of range, exclusive, i.e. [range_start, range_end]. This will increment with each TopUp()
    int32_t next_index = 0; // Position of the next item to generate
    DescriptorCache cache;

    void DeserializeDescriptor(const std::string& str)
    {
        std::string error;
        FlatSigningProvider keys;
        descriptor = Parse(str, keys, error, true);
        if (!descriptor) {
            throw std::ios_base::failure("Invalid descriptor: " + error);
        }
        id = DescriptorID(*descriptor);
    }

    SERIALIZE_METHODS(WalletDescriptor, obj)
    {
        std::string descriptor_str;
        SER_WRITE(obj, descriptor_str = obj.descriptor->ToString());
        READWRITE(descriptor_str, obj.creation_time, obj.next_index, obj.range_start, obj.range_end);
        SER_READ(obj, obj.DeserializeDescriptor(descriptor_str));
     }

    WalletDescriptor() {}
    WalletDescriptor(std::shared_ptr<Descriptor> descriptor, uint64_t creation_time, int32_t range_start, int32_t range_end, int32_t next_index) : descriptor(descriptor), id(DescriptorID(*descriptor)), creation_time(creation_time), range_start(range_start), range_end(range_end), next_index(next_index) { }
};

// NEW: KYC configuration structure
struct KYCConfig
{
    KYCProviderType provider_type{KYCProviderType::NONE};
    std::map<std::string, std::string> provider_config;
    int64_t last_renewal_check{0};
    bool auto_renew{false};
    
    SERIALIZE_METHODS(KYCConfig, obj)
    {
        uint8_t provider_byte = static_cast<uint8_t>(obj.provider_type);
        READWRITE(provider_byte);
        READWRITE(obj.provider_config);
        READWRITE(obj.last_renewal_check);
        READWRITE(obj.auto_renew);
        obj.provider_type = static_cast<KYCProviderType>(provider_byte);
    }
};

} // namespace wallet

#endif // BITCOIN_WALLET_WALLETUTIL_H
