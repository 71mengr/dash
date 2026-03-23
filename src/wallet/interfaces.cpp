// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>

#include <univalue.h>
#include <util/strencodings.h>
#include <util/message.h>
#include <key_io.h>
#include <chain.h>
#include <coinjoin/client.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <interfaces/coinjoin.h>
#include <interfaces/handler.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <script/standard.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/system.h>
#include <util/string.h>
#include <util/translation.h>
#include <util/ui_change_type.h>
#include <validation.h>
#include <wallet/coinjoin.h>
#include <wallet/context.h>
#include <wallet/fees.h>
#include <wallet/ismine.h>
#include <wallet/load.h>
#include <wallet/receive.h>
#include <wallet/rpc/wallet.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/hdchain.h>
#include <wallet/scriptpubkeyman.h>
#include <governance/validators.h>
#include <evo/deterministicmns.h>
#include <masternode/sync.h>
#include <txdb.h>
#include <node/context.h>

#include <cctype>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

using interfaces::Chain;
using interfaces::FoundBlock;
using interfaces::Handler;
using interfaces::LocalVerificationResult;
using interfaces::MakeHandler;
using interfaces::Wallet;
using interfaces::WalletAddress;
using interfaces::WalletBalances;
using interfaces::WalletVerification;
using interfaces::OwnershipProof;
using interfaces::OwnershipProofVerification;
using interfaces::WalletLoader;
using interfaces::WalletOrderForm;
using interfaces::WalletTx;
using interfaces::WalletTxOut;
using interfaces::WalletTxStatus;
using interfaces::WalletValueMap;
using node::NodeContext;

namespace wallet {
namespace {
std::string NormalizeLocalVerificationValue(std::string value)
{
    value = TrimString(value);
    return Join(SplitString(value, ' '), " ");
}

std::string NormalizeLocalVerificationCountry(std::string country)
{
    country = NormalizeLocalVerificationValue(std::move(country));
    std::transform(country.begin(), country.end(), country.begin(), [](unsigned char c) { return std::tolower(c); });
    if (!country.empty()) {
        country[0] = ToUpper(country[0]);
    }
    for (size_t i = 1; i < country.size(); ++i) {
        if (country[i - 1] == ' ' || country[i - 1] == '-') {
            country[i] = ToUpper(country[i]);
        }
    }
    return country;
}

const std::set<std::string>& ValidLocalVerificationCountries()
{
    static const std::set<std::string> countries{
        "Argentina", "Australia", "Austria", "Belgium", "Brazil", "Canada", "Chile", "Colombia",
        "Czech Republic", "Denmark", "Finland", "France", "Germany", "Greece", "Hong Kong", "Hungary",
        "Iceland", "India", "Ireland", "Israel", "Italy", "Japan", "Luxembourg", "Malaysia",
        "Mexico", "Netherlands", "New Zealand", "Norway", "Peru", "Philippines", "Poland", "Portugal",
        "Singapore", "South Africa", "South Korea", "Spain", "Sweden", "Switzerland", "Thailand",
        "United Arab Emirates", "United Kingdom", "United States"
    };
    return countries;
}

std::string NormalizeOwnershipClaim(std::string claim)
{
    std::transform(claim.begin(), claim.end(), claim.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return claim;
}

bool IsSupportedOwnershipClaim(const std::string& claim)
{
    static const std::set<std::string> supported{"full_name", "country", "age", "age_over_18", "age_band", "wallet_address"};
    return supported.count(claim) != 0;
}

UniValue BuildOwnershipProofClaims(const CWalletCredential& cred, const std::vector<std::string>& requested_claims, bilingual_str& error)
{
    UniValue claims(UniValue::VOBJ);
    for (const std::string& claim : requested_claims) {
        if (claim == "full_name") {
            if (!cred.HasAttribute("full_name")) { error = Untranslated("Credential does not contain requested claim: full_name"); return UniValue(); }
            claims.pushKV("full_name", cred.m_attributes.at("full_name"));
            continue;
        }
        if (claim == "country") {
            if (!cred.HasAttribute("country")) { error = Untranslated("Credential does not contain requested claim: country"); return UniValue(); }
            claims.pushKV("country", cred.m_attributes.at("country"));
            continue;
        }
        if (claim == "wallet_address") {
            if (!cred.HasAttribute("wallet_address")) { error = Untranslated("Credential does not contain requested claim: wallet_address"); return UniValue(); }
            claims.pushKV("wallet_address", cred.m_attributes.at("wallet_address"));
            continue;
        }
        if (!cred.HasAttribute("age")) { error = Untranslated(strprintf("Credential does not contain requested claim: %s", claim)); return UniValue(); }
        int64_t age{0};
        if (!ParseInt64(cred.m_attributes.at("age"), &age)) { error = Untranslated("Credential age claim is malformed"); return UniValue(); }
        if (claim == "age") claims.pushKV("age", age);
        else if (claim == "age_over_18") claims.pushKV("age_over_18", age >= 18);
        else if (claim == "age_band") {
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

UniValue BuildOwnershipProofPayload(const CWalletCredential& cred, const CCredentialMetadata& metadata, const std::string& subject_address, const std::string& challenge, const std::vector<std::string>& requested_claims, const std::string& recipient_pubkey, bilingual_str& error)
{
    const int64_t issued_at = GetTime();
    const int64_t expires_at = metadata.nExpiresAt > 0 ? std::min(metadata.nExpiresAt, issued_at + 300) : issued_at + 300;
    UniValue claims = BuildOwnershipProofClaims(cred, requested_claims, error);
    if (!error.empty()) return UniValue();

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("v", 1);
    payload.pushKV("subject_address", subject_address);
    payload.pushKV("claims", claims);
    if (!metadata.issuer.empty()) payload.pushKV("issuer", metadata.issuer);
    if (!metadata.credentialHash.IsNull()) {
        payload.pushKV("credential_hash", metadata.credentialHash.GetHex());
        payload.pushKV("credential_id", metadata.credentialHash.GetHex());
    }
    payload.pushKV("challenge", challenge);
    payload.pushKV("issued_at", issued_at);
    payload.pushKV("expires_at", expires_at);
    if (!recipient_pubkey.empty()) payload.pushKV("recipient_pubkey", recipient_pubkey);
    return payload;
}

//! Construct wallet tx struct.
WalletTx MakeWalletTx(CWallet& wallet, const CWalletTx& wtx)
{
    LOCK(wallet.cs_wallet);
    WalletTx result;
    bool fInputDenomFound{false}, fOutputDenomFound{false};
    result.tx = wtx.tx;
    result.txin_is_mine.reserve(wtx.tx->vin.size());
    for (const auto& txin : wtx.tx->vin) {
        result.txin_is_mine.emplace_back(InputIsMine(wallet, txin));
        if (!fInputDenomFound && result.txin_is_mine.back() && wallet.IsDenominated(txin.prevout)) {
            fInputDenomFound = true;
        }
    }
    result.txout_is_mine.reserve(wtx.tx->vout.size());
    result.txout_address.reserve(wtx.tx->vout.size());
    result.txout_address_is_mine.reserve(wtx.tx->vout.size());
    for (const auto& txout : wtx.tx->vout) {
        result.txout_is_mine.emplace_back(wallet.IsMine(txout));
        result.txout_address.emplace_back();
        result.txout_address_is_mine.emplace_back(ExtractDestination(txout.scriptPubKey, result.txout_address.back()) ?
                                                      wallet.IsMine(result.txout_address.back()) :
                                                      ISMINE_NO);
        if (!fOutputDenomFound && result.txout_address_is_mine.back() && CoinJoin::IsDenominatedAmount(txout.nValue)) {
            fOutputDenomFound = true;
        }
    }
    result.credit = CachedTxGetCredit(wallet, wtx, ISMINE_ALL);
    result.debit = CachedTxGetDebit(wallet, wtx, ISMINE_ALL);
    result.change = CachedTxGetChange(wallet, wtx);
    result.time = wtx.GetTxTime();
    result.value_map = wtx.mapValue;
    result.is_coinbase = wtx.IsCoinBase();
    result.is_platform_transfer = wtx.IsPlatformTransfer();
    // The determination of is_denominate is based on simplified checks here because in this part of the code
    // we only want to know about mixing transactions belonging to this specific wallet.
    result.is_denominate = wtx.tx->vin.size() == wtx.tx->vout.size() && // Number of inputs is same as number of outputs
                           (result.credit - result.debit) == 0 && // Transaction pays no tx fee
                           fInputDenomFound && fOutputDenomFound; // At least 1 input and 1 output are denominated belonging to the provided wallet
    return result;
}

//! Construct wallet tx status struct.
WalletTxStatus MakeWalletTxStatus(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    WalletTxStatus result;
    result.block_height =
        wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height :
        wtx.state<TxStateConflicted>() ? wtx.state<TxStateConflicted>()->conflicting_block_height :
        std::numeric_limits<int>::max();
    result.blocks_to_maturity = wallet.GetTxBlocksToMaturity(wtx);
    result.depth_in_main_chain = wallet.GetTxDepthInMainChain(wtx);
    result.time_received = wtx.nTimeReceived;
    result.lock_time = wtx.tx->nLockTime;
    result.is_trusted = CachedTxIsTrusted(wallet, wtx);
    result.is_abandoned = wtx.isAbandoned();
    result.is_coinbase = wtx.IsCoinBase();
    result.is_in_main_chain = wallet.IsTxInMainChain(wtx);
    result.is_chainlocked = wallet.IsTxChainLocked(wtx);
    result.is_islocked = wallet.IsTxLockedByInstantSend(wtx);
    return result;
}

//! Construct wallet TxOut struct.
WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const CWalletTx& wtx,
    int n,
    int depth) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = wtx.tx->vout[n];
    result.time = wtx.GetTxTime();
    result.depth_in_main_chain = depth;
    result.is_spent = wallet.IsSpent(COutPoint(wtx.GetHash(), n));
    return result;
}

WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const COutput& output) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = output.txout;
    result.time = output.time;
    result.depth_in_main_chain = output.depth;
    result.is_spent = wallet.IsSpent(output.outpoint);
    return result;
}

class WalletImpl : public Wallet
{
public:
    explicit WalletImpl(WalletContext& context, const std::shared_ptr<CWallet>& wallet) : m_context(context), m_wallet(wallet) {}

    void markDirty() override
    {
        m_wallet->MarkDirty();
    }
    bool encryptWallet(const SecureString& wallet_passphrase) override
    {
        return m_wallet->EncryptWallet(wallet_passphrase);
    }
    bool isCrypted() override { return m_wallet->IsCrypted(); }
    bool lock(bool fAllowMixing) override { return m_wallet->Lock(fAllowMixing); }
    bool unlock(const SecureString& wallet_passphrase, bool fAllowMixing) override { return m_wallet->Unlock(wallet_passphrase, fAllowMixing); }
    bool isLocked(bool fForMixing) override { return m_wallet->IsLocked(fForMixing); }
    bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
        const SecureString& new_wallet_passphrase) override
    {
        return m_wallet->ChangeWalletPassphrase(old_wallet_passphrase, new_wallet_passphrase);
    }
    wallet::RescanStatus startRescan(bool from_genesis) override
    {
        int rescan_height{0};
        if (!from_genesis) {
            std::optional<int64_t> time_first_key;
            for (auto spk_man : m_wallet->GetAllScriptPubKeyMans()) {
                int64_t time = spk_man->GetTimeFirstKey();
                if (!time_first_key || time < *time_first_key) time_first_key = time;
            }
            if (time_first_key) {
                m_wallet->chain().findFirstBlockWithTimeAndHeight(*time_first_key - TIMESTAMP_WINDOW, rescan_height,
                                                                  FoundBlock().height(rescan_height));
            }
        }

        WalletRescanReserver reserver(*m_wallet);
        if (!reserver.reserve()) {
            return wallet::RescanStatus::BUSY;
        }
        switch (m_wallet->ScanForWalletTransactions(m_wallet->chain().getBlockHash(rescan_height), rescan_height, /*max_height=*/std::nullopt,
                                                    reserver, /*fUpdate=*/true, /*save_progress=*/false).status) {
        case CWallet::ScanResult::FAILURE:
            return wallet::RescanStatus::FAILURE;
        case CWallet::ScanResult::SUCCESS:
            return wallet::RescanStatus::SUCCESS;
        case CWallet::ScanResult::USER_ABORT:
            return wallet::RescanStatus::USER_ABORT;
        }
        Assume(false); // unreachable
        return wallet::RescanStatus::FAILURE; // fallback for release builds
    }
    void abortRescan() override { m_wallet->AbortRescan(); }
    void autoLockMasternodeCollaterals() override { m_wallet->AutoLockMasternodeCollaterals(); }
    bool backupWallet(const std::string& filename) override { return m_wallet->BackupWallet(filename); }
    bool autoBackupWallet(const fs::path& wallet_path, bilingual_str& error_string, std::vector<bilingual_str>& warnings) override
    {
        return m_wallet->AutoBackupWallet(wallet_path, error_string, warnings);
    }
    int64_t getKeysLeftSinceAutoBackup() override { return m_wallet->nKeysLeftSinceAutoBackup; }
    std::string getWalletName() override { return m_wallet->GetName(); }
    util::Result<CTxDestination> getNewDestination(const std::string& label) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetNewDestination(label);
    }
    bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) override
    {
        std::unique_ptr<SigningProvider> provider = m_wallet->GetSolvingProvider(script);
        if (provider) {
            return provider->GetPubKey(address, pub_key);
        }
        return false;
    }
    SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) override
    {
        return m_wallet->SignMessage(message, pkhash, str_sig);
    }
    bool signSpecialTxPayload(const uint256& hash, const CKeyID& keyid, std::vector<unsigned char>& vchSig) override
    {
        return m_wallet->SignSpecialTxPayload(hash, keyid, vchSig);
    }
    bool isSpendable(const CScript& script) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(script) & ISMINE_SPENDABLE;
    }
    bool isSpendable(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(dest) & ISMINE_SPENDABLE;
    }
    bool haveWatchOnly() override
    {
        auto spk_man = m_wallet->GetLegacyScriptPubKeyMan();
        if (spk_man) {
            return spk_man->HaveWatchOnly();
        }
        return false;
    };
    bool setAddressBook(const CTxDestination& dest, const std::string& name, const std::string& purpose) override
    {
        return m_wallet->SetAddressBook(dest, name, purpose);
    }
    bool delAddressBook(const CTxDestination& dest) override
    {
        return m_wallet->DelAddressBook(dest);
    }
    bool getAddress(const CTxDestination& dest,
        std::string* name,
        wallet::isminetype* is_mine,
        std::string* purpose) override
    {
        LOCK(m_wallet->cs_wallet);
        const auto& entry = m_wallet->FindAddressBookEntry(dest, /*allow_change=*/false);
        if (!entry) return false; // addr not found
        if (name) {
            *name = entry->GetLabel();
        }
        if (is_mine) {
            *is_mine = m_wallet->IsMine(dest);
        }
        if (purpose) {
            *purpose = entry->purpose;
        }
        return true;
    }
    std::vector<WalletAddress> getAddresses() const override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletAddress> result;
        m_wallet->ForEachAddrBookEntry([&](const CTxDestination& dest, const std::string& label, const std::string& purpose, bool is_change) EXCLUSIVE_LOCKS_REQUIRED(m_wallet->cs_wallet) {
            if (is_change) return;
            result.emplace_back(dest, m_wallet->IsMine(dest), label, purpose);
        });
        return result;
    }
    std::vector<std::string> getAddressReceiveRequests() override {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetAddressReceiveRequests();
    }
    bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& value) override {
        LOCK(m_wallet->cs_wallet);
        WalletBatch batch{m_wallet->GetDatabase()};
        return m_wallet->SetAddressReceiveRequest(batch, dest, id, value);
    }
    bool displayAddress(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->DisplayAddress(dest);
    }
    bool lockCoin(const COutPoint& output, const bool write_to_db) override
    {
        LOCK(m_wallet->cs_wallet);
        std::unique_ptr<WalletBatch> batch = write_to_db ? std::make_unique<WalletBatch>(m_wallet->GetDatabase()) : nullptr;
        return m_wallet->LockCoin(output, batch.get());
    }
    bool unlockCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        std::unique_ptr<WalletBatch> batch = std::make_unique<WalletBatch>(m_wallet->GetDatabase());
        return m_wallet->UnlockCoin(output, batch.get());
    }
    bool isLockedCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsLockedCoin(output);
    }
    std::vector<COutPoint> listLockedCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ListLockedCoins();
    }
    std::vector<COutPoint> listProTxCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ListProTxCoins();
    }
    util::Result<CTransactionRef> createTransaction(const std::vector<CRecipient>& recipients,
        const CCoinControl& coin_control,
        bool sign,
        int& change_pos,
        CAmount& fee) override
    {
        LOCK(m_wallet->cs_wallet);
        auto res = CreateTransaction(*m_wallet, recipients, change_pos, coin_control, sign);
        if (!res) return util::Error{util::ErrorString(res)};
        const auto& txr = *res;
        fee = txr.fee;
        change_pos = txr.change_pos;

        return txr.tx;
    }
    void commitTransaction(CTransactionRef tx,
        WalletValueMap value_map,
        WalletOrderForm order_form) override
    {
        LOCK(m_wallet->cs_wallet);
        m_wallet->CommitTransaction(std::move(tx), std::move(value_map), std::move(order_form));
    }
    bool transactionCanBeAbandoned(const uint256& txid) override { return m_wallet->TransactionCanBeAbandoned(txid); }
    bool transactionCanBeResent(const uint256& txid) override { return m_wallet->TransactionCanBeResent(txid); }
    bool abandonTransaction(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->AbandonTransaction(txid);
    }
    bool resendTransaction(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ResendTransaction(txid);
    }
    CTransactionRef getTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return mi->second.tx;
        }
        return {};
    }
    WalletTx getWalletTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    std::set<WalletTx> getWalletTxs() override
    {
        LOCK(m_wallet->cs_wallet);
        std::set<WalletTx> result;
        for (const auto& entry : m_wallet->mapWallet) {
            result.emplace(MakeWalletTx(*m_wallet, entry.second));
        }
        return result;
    }
    bool tryGetTxStatus(const uint256& txid,
        interfaces::WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi == m_wallet->mapWallet.end()) {
            return false;
        }
        num_blocks = m_wallet->GetLastBlockHeight();
        block_time = -1;
        CHECK_NONFATAL(m_wallet->chain().findBlock(m_wallet->GetLastBlockHash(), FoundBlock().time(block_time)));
        tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
        return true;
    }
    WalletTx getWalletTxDetails(const uint256& txid,
        WalletTxStatus& tx_status,
        WalletOrderForm& order_form,
        bool& in_mempool,
        int& num_blocks) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            num_blocks = m_wallet->GetLastBlockHeight();
            in_mempool = mi->second.InMempool();
            order_form = mi->second.vOrderForm;
            tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    int getRealOutpointCoinJoinRounds(const COutPoint& outpoint) override { return m_wallet->GetRealOutpointCoinJoinRounds(outpoint); }
    bool isFullyMixed(const COutPoint& outpoint) override { return m_wallet->IsFullyMixed(outpoint); }

    TransactionError fillPSBT(int sighash_type,
        bool sign,
        bool bip32derivs,
        size_t* n_signed,
        PartiallySignedTransaction& psbtx,
        bool& complete) override
    {
        return m_wallet->FillPSBT(psbtx, complete, sighash_type, sign, bip32derivs, n_signed);
    }
    WalletBalances getBalances() override
    {
        const auto bal = GetBalance(*m_wallet);
        WalletBalances result;
        result.balance = bal.m_mine_trusted;
        result.unconfirmed_balance = bal.m_mine_untrusted_pending;
        result.immature_balance = bal.m_mine_immature;
        result.anonymized_balance = bal.m_anonymized;
        result.have_watch_only = haveWatchOnly();
        if (result.have_watch_only) {
            result.watch_only_balance = bal.m_watchonly_trusted;
            result.unconfirmed_watch_only_balance = bal.m_watchonly_untrusted_pending;
            result.immature_watch_only_balance = bal.m_watchonly_immature;
        }
        result.denominated_untrusted_pending = bal.m_denominated_untrusted_pending;
        result.denominated_trusted = bal.m_denominated_trusted;
        return result;
    }

    util::Result<LocalVerificationResult> runLocalVerification(const std::string& full_name_in, int age, const std::string& country_in) override
    {
        const std::string full_name = NormalizeLocalVerificationValue(full_name_in);
        if (full_name.size() < 5) {
            return util::Error{Untranslated("Full name must be at least 5 characters long")};
        }
        if (full_name.find(' ') == std::string::npos) {
            return util::Error{Untranslated("Full name must include at least first name and last name")};
        }
        for (const char ch : full_name) {
            if (!(std::isalpha(static_cast<unsigned char>(ch)) || ch == ' ' || ch == '\'' || ch == '-' || ch == '.')) {
                return util::Error{Untranslated("Full name contains unsupported characters")};
            }
        }
        if (age < 18 || age > 120) {
            return util::Error{Untranslated("Age must be between 18 and 120")};
        }

        const std::string country = NormalizeLocalVerificationCountry(country_in);
        if (!ValidLocalVerificationCountries().count(country)) {
            return util::Error{Untranslated("Country must be a supported real country name")};
        }

        const auto destination = m_wallet->GetNewDestination("");
        if (!destination) {
            return util::Error{util::ErrorString(destination)};
        }
        const std::string wallet_address = EncodeDestination(*destination);
        const std::string wallet_name = m_wallet->GetName();
        const std::string credential_str = strprintf(
            "{\"issuer\":\"local-verification\",\"type\":[\"VerifiableCredential\",\"FullKYC\"],"
            "\"credentialSubject\":{\"full_name\":\"%s\",\"full_name_hash\":\"%s\",\"email\":\"%s\",\"email_hash\":\"%s\","
            "\"country\":\"%s\",\"age\":%d,\"owner_name\":\"%s\",\"owner_name_verified\":true,\"wallet\":\"%s\",\"wallet_address\":\"%s\"}}",
            full_name,
            Hash(full_name).GetHex(),
            wallet_name,
            Hash(wallet_name).GetHex(),
            country,
            age,
            full_name,
            wallet_name,
            wallet_address);

        std::vector<unsigned char> credential_data(credential_str.begin(), credential_str.end());
        LocalVerificationProvider provider;
        CCredentialMetadata metadata;
        if (!provider.VerifyCredential(credential_data, metadata)) {
            return util::Error{Untranslated("Local verification failed")};
        }

        CWalletCredential credential;
        if (!credential.SetCredential(credential_data)) {
            return util::Error{Untranslated("Failed to create local verification credential")};
        }
        credential.SetMetadata(metadata);

        {
            LOCK(m_wallet->cs_wallet);
            WalletBatch batch(m_wallet->GetDatabase());
            if (!batch.WriteCredential(credential)) {
                return util::Error{Untranslated("Failed to write credential to database")};
            }
            if (!batch.WriteCredentialMetadata(metadata) || !batch.WriteCredentialStatus(credential.GetStatus())) {
                return util::Error{Untranslated("Failed to persist credential metadata")};
            }
            m_wallet->SetCredential(credential);
        }

        LocalVerificationResult result;
        result.full_name = full_name;
        result.age = age;
        result.country = country;
        result.wallet_name = wallet_name;
        result.wallet_address = wallet_address;
        return result;
    }

    util::Result<OwnershipProof> generateOwnershipProof(const std::string& challenge_in, const std::vector<std::string>& requested_claims_in, const std::string& subject_address, const std::string& recipient_pubkey) override
    {
        const std::string challenge = TrimString(challenge_in);
        if (challenge.empty()) return util::Error{Untranslated("Challenge must not be empty")};
        if (!IsValidDestinationString(subject_address)) return util::Error{Untranslated("Invalid subject address")};

        std::vector<std::string> requested_claims;
        std::set<std::string> seen_claims;
        for (const std::string& raw_claim : requested_claims_in) {
            const std::string claim = NormalizeOwnershipClaim(raw_claim);
            if (!IsSupportedOwnershipClaim(claim)) {
                return util::Error{Untranslated(strprintf("Unsupported requested claim: %s", raw_claim))};
            }
            if (seen_claims.insert(claim).second) requested_claims.push_back(claim);
        }
        if (requested_claims.empty()) return util::Error{Untranslated("Select at least one claim to disclose")};

        LOCK(m_wallet->cs_wallet);
        const CWalletCredential cred = m_wallet->GetCredential();
        const CCredentialMetadata metadata = cred.GetMetadata();
        if (!cred.IsValid()) return util::Error{Untranslated(strprintf("Wallet credential is not valid: %s", cred.GetVerificationFailureReason()))};

        const auto dest = DecodeDestination(subject_address);
        const PKHash* pkhash = std::get_if<PKHash>(&dest);
        if (!pkhash) return util::Error{Untranslated("Subject address does not refer to a key")};
        if (m_wallet->IsMine(dest) == ISMINE_NO) return util::Error{Untranslated("Subject address does not belong to this wallet")};
        if (cred.HasAttribute("wallet_address") && cred.m_attributes.at("wallet_address") != subject_address) {
            return util::Error{Untranslated("Subject address does not match the verified wallet address in the credential")};
        }

        bilingual_str payload_error;
        const UniValue payload = BuildOwnershipProofPayload(cred, metadata, subject_address, challenge, requested_claims, recipient_pubkey, payload_error);
        if (!payload_error.empty()) return util::Error{payload_error};
        const std::string payload_str = payload.write();

        std::string signature;
        const SigningResult err = m_wallet->SignMessage(payload_str, *pkhash, signature);
        if (err != SigningResult::OK) return util::Error{Untranslated(SigningResultString(err))};

        UniValue proof(UniValue::VOBJ);
        proof.pushKV("payload", payload);
        proof.pushKV("subject_address", subject_address);
        proof.pushKV("signature", signature);
        proof.pushKV("signature_type", "wallet-message");

        OwnershipProof result;
        result.proof = proof.write();
        result.payload = payload_str;
        result.signature = signature;
        result.expires_at = payload["expires_at"].getInt<int64_t>();
        return result;
    }

    util::Result<OwnershipProofVerification> verifyOwnershipProof(const std::string& proof_string) override
    {
        UniValue proof(UniValue::VOBJ);
        if (!proof.read(proof_string) || !proof.isObject()) return util::Error{Untranslated("Proof must be a valid JSON object serialized as a string")};
        if (!proof.exists("payload") || !proof["payload"].isObject()) return util::Error{Untranslated("Proof is missing payload")};
        if (!proof.exists("subject_address") || !proof["subject_address"].isStr()) return util::Error{Untranslated("Proof is missing subject address")};
        if (!proof.exists("signature") || !proof["signature"].isStr()) return util::Error{Untranslated("Proof is missing signature")};

        const UniValue payload = proof["payload"].get_obj();
        const std::string subject = proof["subject_address"].get_str();
        const std::string signature = proof["signature"].get_str();
        const std::string payload_str = payload.write();

        OwnershipProofVerification result;
        switch (MessageVerify(subject, signature, payload_str)) {
        case MessageVerificationResult::OK: break;
        case MessageVerificationResult::ERR_INVALID_ADDRESS: result.reason = "invalid_address"; return result;
        case MessageVerificationResult::ERR_ADDRESS_NO_KEY: result.reason = "address_no_key"; return result;
        case MessageVerificationResult::ERR_MALFORMED_SIGNATURE: result.reason = "malformed_signature"; return result;
        case MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED:
        case MessageVerificationResult::ERR_NOT_SIGNED: result.reason = "invalid_signature"; return result;
        }
        if (!payload.exists("expires_at") || !payload["expires_at"].isNum()) { result.reason = "missing_expiry"; return result; }
        if (!payload.exists("challenge") || !payload["challenge"].isStr() || payload["challenge"].get_str().empty()) { result.reason = "challenge_mismatch"; return result; }
        if (!payload.exists("subject_address") || !payload["subject_address"].isStr() || payload["subject_address"].get_str() != subject) { result.reason = "subject_address_mismatch"; return result; }
        const int64_t expires_at = payload["expires_at"].getInt<int64_t>();
        if (GetTime() > expires_at) { result.reason = "expired"; return result; }
        if (payload.exists("revoked") && payload["revoked"].isBool() && payload["revoked"].get_bool()) { result.reason = "revoked"; return result; }

        result.valid = true;
        result.expires_at = expires_at;
        result.challenge = payload["challenge"].get_str();
        result.subject_address = subject;
        if (payload.exists("claims") && payload["claims"].isObject()) result.claims = payload["claims"].write(2);
        if (payload.exists("issuer") && payload["issuer"].isStr()) result.issuer = payload["issuer"].get_str();
        if (payload.exists("credential_id") && payload["credential_id"].isStr()) result.credential_id = payload["credential_id"].get_str();
        if (payload.exists("credential_hash") && payload["credential_hash"].isStr()) result.credential_hash = payload["credential_hash"].get_str();
        return result;
    }

    WalletVerification getVerification() override
    {
        LOCK(m_wallet->cs_wallet);
        WalletVerification result;
        result.is_verified = m_wallet->IsVerified();
        result.can_generate_addresses = m_wallet->CanGenerateAddresses();
        result.failure_reason = m_wallet->GetVerificationFailureReason();

        std::string status;
        switch (m_wallet->GetVerificationStatus()) {
        case CredentialStatus::NONE: status = "none"; break;
        case CredentialStatus::PENDING: status = "pending"; break;
        case CredentialStatus::VERIFIED_BASIC: status = "basic"; break;
        case CredentialStatus::VERIFIED_FULL: status = "full"; break;
        case CredentialStatus::EXPIRED: status = "expired"; break;
        case CredentialStatus::REVOKED: status = "revoked"; break;
        default: status = "unknown"; break;
        }
        result.status = status;

        const CWalletCredential credential = m_wallet->GetCredential();
        const CCredentialMetadata metadata = credential.GetMetadata();
        result.has_credential = !credential.GetCredential().empty();
        result.issuer = metadata.issuer;
        result.credential_type = metadata.credentialType;
        result.expires_at = metadata.nExpiresAt;
        if (!metadata.credentialHash.IsNull()) {
            result.credential_hash = metadata.credentialHash.GetHex();
        }
        if (credential.HasAttribute("wallet_address")) {
            result.wallet_address = credential.m_attributes.at("wallet_address");
        }
        return result;
    }
    bool tryGetBalances(WalletBalances& balances, uint256& block_hash) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        block_hash = m_wallet->GetLastBlockHash();
        balances = getBalances();
        return true;
    }
    CAmount getBalance() override { return GetBalance(*m_wallet).m_mine_trusted; }
    CAmount getAnonymizableBalance(bool fSkipDenominated, bool fSkipUnconfirmed) override
    {
        return m_wallet->GetAnonymizableBalance(fSkipDenominated, fSkipUnconfirmed);
    }
    CAmount getNormalizedAnonymizedBalance() override
    {
        return m_wallet->GetNormalizedAnonymizedBalance();
    }
    CAmount getAverageAnonymizedRounds() override
    {
        return m_wallet->GetAverageAnonymizedRounds();
    }
    CAmount getAvailableBalance(const CCoinControl& coin_control) override
    {
        if (coin_control.IsUsingCoinJoin()) {
            return GetBalanceAnonymized(*m_wallet, coin_control);
        } else {
            return GetAvailableBalance(*m_wallet, &coin_control);
        }
    }
    wallet::isminetype txinIsMine(const CTxIn& txin) override
    {
        LOCK(m_wallet->cs_wallet);
        return InputIsMine(*m_wallet, txin);
    }
    wallet::isminetype txoutIsMine(const CTxOut& txout) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(txout);
    }
    CAmount getDebit(const CTxIn& txin, wallet::isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetDebit(txin, filter);
    }
    CAmount getCredit(const CTxOut& txout, wallet::isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return OutputGetCredit(*m_wallet, txout, filter);
    }
    CoinsList listCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        CoinsList result;
        for (const auto& entry : ListCoins(*m_wallet)) {
            auto& group = result[entry.first];
            for (const auto& coin : entry.second) {
                group.emplace_back(coin.outpoint,
                    MakeWalletTxOut(*m_wallet, coin));
            }
        }
        return result;
    }
    std::vector<WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletTxOut> result;
        result.reserve(outputs.size());
        for (const auto& output : outputs) {
            result.emplace_back();
            auto it = m_wallet->mapWallet.find(output.hash);
            if (it != m_wallet->mapWallet.end()) {
                int depth = m_wallet->GetTxDepthInMainChain(it->second);
                if (depth >= 0) {
                    result.back() = MakeWalletTxOut(*m_wallet, it->second, output.n, depth);
                }
            }
        }
        return result;
    }
    CAmount getRequiredFee(unsigned int tx_bytes) override { return GetRequiredFee(*m_wallet, tx_bytes); }
    CAmount getMinimumFee(unsigned int tx_bytes,
        const CCoinControl& coin_control,
        int* returned_target,
        FeeReason* reason) override
    {
        FeeCalculation fee_calc;
        CAmount result;
        result = GetMinimumFee(*m_wallet, tx_bytes, coin_control, &fee_calc);
        if (returned_target) *returned_target = fee_calc.returnedTarget;
        if (reason) *reason = fee_calc.reason;
        return result;
    }
    unsigned int getConfirmTarget() override { return m_wallet->m_confirm_target; }
    bool hdEnabled() override { return m_wallet->IsHDEnabled(); }
    bool canGetAddresses() override { return m_wallet->CanGetAddresses(); }
    bool hasExternalSigner() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER); }
    bool privateKeysDisabled() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS); }
    CAmount getDefaultMaxTxFee() override { return m_wallet->m_default_max_tx_fee; }
    void remove() override
    {
        RemoveWallet(m_context, m_wallet, false /* load_on_start */);
    }
    bool isLegacy() override { return m_wallet->IsLegacy(); }
    bool getMnemonic(SecureString& mnemonic_out, SecureString& mnemonic_passphrase_out) override
    {
        LOCK(m_wallet->cs_wallet);

        mnemonic_out.clear();
        mnemonic_passphrase_out.clear();

        if (m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            return false;
        }

        if (m_wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            // Descriptor wallet
            for (auto spk_man : m_wallet->GetActiveScriptPubKeyMans()) {
                if (auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)) {
                    if (desc_spk_man->GetMnemonicString(mnemonic_out, mnemonic_passphrase_out)) {
                        return true;
                    }
                }
            }
            return false;
        } else {
            // Legacy wallet
            auto spk_man = m_wallet->GetLegacyScriptPubKeyMan();
            if (!spk_man) {
                return false;
            }

            CHDChain hdChainCurrent;
            if (!spk_man->GetHDChain(hdChainCurrent)) {
                return false;
            }

            // Get decrypted HD chain if wallet is encrypted
            if (m_wallet->IsCrypted()) {
                if (!spk_man->GetDecryptedHDChain(hdChainCurrent)) {
                    return false;
                }
            }

            return hdChainCurrent.GetMnemonic(mnemonic_out, mnemonic_passphrase_out);
        }
    }
    std::unique_ptr<Handler> handleUnload(UnloadFn fn) override
    {
        return MakeHandler(m_wallet->NotifyUnload.connect(fn));
    }
    std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) override
    {
        return MakeHandler(m_wallet->ShowProgress.connect(fn));
    }
    std::unique_ptr<Handler> handleStatusChanged(StatusChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyStatusChanged.connect([fn](CWallet*) { fn(); }));
    }
    std::unique_ptr<Handler> handleAddressBookChanged(AddressBookChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyAddressBookChanged.connect(
            [fn](const CTxDestination& address, const std::string& label, bool is_mine,
                 const std::string& purpose, ChangeType status) { fn(address, label, is_mine, purpose, status); }));
    }
    std::unique_ptr<Handler> handleTransactionChanged(TransactionChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyTransactionChanged.connect(
            [fn](const uint256& txid, ChangeType status) { fn(txid, status); }));
    }
    std::unique_ptr<Handler> handleInstantLockReceived(InstantLockReceivedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyISLockReceived.connect(
            [fn]() { fn(); }));
    }
    std::unique_ptr<Handler> handleChainLockReceived(ChainLockReceivedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyChainLockReceived.connect(
            [fn](int chainLockHeight) { fn(chainLockHeight); }));
    }
    std::unique_ptr<Handler> handleWatchOnlyChanged(WatchOnlyChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyWatchonlyChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyCanGetAddressesChanged.connect(fn));
    }
    std::vector<Governance::Object> getGovernanceObjects() override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<Governance::Object> result;
        for (const auto* obj : m_wallet->GetGovernanceObjects()) {
            result.push_back(*obj);
        }
        return result;
    }
    bool prepareProposal(const uint256& govobj_hash, CAmount fee, int32_t revision, int64_t created_time,
                         const std::string& data_hex, const COutPoint& outpoint,
                         std::string& out_fee_txid, std::string& error) override
    {
        LOCK(m_wallet->cs_wallet);
        CTransactionRef tx;
        if (!GenBudgetSystemCollateralTx(*m_wallet, tx, govobj_hash, fee, outpoint)) {
            error = "Error making collateral transaction for governance object.";
            return false;
        }
        if (!m_wallet->WriteGovernanceObject(Governance::Object{uint256{}, revision, created_time, tx->GetHash(), data_hex})) {
            error = "WriteGovernanceObject failed";
            return false;
        }
        m_wallet->CommitTransaction(tx, {}, {});
        out_fee_txid = tx->GetHash().ToString();
        return true;
    }
    bool signGovernanceVote(const CKeyID& keyID, CGovernanceVote& vote) override
    {
        return m_wallet->SignGovernanceVote(keyID, vote);
    }
    CWallet* wallet() override { return m_wallet.get(); }

    WalletContext& m_context;
    std::shared_ptr<CWallet> m_wallet;
};

class WalletLoaderImpl : public WalletLoader
{
private:
    void RegisterRPCs(const Span<const CRPCCommand>& commands)
    {
        for (const CRPCCommand& command : commands) {
            m_rpc_commands.emplace_back(command.category, command.name, [this, &command](const JSONRPCRequest& request, UniValue& result, bool last_handler) {
                JSONRPCRequest wallet_request = request;
                wallet_request.context = m_context;
                return command.actor(wallet_request, result, last_handler);
            }, command.argNames, command.unique_id);
            m_rpc_handlers.emplace_back(m_context.chain->handleRpc(m_rpc_commands.back()));
        }
    }

public:
    WalletLoaderImpl(Chain& chain, ArgsManager& args, NodeContext& node_context,
                     interfaces::CoinJoin::Loader& coinjoin_loader)
    {
        m_context.chain = &chain;
        m_context.args = &args;
        m_context.node_context = &node_context;
        m_context.coinjoin_loader = &coinjoin_loader;
    }
    ~WalletLoaderImpl() override { UnloadWallets(m_context); }

    //! ChainClient methods
    void registerRpcs() override
    {
        RegisterRPCs(GetWalletRPCCommands());
    }
    bool verify() override { return VerifyWallets(m_context); }
    bool load() override { return LoadWallets(m_context); }
    void start(CScheduler& scheduler) override { return StartWallets(m_context, scheduler); }
    void flush() override { return FlushWallets(m_context); }
    void stop() override { return StopWallets(m_context); }
    void setMockTime(int64_t time) override { return SetMockTime(time); }

    //! WalletLoader methods
    void registerOtherRpcs(const Span<const CRPCCommand>& commands) override
    {
        return RegisterRPCs(commands);
    }
    util::Result<std::unique_ptr<Wallet>> createWallet(const std::string& name, const SecureString& passphrase, uint64_t wallet_creation_flags, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_create = true;
        options.create_flags = wallet_creation_flags;
        options.create_passphrase = passphrase;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, CreateWallet(m_context, name, /*load_on_start=*/true, options, status, error, warnings))};
        if (wallet) {
            return {std::move(wallet)};
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> loadWallet(const std::string& name, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_existing = true;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, LoadWallet(m_context, name, /*load_on_start=*/true, options, status, error, warnings))};
        if (wallet) {
            return {std::move(wallet)};
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> restoreWallet(const fs::path& backup_file, const std::string& wallet_name, std::vector<bilingual_str>& warnings) override
    {
        DatabaseStatus status;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, RestoreWallet(m_context, backup_file, wallet_name, /*load_on_start=*/true, status, error, warnings))};
        if (wallet) {
            return {std::move(wallet)};
        } else {
            return util::Error{error};
        }
    }
    std::string getWalletDir() override
    {
        return fs::PathToString(GetWalletDir());
    }
    std::vector<std::string> listWalletDir() override
    {
        std::vector<std::string> paths;
        for (auto& path : ListDatabases(GetWalletDir())) {
            paths.push_back(fs::PathToString(path));
        }
        return paths;
    }
    std::vector<std::unique_ptr<Wallet>> getWallets() override
    {
        std::vector<std::unique_ptr<Wallet>> wallets;
        for (const auto& wallet : GetWallets(m_context)) {
            wallets.emplace_back(MakeWallet(m_context, wallet));
        }
        return wallets;
    }
    std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) override
    {
        return HandleLoadWallet(m_context, std::move(fn));
    }
    WalletContext* context() override  { return &m_context; }

    WalletContext m_context;
    const std::vector<std::string> m_wallet_filenames;
    std::vector<std::unique_ptr<Handler>> m_rpc_handlers;
    std::list<CRPCCommand> m_rpc_commands;
};
} // namespace
} // namespace wallet

namespace interfaces {
std::unique_ptr<Wallet> MakeWallet(wallet::WalletContext& context, const std::shared_ptr<wallet::CWallet>& wallet) { return wallet ? std::make_unique<wallet::WalletImpl>(context, wallet) : nullptr; }
std::unique_ptr<WalletLoader> MakeWalletLoader(Chain& chain, ArgsManager& args, NodeContext& node_context,
                                               interfaces::CoinJoin::Loader& coinjoin_loader)
{
    return std::make_unique<wallet::WalletLoaderImpl>(chain, args, node_context, coinjoin_loader);
}
} // namespace interfaces
