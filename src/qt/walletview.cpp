// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletview.h>

#include <node/psbt.h>
#include <node/transaction.h>
#include <policy/policy.h>
#include <qt/addressbookpage.h>
#include <qt/askpassphrasedialog.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/guiutil_font.h>
#include <qt/mnemonicverificationdialog.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/receivecoinsdialog.h>
#include <qt/rpcconsole.h>
#include <qt/sendcoinsdialog.h>
#include <qt/signverifymessagedialog.h>
#include <qt/transactionrecord.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <node/interface_ui.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QProgressDialog>
#include <QPushButton>
#include <QInputDialog>
#include <QLineEdit>
#include <QSettings>
#include <QVBoxLayout>

WalletView::WalletView(WalletModel* wallet_model, QWidget* parent)
    : QStackedWidget(parent),
      walletModel(wallet_model)
{
    assert(walletModel);
    const auto executeWalletRpc = [this](const QString& title, const QString& command) {
        try {
            std::string result;
            std::string filtered;
            const bool ok = RPCConsole::RPCExecuteCommandLine(walletModel->node(), result, command.toStdString(), &filtered, walletModel);
            QMessageBox::information(
                this,
                title,
                ok
                    ? tr("Command:\n%1\n\nResult:\n%2").arg(command, QString::fromStdString(result))
                    : tr("Command failed:\n%1\n\nError:\n%2").arg(command, QString::fromStdString(result)));
        } catch (const UniValue& obj_error) {
            std::string message;
            try {
                message = obj_error.find_value("message").get_str();
            } catch (const std::runtime_error&) {
                message = obj_error.write();
            }
            QMessageBox::critical(this, title, tr("Command failed:\n%1\n\nError:\n%2").arg(command, QString::fromStdString(message)));
        } catch (const std::exception& e) {
            QMessageBox::critical(this, title, tr("Command failed:\n%1\n\nError:\n%2").arg(command, QString::fromStdString(e.what())));
        }
    };
    const auto rpcQuote = [](QString value) {
        value.replace("\\", "\\\\");
        value.replace("\"", "\\\"");
        return QString("\"%1\"").arg(value);
    };

    // Create tabs
    overviewPage = new OverviewPage(this);
    overviewPage->setWalletModel(walletModel);

    credentialsPage = new QWidget(this);
    {
        auto* layout = new QVBoxLayout(credentialsPage);
        auto* header = new QLabel(tr("Credentials"), credentialsPage);
        header->setObjectName("walletToolsHeader");
        auto* body = new QLabel(tr("Use wallet credential and KYC RPC tools for provider setup, credential import, and verification state checks."), credentialsPage);
        body->setWordWrap(true);
        auto* setProviderButton = new QPushButton(tr("Set KYC Provider"), credentialsPage);
        auto* startKycButton = new QPushButton(tr("Start KYC Session"), credentialsPage);
        auto* importCredentialButton = new QPushButton(tr("Import KYC Credential"), credentialsPage);
        auto* checkCredentialButton = new QPushButton(tr("Check Wallet Credential"), credentialsPage);
        auto* showMnemonicButton = new QPushButton(tr("Show Recovery Phrase"), credentialsPage);

        layout->addWidget(header);
        layout->addWidget(body);
        layout->addWidget(setProviderButton);
        layout->addWidget(startKycButton);
        layout->addWidget(importCredentialButton);
        layout->addWidget(checkCredentialButton);
        layout->addWidget(showMnemonicButton);
        layout->addStretch();

        connect(setProviderButton, &QPushButton::clicked, this, [this, executeWalletRpc, rpcQuote] {
            bool ok = false;
            const QString provider = QInputDialog::getText(this, tr("Set KYC Provider"), tr("Provider (e.g. coinfirm, didit, internal):"), QLineEdit::Normal, "coinfirm", &ok);
            if (!ok || provider.trimmed().isEmpty()) return;
            const QString arg1 = QInputDialog::getText(this, tr("Set KYC Provider"), tr("Provider arg #1 (API key or blank):"), QLineEdit::Normal, "", &ok);
            if (!ok) return;
            const QString arg2 = QInputDialog::getText(this, tr("Set KYC Provider"), tr("Provider arg #2 (workflow/client id or blank):"), QLineEdit::Normal, "", &ok);
            if (!ok) return;
            QString cmd = QString("setkycprovider %1").arg(provider.trimmed());
            if (!arg1.trimmed().isEmpty()) cmd += " " + rpcQuote(arg1.trimmed());
            if (!arg2.trimmed().isEmpty()) cmd += " " + rpcQuote(arg2.trimmed());
            executeWalletRpc(tr("Set KYC Provider"), cmd);
        });
        connect(startKycButton, &QPushButton::clicked, this, [this, executeWalletRpc, rpcQuote] {
            bool ok = false;
            const QString level = QInputDialog::getText(this, tr("Start KYC Session"), tr("KYC level (basic/advanced/full):"), QLineEdit::Normal, "full", &ok);
            if (!ok || level.trimmed().isEmpty()) return;
            executeWalletRpc(tr("Start KYC Session"), QString("startkyc %1").arg(rpcQuote(level.trimmed())));
        });
        connect(importCredentialButton, &QPushButton::clicked, this, [this, executeWalletRpc, rpcQuote] {
            bool ok = false;
            const QString credential = QInputDialog::getMultiLineText(this, tr("Import KYC Credential"), tr("Credential (JWT/VC JSON):"), "", &ok);
            if (!ok || credential.trimmed().isEmpty()) return;
            const QString session_id = QInputDialog::getText(this, tr("Import KYC Credential"), tr("Session ID (optional):"), QLineEdit::Normal, "", &ok);
            if (!ok) return;
            QString cmd = QString("importkyccredential %1").arg(rpcQuote(credential));
            if (!session_id.trimmed().isEmpty()) cmd += " " + rpcQuote(session_id.trimmed());
            executeWalletRpc(tr("Import KYC Credential"), cmd);
        });
        connect(checkCredentialButton, &QPushButton::clicked, this, [executeWalletRpc] {
            executeWalletRpc(QObject::tr("Check Wallet Credential"), "getwalletcredential");
        });
        connect(showMnemonicButton, &QPushButton::clicked, this, &WalletView::showMnemonic);
    }

    chatPage = new QWidget(this);
    {
        auto* layout = new QVBoxLayout(chatPage);
        auto* header = new QLabel(tr("Wallet Chat"), chatPage);
        header->setObjectName("walletToolsHeader");
        auto* body = new QLabel(tr("Use wallet chat message transport commands for direct messaging, inbox sync, and history refresh."), chatPage);
        body->setWordWrap(true);
        auto* sendChatButton = new QPushButton(tr("Send Chat Message"), chatPage);
        auto* syncInboxButton = new QPushButton(tr("Sync Chat Inbox"), chatPage);
        auto* listHistoryButton = new QPushButton(tr("Load Chat History"), chatPage);
        auto* copyAddressButton = new QPushButton(tr("Open Receive Address"), chatPage);

        layout->addWidget(header);
        layout->addWidget(body);
        layout->addWidget(sendChatButton);
        layout->addWidget(syncInboxButton);
        layout->addWidget(listHistoryButton);
        layout->addWidget(copyAddressButton);
        layout->addStretch();

        connect(sendChatButton, &QPushButton::clicked, this, [this, executeWalletRpc, rpcQuote] {
            bool ok = false;
            const QString address = QInputDialog::getText(this, tr("Send Wallet Chat Message"), tr("Peer address:"), QLineEdit::Normal, "", &ok);
            if (!ok || address.trimmed().isEmpty()) return;
            const QString message = QInputDialog::getMultiLineText(this, tr("Send Wallet Chat Message"), tr("Message text:"), "", &ok);
            if (!ok || message.trimmed().isEmpty()) return;
            const QString shared = QInputDialog::getText(this, tr("Send Wallet Chat Message"), tr("Shared secret (optional):"), QLineEdit::Normal, "", &ok);
            if (!ok) return;
            QString cmd = QString("chat message %1 %2").arg(address.trimmed(), rpcQuote(message));
            if (!shared.trimmed().isEmpty()) cmd += " " + rpcQuote(shared.trimmed());
            executeWalletRpc(tr("Send Wallet Chat Message"), cmd);
        });
        connect(syncInboxButton, &QPushButton::clicked, this, [this, executeWalletRpc, rpcQuote] {
            bool ok = false;
            const QString address = QInputDialog::getText(this, tr("Sync Wallet Chat Inbox"), tr("Recipient wallet address:"), QLineEdit::Normal, "", &ok);
            if (!ok || address.trimmed().isEmpty()) return;
            const QString shared = QInputDialog::getText(this, tr("Sync Wallet Chat Inbox"), tr("Shared secret (optional):"), QLineEdit::Normal, "", &ok);
            if (!ok) return;
            QString cmd = QString("chat networkinbox %1").arg(address.trimmed());
            if (!shared.trimmed().isEmpty()) cmd += " " + rpcQuote(shared.trimmed());
            executeWalletRpc(tr("Sync Wallet Chat Inbox"), cmd);
        });
        connect(listHistoryButton, &QPushButton::clicked, this, [this, executeWalletRpc] {
            bool ok = false;
            const QString address = QInputDialog::getText(this, tr("Load Wallet Chat History"), tr("Peer address (optional):"), QLineEdit::Normal, "", &ok);
            if (!ok) return;
            executeWalletRpc(tr("Load Wallet Chat History"),
                address.trimmed().isEmpty() ? "chat list" : QString("chat list %1").arg(address.trimmed()));
        });
        connect(copyAddressButton, &QPushButton::clicked, this, &WalletView::gotoReceiveCoinsPage);
    }

    verifyProofPage = new QWidget(this);
    {
        auto* layout = new QVBoxLayout(verifyProofPage);
        auto* header = new QLabel(tr("Verify Proof"), verifyProofPage);
        header->setObjectName("walletToolsHeader");
        auto* body = new QLabel(tr("Generate and verify challenge-bound ownership proofs backed by wallet credentials."), verifyProofPage);
        body->setWordWrap(true);
        auto* generateProofButton = new QPushButton(tr("Generate Ownership Proof"), verifyProofPage);
        auto* verifyOwnershipProofButton = new QPushButton(tr("Verify Ownership Proof"), verifyProofPage);
        auto* confirmOwnershipButton = new QPushButton(tr("Confirm Local Ownership"), verifyProofPage);
        auto* openHistoryButton = new QPushButton(tr("Open Transaction History"), verifyProofPage);

        layout->addWidget(header);
        layout->addWidget(body);
        layout->addWidget(generateProofButton);
        layout->addWidget(verifyOwnershipProofButton);
        layout->addWidget(confirmOwnershipButton);
        layout->addWidget(openHistoryButton);
        layout->addStretch();

        connect(generateProofButton, &QPushButton::clicked, this, [this, executeWalletRpc, rpcQuote] {
            bool ok = false;
            const QString request_json = QInputDialog::getMultiLineText(
                this, tr("Generate Ownership Proof"), tr("Proof request JSON:"), "{\"challenge\":\"nonce-123\",\"requested_claims\":[\"full_name\",\"country\"],\"subject_address\":\"<wallet_address>\"}", &ok);
            if (!ok || request_json.trimmed().isEmpty()) return;
            executeWalletRpc(tr("Generate Ownership Proof"), QString("generateownershipproof %1").arg(rpcQuote(request_json)));
        });
        connect(verifyOwnershipProofButton, &QPushButton::clicked, this, [this, executeWalletRpc, rpcQuote] {
            bool ok = false;
            const QString proof = QInputDialog::getMultiLineText(this, tr("Verify Ownership Proof"), tr("Proof blob:"), "", &ok);
            if (!ok || proof.trimmed().isEmpty()) return;
            executeWalletRpc(tr("Verify Ownership Proof"), QString("verifyownershipproof %1").arg(rpcQuote(proof)));
        });
        connect(confirmOwnershipButton, &QPushButton::clicked, this, [this, executeWalletRpc, rpcQuote] {
            bool ok = false;
            const QString hash = QInputDialog::getText(this, tr("Confirm Local Ownership"), tr("Credential hash:"), QLineEdit::Normal, "", &ok);
            if (!ok || hash.trimmed().isEmpty()) return;
            executeWalletRpc(tr("Confirm Local Ownership"), QString("confirmownership %1").arg(rpcQuote(hash.trimmed())));
        });
        connect(openHistoryButton, &QPushButton::clicked, this, &WalletView::gotoHistoryPage);
    }

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    QHBoxLayout *hbox_buttons = new QHBoxLayout();
    transactionView = new TransactionView(this);
    transactionView->setModel(walletModel);

    vbox->addWidget(transactionView);
    QPushButton *exportButton = new QPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
    hbox_buttons->addStretch();

    // Sum of selected transactions
    QLabel *transactionSumLabel = new QLabel(); // Label
    transactionSumLabel->setObjectName("transactionSumLabel"); // Label ID as CSS-reference
    transactionSumLabel->setText(tr("Selected amount:"));
    hbox_buttons->addWidget(transactionSumLabel);

    transactionSum = new QLabel(); // Amount
    transactionSum->setObjectName("transactionSum"); // Label ID as CSS-reference
    transactionSum->setMinimumSize(200, 8);
    transactionSum->setTextInteractionFlags(Qt::TextSelectableByMouse);

    GUIUtil::setFont({transactionSumLabel,
                      transactionSum,
                     }, {GUIUtil::FontWeight::Bold, 14});
    GUIUtil::updateFonts();

    hbox_buttons->addWidget(transactionSum);

    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    transactionsPage->setLayout(vbox);

    receiveCoinsPage = new ReceiveCoinsDialog();
    receiveCoinsPage->setModel(walletModel);

    sendCoinsPage = new SendCoinsDialog();
    sendCoinsPage->setModel(walletModel);

    coinJoinCoinsPage = new SendCoinsDialog(true);
    coinJoinCoinsPage->setModel(walletModel);

    usedSendingAddressesPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedSendingAddressesPage->setModel(walletModel->getAddressTableModel());

    usedReceivingAddressesPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);
    usedReceivingAddressesPage->setModel(walletModel->getAddressTableModel());

    addWidget(overviewPage);
    addWidget(credentialsPage);
    addWidget(chatPage);
    addWidget(verifyProofPage);
    addWidget(transactionsPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);
    addWidget(coinJoinCoinsPage);

    masternodeListPage = new MasternodeList();
    masternodeListPage->setWalletModel(walletModel);
    addWidget(masternodeListPage);

    proposalListPage = new ProposalList();
    proposalListPage->setWalletModel(walletModel);
    addWidget(proposalListPage);

    connect(proposalListPage, &ProposalList::showProposalInfo, this, &WalletView::showProposalInfo);

    connect(overviewPage, &OverviewPage::transactionClicked, this, &WalletView::transactionClicked);
    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, &OverviewPage::transactionClicked, transactionView, qOverload<const QModelIndex&>(&TransactionView::focusTransaction));
    connect(overviewPage, &OverviewPage::outOfSyncWarningClicked, this, &WalletView::outOfSyncWarningClicked);

    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, this, &WalletView::coinsSent);
    connect(coinJoinCoinsPage, &SendCoinsDialog::coinsSent, this, &WalletView::coinsSent);
    // Highlight transaction after send
    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, transactionView, qOverload<const uint256&>(&TransactionView::focusTransaction));
    connect(coinJoinCoinsPage, &SendCoinsDialog::coinsSent, transactionView, qOverload<const uint256&>(&TransactionView::focusTransaction));

    // Update wallet with sum of selected transactions
    connect(transactionView, &TransactionView::trxAmount, this, &WalletView::trxAmount);

    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, &QPushButton::clicked, transactionView, &TransactionView::exportClicked);

    // Pass through messages from SendCoinsDialog
    connect(sendCoinsPage, &SendCoinsDialog::message, this, &WalletView::message);
    connect(coinJoinCoinsPage, &SendCoinsDialog::message, this, &WalletView::message);

    // Pass through messages from transactionView
    connect(transactionView, &TransactionView::message, this, &WalletView::message);

    connect(this, &WalletView::setPrivacy, overviewPage, &OverviewPage::setPrivacy);

    // Receive and pass through messages from wallet model
    connect(walletModel, &WalletModel::message, this, &WalletView::message);

    // Handle changes in encryption status
    connect(walletModel, &WalletModel::encryptionStatusChanged, this, &WalletView::encryptionStatusChanged);

    // Balloon pop-up for new transaction
    connect(walletModel->getTransactionTableModel(), &TransactionTableModel::rowsInserted, this, &WalletView::processNewTransaction);

    // Ask for passphrase if needed
    connect(walletModel, &WalletModel::requireUnlock, this, &WalletView::unlockWallet);

    // Show progress dialog
    connect(walletModel, &WalletModel::showProgress, this, &WalletView::showProgress);

    GUIUtil::disableMacFocusRect(this);
}

WalletView::~WalletView() = default;

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (overviewPage != nullptr) {
        overviewPage->setClientModel(_clientModel);
    }
    if (sendCoinsPage != nullptr) {
        sendCoinsPage->setClientModel(_clientModel);
    }
    if (coinJoinCoinsPage != nullptr) {
        coinJoinCoinsPage->setClientModel(_clientModel);
    }
    if (masternodeListPage != nullptr) {
        masternodeListPage->setClientModel(_clientModel);
    }
    if (proposalListPage != nullptr) {
        proposalListPage->setClientModel(_clientModel);
    }
    walletModel->setClientModel(_clientModel);
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!clientModel || clientModel->node().isInitialBlockDownload()) {
        return;
    }

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QModelIndex index = ttm->index(start, 0, parent);
    QSettings settings;
    if (!settings.value("fShowCoinJoinPopups").toBool()) {
        QVariant nType = ttm->data(index, TransactionTableModel::TypeRole);
        if (nType == TransactionRecord::CoinJoinMixing ||
            nType == TransactionRecord::CoinJoinCollateralPayment ||
            nType == TransactionRecord::CoinJoinMakeCollaterals ||
            nType == TransactionRecord::CoinJoinCreateDenominations) return;
    }

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = GUIUtil::HtmlEscape(ttm->data(index, TransactionTableModel::LabelRole).toString());

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label, GUIUtil::HtmlEscape(walletModel->getWalletName()));
}

void WalletView::gotoGovernancePage()
{
    setCurrentWidget(proposalListPage);
}

void WalletView::gotoOverviewPage()
{
    setCurrentWidget(overviewPage);
}

void WalletView::gotoCredentialsPage()
{
    setCurrentWidget(credentialsPage);
}

void WalletView::gotoChatPage()
{
    setCurrentWidget(chatPage);
}

void WalletView::gotoVerifyProofPage()
{
    setCurrentWidget(verifyProofPage);
}

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoMasternodePage()
{
    setCurrentWidget(masternodeListPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty()) {
        sendCoinsPage->setAddress(addr);
    }
}

void WalletView::gotoCoinJoinCoinsPage(QString addr)
{
    setCurrentWidget(coinJoinCoinsPage);

    if (!addr.isEmpty())
        coinJoinCoinsPage->setAddress(addr);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog* signVerifyMessageDialog = new SignVerifyMessageDialog(this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog* signVerifyMessageDialog = new SignVerifyMessageDialog(this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    return sendCoinsPage->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

void WalletView::encryptWallet()
{
    auto dlg = new AskPassphraseDialog(AskPassphraseDialog::Encrypt, this);
    dlg->setModel(walletModel);
    connect(dlg, &QDialog::finished, this, &WalletView::encryptionStatusChanged);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        //: Name of the wallet data file format.
        tr("Wallet Data") + QLatin1String(" (*.dat)"), nullptr);

    if (filename.isEmpty())
        return;

    if (!walletModel->wallet().backupWallet(filename.toLocal8Bit().data())) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::changePassphrase()
{
    auto dlg = new AskPassphraseDialog(AskPassphraseDialog::ChangePass, this);
    dlg->setModel(walletModel);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

void WalletView::showMnemonic()
{
    // Check if wallet supports mnemonic retrieval
    if (walletModel->wallet().privateKeysDisabled()) {
        QMessageBox::warning(this, tr("No Recovery Phrase"),
            tr("This wallet does not have private keys and therefore has no recovery phrase."));
        return;
    }

    if (!walletModel->wallet().hdEnabled()) {
        QMessageBox::warning(this, tr("No Recovery Phrase"),
            tr("This wallet was not created with HD (Hierarchical Deterministic) mode and does not have a recovery phrase."));
        return;
    }

    // Request unlock if needed - UnlockContext will restore lock state on destruction
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        // User cancelled unlock
        return;
    }

    // Retrieve mnemonic
    SecureString mnemonic;
    SecureString mnemonic_passphrase;
    bool has_mnemonic = walletModel->wallet().getMnemonic(mnemonic, mnemonic_passphrase);

    if (!has_mnemonic || mnemonic.empty()) {
        QMessageBox::warning(this, tr("Mnemonic Retrieval Failed"),
            tr("Could not retrieve the recovery phrase from this wallet."));
        return;
    }

    // Show mnemonic verification dialog in view-only mode (no verification required)
    MnemonicVerificationDialog verify_dialog(mnemonic, this, true);
    verify_dialog.setWindowModality(Qt::ApplicationModal);

    // Clear mnemonic from local variables after dialog has copied it
    const size_t mnemonic_size = mnemonic.size();
    const size_t passphrase_size = mnemonic_passphrase.size();
    mnemonic.assign(mnemonic_size, 0);
    mnemonic_passphrase.assign(passphrase_size, 0);

    verify_dialog.exec();

    // UnlockContext destructor will automatically restore the wallet lock state
}

void WalletView::unlockWallet(bool fForMixingOnly)
{
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked || walletModel->getEncryptionStatus() == WalletModel::UnlockedForMixingOnly) {
        AskPassphraseDialog dlg(fForMixingOnly ? AskPassphraseDialog::UnlockMixing : AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        // A modal dialog must be synchronous here as expected
        // in the WalletModel::requestUnlock() function.
        dlg.exec();
    }
}

void WalletView::lockWallet()
{
    walletModel->setWalletLocked(true);
}

void WalletView::usedSendingAddresses()
{
    GUIUtil::bringToFront(usedSendingAddressesPage);
}

void WalletView::usedReceivingAddresses()
{
    GUIUtil::bringToFront(usedReceivingAddressesPage);
}

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0) {
        progressDialog = new QProgressDialog(title, tr("Cancel"), 0, 100, this);
        GUIUtil::PolishProgressDialog(progressDialog);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    } else if (nProgress == 100) {
        if (progressDialog) {
            progressDialog->close();
            progressDialog->deleteLater();
            progressDialog = nullptr;
        }
    } else if (progressDialog) {
        if (progressDialog->wasCanceled()) {
            getWalletModel()->wallet().abortRescan();
        } else {
            progressDialog->setValue(nProgress);
        }
    }
}

/** Update wallet with the sum of the selected transactions */
void WalletView::trxAmount(QString amount)
{
    transactionSum->setText(amount);
}
