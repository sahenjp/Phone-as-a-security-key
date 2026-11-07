import LocalAuthentication
import SwiftUI
import UIKit

/// 設定画面。メイン画面の歯車ボタンからシートで開く。
///
/// セキュリティ方針: ここには安全性を弱める設定を置かない。
/// 生体認証オフ、自動承認、この PC を常に信頼、といった項目は存在しない。
/// 破壊的操作 (資格情報の削除) は確認ダイアログ + Face ID の両方を通す。
struct SettingsView: View {
    @EnvironmentObject private var appState: AppState
    @EnvironmentObject private var locale: LocaleManager
    @Environment(\.dismiss) private var dismiss

    @State private var credentialPendingDelete: CredentialMetadata?
    @State private var showDeleteCredentialConfirm = false
    @State private var deleteErrorMessage: String?

    @State private var showRegeneratePSKConfirm = false
    @State private var showDeletePSKConfirm = false
    @State private var pairingKeyCopied = false
    @State private var showQRPairing = false

    /// 導入画面の再表示用 (ContentView と同じ保存キー)。
    @AppStorage("hasCompletedOnboarding") private var onboardingDone = true

    var body: some View {
        NavigationStack {
            Form {
                languageSection
                credentialsSection
                pairingSection
                aboutSection
            }
            .navigationTitle("settings.title")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("settings.done") { dismiss() }
                }
            }
            .confirmationDialog(
                Text("settings.credentials.delete.title"),
                isPresented: $showDeleteCredentialConfirm,
                titleVisibility: .visible,
                presenting: credentialPendingDelete
            ) { credential in
                Button("common.delete", role: .destructive) {
                    Task { await deleteCredentialWithFaceID(credential) }
                }
                Button("common.cancel", role: .cancel) {}
            } message: { credential in
                Text(
                    String(
                        format: NSLocalizedString(
                            "settings.credentials.delete.message",
                            comment: "Delete credential confirmation, with rpId"
                        ),
                        credential.rpId
                    )
                )
            }
            .confirmationDialog(
                "pairing.regenerate.title",
                isPresented: $showRegeneratePSKConfirm,
                titleVisibility: .visible
            ) {
                Button("pairing.regenerate.confirm", role: .destructive) {
                    appState.generatePSK()
                }
                Button("common.cancel", role: .cancel) {}
            } message: {
                Text("pairing.regenerate.message")
            }
            .confirmationDialog(
                "pairing.delete.title",
                isPresented: $showDeletePSKConfirm,
                titleVisibility: .visible
            ) {
                Button("common.delete", role: .destructive) {
                    appState.deletePSK()
                }
                Button("common.cancel", role: .cancel) {}
            } message: {
                Text("pairing.delete.message")
            }
            .alert(
                Text("settings.error.title"),
                isPresented: Binding(
                    get: { deleteErrorMessage != nil },
                    set: { if !$0 { deleteErrorMessage = nil } }
                )
            ) {
                Button("common.ok", role: .cancel) {}
            } message: {
                Text(deleteErrorMessage ?? "")
            }
        }
    }

    // MARK: - 言語

    private var languageSection: some View {
        Section("settings.language.section") {
            Picker(
                "settings.language.section",
                selection: $locale.selectedCode
            ) {
                Text("settings.language.system")
                    .tag(nil as String?)
                ForEach(LocaleManager.supportedLanguages, id: \.code) { language in
                    Text(verbatim: language.nativeName)
                        .tag(language.code as String?)
                }
            }
            .pickerStyle(.inline)
            .labelsHidden()
        }
    }

    // MARK: - 資格情報

    private var credentialsSection: some View {
        Section("credentials.section") {
            if appState.credentials.isEmpty {
                Text("credentials.empty")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(appState.credentials) { credential in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(credential.rpId)
                            .font(.headline)
                        Text(credential.userDisplayName ?? credential.userName)
                            .foregroundStyle(.secondary)
                        HStack {
                            Text("settings.credentials.created")
                            Spacer()
                            Text(
                                credential.createdAt.formatted(
                                    date: .abbreviated,
                                    time: .shortened
                                )
                            )
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        HStack {
                            Text(credentialIDText(credential))
                            Spacer()
                            Text(signCountText(credential))
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 2)
                    // 削除はスワイプで。確認ダイアログ + Face ID のゲートは
                    // 従来どおり (deleteCredentialWithFaceID)。
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            credentialPendingDelete = credential
                            showDeleteCredentialConfirm = true
                        } label: {
                            Label("common.delete", systemImage: "trash")
                        }
                    }
                }
            }
        }
    }

    private func credentialIDText(_ credential: CredentialMetadata) -> String {
        String(
            format: NSLocalizedString("credential.id", comment: "Credential ID row, with short credential id"),
            credential.shortCredentialId
        )
    }

    private func signCountText(_ credential: CredentialMetadata) -> String {
        String(
            format: NSLocalizedString("credential.sign_count", comment: "Signature count row"),
            Int64(credential.signCount)
        )
    }

    /// 資格情報の削除は Face ID を通した場合だけ実行する。
    /// 確認に失敗したら削除せず、理由をアラートで伝える。
    private func deleteCredentialWithFaceID(_ credential: CredentialMetadata) async {
        let context = LAContext()
        let reason = NSLocalizedString(
            "settings.credentials.delete.reason",
            comment: "Face ID reason shown when deleting a credential"
        )
        var authError: NSError?
        let canEvaluate = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &authError
        )
        let success: Bool
        if canEvaluate {
            success = await withCheckedContinuation { continuation in
                context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithBiometrics,
                    localizedReason: reason
                ) { ok, _ in
                    continuation.resume(returning: ok)
                }
            }
        } else {
            success = false
        }
        guard success else {
            deleteErrorMessage = NSLocalizedString(
                "settings.credentials.delete.failed",
                comment: "Shown when Face ID confirmation for deletion fails"
            )
            return
        }
        appState.deleteCredential(credential)
    }

    // MARK: - ペアリング

    private var pairingSection: some View {
        Section("pairing.section") {
            HStack {
                Text("settings.pairing.status_label")
                Spacer()
                Text(pairingStateKey)
                    .foregroundStyle(.secondary)
            }
            if let base32 = appState.pskBase32Grouped, let sas = appState.sasCode {
                HStack {
                    Text("pairing.sas_label")
                    Spacer()
                    Text(sas)
                        .font(.system(.body, design: .monospaced))
                        .bold()
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("pairing.key_label")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text(base32)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                }
                Button {
                    // Copy the RAW key (no grouping spaces) so it pastes
                    // cleanly anywhere; the display above is grouped.
                    UIPasteboard.general.string = appState.pskBase32 ?? base32
                    pairingKeyCopied = true
                    Task {
                        try? await Task.sleep(nanoseconds: 2_000_000_000)
                        pairingKeyCopied = false
                    }
                } label: {
                    Label(
                        copyButtonKey,
                        systemImage: pairingKeyCopied ? "checkmark" : "doc.on.doc"
                    )
                }
                Button {
                    showQRPairing = true
                } label: {
                    Label("pairing.qr.scan_button", systemImage: "qrcode.viewfinder")
                }
                Button("pairing.regenerate", role: .destructive) {
                    showRegeneratePSKConfirm = true
                }
                Button("pairing.delete", role: .destructive) {
                    showDeletePSKConfirm = true
                }
            } else {
                Button("pairing.generate") {
                    appState.generatePSK()
                }
                Button {
                    showQRPairing = true
                } label: {
                    Label("pairing.qr.scan_button", systemImage: "qrcode.viewfinder")
                }
            }
        }
        .sheet(isPresented: $showQRPairing) {
            QRPairingView()
                .environmentObject(appState)
        }
    }

    private var pairingStateKey: LocalizedStringKey {
        appState.isPaired ? "settings.pairing.paired" : "settings.pairing.not_paired"
    }

    private var copyButtonKey: LocalizedStringKey {
        pairingKeyCopied ? "settings.pairing.copied" : "settings.pairing.copy"
    }

    // MARK: - このアプリについて

    private var aboutSection: some View {
        Section("settings.about.section") {
            Button {
                onboardingDone = false
                dismiss()
            } label: {
                Text("settings.about.show_intro")
                    .foregroundStyle(.primary)
            }
            HStack {
                Text("settings.about.version")
                Spacer()
                Text(appVersionText)
                    .foregroundStyle(.secondary)
            }
            Link(destination: Self.repositoryURL) {
                HStack {
                    Text("settings.about.repository")
                        .foregroundStyle(.primary)
                    Spacer()
                    Text(verbatim: "github.com/sahenjp/Phone-as-a-security-key")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Image(systemName: "arrow.up.forward.square")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private static let repositoryURL = URL(
        string: "https://github.com/sahenjp/Phone-as-a-security-key"
    )!

    private var appVersionText: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "-"
        let build = info?["CFBundleVersion"] as? String ?? "-"
        return "\(version) (\(build))"
    }
}
