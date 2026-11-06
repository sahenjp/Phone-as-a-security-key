import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var appState: AppState
    @EnvironmentObject private var approval: ApprovalCoordinator
    @EnvironmentObject private var locale: LocaleManager

    @State private var showRegeneratePSKConfirm = false
    @State private var showDeletePSKConfirm = false
    @State private var showSettings = false

    /// Binding for the approval sheet. `ApprovalCoordinator.pending` is
    /// `private(set)` on purpose: only the coordinator may present or
    /// clear a request (approve / deny / timeout). SwiftUI's
    /// `sheet(item:)` wants a writable binding so it can write nil on
    /// dismissal; dismissal is disabled interactively and clearing is
    /// the coordinator's job, so view-side writes are ignored.
    private var pendingBinding: Binding<PendingApproval?> {
        Binding(
            get: { approval.pending },
            set: { _ in }
        )
    }

    var body: some View {
        NavigationStack {
            List {
                statusSection
                pairingSection
                credentialsSection
                noteSection
            }
            .navigationTitle("Phone FIDO Key")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showSettings = true
                    } label: {
                        Label("settings.title", systemImage: "gearshape")
                            .labelStyle(.iconOnly)
                    }
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
                    .environmentObject(appState)
                    .environmentObject(locale)
            }
            .sheet(item: pendingBinding) { pending in
                ApprovalView(pending: pending)
                    .environmentObject(approval)
                    .interactiveDismissDisabled(true)
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
        }
    }

    // MARK: - 接続状態

    private var statusSection: some View {
        Section("status.section") {
            HStack {
                Text("status.listener")
                Spacer()
                Text(listenerStateText)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Text("status.port")
                Spacer()
                Text("\(BridgeConstants.listenPort)")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            HStack {
                Text("status.pc_connection")
                Spacer()
                Circle()
                    .fill(appState.isConnected ? Color.green : Color.gray.opacity(0.5))
                    .frame(width: 9, height: 9)
                Text(connectionStateKey)
                    .foregroundStyle(.secondary)
            }
            if !appState.lastEvent.isEmpty {
                Text(appState.lastEvent)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if approval.pending != nil {
                Label("status.pending_approval", systemImage: "exclamationmark.shield")
                    .foregroundStyle(.orange)
            }
        }
    }

    private var connectionStateKey: LocalizedStringKey {
        appState.isConnected ? "status.connected" : "status.disconnected"
    }

    private var listenerStateText: String {
        switch appState.listenerState {
        case .stopped:
            return NSLocalizedString("listener.stopped", comment: "Listener state: stopped")
        case .listening:
            return NSLocalizedString("listener.listening", comment: "Listener state: listening")
        case .failed(let message):
            return String(
                format: NSLocalizedString("listener.failed", comment: "Listener state: failed, with error detail"),
                message
            )
        }
    }

    // MARK: - ペアリング

    private var pairingSection: some View {
        Section("pairing.section") {
            if let base32 = appState.pskBase32, let sas = appState.sasCode {
                VStack(alignment: .leading, spacing: 8) {
                    Text("pairing.key_label")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text(base32)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                    HStack {
                        Text("pairing.sas_label")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(sas)
                            .font(.system(.title3, design: .monospaced))
                            .bold()
                    }
                    Text("pairing.sas_instruction")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Button("pairing.regenerate", role: .destructive) {
                    showRegeneratePSKConfirm = true
                }
                Button("pairing.delete", role: .destructive) {
                    showDeletePSKConfirm = true
                }
            } else {
                Text("pairing.unpaired")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button("pairing.generate") {
                    appState.generatePSK()
                }
            }
        }
    }

    // MARK: - 資格一覧

    private var credentialsSection: some View {
        Section("credentials.section") {
            if appState.credentials.isEmpty {
                Text("credentials.empty")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(appState.credentials) { credential in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(credential.rpId)
                            .font(.headline)
                        Text(credential.userDisplayName ?? credential.userName)
                            .foregroundStyle(.secondary)
                        HStack {
                            Text(credentialIDText(credential))
                            Spacer()
                            Text(signCountText(credential))
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
                .onDelete { offsets in
                    for index in offsets {
                        appState.deleteCredential(appState.credentials[index])
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

    // MARK: - 注意

    private var noteSection: some View {
        Section {
            Text("note.keep_foreground")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - 承認シート

struct ApprovalView: View {
    @EnvironmentObject private var approval: ApprovalCoordinator
    let pending: PendingApproval

    private var approveButtonKey: LocalizedStringKey {
        pending.operation == .createCredential
            ? "approval.button.create"
            : "approval.button.signin"
    }

    var body: some View {
        VStack(spacing: 24) {
            ApprovalIcon()

            Text(pending.operation.displayName)
                .font(.title2)
                .bold()

            VStack(spacing: 8) {
                Text("approval.site")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(pending.rpId)
                    .font(.title3)
                    .bold()
                    .multilineTextAlignment(.center)
                Text("approval.user")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(pending.userName)
                    .font(.title3)
                    .multilineTextAlignment(.center)
            }

            Text("approval.warning")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            VStack(spacing: 12) {
                Button {
                    approval.approve()
                } label: {
                    Text(approveButtonKey)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button(role: .destructive) {
                    approval.deny()
                } label: {
                    Text("approval.deny")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
            }
        }
        .padding(24)
    }
}

// MARK: - 承認アイコン
//
// ガラス質感の円に鍵アイコンを乗せる。標準コントロール
// (List / Section / ボタン / シート) は iOS 26 では OS 側で自動的に
// Liquid Glass の見た目になる。glassEffect 等の iOS 26 専用 API は
// CI の SDK ではまだ使えないため、ここではマテリアルで質感を作る
// (どの SDK でもコンパイルできる書き方に留める)。

/// 承認シートのアイコン。半透明マテリアルの円 + 縁取り。
struct ApprovalIcon: View {
    var body: some View {
        Image(systemName: "key.shield")
            .font(.system(size: 40))
            .foregroundStyle(.blue)
            .frame(width: 88, height: 88)
            .background(.ultraThinMaterial, in: Circle())
            .overlay {
                Circle()
                    .strokeBorder(
                        LinearGradient(
                            colors: [.white.opacity(0.55), .white.opacity(0.08)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 1
                    )
            }
            .shadow(color: .black.opacity(0.08), radius: 10, y: 4)
    }
}
