import SwiftUI
import UIKit

struct ContentView: View {
    @EnvironmentObject private var appState: AppState
    @EnvironmentObject private var approval: ApprovalCoordinator
    @EnvironmentObject private var locale: LocaleManager

    @State private var showRegeneratePSKConfirm = false
    @State private var showDeletePSKConfirm = false
    @State private var showSettings = false
    @State private var showQRPairing = false

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
                    .presentationDetents([.fraction(0.85), .large])
                    .presentationDragIndicator(.hidden)
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
        case .failed:
            // associated value には生の NWError 文字列が入っているが、
            // 画面には出さない (内部詳細として保持するだけ)。
            return NSLocalizedString("listener.failed", comment: "Listener state: failed")
        }
    }

    // MARK: - ペアリング

    private var pairingSection: some View {
        Section("pairing.section") {
            if let base32 = appState.pskBase32Grouped, let sas = appState.sasCode {
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
                qrPairingButton
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
                qrPairingButton
            }
        }
        .sheet(isPresented: $showQRPairing) {
            QRPairingView()
                .environmentObject(appState)
        }
    }

    private var qrPairingButton: some View {
        Button {
            showQRPairing = true
        } label: {
            Label("pairing.qr.scan_button", systemImage: "qrcode.viewfinder")
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
            TimelineView(.periodic(from: pending.requestedAt, by: 0.2)) { context in
                let elapsed = context.date.timeIntervalSince(pending.requestedAt)
                ZStack {
                    CountdownRing(fraction: 1 - elapsed / 60)
                    ApprovalIcon()
                }
            }

            Text(pending.operation.displayName)
                .font(.title2)
                .bold()

            VStack(spacing: 8) {
                Text("approval.site")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .tracking(1.0)
                Text(pending.rpId)
                    .font(.title2)
                    .bold()
                    .multilineTextAlignment(.center)
                Text("approval.user")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .tracking(1.0)
                Text(pending.userName)
                    .font(.title3)
                    .multilineTextAlignment(.center)
            }

            Text("approval.warning")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            VStack(spacing: 10) {
                Button {
                    UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                    approval.approve()
                } label: {
                    Text(approveButtonKey)
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 16)
                }
                .background(Color.blue)
                .foregroundStyle(.white)
                .clipShape(Capsule())

                Button {
                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    approval.deny()
                } label: {
                    Text("approval.deny")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.red)
            }
        }
        .padding(24)
    }
}

// MARK: - 承認アイコン
//
// フラットなメダリオン: 薄いブルーの円 + 盾と錠のシンボル。
// その外周に、残り時間 (60 秒) を示すカウントダウンリングを重ねる。
// リングは装飾ではなく、自動拒否までの残り時間そのもの。

/// 承認シートのアイコン。フラットな円 + シンボル。
struct ApprovalIcon: View {
    var body: some View {
        Image(systemName: "lock.shield.fill")
            .font(.system(size: 40))
            .foregroundStyle(.blue)
            .frame(width: 92, height: 92)
            .background(Color.blue.opacity(0.12), in: Circle())
    }
}

/// メダリオンの外周を回る残り時間リング。
struct CountdownRing: View {
    /// 0.0 (時間切れ) 〜 1.0 (残り全部)
    let fraction: Double

    var body: some View {
        ZStack {
            Circle()
                .stroke(Color.blue.opacity(0.15), lineWidth: 3)
            Circle()
                .trim(from: 0, to: max(0, min(1, fraction)))
                .stroke(
                    Color.blue,
                    style: StrokeStyle(lineWidth: 3, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
        }
        .frame(width: 106, height: 106)
    }
}
