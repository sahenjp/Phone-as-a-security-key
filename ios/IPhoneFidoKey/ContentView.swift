import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var appState: AppState
    @EnvironmentObject private var approval: ApprovalCoordinator

    @State private var showRegeneratePSKConfirm = false
    @State private var showDeletePSKConfirm = false

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
            .navigationTitle("iPhone FIDO Key")
            .sheet(item: pendingBinding) { pending in
                ApprovalView(pending: pending)
                    .environmentObject(approval)
                    .interactiveDismissDisabled(true)
            }
            .confirmationDialog(
                "ペアリングキーを再生成しますか？",
                isPresented: $showRegeneratePSKConfirm,
                titleVisibility: .visible
            ) {
                Button("再生成する", role: .destructive) {
                    appState.generatePSK()
                }
                Button("キャンセル", role: .cancel) {}
            } message: {
                Text("今のキーでペアリングした PC とは通信できなくなります。新しいキーを PC 側に入力し直してください。")
            }
            .confirmationDialog(
                "ペアリングキーを削除しますか？",
                isPresented: $showDeletePSKConfirm,
                titleVisibility: .visible
            ) {
                Button("削除する", role: .destructive) {
                    appState.deletePSK()
                }
                Button("キャンセル", role: .cancel) {}
            } message: {
                Text("削除すると PC からの接続はすべて拒否されます。")
            }
        }
    }

    // MARK: - 接続状態

    private var statusSection: some View {
        Section("接続状態") {
            HStack {
                Text("待ち受け")
                Spacer()
                Text(listenerStateText)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Text("ポート")
                Spacer()
                Text("\(BridgeConstants.listenPort)")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            HStack {
                Text("PC 接続")
                Spacer()
                Text(appState.isConnected ? "接続中" : "未接続")
                    .foregroundStyle(.secondary)
            }
            if !appState.lastEvent.isEmpty {
                Text(appState.lastEvent)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if approval.pending != nil {
                Label("承認待ちのリクエストがあります", systemImage: "exclamationmark.shield")
                    .foregroundStyle(.orange)
            }
        }
    }

    private var listenerStateText: String {
        switch appState.listenerState {
        case .stopped: return "停止"
        case .listening: return "待ち受け中"
        case .failed(let message): return "失敗: \(message)"
        }
    }

    // MARK: - ペアリング

    private var pairingSection: some View {
        Section("ペアリング") {
            if let base32 = appState.pskBase32, let sas = appState.sasCode {
                VStack(alignment: .leading, spacing: 8) {
                    Text("ペアリングキー (PC の `iphone-fido pair` に入力)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text(base32)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                    HStack {
                        Text("確認コード (SAS)")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(sas)
                            .font(.system(.title3, design: .monospaced))
                            .bold()
                    }
                    Text("確認コードが PC 側の表示と一致することを必ず確認してください。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Button("ペアリングキーを再生成", role: .destructive) {
                    showRegeneratePSKConfirm = true
                }
                Button("ペアリングキーを削除", role: .destructive) {
                    showDeletePSKConfirm = true
                }
            } else {
                Text("未ペアリングです。キーを生成し、PC 側に手入力するとペアリングできます。キーは USB 通信では流れません。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button("ペアリングキーを生成") {
                    appState.generatePSK()
                }
            }
        }
    }

    // MARK: - 資格一覧

    private var credentialsSection: some View {
        Section("資格情報 (パスキー)") {
            if appState.credentials.isEmpty {
                Text("まだ資格情報がありません。WebAuthn 対応サイトの登録フローから作成されます。")
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
                            Text("ID: \(credential.shortCredentialId)")
                            Spacer()
                            Text("署名回数: \(credential.signCount)")
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

    // MARK: - 注意

    private var noteSection: some View {
        Section {
            Text("認証中はこのアプリを画面に表示したままにしてください。バックグラウンドに移ると接続が止まります。承認は必ずこの画面のボタンと Face ID が必要で、USB 接続だけでは承認されません。")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - 承認シート

struct ApprovalView: View {
    @EnvironmentObject private var approval: ApprovalCoordinator
    let pending: PendingApproval

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "key.shield")
                .font(.system(size: 48))
                .foregroundStyle(.blue)

            Text(pending.operation.displayName)
                .font(.title2)
                .bold()

            VStack(spacing: 8) {
                Text("サイト")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(pending.rpId)
                    .font(.title3)
                    .bold()
                    .multilineTextAlignment(.center)
                Text("ユーザー")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(pending.userName)
                    .font(.title3)
                    .multilineTextAlignment(.center)
            }

            Text("心当たりのないリクエストは拒否してください。承認すると続けて Face ID が求められます。60 秒で自動的に拒否されます。")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            VStack(spacing: 12) {
                Button {
                    approval.approve()
                } label: {
                    Text(pending.operation == .createCredential ? "作成を承認" : "サインインを承認")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button(role: .destructive) {
                    approval.deny()
                } label: {
                    Text("拒否")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
            }
        }
        .padding(24)
    }
}
