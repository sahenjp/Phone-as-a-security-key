import SwiftUI
import UIKit

// MARK: - 素材ヘルパー
//
// 色と素材の方針は Apple の HIG に合わせる (Materials / Color、
// 2026-11-07 確認):
// - Liquid Glass は操作系の層だけに使う。標準のボタン様式
//   (.glassProminent) がその場所で、自前の glassEffect は使わない。
// - コンテンツ層は標準マテリアルとシステム色。カードは
//   secondarySystemGroupedBackground、背景はシステムの地色。
// - ガラスに色を付けない ("there's no need to tint the glass
//   itself")。薄いティントは「光の不一致」に見えて色が変になる。
//   色はコンテンツ側 (シンボルやボタンのアクセント) で出す。

extension View {
    /// アイコンのバッジ地。ガラスではなくフラットな円。
    /// 参考画像 (承認画面のモック) と同じ、無地 + 青シンボルの形。
    func iconBadge() -> some View {
        self.background(Color(.secondarySystemFill), in: Circle())
    }

    /// コンテンツ用カードの地。グループ背景の上の標準カード色。
    func contentCard(cornerRadius: CGFloat = 24) -> some View {
        self.background(
            Color(.secondarySystemGroupedBackground),
            in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        )
    }
}

/// 画面の主要ボタン。iOS 26 では glassProminent、
/// それ以前ではベタ塗りのカプセル。
struct PrimaryButton: View {
    let titleKey: LocalizedStringKey
    let action: () -> Void

    var body: some View {
        if #available(iOS 26.0, *) {
            Button(action: action) {
                Text(titleKey)
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
            }
            .buttonStyle(.glassProminent)
            .tint(.blue)
            .controlSize(.large)
        } else {
            Button(action: action) {
                Text(titleKey)
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
            }
            .background(Color.blue)
            .foregroundStyle(.white)
            .clipShape(Capsule())
        }
    }
}

// MARK: - メイン画面

struct ContentView: View {
    @EnvironmentObject private var appState: AppState
    @EnvironmentObject private var approval: ApprovalCoordinator
    @EnvironmentObject private var locale: LocaleManager

    /// 初回起動の導入 (オンボーディング) を見たかどうか。
    /// 設定の「このアプリについて」から再表示もできる。
    @AppStorage("hasCompletedOnboarding") private var onboardingDone = false
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
        Group {
            if onboardingDone {
                mainContent
            } else {
                OnboardingView(
                    onFinish: { onboardingDone = true },
                    onOpenSettings: {
                        onboardingDone = true
                        showSettings = true
                    }
                )
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
    }

    // MARK: - 本体 (導入のあと)

    private var mainContent: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    headerView
                    statusBlock
                    credentialsBlock
                    Text("note.keep_foreground")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .padding(20)
            }
            .background(Color(.systemGroupedBackground).ignoresSafeArea())
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
        }
    }

    private var headerView: some View {
        HStack(spacing: 14) {
            Image(systemName: "key.fill")
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(.blue)
                .frame(width: 46, height: 46)
                .iconBadge()
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: "Phone FIDO Key")
                    .font(.title3)
                    .bold()
                Text("onboarding.tagline")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private func sectionCaption(_ key: LocalizedStringKey) -> some View {
        Text(key)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .textCase(.uppercase)
            .tracking(1.0)
    }

    // MARK: - 接続状態

    private var statusBlock: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionCaption("status.section")
            VStack(spacing: 12) {
                HStack {
                    Text("status.listener")
                    Spacer()
                    Text(listenerStateText)
                        .foregroundStyle(.secondary)
                }
                Divider()
                HStack {
                    Text("status.pc_connection")
                    Spacer()
                    Circle()
                        .fill(appState.isConnected ? Color.green : Color.gray.opacity(0.5))
                        .frame(width: 9, height: 9)
                    Text(connectionStateKey)
                        .foregroundStyle(.secondary)
                }
                Divider()
                HStack {
                    Text("status.port")
                    Spacer()
                    Text("\(BridgeConstants.listenPort)")
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                if approval.pending != nil {
                    Label("status.pending_approval", systemImage: "exclamationmark.shield")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
                if !appState.lastEvent.isEmpty {
                    Text(appState.lastEvent)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(16)
            .contentCard()
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

    // MARK: - 資格一覧 (読み取り専用。削除は設定から Face ID 経由で)

    private var credentialsBlock: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionCaption("credentials.section")
            VStack(spacing: 0) {
                if appState.credentials.isEmpty {
                    Text("credentials.empty")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(16)
                } else {
                    ForEach(Array(appState.credentials.enumerated()), id: \.element.id) { index, credential in
                        if index > 0 { Divider() }
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
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(16)
                    }
                }
            }
            .contentCard()
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
}

// MARK: - 初回起動の導入 (オンボーディング)
//
// 4 ページ: ようこそ → USB 接続 → 鍵は端末内 → ペアリングは設定から。
// 最後のページの主ボタンは、導入を終えてそのまま設定を開く。

struct OnboardingView: View {
    let onFinish: () -> Void
    let onOpenSettings: () -> Void

    @State private var page = 0

    var body: some View {
        VStack(spacing: 0) {
            TabView(selection: $page) {
                welcomePage.tag(0)
                introPage(
                    icon: "cable.connector",
                    titleKey: "onboarding.how.title",
                    bodyKey: "onboarding.how.body"
                ).tag(1)
                introPage(
                    icon: "lock.shield.fill",
                    titleKey: "onboarding.security.title",
                    bodyKey: "onboarding.security.body"
                ).tag(2)
                introPage(
                    icon: "qrcode.viewfinder",
                    titleKey: "onboarding.pair.title",
                    bodyKey: "onboarding.pair.body"
                ).tag(3)
            }
            .tabViewStyle(.page(indexDisplayMode: .always))

            controls
                .padding(24)
        }
        .background(Color(.systemBackground).ignoresSafeArea())
    }

    private var welcomePage: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "key.fill")
                .font(.system(size: 48))
                .foregroundStyle(.blue)
                .frame(width: 116, height: 116)
                .iconBadge()
            Text(verbatim: "Phone FIDO Key")
                .font(.largeTitle)
                .bold()
                .multilineTextAlignment(.center)
            Text("onboarding.tagline")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            Spacer()
        }
        .padding(.horizontal, 32)
    }

    private func introPage(
        icon: String,
        titleKey: LocalizedStringKey,
        bodyKey: LocalizedStringKey
    ) -> some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: icon)
                .font(.system(size: 48))
                .foregroundStyle(.blue)
                .frame(width: 116, height: 116)
                .iconBadge()
            Text(titleKey)
                .font(.title)
                .bold()
                .multilineTextAlignment(.center)
            Text(bodyKey)
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            Spacer()
        }
        .padding(.horizontal, 32)
    }

    @ViewBuilder
    private var controls: some View {
        VStack(spacing: 10) {
            if page < 3 {
                PrimaryButton(titleKey: "onboarding.continue") {
                    withAnimation { page += 1 }
                }
                Button("onboarding.skip") { onFinish() }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
            } else {
                PrimaryButton(titleKey: "onboarding.open_settings") {
                    onOpenSettings()
                }
                Button("onboarding.later") { onFinish() }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
            }
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
                PrimaryButton(titleKey: approveButtonKey) {
                    UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                    approval.approve()
                }

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
// メダリオン: フラットな円バッジ + 盾と錠のシンボル。
// その外周に、残り時間 (60 秒) を示すカウントダウンリングを重ねる。
// リングは装飾ではなく、自動拒否までの残り時間そのもの。

/// 承認シートのアイコン。
struct ApprovalIcon: View {
    var body: some View {
        Image(systemName: "lock.shield.fill")
            .font(.system(size: 40))
            .foregroundStyle(.blue)
            .frame(width: 92, height: 92)
            .iconBadge()
    }
}

/// メダリオンの外周を回る残り時間リング。
struct CountdownRing: View {
    /// 0.0 (時間切れ) 〜 1.0 (残り全部)
    let fraction: Double

    var body: some View {
        ZStack {
            Circle()
                .stroke(Color.primary.opacity(0.08), lineWidth: 3)
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
