import SwiftUI

@main
struct IPhoneFidoKeyApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var localeManager = LocaleManager()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // 保存済みの言語選択を、最初の View が描かれる前に Bundle へ反映する。
        LocaleManager.applyStoredSelection()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .environmentObject(appState.approval)
                .environmentObject(localeManager)
                .environment(\.locale, localeManager.effectiveLocale)
                .onAppear {
                    appState.onAppear()
                }
                .onChange(of: scenePhase) { phase in
                    // フォアグラウンドに戻るたびに待ち受けを自動で立て直す。
                    if phase == .active {
                        appState.onSceneActive()
                    }
                }
        }
    }
}
