import SwiftUI

@main
struct IPhoneFidoKeyApp: App {
    @StateObject private var appState = AppState()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .environmentObject(appState.approval)
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
