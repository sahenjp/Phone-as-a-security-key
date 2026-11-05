import SwiftUI

@main
struct IPhoneFidoKeyApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .environmentObject(appState.approval)
                .onAppear {
                    appState.onAppear()
                }
        }
    }
}
