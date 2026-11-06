import Foundation

// MARK: - 実行時言語切り替え (設定画面の言語ピッカー用)
//
// 仕組み:
// - 選択は UserDefaults に保持し、AppleLanguages にも反映する
//   (LAContext など OS 側ダイアログは次回起動時に追従する)。
// - アプリ内表示を即時に切り替えるため、Bundle.main のクラスを差し替えて
//   localizedString の参照先 .lproj を選択言語に向ける (定番の手法)。
// - SwiftUI 側は environment(\.locale) とルート View の .id 更新で
//   再描画し、LocalizedStringKey の解決も新しい言語で行われる。
// - 「システム」が既定値。その場合は上書きを一切せず、通常どおり
//   端末の言語設定に従う。

/// Bundle.main 差し替え用のサブクラス。言語が指定されている間だけ
/// その言語の .lproj バンドルから文字列を引く。
private final class LocalizedBundle: Bundle {
    static var languageCode: String?
    private static var cachedLanguage: String?
    private static var cachedBundle: Bundle?

    override func localizedString(
        forKey key: String,
        value: String?,
        table tableName: String?
    ) -> String {
        if let code = Self.languageCode {
            if Self.cachedLanguage != code {
                Self.cachedLanguage = code
                Self.cachedBundle = Bundle.main.path(
                    forResource: code,
                    ofType: "lproj"
                ).flatMap { Bundle(path: $0) }
            }
            if let bundle = Self.cachedBundle {
                return bundle.localizedString(
                    forKey: key,
                    value: value,
                    table: tableName
                )
            }
        }
        return super.localizedString(forKey: key, value: value, table: tableName)
    }
}

/// アプリの表示言語を管理する。nil = システム設定に従う。
@MainActor
final class LocaleManager: ObservableObject {
    /// ピッカー表示用 (コード, その言語自身での表記)。表記は固有名詞なので
    /// ローカライズ対象外 (各言語の自称をそのまま出すのが標準的な流儀)。
    static let supportedLanguages: [(code: String, nativeName: String)] = [
        ("en", "English"),
        ("ja", "日本語"),
        ("de", "Deutsch"),
        ("fr", "Français"),
        ("es", "Español"),
        ("pt-BR", "Português (Brasil)"),
        ("ko", "한국어"),
        ("zh-Hans", "简体中文"),
        ("zh-Hant", "繁體中文"),
    ]

    private static let defaultsKey = "PhoneFidoKey.language"

    /// 選択中の言語コード。nil はシステム設定に従う。
    @Published var selectedCode: String? {
        didSet { Self.apply(selectedCode) }
    }

    /// SwiftUI の environment(\.locale) に渡す値。
    var effectiveLocale: Locale {
        selectedCode.map { Locale(identifier: $0) } ?? .autoupdatingCurrent
    }

    init() {
        let stored = UserDefaults.standard.string(forKey: Self.defaultsKey)
        let code = stored.flatMap { code in
            Self.supportedLanguages.contains { $0.code == code } ? code : nil
        }
        selectedCode = code
        Self.apply(code)
    }

    /// 保存済みの選択をプロセス起動直後に反映する (View が作られる前に呼ぶ)。
    /// UserDefaults と Bundle しか触らないため nonisolated でよい。
    nonisolated static func applyStoredSelection() {
        let stored = UserDefaults.standard.string(forKey: defaultsKey)
        let code = stored.flatMap { code in
            supportedLanguages.contains { $0.code == code } ? code : nil
        }
        apply(code)
    }

    nonisolated private static func apply(_ code: String?) {
        if let code {
            UserDefaults.standard.set(code, forKey: defaultsKey)
            // OS 側の言語解決 (システムダイアログ等) も次回起動から追従させる。
            UserDefaults.standard.set([code], forKey: "AppleLanguages")
        } else {
            UserDefaults.standard.removeObject(forKey: defaultsKey)
            UserDefaults.standard.removeObject(forKey: "AppleLanguages")
        }
        LocalizedBundle.languageCode = code
        if !(Bundle.main is LocalizedBundle) {
            object_setClass(Bundle.main, LocalizedBundle.self)
        }
    }
}
