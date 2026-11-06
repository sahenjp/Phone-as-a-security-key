# Windows 対応の設計メモ

状態: **方式決定済み、実装中。未検証の機能であり、現時点では「Windows 対応」を謳いません。**

調査の全文（一次ソースへのリンク付き）は開発ノート側にあります。本書はリポジトリ内の設計判断の要約です。

## 方式: Windows 11 の WebAuthn パスキープラグイン API

Windows 11 24H2 / 25H2（2025 年 11 月のセキュリティ更新 KB5068861 以降）で GA になった、サードパーティのパスキープロバイダ向けプラグイン API を使います。

- プラグインが実装するのは COM インターフェース `IPluginAuthenticator`（`MakeCredential` / `GetAssertion` / `CancelOperation` / `GetLockStatus`）の 1 つだけです。
- 要求と応答のペイロードは **CTAP2 CBOR そのもの**（コマンドバイト + パラメータ）で、Linux daemon の `ctap2::process()` が受けている形式と同一です。登録 API `WebAuthNPluginAddAuthenticator` には、既存の GetInfo CBOR をそのまま渡せます。
- 配布は MSIX（`windows.comServer` 拡張 + `runFullTrust`）。自己署名証明書でサイドロード可能（ユーザーが証明書を信頼する手順が 1 つ増えます）。
- 有効化はユーザーが「設定 → アカウント → パスキー」でプロバイダをオンにします（Windows Hello で保護されており、自動化できません）。
- 拡張は API 側で hmac-secret / hmac-secret-mc / **prf（生の salt）** / credProtect / credBlob が解釈され、応答には unsignedExtensionOutputs の枠があります。Microsoft 公式サンプル自身が GetInfo に `["prf", "hmac-secret"]` を広告しています。

## 採用しない方式: 仮想 HID ドライバ (VHF)

Virtual HID Framework で Linux の UHID 相当を作る案は技術的には可能ですが、実運用でロードできる署名を得るには Microsoft の attestation / WHCP 署名が必要で、その前提として EV 証明書付きの Partner Center ハードウェアアカウント（有償・本人確認・年次更新）が要ります。趣味 OSS の配布形態としては不採用です。テスト署名は Secure Boot 無効化やテストモードが前提で、配布できません。

## 構成（予定）

| 部品 | 内容 |
|---|---|
| Rust コア（既存の再利用） | `bridge` / `phone` / `ctap2` / `cbor_util` はほぼ無変更で流用。UHID / CTAPHID / Linux transport は feature で分離 |
| Rust C ABI ラッパ | staticlib としてプラグインから呼ばれる薄い層 |
| C++ COM シム | 公式サンプル PasskeyManager 派生。プラットフォーム署名の検証、Rust 呼び出し、登録、資格メタデータの同期だけを持つ |
| usbmuxd クライアント (Rust) | Windows では Apple の「Apple Devices」アプリが入れる Apple Mobile Device Service が 127.0.0.1:27015 で usbmuxd プロトコルを話します。iproxy.exe の第三者ビルドに依存せず、自前の小さいクライアントで電話の TCP 18765 へ中継します。Android は `adb forward tcp:18766 tcp:18765` がそのまま使えます |
| MSIX | マニフェスト + 自己署名ビルド。GitHub Actions (windows-latest) で成果物化 |

電話側（iOS / Android アプリ）と Bridge Protocol は無変更です。Linux daemon が iproxy 経由で話していた相手が、Windows ではプラグイン + usbmuxd クライアントに替わるだけです。

## 本人確認 (UV) の扱い

プラグイン API には Windows Hello で本人確認するヘルパー（`WebAuthNPluginPerformUserVerification`）がありますが、これは金庫型マネージャ向けの補助で、API 契約上の必須ではありません。本プロジェクトの UV は従来どおり**電話側の生体認証**です。`GetLockStatus` は電話セッションの生存に写像します。

## 未解決事項（実機で潰す）

1. プラットフォームが authData の UV ビットを Windows Hello セッションと突き合わせるか（強制される場合は設計変更が要ります。確率は低いと見ていますが未検証です）。
2. hmac-secret / hmac-secret-mc の暗号化 salt の鍵合意の出自。ClientPIN 往復のないプラグインにどう届くかが公開情報では未解読です。**prf 拡張は無関係**（生の salt が届き、既存の prf 経路がそのまま使えます）。最悪の場合は Windows 版の GetInfo 広告から hmac-secret を外して切り分けます。
3. 資格削除のプラットフォーム側への伝播の意味論（IDL に専用コールバックがありません）。
4. Firefox がプラグインを列挙するか（独自スタックのため対象外になる可能性があります）。

## 進め方

- Phase 0（スパイク、Windows 実機 + 同席が必須）: Windows のビルド番号確認、公式サンプルそのままで登録と webauthn.io の作成が通ることの確認、未解決事項 1 と 2 の観測。
- Phase 1（実装）: Rust の C ABI 化と usbmuxd クライアント、C++ シム、MSIX、Windows CI。
- Phase 2（実機検証）: インストール → 有効化 → webauthn.io → GitHub → ppq.ai (PRF) を REAL-DEVICE-TEST と同じ段取りで記録。
- Phase 3（配布整備）: 証明書方針、README の Windows 節、手順書、リリースアセットへの MSIX 追加。

正式リリースでの扱いは、検証が済んだ範囲だけを書くという本プロジェクトのルールに従います。Phase 2 の webauthn.io までが実機で通れば「プレビュー」として同梱し、GitHub と PRF が通った次のリリースで初めて「対応」と謳います。
