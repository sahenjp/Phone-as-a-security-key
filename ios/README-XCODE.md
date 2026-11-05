# iPhone FIDO Key — iOS アプリのビルドとサイドロード手順

iPhone を FIDO2 / WebAuthn セキュリティキーとして使うための iPhone 側アプリ。
仕様は `../docs/BRIDGE-PROTOCOL.md` が正で、このアプリはその「電話側」を実装する。
秘密鍵は Secure Enclave の中だけで生成・使用し、Fedora 側には渡らない。

> 状態について: このソース一式はコンパイル検証を経ていない。
> 初回ビルドで小さな修正が必要になる可能性を前提に、手順と直し方の見当も含めて書いてある。
> 「実機で動いた」と言えるのは、下の実機確認チェックリストを通してから。

## 構成

```
ios/
├── IPhoneFidoKey.xcodeproj/      Xcode プロジェクト (手書きの最小構成)
├── IPhoneFidoKey/
│   ├── IPhoneFidoKeyApp.swift    アプリ入口
│   ├── ContentView.swift         メイン画面 + 承認シート
│   ├── AppState.swift            画面状態 + 承認調整 (ApprovalCoordinator)
│   ├── BridgeServer.swift        NWListener (TCP 18765) + ハンドシェイク + 暗号化チャネル
│   ├── AuthenticatorService.swift  create / get / list の処理と authData 組み立て
│   ├── SecureEnclaveKeyStore.swift Secure Enclave 鍵の生成・署名 (Face ID)
│   ├── KeychainStore.swift       PSK と資格メタデータの Keychain 保存
│   ├── SessionCrypto.swift       ECDH (SecKey) / HKDF / ChaCha20-Poly1305、鍵導出の純粋関数
│   ├── CryptoUtils.swift         乱数 / SHA-256 / HMAC / Base32 / SAS
│   ├── CBOR.swift                最小 CBOR エンコーダ + COSE_Key 生成
│   ├── Models.swift              定数・型定義
│   ├── Info.plist                NSFaceIDUsageDescription 等
│   └── IPhoneFidoKey.entitlements  (空。余分な entitlement は付けていない)
└── IPhoneFidoKeyTests/
    └── BridgeCoreTests.swift     鍵導出・MAC・COSE・authData の既知答テスト
```

## 前提

- Mac + Xcode 15 以降
- iPhone (iOS 16 以降、Face ID 対応機)。Secure Enclave が必要なのでシミュレータでは署名系は動かない
- USB ケーブル (iPhone ↔ Mac はインストール用、iPhone ↔ Fedora は運用用)
- Apple ID (無料でよい。下の「署名の有効期限」を参照)

## ビルドと実機インストール (Xcode から)

1. `IPhoneFidoKey.xcodeproj` を Xcode で開く。
2. ナビゲータでプロジェクト `IPhoneFidoKey` を選び、ターゲット `IPhoneFidoKey` →
   **Signing & Capabilities** で **Team** に自分の Apple ID のチームを選ぶ
   (Xcode の Settings → Accounts で Apple ID を追加しておく)。
3. Bundle Identifier は初期値 `site.sahen.IPhoneFidoKey`。
   他人の識別子と衝突して署名に失敗する場合は、自分用に変える
   (例: `site.sahen.IPhoneFidoKey.<自分の名前>`)。コード側への影響はない。
4. iPhone を Mac に USB 接続し、iPhone 側で「このコンピュータを信頼」を許可する。
   Xcode の実行先にその iPhone を選ぶ。
5. 初回は iPhone の **設定 → 一般 → VPN とデバイス管理** で、自分の開発者証明書を「信頼」する。
   あわせて **設定 → プライバシーとセキュリティ → デベロッパモード** をオンにする (iOS 16 以降)。
6. Run (⌘R) でインストールと起動をする。

起動したら:

- 「ペアリングキーを生成」を押し、表示された Base32 (52 文字) を Fedora 側の
  `iphone-fido pair` に手入力する。SAS の 6 桁が両側で一致することを確認する。
- 認証するときはアプリを画面に表示したままにする
  (バックグラウンドでは NWListener が suspend され、接続が止まる前提)。

## 署名の有効期限と再インストール

- 無料 Apple ID の開発用プロビジョニングでは、インストールしたアプリは **7 日で期限切れ** になる。
  期限が切れたら Xcode から再 Run するか、下の AltStore / SideStore で再署名する。
- 有料の Apple Developer Program (年額あり) では 1 年有効になる。このプロジェクトは無料運用を前提にしている。

## AltStore / SideStore を使う場合の注意

- **AltStore**: Mac / PC 上の AltServer が同じネットワーク (または USB) 経由で定期的に再署名する。
  AltServer が動いている環境に定期的に戻る必要がある。
- **SideStore**: iPhone 単体で再署名できるが、初回セットアップにペアリングファイルの作成などが要る。
  再署名のたびに VPN 接続を使う方式なので、運用中の USB ブリッジと干渉しないかは実機で確認すること。
- どちらでも、**再署名で Bundle ID や署名が変わっても Keychain と Secure Enclave の鍵は
  同一アプリとして残るのが通常**だが、アプリを削除すると資格情報ごと消える。
  パスキーを登録した後にアプリを削除しないこと。削除 = その資格は二度と使えない。
- サイドロードしたアプリも「VPN とデバイス管理」での信頼が必要になる場合がある。

## プロジェクトが開けない / ビルドが通らない場合の作り直し手順

`project.pbxproj` は手書きの最小構成なので、Xcode のバージョン差で開けないことがあり得る。
その場合は新規プロジェクトにソースを流し込む方が早い。

1. Xcode で新規プロジェクト: App テンプレート、Interface = SwiftUI、Language = Swift、
   Product Name = `IPhoneFidoKey`、Organization Identifier は上記 Bundle ID に合わせて作る。
2. 自動生成された `IPhoneFidoKeyApp.swift` / `ContentView.swift` / `Assets.xcassets` は削除する
   (Assets は残しても害はない)。
3. Finder から `ios/IPhoneFidoKey/` フォルダ内の全ファイル (`.swift` / `Info.plist` /
   `.entitlements`) をプロジェクトへドラッグし、「Copy items if needed」と
   ターゲット `IPhoneFidoKey` への追加にチェックを入れる。
4. テストを使う場合は `ios/IPhoneFidoKeyTests/BridgeCoreTests.swift` を
   テストターゲットに追加する (無ければターゲット追加で Unit Testing Bundle を作る)。
5. ターゲットの Build Settings で次を確認する:
   - `INFOPLIST_FILE` = `IPhoneFidoKey/Info.plist`、`GENERATE_INFOPLIST_FILE` = NO
     (自動生成と併用すると NSFaceIDUsageDescription が上書きされることがある)
   - `CODE_SIGN_ENTITLEMENTS` = `IPhoneFidoKey/IPhoneFidoKey.entitlements` (空でよい)
   - Deployment Target = iOS 16.0、Swift Language Version = Swift 5
6. Signing & Capabilities で Team を選び直す。

## 実機確認チェックリスト (未検証のまま残っている点)

実装時に推測で決めた / 実機でしか分からない点。確認したら結果をここに追記する。

- [ ] usbmuxd / iproxy の転送が、通常アプリの NWListener (18765) に届くか (特に iOS 17 以降)
- [ ] NWListener の初回起動時にローカルネットワーク許可ダイアログが出るか、出る場合は許可後に待ち受けが回復するか
- [ ] `.privateKeyUsage + .biometryCurrentSet` の鍵で、生成時に Face ID が出ず、署名時にだけ出るか
- [ ] Face ID prompt の文言に LAContext の localizedReason (`<rp_id> へのサインインを承認`) が反映されるか
- [ ] Face ID をキャンセルしたときに `errSecUserCanceled` で拾えて `user_cancelled` を返せるか
- [ ] SecKey の ECDH (`ecdhKeyExchangeStandard`) の戻りが常に 32 byte か
      (コード側で 32 byte への正規化は入れてある)
- [ ] バックグラウンド遷移で接続がどう切れるか、復帰後に再接続できるか
- [ ] `fmt: "none"` の attestation を GitHub / Google が受理するか (検証は Fedora 側と共同)

## テスト

`BridgeCoreTests` は Mac 上のシミュレータ / 実機どちらでも実行できる (Xcode で ⌘U)。
内容は BRIDGE-PROTOCOL から独立に計算した既知答ベクタ:

- HKDF 鍵導出 (k_pc_phone / k_phone_pc / confirm_key)
- confirm / confirm_ack の HMAC
- Base32 表示 (52 文字) と SAS 6 桁
- COSE_Key の CBOR バイト列、makeCredential 用 authData のバイト列
- ChaCha20-Poly1305 フレームの往復と seq 再送の拒否
- SecKey 経由 ECDH の対称性

Rust 側のベクタと突き合わせるときは、このテストの入力
(PSK = `00..1f`、ECDH 共有秘密 = `20..3f`、pc_random = `40..5f`、phone_random = `60..7f`)
と期待値が基準になる。
