# iphone-fido-key

Fedora Linux と USB ケーブルで接続した iPhone を、FIDO2 / WebAuthn セキュリティキーとして使うための OSS です。

iPhone の Secure Enclave に秘密鍵を保持し、署名のたびに iPhone 上で RP（依拠当事者）を表示してユーザーがタップで承認し、Face ID を通したときだけ署名します。Fedora 側は仮想 FIDO2 デバイス（UHID）としてブラウザに見え、CTAP2 を終端します。秘密鍵は Fedora に渡りません。

- Bluetooth 不要
- 脱獄不要
- iPhone アプリはサイドロード可能にする想定（App Store 配布は前提にしない）
- 既存の iCloud パスキーの読み出しはしません。本プロジェクト専用の資格を新規に作ります

共通仕様は [docs/BRIDGE-PROTOCOL.md](docs/BRIDGE-PROTOCOL.md) が唯一の正です。Rust 実装と Swift 実装が食い違ったら、コードではなくそちらに合わせます。

## 構成

```text
ブラウザ / WebAuthn RP
  GitHub / Google / webauthn.io 等
        |  WebAuthn (navigator.credentials)
        v
ブラウザの CTAP2 トランスポート
        |  CTAPHID over UHID
        v
Fedora: iphone-fido daemon (Rust)          <-- このリポジトリの crates/
  - /dev/uhid に仮想 FIDO2 デバイスを登録
  - CTAP2: getInfo / makeCredential / getAssertion を終端
  - authData の材料と署名は iPhone から受け取る (加工しない)
        |  Bridge Protocol v1 (docs/BRIDGE-PROTOCOL.md)
        |  PSK ペアリング + 一時 ECDH + HKDF
        |  ChaCha20-Poly1305 で認証・暗号化
        v
Fedora: iproxy 18766 18765 (libusbmuxd-tools)
        |  usbmuxd 経由 / USB
        v
iPhone: iphone-fido アプリ (Swift)         <-- このリポジトリの ios/
  - TCP 18765 で待ち受け (フォアグラウンド必須)
  - rp_id と user_name を画面表示し、タップ承認を待つ
  - Secure Enclave (P-256 / ES256) で鍵生成・署名
  - 署名時は SecAccessControl により Face ID を必須にする
  - authData は電話側で組み立てる
```

役割分担の要点:

| 層 | 担当 | しないこと |
|---|---|---|
| Fedora daemon (Rust) | UHID、CTAPHID、CTAP2 終端、iproxy 起動、ペアリング PSK の保管 (`~/.config/iphone-fido/pairing.bin`, mode 0600) | 秘密鍵の保持、任意バイト列への署名要求、authData の加工 |
| iPhone アプリ (Swift) | 鍵生成・保持、rp 表示、タップ承認、Face ID、authData 組み立て、署名 | CTAP の解釈、Fedora 側の表示を信用すること |
| Bridge Protocol | ペアリング、セッション鍵、暗号化フレーム、意味操作 (`ping` / `create_credential` / `get_assertion` / `list_credentials`) | 平文での署名要求の受け付け |

先行 OSS との違い: Go の virtual-fido、Rust の soft-fido2 / passless など、PC 上で完結する仮想 FIDO2 の前例はあります。本プロジェクトはそれらのラッパーではなく、PC はトランスポートと CTAP 終端だけを担い、authenticator 本体（鍵と本人確認）を電話に置く点が差分です。

## 検証状況（誇張しない）

凡例: ✅ 検証済み / ⚠️ 前提・公開資料で確認済みだが本プロジェクトでは未検証 / ❌ 未検証・未実施 / 🚧 実装中・部分実装

| 項目 | 状態 | 根拠・備考 |
|---|---|---|
| Bridge Protocol v1 の仕様策定 | ✅ | [docs/BRIDGE-PROTOCOL.md](docs/BRIDGE-PROTOCOL.md) |
| usbmuxd / iproxy が端末側ソケットへ中継できる原理 | ⚠️ | 公開資料で確認。WebDriverAgent（ポート 8100）を iproxy 転送で使う前例あり |
| 実機 iPhone ⇄ Fedora の USB 疎通（本プロジェクトのアプリ、ポート 18765） | 🚧 | 2026-11-05 に段階 (a) 端末認識は合格（iPhone 17 / iOS 27.0、usbmuxd active、idevicepair validate SUCCESS）。アプリ到達はアプリ未導入のため未実施。記録は [docs/REAL-DEVICE-TEST.md](docs/REAL-DEVICE-TEST.md) §11 |
| iOS 17 以降で通常アプリの待ち受けポートへ iproxy 転送が届くか | 🚧 | iOS 27.0 実機で、iproxy 経由の接続試行が端末の TCP スタックまで届き接続拒否が返ることは 2026-11-05 に確認済み。アプリが待ち受けた時にアプリへ届くかは未検証。詳細は FEASIBILITY を参照 |
| Rust 仮想 FIDO2 デバイス（UHID / CTAPHID / CTAP2 getInfo） | ✅ | 2026-11-05 に実機 Fedora で確認済み: udev ルール導入後 root 不要で daemon が起動し、仮想 HID (hidraw, VID 0x1209/PID 0xF1D0) が出現。外部プロセスから実 UHID 経由で CTAPHID INIT と CTAP2 getInfo (status 0x00) の応答を確認。さらに同日、Firefox が authenticator として認識し webauthn.io の登録・認証まで通った（下記。記録は REAL-DEVICE-TEST §11） |
| Secure Enclave が P-256 / ES256 (COSE `-7`) に対応すること | ⚠️ | Secure Enclave は P-256 のみで、WebAuthn の ES256 と一致する、というプラットフォーム仕様として確認済み。本アプリでの動作は未検証 |
| Face ID を署名時にハードウェア強制する設計 | ⚠️ | `SecAccessControl` の `.biometryCurrentSet` + `.privateKeyUsage` を使う設計で、先行プロダクトでも使われている。本アプリでの prompt の出るタイミングは未検証（BRIDGE-PROTOCOL §5） |
| CTAP2 makeCredential / getAssertion の電話連携 | 🚧 | モック電話（`--mock-phone`）連携は実機 Fedora + 実ブラウザで検証済み（2026-11-05）。実電話（iOS アプリ）との連携は未検証。モックで作った資格を本物と誤認しないこと |
| webauthn.io 等のテストサイトでの登録・認証 | 🚧 | 2026-11-05、Firefox + モック電話で webauthn.io の登録 (makeCredential status 0x00) と認証 (getAssertion status 0x00) を確認。`fmt:"none"` は webauthn.io に受理された。実電話での再実施は段階 (d) として未実施 |
| GitHub での登録・認証 | ❌ 未実施 | 実機検証の段階 (f)。`fmt:"none"` を受理するか含め未確認 |
| Google での登録・認証 | ❌ 未実施 | 実機検証の段階 (g)。`fmt:"none"` を受理するか含め未確認 |
| ペアリング + ECDH + AEAD による通信の認証・保護 | 🚧 | 仕様は BRIDGE-PROTOCOL §1–§2。鍵導出・confirm MAC・SAS・Base32・COSE/authData のテストベクタは Rust 実装と Swift テストコードで一致を確認済み (2026-11-05)。実機アプリとのライブ疎通は未検証 |
| 同一 RP に複数資格がある場合の選択 | ❌ 未実装 | 現状の iPhone アプリは作成順の先頭 1 件を選ぶ。選択 UI は今後の実装 |
| Swift アプリのコンパイル | ❌ 未検証 | この開発環境には Xcode / Swift が無く未コンパイル。Mac 上の初回ビルドで API シグネチャ等の修正が入る可能性がある (ios/README-XCODE.md に復旧手順あり) |

未検証の機能を完成済みとして扱いません。状態が変わったら、この表と各ドキュメントを同じ変更で更新してください。

## ドキュメント

- [docs/BRIDGE-PROTOCOL.md](docs/BRIDGE-PROTOCOL.md) — Fedora ⇄ iPhone の共通仕様（唯一の正、編集は慎重に）
- [docs/FEASIBILITY.md](docs/FEASIBILITY.md) — 実装順序 1「USB 通信の成立可能性」の検証報告と、失敗時の切り分け手順
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — 脅威モデル、対策、残存リスク
- [docs/REAL-DEVICE-TEST.md](docs/REAL-DEVICE-TEST.md) — 実機検証の手順書と記録テンプレート
- [scripts/verify-usb-fedora.sh](scripts/verify-usb-fedora.sh) — Fedora 実機で実行する読み取り中心の USB 検証スクリプト

## ビルド / 利用手順（概要）

詳細は各担当の README と [docs/REAL-DEVICE-TEST.md](docs/REAL-DEVICE-TEST.md) を参照してください。ここは全体の流れだけです。

### Fedora 側

前提パッケージ（詳細は REAL-DEVICE-TEST を参照）:

```sh
sudo dnf install libimobiledevice usbmuxd libusbmuxd-tools
```

流れ:

1. iPhone を USB で接続し、`idevicepair pair` で trust を確立する。
2. USB 疎通を先に単体で確認する: `scripts/verify-usb-fedora.sh`
3. daemon をビルドする（Rust / Cargo、UHID を使うため `/dev/uhid` へのアクセス権が必要）。
4. iPhone アプリを起動した状態でペアリングする: アプリ画面の Base32（52 文字）を `iphone-fido pair` に手入力し、両側の SAS 6 桁が一致することを目で確認する。
5. daemon を起動し、ブラウザから WebAuthn テストサイトで登録・認証する。

開発時のみ、電話なしで進めるためのモック電話があります（`--mock-phone`、起動時に警告が出ます）。モックはソフトウェア鍵であり、Secure Enclave でも Face ID でもありません。本番の検証には使わないでください。

### iPhone 側

1. `ios/` のアプリをビルドし、サイドロード可能な形で実機に入れる（手順の詳細は REAL-DEVICE-TEST を参照）。
2. アプリをフォアグラウンドで起動する（バックグラウンドでは NWListener が suspend される前提で、待ち受けは維持されません）。
3. 初回はペアリング表示を確認し、以降は操作ごとに画面の rp を確認して承認し、Face ID を通す。

## セキュリティの要点

全文は [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) を参照してください。

- 秘密鍵は Secure Enclave 内でのみ生成・保持し、Fedora には渡しません。Fedora が受け取るのは公開鍵、authData、署名だけです。
- USB 接続だけで認証を承認しません。iPhone 上の明示的なタップ承認と Face ID の二重ゲートが必須です。
- PC は任意バイト列への署名を電話に求めません。電話が rpId から authData を自ら組み立て、表示し、承認されたときだけ署名します。
- PC ⇄ 電話の通信は、帯域外で共有した PSK によるペアリングと、接続ごとの一時 ECDH + AEAD で認証・保護します。
- ただし Fedora 自体が侵害された場合、表示内容の騙しなどを完全には防げません。残存リスクを THREAT-MODEL に正直に書いてあります。

## ライセンス

MIT License — [LICENSE](LICENSE) を参照してください。
