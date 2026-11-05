# サイドロード手順（このプロジェクトの利用者環境向け）

前提の環境: iPhone 側には **SideStore** と **LiveContainer** が入っており、
PC 側のローダーは **iLoader** を使っている。この文書はその構成に合わせた手順。
一般論は ios/README-XCODE.md を参照。

## 流れ

1. GitHub Actions（`.github/workflows/ios-ipa.yml`）が macOS ランナーで
   **未署名 IPA**（`IPhoneFidoKey-unsigned.ipa`）をビルドし、artifact として置く。
   このリポジトリは private なので、artifact のダウンロードにもログインが要る。
2. IPA を PC（Fedora / Windows）にダウンロードする。
3. **iLoader** で iPhone にインストールする。iLoader が Apple ID で署名して入れる
   （SideStore 本体を入れた時と同じ要領）。USB 接続した iPhone が対象。
   - もしくは IPA を iPhone に転送し、**SideStore** 側からインストールしてもよい。
4. インストール後、iPhone 上でアプリが単独アイコンとして存在することを確認する。
5. 以後の更新も同じ流れ（新しい IPA を入れ直す）。無料 Apple ID の署名は
   7 日で切れるので、SideStore の自動更新（Wi-Fi）に載せるか、切れる前に入れ直す。

## LiveContainer について（重要）

LiveContainer のゲストとして動かすことも原理的には可能だが、**本物の資格を作る用途では推奨しない**。理由:

- ゲストアプリは LiveContainer のプロセスとコンテナの中で動くため、Keychain の
  アクセス先や保存先が「このアプリ専用」とは言い切れない（未検証）。
- Face ID の使用説明文や生体認証の挙動もホスト側（LiveContainer）のものになる。
- Secure Enclave の鍵生成 API 自体は使える見込みだが、鍵参照の永続化が
  コンテナのライフサイクルに引きずられる恐れがある（未検証）。

最初の疎通確認（アプリが起動して待ち受けるか）だけなら LiveContainer で試す価値はあるが、
登録（makeCredential）を始める前に、SideStore / iLoader で通常インストールした状態にすること。

## 署名と資格の関係で知っておくこと

- アプリを **削除すると資格（Secure Enclave の鍵とメタデータ）は失われる**。
  再インストールしても復元できない。これがこの設計の前提（鍵は端末外に出ない）。
- 署名の更新（リフレッシュ）では通常データは消えないが、Bundle ID が変わるような
  入れ方をすると別アプリ扱いになり、既存の資格に届かなくなる。iLoader / SideStore でも
  毎回同じ Apple ID と同じ Bundle ID（`site.sahen.IPhoneFidoKey`）で入れること。
- 実機で登録を始める前に、消えて困るアカウントから試さないこと。
  まずは webauthn のテストサイトで登録・認証の往復を確認してから、GitHub、Google の順に進める
  （docs/REAL-DEVICE-TEST.md の段階 (d)〜(g)）。
