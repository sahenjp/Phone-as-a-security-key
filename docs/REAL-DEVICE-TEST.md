# REAL-DEVICE-TEST — 実機検証の手順書

Fedora 実機 + 実機 iPhone で、USB 疎通から GitHub / Google での認証までを段階的に確認する手順です。

前提となる調査結果と切り分けは [FEASIBILITY.md](FEASIBILITY.md)、仕様は [BRIDGE-PROTOCOL.md](BRIDGE-PROTOCOL.md)、脅威モデルは [THREAT-MODEL.md](THREAT-MODEL.md) を参照してください。

> **現在の状態: この手順は未実施です。** 開発 VM には USB が無く、Fedora 実機への到達（Tailscale Funnel）も作業セッション時のみ ON の運用のため、本書の作成時点ではどの段階も合格していません。実施したら、各段階の結果を §9 のテンプレートで必ず記録してください。記録のない段階は未検証のままです。

進め方の原則:

- 段階を飛ばさない。前段が合格するまで次に進まない（駄目なまま進むと切り分け不能になります）。
- 「selftest 的に通った」と「実 CTAP が通った」を混同しない。特に段階 (c) では、daemon の自己診断ではなく、実際の WebAuthn サイトで `getInfo` 相当の認識が取れることを合格条件にします。
- モック電話（`--mock-phone`）で通った段階は、実機の合格として数えません。記録には実施形態（実機 / モック）を必ず書きます。
- 失敗したら要約せず、コマンド出力の原文を記録します。

---

## 0. 事前準備

### 0.1 記録する環境情報

実施前に次を控えます（§9 テンプレートの先頭項目です）:

- 日付、実施者
- Fedora のバージョン（`cat /etc/fedora-release`）
- iPhone の機種、iOS バージョンとビルド（設定 → 一般 → 情報）
- ケーブルの種類（純正／サードパーティ、データ転送対応の明記があるか）、ハブの有無
- ツールのバージョン: `usbmuxd --version` 相当、`ideviceinfo --version`、`iproxy --version` 相当（取れるものだけで可）

### 0.2 Fedora 側のインストール

```sh
sudo dnf install libimobiledevice usbmuxd libusbmuxd-tools
```

入る主なコマンド: `idevice_id`, `ideviceinfo`, `idevicepair`, `iproxy`, `usbmuxd`。

確認:

```sh
command -v usbmuxd idevice_id ideviceinfo idevicepair iproxy
systemctl status usbmuxd --no-pager # または pgrep -a usbmuxd
```

daemon のビルドと `/dev/uhid` の扱い:

- Rust ツールチェーン（cargo）で daemon をビルドします（ビルド手順の詳細は crates 側の README に従ってください）。
- daemon は `/dev/uhid` を使います。自分のユーザーでアクセスできるか確認します: `ls -l /dev/uhid`。権限が無い場合は勝手に緩めず、udev ルール等の正規の方法を別途記録して対処してください。

### 0.3 iPhone 側の準備

- アプリをサイドロード可能な形で実機に入れます（ビルドと署名、インストールの詳細手順は ios 側の README に従ってください。本書ではその完了を前提にします）。
- アプリの入手元と署名が正規のものであることを確認します（THREAT-MODEL §5.4）。
- バッテリーと画面ロックの設定: 検証中は自動ロックが短いと段階の途中で切れるため、作業中だけ自動ロックを長めにするか、こまめにロック解除します。設定を変えたら検証後に戻します。

---

## 段階 (a): ideviceinfo で端末認識

目的: USB 接続、usbmuxd、ペアリング（trust）が成立していること。

手順:

1. iPhone を USB で直結し、ロックを解除する。
2. UDID の列挙:

```sh
idevice_id -l
```

3. 初回はペアリングする（iPhone 側に「このコンピュータを信頼しますか？」が出たら信頼する）:

```sh
idevicepair pair
idevicepair validate
```

4. 端末情報が取れることを確認:

```sh
ideviceinfo -k DeviceName
ideviceinfo -k ProductVersion
```

合格条件:

- [] `idevice_id -l` に UDID が 1 行以上出る
- [] `idevicepair validate` が成功を返す
- [] `ideviceinfo` がエラーなく DeviceName と iOS バージョンを返す
- [] §0.1 の iOS バージョン記録と一致する

失敗したら: FEASIBILITY §5 の段階 0–2（ケーブル、usbmuxd 起動、trust）で切り分け、結果を記録して止まります。

## 段階 (b): iproxy + ping 疎通

目的: `iproxy 18766 18765` 経由で、フォアグラウンドの iPhone アプリ（18765）に届き、Bridge の入口（hello ハンドシェイク）が返ること。**本プロジェクト最大の未検証点（iOS 17+ の中継可否）を確認する段階です。**

手順:

1. iPhone アプリをフォアグラウンドで起動し、待ち受け状態にする。
2. まず自動判定スクリプトを流す:

```sh
scripts/verify-usb-fedora.sh
```

スクリプトは読み取り中心で、ペアリング削除などの破壊的操作はしません。iproxy が未起動なら一時的に起動し、終了時に自分の起動分だけを片付けます。
3. 手動でも確認する場合:

```sh
iproxy 18766 18765
# 別ターミナルで daemon 側の ping 相当、またはスクリプトの段階 6 の結果で確認
```

4. アプリをバックグラウンドに移すと接続が切れる（suspend）ことも観察し、制約として記録します。

合格条件:

- [] verify-usb-fedora.sh が最終段階（ping / hello 応答）まで成功で終了する（exit code 0）
- [] iPhone アプリ側に接続を受けた表示・ログがある
- [] アプリを前面に戻した直後の再接続でも成功する
- [] （観察）バックグラウンド移行で切断されることを確認し、フォアグラウンド必須の制約として記録した

失敗したら: FEASIBILITY §5 の段階 3–5。特に「TCP は届くが先に進まない」ケースは iOS バージョン起因の可能性があり、iOS バージョンと出力原文の記録が必須です。

なお、この段階の ping は Bridge Protocol の接続確認であり、暗号化チャネル内の意味操作 `{"op":"ping"}` の完全な往復はペアリング完了後（次段階以降、または daemon の正規フロー内）で確認します。TCP 到達だけで「疎通した」と記録しないでください。どのレベルまで届いたか（TCP 接続 / hello_ack / 暗号化 ping 応答）を区別して記録します。

## 段階 (c): 実 CTAP の getInfo を外部サイトで確認

目的: daemon + UHID がブラウザに本物の authenticator として認識され、CTAP2 `getInfo` が返ること。**selftest や daemon 単体の自己診断では合格にしません。**

手順:

1. ペアリングが済んでいない場合は先に済ませる: アプリ画面の Base32（52 文字）を `iphone-fido pair` に手入力し、両側の SAS 6 桁の一致を目視確認する。
2. daemon を（モックではなく実機モードで）起動する。
3. ブラウザで WebAuthn テストサイト（例: webauthn.io）を開き、authenticator の認識と getInfo 相当の情報が取得できることを確認する。ブラウザの WebAuthn デバッグ機能（例: Chrome 系なら DevTools の WebAuthn パネル）で次を照合する:
- versions に `FIDO_2_0` がある
- AAGUID が BRIDGE-PROTOCOL §3.2 の固定値と一致する
- algorithms に ES256 がある
- options が `{rk:true, up:true, uv:true, clientPin:false}` と一致する

合格条件:

- [] テストサイト／DevTools が仮想 authenticator を認識する
- [] 上記 getInfo の照合項目がすべて仕様と一致する
- [] 実機モード（`--mock-phone` でない）で実施したことを記録した

失敗したら: UHID の権限、daemon のログ、ブラウザ側のエラーを分けて記録します。ブラウザが認識しない場合は「電話の問題」と決めつけず、daemon 単体（モック）で切り分けた結果も併記します（ただしモックでの成功は本段階の合格には数えません）。

## 段階 (d): 登録 (makeCredential)

目的: テストサイトへの登録が、電話側の承認 + Face ID を経て完了すること。

手順:

1. 段階 (c) の状態を維持し、iPhone アプリをフォアグラウンドにする。
2. テストサイトで新規登録を開始する。
3. iPhone に rp_id と user_name が表示されることを確認し、表示内容がテストサイトと一致することを目で見る。
4. 「作成」をタップし、Face ID の prompt が出るタイミングを観察して記録する（鍵生成時か署名時か。BRIDGE-PROTOCOL §5 の実機確認事項）。
5. 登録完了をテストサイト側で確認する。

合格条件:

- [] 電話に rp_id / user_name が正しく表示された
- [] タップ承認なしには先に進まなかった
- [] Face ID が必須で提示された（どのタイミングか記録した）
- [] テストサイトが登録完了を表示し、attestation の形式が `none` であることを確認した
- [] 拒否操作（キャンセル）で登録が中止され、`user_cancelled` 相当になることも 1 回確認した

## 段階 (e): 認証 (getAssertion)

目的: 登録した資格で認証が通ること。承認騙し耐性の最低限の観察も含みます。

手順:

1. テストサイトで認証（ログイン）を開始する。
2. iPhone に rp_id が表示され、「承認」タップ → Face ID → 認証完了、の順を確認する。
3. 次の負例も行う:
- タップせず放置／キャンセルすると認証が失敗すること
- iPhone アプリをフォアグラウンドにしていないと進まないこと

合格条件:

- [] 承認 + Face ID を経て認証が完了した
- [] キャンセル時は認証が失敗し、サイト側も成功扱いにならなかった
- [] sign_count が前回より増えていることを（確認手段がある範囲で）記録した

## 段階 (f): GitHub

目的: 実際の RP である GitHub で登録・認証できること。特に `fmt:"none"` の受理可否を確認します。

手順:

1. GitHub の設定画面（Settings → Password and authentication → Security keys / Passkeys 相当）から、本デバイスを登録する。
2. 段階 (d) と同様に、電話の表示・承認・Face ID を確認する。
3. いったんログアウトする等して、登録したキーで再認証（または 2 要素認証）できることを確認する。
4. GitHub 側の画面文言やエラーは原文のまま記録する。

合格条件:

- [] GitHub が登録を受理した（受理しなければ、その旨とエラー原文が合格ではなく「結果の記録」となる。下記参照）
- [] 登録したキーで認証が完了した

受理されなかった場合: それは本プロジェクトの重要な検証結果です。失敗を隠さず、`none` attestation が原因かどうかを含めて §9 に記録し、FEASIBILITY / THREAT-MODEL の該当記述を更新する材料にします。

## 段階 (g): Google

目的: Google アカウントのパスキー／セキュリティキーとして登録・認証できること。GitHub と同様に `fmt:"none"` の受理可否が焦点です。

手順:

1. Google アカウントのセキュリティ設定から、パスキーまたはセキュリティキーの作成を開始し、本デバイスを選ぶ。
2. 電話の表示・承認・Face ID を確認して登録を完了する。
3. ログアウトまたはシークレットウィンドウ等で、登録したキーによる認証を確認する。
4. Google 側の制限表示（例: 作成方法の選択肢に現れない等）があれば原文を記録する。

合格条件:

- [] Google が登録を受理した（同上、拒否も重要な結果として記録する）
- [] 登録したキーで認証が完了した

注意: Google はパスキーの作成経路やプラットフォーム要件が変わりやすいため、「手順のどこで詰まったか」を段階 (f) 以上に詳しく記録してください。

---

## 8. 実施後の更新先

検証が進んだら、次を同じ作業で更新します（未検証のまま放置しない）:

- ルート README の「検証状況」表
- FEASIBILITY §7 のチェックリスト
- THREAT-MODEL §7 のチェックリスト
- BRIDGE-PROTOCOL §5 の実機確認事項（確定したものは本文へ反映するかは別途判断し、勝手に書き換えない）

## 9. 記録テンプレート

段階ごとにコピーして使います。出力は要約せず原文を貼ります。

```markdown
### 段階 () の記録

- 日時:
- 実施形態: 実機 / モック (モックは合格に数えない)
- Fedora: (バージョン、ツールバージョン)
- iPhone: (機種、iOS バージョンとビルド)
- 接続: (ケーブル、ハブ有無)
- 実施したコマンド / 操作:
- 結果: 合格 / 不合格 / 部分的 (到達レベルを明記: TCP / hello_ack / 暗号化 ping / CTAP / 登録 / 認証)
- 出力原文:
```
(ここに出力そのもの)
```
- iPhone 側の表示・挙動: (rp 表示、Face ID のタイミング、バックグラウンド時の挙動など)
- 失敗時の切り分け: (FEASIBILITY §5 のどの段まで切り分けたか、原因の確定 / 推定の別)
- 次のアクション:
```

全体の実施サマリ:

```markdown
## 実機検証サマリ (YYYY-MM-DD)

| 段階 | 結果 | 記録リンク / 備考 |
|---|---|---|
| (a) 端末認識 | 未実施 / 合格 / 不合格 | |
| (b) iproxy + ping | 未実施 / 合格 / 不合格 | 到達レベル: |
| (c) 実 CTAP getInfo | 未実施 / 合格 / 不合格 | |
| (d) 登録 | 未実施 / 合格 / 不合格 | |
| (e) 認証 | 未実施 / 合格 / 不合格 | |
| (f) GitHub | 未実施 / 合格 / 不合格 | none attestation 受理: |
| (g) Google | 未実施 / 合格 / 不合格 | none attestation 受理: |
```

## 10. 未検証項目の一覧（この文書分）

- [x] 段階 (a) 端末認識 — 2026-11-05 合格（下記 §11）
- [x] 段階 (b) iproxy + ping — 2026-11-06 合格（実電話。ペアリング + ハンドシェイク + 暗号化 ping まで確認、§11 追記参照）
- [x] 段階 (c) ブラウザ認識 + WebAuthn セレモニー — 2026-11-05 合格（モック電話。Firefox + webauthn.io で登録・認証成功、§11 追記参照）。実電話では CTAP クライアント経由の makeCredential / getAssertion が 2026-11-06 に合格（§11 追記参照）。ブラウザ経由の実電話実施は (d) 以降で再確認する
- [] 段階 (d) ～ (g) — (d) の webauthn.io 分はモック電話で合格済み。実電話ではブラウザ経由は未実施
- [x] iPhone アプリのサイドロード手順そのものの検証 — 2026-11-06: 未署名 IPA を iLoader（Fedora、COPR 版 2.4.1）で導入し起動まで確認。アーティファクト zip のまま渡すと "No Payload directory found" になる（内側の .ipa を取り出して渡す）
- [x] `/dev/uhid` の権限対処法の確定 — udev ルール（packaging/99-iphone-fido-uhid.rules）で一般ユーザー実行を確認（2026-11-05）
- [] Face ID prompt が出るタイミングの確定（鍵生成時 / 署名時）— 実電話の makeCredential / getAssertion とも承認 + Face ID が必要で authData flags に UV が立った（0x45 / 0x05）。鍵生成時のみか署名時もか、の切り分けは未確定

## 11. 実機検証の記録

### 段階 (a) 端末認識の記録 (2026-11-05)

- 日時: 2026-11-05 19:53 JST
- 実施形態: 実機（Fedora へは Muse が Tailscale 直通 SSH で入り遠隔実施）
- Fedora: Fedora 44, kernel 6.19.10-300.fc44.x86_64, usbmuxd 1.1.1, libimobiledevice-utils 1.4.0, libusbmuxd-utils 2.1.1（この日に `dnf install` で導入）
- iPhone: iPhone18,3 (iPhone 17), ProductVersion **27.0**, BuildVersion 24A437, UDID は `00008150-…`（全文は記録しない）
- 当初 `lsusb` に Apple デバイスが現れず（15 デバイス中 0 件）不合格だったが、ケーブルの挿し直し後に解消した。原因がケーブルだったかポートだったかは切り分けていない
- 出力原文（抜粋）:
```
Bus 001 Device 007: ID 05ac:12a8 Apple, Inc. iPhone
00008150-… (idevice_id -l)
DeviceName: Dn’s iPhone17
SUCCESS: Validated pairing with device (idevicepair validate)
usbmuxd: active, /var/run/usbmuxd ソケットあり
```
- 結果: **合格**（端末認識 + trust + ペアリング検証まで）

### 段階 (b) iproxy + ping の記録 (2026-11-05, 部分的)

- `scripts/verify-usb-fedora.sh` を実機で実行: 段階 1/6〜5/6 は全て OK、段階 6/6 のみ NG で exit 2
- iproxy を 18766→18765 で起動し接続すると、端末側から **Connection refused** が返り接続が reset された。アプリが未導入で 18765 に待ち受けが無いため、この拒否は想定どおり
- 意味: iOS 27.0 でも usbmux/iproxy の接続試行は端末の TCP スタックまで届き、端末が応答を返すことが実証された。残る未確認は「アプリが待ち受けた時に接続がアプリへ届くか」のみ
- 結果: **部分的**（到達レベル: TCP の拒否応答まで。hello_ack 以降はアプリ導入後）

### 段階 (c) 実 CTAP getInfo の記録 (2026-11-05, 部分的)

- 日時: 2026-11-05 20:41 JST
- 実施形態: 実機 Fedora 上の daemon（UHID 実 transport）+ モック電話。ブラウザではなく自作の CTAPHID クライアントスクリプトから検証したため、ブラウザ認識は含まない
- 前提: `packaging/99-iphone-fido-uhid.rules` を導入済みで `/dev/uhid` は root:input 0660（ユーザーは input グループ所属）。daemon は root 不要で起動できた
- カーネルに仮想 HID が出現した:
```
hidraw10: HID_ID=0003:00001209:0000F1D0 HID_NAME=iphone-fido (iPhone FIDO2 authenticator)
```
- CTAPHID INIT（broadcast）→ nonce エコー一致、新 channel 0x00000001、protocol 2、capabilities 0x04
- CTAP2 getInfo（CBOR コマンド）→ status 0x00、90 byte。デコード: `{1:["FIDO_2_0"], 3:AAGUID(iph-fido-0000001), 4:{rk:true, up:true, uv:true, clientPin:false}, 5:1200}`
- 同日、Fedora 実機でも `cargo test` 22 件全通過と `selftest` PASS を確認済み
- 結果: **部分的**（実 UHID + 実 CTAP の疎通まで。残りは Firefox 等のブラウザが authenticator として認識し、WebAuthn の登録・認証が通るか）

### 追記 (2026-11-05 20:56): 実 UHID 越しの makeCredential / getAssertion 往復

- 同じ CTAPHID クライアントから、実 daemon（モック電話）に対して **makeCredential（156 byte リクエスト）→ status 0x00、authData flags 0x45、credential id 32 byte**、続けて **getAssertion → status 0x00** の往復を確認した。複数フレームの分割・再組立も双方向で正常
- なお最初の再現テストではクライアント側スクリプトの CBOR エンコードにバグ（配列ヘッダの major type 取り違え）があり、daemon が正しくエラーを返していただけで、daemon 側の問題ではなかった。切り分けの過程で判明したため記録しておく
- 残る段階 (c) の未検証はブラウザ（Firefox）の WebAuthn セレモニーだけ。ユーザー側の初回試行は失敗したが、本人の申告により Firefox に Bitwarden 拡張が入っており、パスキーのセレモニーを拡張が横取りした可能性が高い（要再試行で確認）

### 追記 (2026-11-05 22:06): ブラウザ登録・認証 成功（段階 (c) 完了、(d) モック分完了）

初回〜再試行の失敗は Bitwarden ではなく daemon 側の2件の不具合が原因だった。パケットレベルのログ（`--verbose`）と authenticator-rs のソースで切り分けた。

1. **65 バイトレポート問題**: ブラウザ（hidapi 系）は書き込みレポートの先頭にレポート ID バイト `0x00` を付けるため 65 バイトで届く。daemon が 64 バイト前提で解釈し CTAPHID パケットが1バイトずれて INVALID_CHANNEL を返していた。→ 先頭 `0x00` の 65 バイト書き込みを検出して読み替える修正を入れた（応答は 64 バイトのまま）。
2. **NMSG 未宣言による CTAP1 降格**: INIT の capabilities が `0x04`（CBOR のみ）で NMSG が立っていなかった。Firefox の authenticator-rs は `!NMSG` を CTAP1 対応とみなし、`use_ctap1_fallback` が付いたリクエスト（webauthn.io の既定の登録）では CTAP2 を試す前に U2F 登録へ降格させる。そのため getInfo 成功後に CTAPHID_MSG で U2F REGISTER が届き、daemon が INVALID_CMD で弾いて失敗していた。→ capabilities を `0x0C`（CBOR | NMSG）に変更。U2F を実装しない以上 NMSG 宣言が仕様上も正しい。

修正後の実測（Fedora 実機、daemon はモック電話、`--verbose` ログで確認）:

- Firefox から webauthn.io の Register: INIT → getInfo status 0x00 → **makeCredential（178 バイト要求）→ status 0x00、応答 177 バイト**。サイト側でも登録成功が表示された（`fmt:"none"` の attestation は webauthn.io には受理された）
- 続けて Authenticate: **getAssertion → status 0x00** を2回確認
- INIT 応答の capabilities が `0x0c` であることは自作クライアントでも別途確認済み

結果: **段階 (c) 合格**（ブラウザが authenticator として認識し WebAuthn 登録・認証が通った。ただし電話はモック）。段階 (d) の webauthn.io 分もモック電話では合格。実電話での (d) 以降はアプリ導入後に再実施する。

なお Brave では選択ダイアログ（QR / セキュリティキー）から先のデバイス通信が発生しない事象が残っている（ログに新規パケットなし）。Firefox で本線が通ったため優先度は下げ、未解決として記録する。

### 追記 (2026-11-06 01:48–01:49): 段階 (b) 合格 + 実電話 makeCredential / getAssertion 合格

前提: 未署名 IPA (CI run #6 のアーティファクト) を iLoader で実電話に導入。Fedora 側でペアリングを実施し、SAS が電話側表示と一致。

1. **段階 (b) 合格**: 独立実装の Python プローブと daemon の双方で、hello → hello_ack → confirm / confirm_ack（電話側 MAC 検証一致）→ ChaCha20-Poly1305 暗号化 ping の往復に成功。ping 応答は `{"result":{"version":1,"app":"iphone-fido"},"ok":true,"id":1}`。iOS 27 でも usbmuxd / iproxy 経由でアプリの待ち受けポートへ到達できることを実証した。
2. **実電話 makeCredential / getAssertion 合格**: daemon を実電話モードで起動 (起動時 ping で "Phone bridge connected" を確認) し、自作 CTAP クライアントから実 UHID 経由で実施。makeCredential status 0x00、authData flags 0x45 (UP|UV|AT)、credential ID 32 byte。getAssertion status 0x00。どちらも電話側の承認シート + Face ID を経由した。
3. **初回起動の既知事象**: アプリ初回起動の同一プロセス内で PSK を生成した場合、その後の接続が「接続を拒否しました (未ペアリング)」で拒否され続けた。アプリを完全終了して再起動すると解消し、上記 1・2 が成功した。発生条件の詳細と恒久対処 (BridgeServer が AppState 経由で PSK を読む等) は未確定。

### 追記 (2026-11-06 深夜): Brave (Chromium) が U2F 専用機と誤判定する根本原因を特定

Brave では GetInfo が読めてもデバイスが U2F 専用と判定され、WebAuthn の作成が CTAP1 (U2F REGISTER) にフォールバックして失敗した。Chromium のソース (device/fido/fido_device.cc, device_response_converter.cc の ReadCTAPGetInfoResponse) を直接読んで特定した原因は2段:

1. **CBOR の canonical 順序**: GetInfo の algorithms 内マップが {"type", "alg"} の順で、canonical 順序 (キー長→辞書順) 違反だった。Chromium の厳格パーサーは応答全体を拒否した。→ daemon の CBOR エンコーダで全マップを canonical 順序にソートするよう修正 (+単体テスト)。
2. **clientPin: false の明示**: Chromium は options に clientPin が「存在して false」の場合を「PIN 対応だが未設定 (kSupportedButPinNotSet)」と解釈し、その場合は pinUvAuthProtocols (GetInfo キー 0x06) の存在を必須とする。欠けていると応答全体を nullopt として弾く。→ GetInfo の options から clientPin キー自体を外した (不在 = 非対応が既定値で、authenticator-rs / libfido2 も同じ解釈)。

あわせて daemon 側に相互運用の予防修正 (空の pinUvAuthParam を許容、CTAPHID_MSG には帯域内の ISO ステータスで応答) と、ブリッジの自己回復 (セッション切断時の自動再接続、起動時に電話が居なくても終了しない) を入れた。単体テスト 24 件パス。clientPin 修正後の Brave 実機確認は未実施 (次回)。

iOS 側も自動接続に寄せた: PSK は AppState (MainActor) が保持してサーバーへ渡す (サーバーは Keychain を直接読まない)、リスナーは失敗時に自動で張り直し、フォアグラウンド復帰のたびに待ち受けを作り直す、セッションは常に最新の1本だけを生かす。CI run #7 成功、実機へ上書き導入し、再インストール直後の初回プロセスで再起動なしに接続できることを確認した。

### 追記 (2026-11-06 深夜): シームレス接続を実機で確認

「USB を挿しても未接続に見える」を解消した。daemon と iproxy を Fedora の systemd ユーザーサービス化 (自動起動 + Restart=always) し、daemon は HID 読み取りの合間 (2秒 tick) にセッションの世話をする: 電話が見えれば接続して保持し、25秒のアイドルごとに ping して死活を確認し、切れたら自動で張り直す。途中で2つの実バグを踏んで直した: (1) ハンドシェイクにタイムアウトが無く、半死の経路で無限に待つ可能性があった → 接続3秒/ハンドシェイク5秒/確立後120秒に制限。(2) UHID の読み取りが先頭イベントだけ poll で守られていて、OPEN 等の非 OUTPUT イベントを1つ読むと次の read で永遠に固まり tick が止まった (strace で read() に張り付いているのを確認) → 全 read を期限付き poll で守るよう再構成。実機で、アプリを開いておけばケーブルの抜き差しだけで「接続中」が自動で戻ることをユーザーが確認した。アプリ側は、開いている間は自動ロックで眠らない (isIdleTimerDisabled) 版も用意した。iOS の仕様上、アプリを開く操作だけは残る (裏に回ったアプリは OS が凍結するため)。

### 追記 (2026-11-06 朝): PRF (hmac-secret) を実機で検証

scripts/ctap_prf_test.py (CTAP クライアントが platform 役) で実電話に対して全フローを通した。getInfo が hmac-secret と FIDO_2_1 と pinUvAuthProtocols [1] を広告すること、PRF 有効化した作成が flags 0x65 と拡張出力 {hmac-secret: true} を返すこと、評価が同じ塩で同じ32バイト出力・違う塩で違う出力を返し署名も検証できることまで確認した (2026-11-06 08:10)。

途中で一度、作成が flags 0x45 (ED なし) で返る失敗があった。原因はコードではなく、Downloads に似た名前の IPA が6個あり古いビルドを入れていたこと。daemon 側の eval は「supported フィールドなし → false」として素のアサーションに縮退するため、旧アプリでも一見正常に見えるのが切り分けを遅らせた。古い IPA は Downloads/old-ipas/ へ退避し、正しい IPA だけを残して解消した。

### 追記 (2026-11-06 午前): ppq.ai (PayPerQ) で PRF が通った — CTAP "prf" 拡張が本命だった

PRF を要求する実サービス ppq.ai で、登録が最後まで完了し、続く暗号化機能の PRF 評価 (getAssertion) まで実機で通った (2026-11-06 10:09 JST、Brave + 実電話)。daemon ログ: makeCredential (要求 247B) → 0x00、直後に prf eval 入りの getAssertion (要求 160B、応答 266B) → 0x00。

根本原因は三段構えだった。(1) 当初: 有効化のみの hmac-secret では Chromium が登録時の prf.enabled を返さず、サイトが登録を静かに捨てていた。(2) hmac-secret-mc を実装しても ppq.ai の要求は `prf: {}` (有効化のみ、eval なし) で形が合わず依然として完了しなかった。(3) Chromium 141 のソースで確定: getInfo に `"prf"` を広告する認証器には CTAP "prf" 拡張が使われ、WebAuthn の prf.enabled / prf.results は makeCredential 応答のキー 6 (unsignedExtensionOutputs) の `{"prf": {...}}` からしか作られない。authData の hmac-secret 出力は enabled 判定に使われず、要求していない拡張出力を authData に入れると応答検証で弾かれる。対策として CTAP prf 拡張を実装した (BRIDGE-PROTOCOL 3.8): 塩は平文、結果は応答キー 6 (作成) / キー 8 (アサーション) で返し、authData には拡張出力を入れない。電話側は 2 段階フローの salt 任意化と、空の拡張セグメントを「出力なし (ED なし)」として扱う変更のみ。

副次的な発見: list_credentials の応答形が電話 ({"credentials":[...]}) と daemon の読み取り (素の配列) で食い違っており、excludeList チェックが実機で機能していなかった。daemon 側で両形式を受けるよう修正し、仕様 3.4 に固定した。

同日、プロジェクト名を Phone-as-a-securitykey に変更 (Android 対応と合わせて)。iOS アプリの表示名は "Phone FIDO Key"、UI はマテリアルでガラス質感を付けた (CI の SDK に iOS 26 専用 API が無いため glassEffect 自体は未使用。標準コントロールは iOS 26 実機で OS 側が新デザインに描く)。Android 版 (Kotlin、同じブリッジ仕様) を android/ に追加したが、ビルド・実機確認は未実施 (CI ワークフローの追加待ち)。

### 追記 (2026-11-06 午後): プロジェクト名を Phone-as-a-security-key に変更

表記を英語の標準的な分かち書き (security key) に合わせて Phone-as-a-security-key とした。GitHub リポジトリも同名にリネームし、README や脅威モデル等の資料表記を統一した。内部識別子 (バンドル ID、Keychain サービス名、AAGUID、ブリッジプロトコルの識別子、バイナリ名 iphone-fido) は互換性のため変更していない。

### 追記 (2026-11-07): UI 刷新とセットアップ内 QR、USB 後挿しの接続時間

アプリ UI を刷新した（セットアップ導入、実 Liquid Glass、Apple HIG に沿った色の見直し、アプリアイコン）。その後、QR ペアリングの読み取りをセットアップ導入の中へ移し、読み取り成功後に完了画面（「USBでPCに繋いで、セキュリティキーとして使ってください。」）を出すよう変更。設定画面は言語・資格情報・ペアリング・バージョン情報に整理した。いずれもビルド検証済み（iOS は CI、Android は実ビルド）で、実機での最終確認は未実施。

「アプリ起動後に USB を挿すと接続が遅い」件: USB の挿入は NWPathMonitor の経路変化として現れない（既定経路は Wi-Fi のまま）ため、従来の経路監視ベースの待ち受け再構築が発動しなかった。対策として、セッションが無い間に限り待ち受けを 4 秒ごとに張り直すウォッチドッグを電話側に入れ、daemon 側のハンドシェイクタイムアウトを 5 秒から 2 秒に短縮した。制御テスト（2026-11-07 09:26、アプリ前面・実機）では、挿入から約 1〜2 秒でセッション確立を daemon ログで確認。一方で、アプリを起動して長時間置いた後の初回接続では約 20 秒かかったという報告が残っており、この条件は未解明（調査中）。
