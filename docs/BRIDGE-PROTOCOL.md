# Bridge Protocol v1 — Fedora ⇄ iPhone (共通仕様 / 両実装はこれに従う)

この文書が Rust 実装と Swift 実装の唯一の共通仕様。食い違いがあればコードでなくこの文書が正。

## 0. トランスポート

- iPhone アプリが TCP サーバーとして待ち受ける: ポート **18765**、全インターフェース bind
  (usbmuxd は端末の localhost ソケットへ中継するが、NWListener は loopback 指定だと
  usbmux 経由で届かない事例があるため bind は all、到達制御は暗号層で行う)。
- Fedora 側は外部コマンド `iproxy 18766 18765` (libusbmuxd-tools) を起動し、
  `127.0.0.1:18766` へ接続する。daemon 自体は iproxy を子プロセスとして起動してもよいし、
  既に張られている前提でもよい (設定で切替)。
- フレーミング: 全フレーム = 4 byte big-endian 長さ (payload 長, 最大 1 MiB) + payload。

## 1. ペアリング (初回のみ, 帯域外)

- iPhone アプリが 32 byte のランダムな **pairing secret (PSK)** を生成し Keychain に保存する。
- アプリは PSK を Base32 (RFC4648, padding なし, 52 文字) で画面表示する。
- ユーザーが Fedora 側 CLI `iphone-fido pair` にその文字列を手入力する (USB を流れさせない)。
- Fedora 側は PSK を `~/.config/iphone-fido/pairing.bin` に mode 0600 で保存する。
- 確認用 SAS: 両側とも `SHA-256(PSK || "iphone-fido-sas-v1")` の先頭 3 byte を
  10 進 6 桁 (各 byte を連結せず、整数として mod 1_000_000, ゼロ埋め) で表示し、ユーザーが一致を確認する。

## 2. セッションハンドシェイク (接続ごと)

平文フレームは JSON (UTF-8)。フィールド名は厳密に以下。

1. PC → Phone:
```json
{"type":"hello","version":1,"pc_random":"<base64 32B>","pc_ephemeral_pubkey":"<base64 x963 65B>"}
```
2. Phone → PC:
```json
{"type":"hello_ack","version":1,"phone_random":"<base64 32B>","phone_ephemeral_pubkey":"<base64 x963 65B>"}
```
3. 両側で計算:
   - `ecdh = ECDH(ephemeral 自分秘密鍵, 相手公開鍵)` の x 座標 32 byte
   - `ikm = ecdh || PSK` (この順で連結)
   - `salt = pc_random || phone_random`
   - `prk = HKDF-Extract(SHA-256, salt, ikm)`
   - `k_pc_phone   = HKDF-Expand(prk, "iphone-fido v1 pc-to-phone",   32)`
   - `k_phone_pc   = HKDF-Expand(prk, "iphone-fido v1 phone-to-pc",   32)`
   - `confirm_key  = HKDF-Expand(prk, "iphone-fido v1 confirm",       32)`
4. PC → Phone (平文フレーム, JSON):
```json
{"type":"confirm","mac":"<base64 HMAC-SHA256(confirm_key, \"pc\" || pc_random || phone_random)>"}
```
   Phone は検証に失敗したら接続を切る。
5. Phone → PC:
```json
{"type":"confirm_ack","mac":"<base64 HMAC-SHA256(confirm_key, \"phone\" || pc_random || phone_random)>"}
```
   PC は検証に失敗したら接続を切る。

これ以降の全フレームは暗号化フレーム:
`payload = seq (8 byte BE, 方向ごとに 0 から単調増加) || ChaCha20-Poly1305 ciphertext`
nonce (12 byte) = `0x00000000 || seq (8 byte BE)`。
復号失敗は即切断。以後の平文 (暗号化の中身) は JSON。

## 3. 意味操作 (暗号化チャネルの中身)

原則: **PC は任意バイト列への署名を電話に求めない。**
電話が rpId から authData を自ら組み立て、表示し、ユーザーが承認 + Face ID を通した時だけ署名する。

### 3.1 ping
req: `{"op":"ping","id":1}`
res: `{"id":1,"ok":true,"result":{"app":"iphone-fido","version":1}}`

### 3.2 create_credential
req:
```json
{"op":"create_credential","id":2,
 "rp_id":"github.com","rp_name":"GitHub",
 "user_id":"<base64>","user_name":"sahen","user_display_name":"sahen",
 "client_data_hash":"<base64 32B>"}
```
電話の処理:
1. rp_id と user_name を画面に表示し、ユーザーの「作成」タップを待つ (拒否 → `ok:false,error:"user_cancelled"`)。
2. Secure Enclave に P-256 鍵を新規生成する。access control:
   `.privateKeyUsage + .biometryCurrentSet`、認証コンテキストは操作ごとに新規。
   ※ 鍵生成自体は生体認証を要求しない設定にし、**使用時 (署名時)** に Face ID を必須にする
   (生成時に biometry を付けると作成フローでも prompt が出る実装詳細は実機で確認すること。
   いずれにせよ署名時の prompt が必須条件)。
3. credential_id = ランダム 32 byte を生成。メタデータ (rp_id, user_id, user_name,
   credential_id, 公開鍵 x963, sign_count=0, 鍵参照) を Keychain に保存する。
4. authData を電話が組み立てる:
   `SHA-256(rp_id) || flags(0x45 = UP|UV|AT) || sign_count(4BE, 0) ||
    AAGUID(16B) || cred_id_len(2BE) || credential_id || COSE_Key(公開鍵)`
   AAGUID は本プロジェクト固定値: `69 70 68 2d 66 69 64 6f 2d 30 30 30 30 30 30 31`
   (16 進表記が正。デコードすると ASCII "iph-fido-0000001" の 16 byte)。
   COSE_Key = CBOR map `{1:2, 3:-7, -1:1, -2:x(32B), -3:y(32B)}`。
5. attestation は `fmt:"none"` とし、attestation 署名は作らない。

res:
```json
{"id":2,"ok":true,"result":{
  "credential_id":"<base64>","public_key_x963":"<base64 65B>",
  "auth_data":"<base64>","fmt":"none"}}
```

### 3.3 get_assertion
req:
```json
{"op":"get_assertion","id":3,"rp_id":"github.com",
 "client_data_hash":"<base64 32B>",
 "allow_credential_ids":["<base64>", "..."]}
```
電話の処理:
1. rp_id が一致し、allow リスト (空なら rp_id の全資格) に含まれる資格を Keychain から探す。
   なければ `ok:false,error:"no_credentials"`。
2. rp_id と user_name を画面表示し「承認」タップを待つ (必須。これが無い署名は禁止)。
3. sign_count を +1 し永続化する。
4. authData = `SHA-256(rp_id) || flags(0x05 = UP|UV) || sign_count(4BE)` を組み立てる。
5. `authData || client_data_hash` を Secure Enclave 鍵で署名する。
   この操作が Face ID prompt を出す。署名は ECDSA P-256 + SHA-256、出力は ASN.1 DER
   (WebAuthn の ES256 署名形式そのもの)。
res:
```json
{"id":3,"ok":true,"result":{
  "credential_id":"<base64>","auth_data":"<base64>",
  "signature":"<base64 DER>","user_handle":"<base64>"}}
```

### 3.4 list_credentials (管理用、署名なし)
res は rp_id / user_name / credential_id の一覧 (秘密情報なし)。

### 3.5 エラー
`{"id":<req id>,"ok":false,"error":"<code>"}` — code は
`user_cancelled | no_credentials | not_found | internal | bad_request` のいずれか。

## 4. Fedora 側 authenticator の責務

- CTAPHID / CTAP2 は Fedora 側で終端する。電話は CTAP を知らない (上の意味操作だけ)。
- getInfo: versions `["FIDO_2_0"]`, aaguid 上記, algorithms ES256,
  options `{rk:true, up:true, uv:true, clientPin:false}`, maxMsgSize 1200 以上。
- makeCredential: 必須パラメータ検証、excludeList の既存資格チェック、
  bridge の create_credential を呼ぶ。応答 CBOR:
  `{1: fmt, 2: authData, 3: {}}` (attStmt は none なので空 map)。
- getAssertion: allowList を bridge に渡し、応答 CBOR:
  `{1: credential {type:"public-key", id}, 2: authData, 3: signature, 4: user {id, name}}`。
- signCount は電話側の値を authData に含めて返すので Fedora 側は加工しない。
- **モック電話**: 開発専用のソフトウェア実装 (鍵はメモリ内ソフトウェア P-256)。
  製品ビルドでは明示フラグ `--mock-phone` の時だけ有効で、起動時に警告を出す。
  モックで作った資格を本物と誤認させない。

## 5. 未決定 / 実機確認事項 (推測で埋めない)

- iOS のバージョン別に usbmux iproxy 転送が通常アプリの待ち受けポートへ届くか (特に iOS 17+)。
- Secure Enclave 鍵の access control 組み合わせと Face ID prompt が出る正確なタイミング。
- NWListener がバックグラウンドで suspend される前提のため、アプリはフォアグラウンド必須。
- `fmt:"none"` を GitHub / Google が実際に受理するか (webauthn.io 等の検証が先)。
