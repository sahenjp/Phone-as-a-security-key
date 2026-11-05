#!/usr/bin/env bash
# verify-usb-fedora.sh - Fedora 実機で iPhone との USB 疎通を段階確認する
#
# 使い方:
#   scripts/verify-usb-fedora.sh
#   LOCAL_PORT=18766 DEVICE_PORT=18765 scripts/verify-usb-fedora.sh
#
# 終了コード:
#   0 = 全段階成功 (アプリの hello 応答まで確認)
#   1 = 前提の失敗 (ツール不足 / usbmuxd 未起動 / 端末未認識 / 未ペアリング等)
#   2 = 端末までは OK だがアプリ到達に失敗 (iproxy / TCP / hello のいずれか)
#
# 方針:
#   - 読み取り中心。ペアリング削除などの破壊的操作はしない。
#   - 自分で起動した iproxy だけを終了時に片付ける。
#   - 失敗箇所を明示し、後段は可能な範囲で継続して報告する。
#
# 仕様: docs/BRIDGE-PROTOCOL.md §0 (iproxy 18766 18765, フレーミング, hello)
# 手順: docs/REAL-DEVICE-TEST.md 段階 (a), (b) / 切り分け: docs/FEASIBILITY.md §5

set -u

LOCAL_PORT="${LOCAL_PORT:-18766}"
DEVICE_PORT="${DEVICE_PORT:-18765}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"

PASS_COUNT=0
FAIL_COUNT=0
HARD_FAIL=0
REACH_FAIL=0
STARTED_IPROXY_PID=""
UDID=""

log_stage() { printf '\n== %s ==\n' "$1"; }
log_ok()    { printf '[ OK ] %s\n' "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
log_ng()    { printf '[ NG ] %s\n' "$1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
log_info()  { printf '[ .. ] %s\n' "$1"; }
log_hint()  { printf '       -> %s\n' "$1"; }

cleanup() {
    if [ -n "$STARTED_IPROXY_PID" ]; then
        if kill -0 "$STARTED_IPROXY_PID" 2>/dev/null; then
            kill "$STARTED_IPROXY_PID" 2>/dev/null || true
            wait "$STARTED_IPROXY_PID" 2>/dev/null || true
            log_info "自分で起動した iproxy (pid $STARTED_IPROXY_PID) を終了しました"
        fi
    fi
}
trap cleanup EXIT

have() { command -v "$1" >/dev/null 2>&1; }

port_listening() {
    # $1 = port. ss があればそれを、無ければ /dev/tcp で判定する。
    if have ss; then
        ss -ltn 2>/dev/null | grep -q ":$1 " && return 0
        return 1
    fi
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    return 1
}

printf 'iphone-fido-key USB 検証 (Fedora 実機用)\n'
printf '転送: iproxy %s %s (127.0.0.1:%s -> iPhone:%s)\n' \
    "$LOCAL_PORT" "$DEVICE_PORT" "$LOCAL_PORT" "$DEVICE_PORT"
printf '前提: iPhone を USB 接続し、ロック解除し、アプリをフォアグラウンドで起動してください。\n'

# ---------------------------------------------------------------- 段階 1
log_stage "段階 1/6: 必要なツールの存在"
MISSING=0
for tool in usbmuxd idevice_id idevicepair iproxy; do
    if have "$tool"; then
        log_ok "$tool が見つかりました ($(command -v "$tool"))"
    else
        log_ng "$tool が見つかりません"
        MISSING=1
    fi
done
if have ideviceinfo; then
    log_ok "ideviceinfo が見つかりました (任意ツール)"
else
    log_info "ideviceinfo はありません (任意ツールのため継続します)"
fi
if [ "$MISSING" -ne 0 ]; then
    HARD_FAIL=1
    log_hint "未導入の場合: sudo dnf install libimobiledevice usbmuxd libusbmuxd-tools"
    log_hint "ツールが揃わないため、以降の段階は意味を持ちません。ここで終了します。"
    printf '\n結果: 前提不足 (exit 1)  OK=%s NG=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
    exit 1
fi

# ---------------------------------------------------------------- 段階 2
log_stage "段階 2/6: usbmuxd の起動状態"
USBMUX_RUNNING=0
if have systemctl && systemctl is-active usbmuxd >/dev/null 2>&1; then
    USBMUX_RUNNING=1
    log_ok "usbmuxd サービスが active です"
elif pgrep -x usbmuxd >/dev/null 2>&1; then
    USBMUX_RUNNING=1
    log_ok "usbmuxd プロセスが動いています"
elif [ -S /var/run/usbmuxd ]; then
    USBMUX_RUNNING=1
    log_ok "usbmuxd ソケット /var/run/usbmuxd があります"
fi
if [ "$USBMUX_RUNNING" -eq 0 ]; then
    HARD_FAIL=1
    log_ng "usbmuxd が動いていることを確認できませんでした"
    log_hint "確認: systemctl status usbmuxd / pgrep -a usbmuxd"
    log_hint "端末を挿した状態で再確認してください (udev 起動の構成もあります)"
fi

# ---------------------------------------------------------------- 段階 3
log_stage "段階 3/6: 接続中 iPhone の認識 (idevice_id)"
UDID="$(idevice_id -l 2>/dev/null | head -n 1 | tr -d '[:space:]')"
if [ -n "$UDID" ]; then
    log_ok "iPhone を認識しました (UDID: $UDID)"
else
    HARD_FAIL=1
    log_ng "接続中の iPhone が見つかりません (idevice_id -l が空)"
    log_hint "切り分け: ケーブル (データ転送対応か) / 直結 / ロック解除 / 段階 2 の usbmuxd"
    log_hint "詳細: docs/FEASIBILITY.md §5 段階 0-2"
fi
if [ -n "$UDID" ] && have ideviceinfo; then
    DEVICE_NAME="$(ideviceinfo -u "$UDID" -k DeviceName 2>/dev/null || true)"
    IOS_VERSION="$(ideviceinfo -u "$UDID" -k ProductVersion 2>/dev/null || true)"
    if [ -n "$DEVICE_NAME" ]; then
        log_info "DeviceName: $DEVICE_NAME"
    fi
    if [ -n "$IOS_VERSION" ]; then
        log_info "iOS バージョン (ideviceinfo): $IOS_VERSION"
        log_hint "この値を docs/REAL-DEVICE-TEST.md の記録に必ず残してください"
    fi
fi

# ---------------------------------------------------------------- 段階 4
log_stage "段階 4/6: ペアリング状態 (idevicepair validate)"
if [ -n "$UDID" ]; then
    PAIR_OUTPUT="$(idevicepair validate 2>&1 || true)"
    printf '%s\n' "$PAIR_OUTPUT" | sed 's/^/       /'
    if printf '%s' "$PAIR_OUTPUT" | grep -qiE 'SUCCESS|Validated'; then
        log_ok "ペアリング記録が有効です"
    else
        HARD_FAIL=1
        log_ng "ペアリングが有効と確認できませんでした"
        log_hint "未ペアリングなら手動で: idevicepair pair (iPhone 側で「信頼する」を確認)"
        log_hint "このスクリプトはペアリングの作成・削除を自動では行いません"
    fi
else
    log_ng "端末未認識のためペアリング確認をスキップしました"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    HARD_FAIL=1
fi

# 前提段階で失敗していたら、到達確認はせず終了する
if [ "$HARD_FAIL" -ne 0 ]; then
    printf '\n結果: 前提段階で失敗 (exit 1)  OK=%s NG=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
    printf '切り分け手順: docs/FEASIBILITY.md §5 / 手順書: docs/REAL-DEVICE-TEST.md 段階 (a)\n'
    exit 1
fi

# ---------------------------------------------------------------- 段階 5
log_stage "段階 5/6: iproxy 転送 (127.0.0.1:$LOCAL_PORT -> iPhone:$DEVICE_PORT)"
if port_listening "$LOCAL_PORT"; then
    log_ok "ポート $LOCAL_PORT は既に待ち受けがあります (既存の iproxy 等を再利用します)"
else
    log_info "iproxy を一時起動します: iproxy $LOCAL_PORT $DEVICE_PORT"
    IPROXY_LOG="$(mktemp)"
    if [ -n "$UDID" ]; then
        iproxy "$LOCAL_PORT" "$DEVICE_PORT" -u "$UDID" >"$IPROXY_LOG" 2>&1 &
    else
        iproxy "$LOCAL_PORT" "$DEVICE_PORT" >"$IPROXY_LOG" 2>&1 &
    fi
    STARTED_IPROXY_PID=$!
    sleep 2
    if ! kill -0 "$STARTED_IPROXY_PID" 2>/dev/null; then
        REACH_FAIL=1
        log_ng "iproxy が起動直後に終了しました"
        sed 's/^/       /' "$IPROXY_LOG" || true
        log_hint "ポート競合の確認: ss -ltnp | grep $LOCAL_PORT"
    elif port_listening "$LOCAL_PORT"; then
        log_ok "iproxy がポート $LOCAL_PORT で待ち受けています"
    else
        REACH_FAIL=1
        log_ng "iproxy は動いていますがポート $LOCAL_PORT の待ち受けを確認できません"
        sed 's/^/       /' "$IPROXY_LOG" || true
    fi
    rm -f "$IPROXY_LOG"
fi

# ---------------------------------------------------------------- 段階 6
log_stage "段階 6/6: アプリへの到達と hello ハンドシェイク入口"
if [ "$REACH_FAIL" -ne 0 ]; then
    log_ng "段階 5 の失敗のため到達確認をスキップしました"
    printf '\n結果: アプリ到達に失敗 (exit 2)  OK=%s NG=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
    exit 2
fi

if ! have python3; then
    log_ng "python3 が無いため hello 確認ができません (TCP 到達のみでは合格にしません)"
    log_hint "python3 を導入して再実行してください"
    printf '\n結果: アプリ到達を未確認 (exit 2)  OK=%s NG=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
    exit 2
fi

# BRIDGE-PROTOCOL §0/§2: 4byte BE 長 + JSON で hello を送り、hello_ack を期待する。
# ここで試すのはハンドシェイクの入口まで。暗号化 ping の往復はペアリング後の
# 正規フロー (daemon) で確認すること。到達レベルを混同しないため結果を区別する。
HELLO_RESULT="$(LOCAL_PORT="$LOCAL_PORT" CONNECT_TIMEOUT="$CONNECT_TIMEOUT" python3 - <<'PYEOF' 2>&1
import base64
import json
import os
import socket
import struct
import sys

port = int(os.environ["LOCAL_PORT"])
timeout = float(os.environ["CONNECT_TIMEOUT"])

hello = {
    "type": "hello",
    "version": 1,
    "pc_random": base64.b64encode(b"\x00" * 32).decode(),
    # 検証用のダミー一時鍵 (未圧縮点形式 65B)。実鍵ではない。
    "pc_ephemeral_pubkey": base64.b64encode(b"\x04" + b"\x00" * 64).decode(),
}
payload = json.dumps(hello).encode()
frame = struct.pack(">I", len(payload)) + payload

try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
except OSError as exc:
    print(f"TCP_FAIL {exc}")
    sys.exit(0)

print("TCP_OK")
try:
    sock.settimeout(timeout)
    sock.sendall(frame)
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            break
        header += chunk
    if len(header) < 4:
        print("HELLO_FAIL 応答フレームが返りませんでした (接続はされたが即切断/無応答)")
        sys.exit(0)
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > 1024 * 1024:
        print(f"HELLO_FAIL 異常なフレーム長: {length}")
        sys.exit(0)
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    try:
        msg = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        print(f"HELLO_FAIL JSON として解釈できません: {exc}")
        sys.exit(0)
    if msg.get("type") == "hello_ack":
        print("HELLO_OK hello_ack を受信しました")
    else:
        print(f"HELLO_FAIL 予期しない応答 type: {msg.get('type')!r}")
except OSError as exc:
    print(f"HELLO_FAIL {exc}")
finally:
    sock.close()
PYEOF
)"

printf '%s\n' "$HELLO_RESULT" | sed 's/^/       /'
if printf '%s' "$HELLO_RESULT" | grep -q '^HELLO_OK'; then
    log_ok "TCP 接続と hello_ack の応答を確認しました"
    log_info "注意: 暗号化チャネル内の ping 往復は、ペアリング後の daemon 正規フローで別途確認してください"
    printf '\n結果: 全段階成功 (exit 0)  OK=%s NG=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
    printf '次: docs/REAL-DEVICE-TEST.md 段階 (c) 以降へ進んでください。\n'
    exit 0
fi

if printf '%s' "$HELLO_RESULT" | grep -q '^TCP_OK'; then
    log_ng "TCP は届きましたが hello_ack が確認できませんでした"
    log_hint "疑う順: アプリがフォアグラウンドか / 待ち受けポートが $DEVICE_PORT か / iOS バージョン起因の中継挙動"
    log_hint "詳細: docs/FEASIBILITY.md §5 段階 4-5 (iOS バージョンと出力原文を記録すること)"
else
    log_ng "127.0.0.1:$LOCAL_PORT への TCP 接続に失敗しました"
    log_hint "疑う順: アプリ未起動 / フォアグラウンドでない (suspend) / iproxy の転送先ポート"
    log_hint "詳細: docs/FEASIBILITY.md §5 段階 3-4"
fi
printf '\n結果: アプリ到達に失敗 (exit 2)  OK=%s NG=%s\n' "$PASS_COUNT" "$FAIL_COUNT"
exit 2
