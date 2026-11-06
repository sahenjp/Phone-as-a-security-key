#!/bin/sh
# Phone-as-a-security-key —かんたんセットアップ (Fedora / Linux, iPhone 経路)
#
# やること:
#   1. daemon (iphone-fido) を ~/.local/bin に入れる
#   2. systemd ユーザーサービス (daemon + iproxy) を入れて起動する
#   3. /dev/uhid の udev ルールを入れる (この部分だけ sudo が必要)
#   4. 最後に対話的であればその場で QR ペアリングまで行う
#      (ペアリングは daemon が自動で拾うので再起動は不要)
#
# 何度実行しても安全 (冪等)。Android の場合は iproxy の代わりに
# `adb forward tcp:18766 tcp:18765` が必要な点だけが違う (docs/SIDELOAD.md)。
set -eu

# Messages follow the system language: Japanese when LANG is ja*, English otherwise.
case "${LANG:-}" in ja*) JA=1 ;; *) JA=0 ;; esac
L() { if [ "$JA" = 1 ]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }

BIN_SRC=""
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -x "$SCRIPT_DIR/iphone-fido" ]; then
  BIN_SRC="$SCRIPT_DIR/iphone-fido"
elif [ -x "$SCRIPT_DIR/../target/release/iphone-fido" ]; then
  BIN_SRC="$SCRIPT_DIR/../target/release/iphone-fido"
elif command -v iphone-fido >/dev/null 2>&1; then
  BIN_SRC=$(command -v iphone-fido)
fi

if [ -z "$BIN_SRC" ]; then
  L "エラー: iphone-fido バイナリが見つかりません。" "error: iphone-fido binary not found." >&2
  L "リリースの tarball を展開したフォルダで実行するか、先に cargo build --release してください。" "Run this from the extracted release tarball folder, or cargo build --release first." >&2
  exit 1
fi

L "==> daemon を ~/.local/bin にインストール" "==> Installing the daemon into ~/.local/bin"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$BIN_SRC" "$HOME/.local/bin/iphone-fido"

L "==> systemd ユーザーサービスをインストール" "==> Installing systemd user services"
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/iphone-fido-iproxy.service" <<'EOF'
[Unit]
Description=iproxy forward for Phone-as-a-security-key (18766 -> phone 18765)
After=network.target

[Service]
ExecStart=/usr/bin/iproxy 18766 18765
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
EOF
cat > "$HOME/.config/systemd/user/iphone-fido.service" <<'EOF'
[Unit]
Description=Phone-as-a-security-key daemon (phone as FIDO2 security key)
After=network.target iphone-fido-iproxy.service
Wants=iphone-fido-iproxy.service

[Service]
ExecStart=%h/.local/bin/iphone-fido run
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload

# iproxy が無ければ入れ方だけ案内する (勝手にパッケージは入れない)
if ! command -v iproxy >/dev/null 2>&1; then
  L "注意: iproxy が見つかりません。先に libimobiledevice-utils を入れてください:" "Note: iproxy not found. Install libimobiledevice-utils first:" >&2
  if command -v apt >/dev/null 2>&1 && ! command -v dnf >/dev/null 2>&1; then
    echo "  sudo apt install libimobiledevice-utils usbmuxd" >&2
  else
    echo "  sudo dnf install libimobiledevice-utils usbmuxd" >&2
  fi
fi

# udev ルール (sudo が要るのはここだけ)。対話できない環境では手順だけ出す。
RULE='KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="input", MODE="0660", TAG+="uaccess"'
if [ ! -f /etc/udev/rules.d/99-iphone-fido-uhid.rules ]; then
  if [ -t 0 ] && command -v sudo >/dev/null 2>&1; then
    L "==> udev ルールを入れます (sudo パスワードが必要です)" "==> Installing the udev rule (sudo password required)"
    echo "$RULE" | sudo tee /etc/udev/rules.d/99-iphone-fido-uhid.rules >/dev/null
    sudo udevadm control --reload
    sudo chmod 0660 /dev/uhid 2>/dev/null || true
  else
    L "注意: /dev/uhid の udev ルールが未インストールです。次を実行してください:" "Note: the /dev/uhid udev rule is not installed yet. Run:" >&2
    echo "  echo '$RULE' | sudo tee /etc/udev/rules.d/99-iphone-fido-uhid.rules" >&2
    echo "  sudo udevadm control --reload" >&2
  fi
fi

L "==> サービスを起動" "==> Starting services"
systemctl --user enable --now iphone-fido-iproxy.service iphone-fido.service

# ペアリング。対話できる環境ではその場で QR ペアリングまで進める。
# daemon はペアリングファイルを再接続のたびに読み直すので、
# この後にペアリングしても daemon の再起動は要らない。
PAIRING_FILE="$HOME/.config/iphone-fido/pairing.bin"
if [ -f "$PAIRING_FILE" ]; then
  L "ペアリング済みです (再ペアリングする場合は iphone-fido pair-qr)。" "Already paired. (To pair again: iphone-fido pair-qr.)"
elif [ -t 0 ]; then
  L "==> ペアリング (QR コード) を開始します" "==> Starting pairing (QR code)"
  L "電話で Phone FIDO Key アプリを開いてください。表示される QR をアプリの「QR コードでペアリング」から読み取り、確認コード (SAS) が両側で一致したら保存してください。" "Open the Phone FIDO Key app on your phone. Scan the QR code below from the app's \"Pair with QR code\", check the confirmation code (SAS) matches on both sides, and save."
  "$HOME/.local/bin/iphone-fido" pair-qr || L "ペアリングは後でもできます: iphone-fido pair-qr" "You can pair later with: iphone-fido pair-qr"
else
  if [ "$JA" = 1 ]; then
cat <<'EOF'

セットアップ完了。あとはペアリングだけです (推奨は QR コード)。

  1. PC で次を実行 (QR コードと確認コードが表示されます):
       iphone-fido pair-qr
  2. 電話で Phone FIDO Key アプリを開き、「QR コードでペアリング」から読み取る
  3. アプリ側と PC 側の確認コード (SAS、6 桁) が一致するか目で確認して保存

daemon の再起動は不要です (ペアリングを自動で拾います)。
QR が使えない環境では、アプリに表示されるキーを手入力する方法もあります:
  iphone-fido pair <ペアリングキー>

以後は USB でつなぐだけで使えます。状態確認: systemctl --user status iphone-fido
EOF
  else
cat <<'EOF'

Setup complete. Only pairing remains (QR code recommended):

  1. On the PC, run (shows a QR code and a confirmation code):
       iphone-fido pair-qr
  2. Open the Phone FIDO Key app and choose "Pair with QR code" to scan it
  3. Visually check that the confirmation code (SAS, 6 digits) matches, then save

No daemon restart is needed (pairing is picked up automatically).
If QR is not available, you can type the key shown in the app instead:
  iphone-fido pair <pairing key>

From now on, just plug in the USB cable. Status: systemctl --user status iphone-fido
EOF
  fi
fi
