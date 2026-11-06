#!/bin/sh
# Phone-as-a-security-key —かんたんセットアップ (Fedora / Linux, iPhone 経路)
#
# やること:
#   1. daemon (iphone-fido) を ~/.local/bin に入れる
#   2. systemd ユーザーサービス (daemon + iproxy) を入れて起動する
#   3. /dev/uhid の udev ルールを入れる (この部分だけ sudo が必要)
#   4. 最後にペアリングの手順を表示する
#
# 何度実行しても安全 (冪等)。Android の場合は iproxy の代わりに
# `adb forward tcp:18766 tcp:18765` が必要な点だけが違う (docs/SIDELOAD.md)。
set -eu

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
  echo "エラー: iphone-fido バイナリが見つかりません。" >&2
  echo "リリースの tarball を展開したフォルダで実行するか、先に cargo build --release してください。" >&2
  exit 1
fi

echo "==> daemon を ~/.local/bin にインストール"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$BIN_SRC" "$HOME/.local/bin/iphone-fido"

echo "==> systemd ユーザーサービスをインストール"
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
  echo "注意: iproxy が見つかりません。先に libimobiledevice-utils を入れてください:" >&2
  echo "  sudo dnf install libimobiledevice-utils usbmuxd" >&2
fi

# udev ルール (sudo が要るのはここだけ)。対話できない環境では手順だけ出す。
RULE='KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="input", MODE="0660", TAG+="uaccess"'
if [ ! -f /etc/udev/rules.d/99-iphone-fido-uhid.rules ]; then
  if [ -t 0 ] && command -v sudo >/dev/null 2>&1; then
    echo "==> udev ルールを入れます (sudo パスワードが必要です)"
    echo "$RULE" | sudo tee /etc/udev/rules.d/99-iphone-fido-uhid.rules >/dev/null
    sudo udevadm control --reload
    sudo chmod 0660 /dev/uhid 2>/dev/null || true
  else
    echo "注意: /dev/uhid の udev ルールが未インストールです。次を実行してください:" >&2
    echo "  echo '$RULE' | sudo tee /etc/udev/rules.d/99-iphone-fido-uhid.rules" >&2
    echo "  sudo udevadm control --reload" >&2
  fi
fi

echo "==> サービスを起動"
systemctl --user enable --now iphone-fido-iproxy.service iphone-fido.service

cat <<'EOF'

セットアップ完了。あとはペアリングだけです。

  1. 電話で Phone FIDO Key アプリを開く (ペアリングキーが表示されます)
  2. PC で次を実行して、表示されたコードを入力:
       iphone-fido pair <ペアリングキー>
  3. アプリ側と PC 側の確認コード (SAS、6 桁) が一致するか目で確認

以後は USB でつなぐだけで使えます。状態確認: systemctl --user status iphone-fido
EOF
