#!/usr/bin/env bash
set -euo pipefail
echo "[*] DomWatch installer starting..."
if ! command -v curl >/dev/null 2>&1; then
  sudo apt update && sudo apt install -y curl
fi
if ! command -v go >/dev/null 2>&1; then
  echo "[*] Installing Go 1.22.5"
  curl -L https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -o /tmp/go.tgz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tgz
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
fi
if ! command -v subfinder >/dev/null 2>&1; then
  echo "[*] Installing subfinder..."
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  sudo ln -sf "$(command -v subfinder)" /usr/local/bin/subfinder || true
fi
echo "[*] Building domwatch..."
go build -o domwatch ./cmd/domwatch
sudo mv domwatch /usr/local/bin/domwatch
sudo chmod +x /usr/local/bin/domwatch
sudo mkdir -p /opt/domwatch/data
sudo chown -R "$USER":"$USER" /opt/domwatch
echo "=== Notifier Setup ==="
read -r -p "Discord notifications? (y/N): " DYN
if [[ "${DYN,,}" == "y" ]]; then
  read -r -p "Discord Webhook URL: " DURL
  if [[ -n "${DURL}" ]]; then /usr/local/bin/domwatch config set-webhook "${DURL}" || true; fi
fi
read -r -p "Telegram notifications? (y/N): " TYN
if [[ "${TYN,,}" == "y" ]]; then
  read -r -p "Telegram Bot Token: " TBOT
  read -r -p "Telegram Chat ID: " TCHAT
  if [[ -n "${TBOT}" && -n "${TCHAT}" ]]; then /usr/local/bin/domwatch config set-telegram "${TBOT}" "${TCHAT}" || true; fi
fi
sudo cp -f ./deploy/systemd/domwatch-all.service /etc/systemd/system/domwatch-all.service
sudo cp -f ./deploy/systemd/domwatch-all.timer /etc/systemd/system/domwatch-all.timer
sudo systemctl daemon-reload
sudo systemctl enable --now domwatch-all.timer
echo "[✅] Done. Try: domwatch add example.com && domwatch scan example.com"
