<p align="center">
  <img src="assets/banner-0x0sadat.png" width="100%" alt="DomWatch banner"/>
</p>

<h1 align="center">DomWatch — Subdomain Monitor (AI-assisted)</h1>
<p align="center">
by <b>0x0sadat</b> • twitter: <a href="https://x.com/SadatTamzit">@SadatTamzit</a> • Bug Bounty Hunter
</p>

---

DomWatch discovers subdomains using <code>subfinder</code>, tracks history, and notifies you <b>only when new subdomains appear</b>. Notifications: <b>Discord</b> and/or <b>Telegram</b>. Optional AI summaries via OpenAI.

## Install (like nuclei)

### Option 1: Go install (recommended)
Requires Go ≥ 1.22 installed.
```bash
go install -v github.com/0xSADAT/domwatch/cmd/domwatch@latest
```

### Option 2: One-shot installer (auto-installs Go + subfinder)
Clone or download this repo on the target host, then:
```bash
chmod +x ./scripts/install.sh
./scripts/install.sh
```

The installer will:
- Install <b>Go</b> (if missing)
- Install <b>subfinder</b>
- Build & install <b>/usr/local/bin/domwatch</b>
- Prompt for Discord / Telegram webhook
- Enable a systemd timer that runs <code>domwatch scan --all</code> every <b>6 hours</b>

## Quick Start
```bash
domwatch add example.com
domwatch scan example.com
domwatch scan --all
domwatch notify-test example.com

# (optional) AI
domwatch config set-openai "sk-..."
domwatch scan example.com --ai

# Notifiers
domwatch config set-webhook "https://discord.com/api/webhooks/...."
domwatch config set-telegram "<bot_token>" "<chat_id>"
```

**Home dir**: <code>/opt/domwatch</code> (override with <code>DOMWATCH_HOME</code>)  
**Data**: <code>/opt/domwatch/data/&lt;domain&gt;.txt</code>  
**Config**: <code>/opt/domwatch/config.json</code> (0600)

## Systemd
```bash
sudo cp deploy/systemd/domwatch-all.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now domwatch-all.timer
systemctl list-timers | grep domwatch-all
journalctl -u domwatch-all.service -n 200 -f
```

## Env
- DOMWATCH_HOME
- SUBFINDER_PATH
- DISCORD_WEBHOOK_URL
- TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
- OPENAI_API_KEY

## License
MIT
