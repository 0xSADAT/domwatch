package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	Version       = "v1.1.0"
	DefaultHome   = "/opt/domwatch" // override with DOMWATCH_HOME
	ConfigRelPath = "config.json"
	DataRelDir    = "data"
)

type Config struct {
	DiscordWebhookURL string `json:"discord_webhook_url,omitempty"`
	TelegramBotToken  string `json:"telegram_bot_token,omitempty"`
	TelegramChatID    string `json:"telegram_chat_id,omitempty"`
	OpenAIAPIKey      string `json:"openai_api_key,omitempty"`
}

func Run() int {
	if len(os.Args) < 2 {
		usage()
		return 2
	}
	switch os.Args[1] {
	case "add":
		return cmdAdd(os.Args[2:])
	case "scan":
		return cmdScan(os.Args[2:])
	case "list":
		return cmdList(os.Args[2:])
	case "remove":
		return cmdRemove(os.Args[2:])
	case "config":
		return cmdConfig(os.Args[2:])
	case "notify-test":
		return cmdNotifyTest(os.Args[2:])
	case "setup":
		return cmdSetup(os.Args[2:])
	case "-h","--help","help":
		usage()
		return 0
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Println(` + "`" + `DomWatch ` + "`" + ` + Version + ` + "`" + ` — Subdomain monitor (new vs old) + Discord/Telegram + optional AI

Usage:
  domwatch add <domain>                          # add target & create storage
  domwatch scan <domain> [--ai]                  # run subfinder, compare, write results, AI summary optional
  domwatch scan --all [--ai]                     # scan all domains listed in domains.txt
  domwatch list <domain>                         # print current inventory
  domwatch remove <domain>                       # remove domain (data only; timers best-effort)
  domwatch config [show|set-webhook|set-telegram|set-openai]
  domwatch notify-test <domain>                  # send a test notification
  domwatch setup                                 # guided setup (deps + notifiers)

Env:
  DOMWATCH_HOME           # base dir (default /opt/domwatch)
  SUBFINDER_PATH          # custom path to subfinder binary
  DISCORD_WEBHOOK_URL     # alt to config file value
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
  OPENAI_API_KEY          # for --ai` + "`" + `)
}

// ---------- paths/helpers ----------

func homeDir() string {
	if v := strings.TrimSpace(os.Getenv("DOMWATCH_HOME")); v != "" {
		return v
	}
	return DefaultHome
}
func dataDir() string { return filepath.Join(homeDir(), DataRelDir) }
func configPath() string { return filepath.Join(homeDir(), ConfigRelPath) }

func ensureDirs() error {
	if err := os.MkdirAll(dataDir(), 0o755); err != nil { return err }
	return nil
}

func readLines(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) { return []string{}, nil }
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s != "" { out = append(out, s) }
	}
	return out, sc.Err()
}
func writeLines(p string, lines []string) error {
	tmp := p + ".tmp"
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { return err }
	f, err := os.Create(tmp); if err != nil { return err }
	defer f.Close()
	for _, l := range lines { if _, err := io.WriteString(f, l+"\n"); err != nil { return err } }
	return os.Rename(tmp, p)
}
func uniqueSorted(in []string) []string {
	m := map[string]struct{}{}; for _, s := range in { s=strings.TrimSpace(s); if s!="" { m[s]=struct{}{} } }
	out := make([]string,0,len(m)); for s:=range m { out = append(out,s) }
	sort.Strings(out); return out
}
func isInteractive() bool { st,_ := os.Stdin.Stat(); return (st.Mode() & os.ModeCharDevice) != 0 }

// ---------- config ----------
func loadConfig() (*Config, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) { return &Config{}, nil }
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil { return nil, err }
	return &c, nil
}
func saveConfig(c *Config) error {
	if err := os.MkdirAll(homeDir(), 0o755); err != nil { return err }
	b, _ := json.MarshalIndent(c,"","  ")
	tmp := configPath()+".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil { return err }
	return os.Rename(tmp, configPath())
}

func cleanWebhook(s string) string {
	s = strings.TrimSpace(s)
	if s=="" || s=="YOUR_WEBHOOK_URL_HERE" || s=="YOUR_WEBHOOK_URL" { return "" }
	if !(strings.HasPrefix(s,"http://") || strings.HasPrefix(s,"https://")) { return "" }
	return s
}

// ---------- deps ----------
func ensureGo() error {
	if _, err := exec.LookPath("go"); err == nil { return nil }
	if !isInteractive() { return errors.New("Go not found. Run scripts/bootstrap-go.sh or install Go manually.") }
	fmt.Println("[*] Go not found, installing Go 1.22.5 (requires sudo)...")
	cmd := exec.Command("bash", "-lc", "curl -L https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -o /tmp/go.tgz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz && echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc && export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
func ensureSubfinder() error {
	if _, err := exec.LookPath("subfinder"); err == nil { return nil }
	if !isInteractive() { return errors.New("subfinder not found. Install it or run scripts/install.sh") }
	fmt.Println("[*] subfinder not found, installing (requires Go)...")
	if err := ensureGo(); err != nil { return err }
	cmd := exec.Command("bash","-lc","go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && sudo ln -sf \"$(command -v subfinder)\" /usr/local/bin/subfinder")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// ---------- subfinder ----------
func runSubfinder(domain string) ([]string, error) {
	bin := strings.TrimSpace(os.Getenv("SUBFINDER_PATH"))
	if bin == "" { bin = "subfinder" }
	cmd := exec.Command(bin, "-silent", "-d", domain)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("subfinder failed: %v\n%s", err, string(ee.Stderr))
		}
		return nil, err
	}
	var res []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" { res = append(res, line) }
	}
	return uniqueSorted(res), nil
}
func diff(old, now []string) (added, existing []string) {
	oldSet := map[string]struct{}{}; for _, s := range old { oldSet[s]=struct{}{} }
	for _, s := range now {
		if _, ok := oldSet[s]; ok { existing = append(existing, s) } else { added = append(added, s) }
	}
	return
}

// ---------- notifiers ----------
func getDiscordWebhook() string {
	if s := cleanWebhook(os.Getenv("DISCORD_WEBHOOK_URL")); s != "" { return s }
	if c,_ := loadConfig(); c!=nil { return cleanWebhook(c.DiscordWebhookURL) }
	return ""
}
func getTelegram() (string,string) {
	tok := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	ch  := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	if tok!="" && ch!="" { return tok, ch }
	if c,_ := loadConfig(); c!=nil { return strings.TrimSpace(c.TelegramBotToken), strings.TrimSpace(c.TelegramChatID) }
	return "",""
}
func postDiscord(webhook, title string, lines []string) error {
	webhook = cleanWebhook(webhook)
	if webhook=="" || len(lines)==0 { return nil }
	const maxLen = 1800
	header := title
	cur := header+"\n"
	var chunks []string
	for _, ln := range lines {
		if len(cur)+len(ln)+1 > maxLen { chunks = append(chunks, cur); cur = header+"\n" }
		cur += ln+"\n"
	}
	if strings.TrimSpace(cur)!="" { chunks = append(chunks, cur) }
	for _, msg := range chunks {
		payload := map[string]any{"content":msg, "username":"DomWatch"}
		b,_ := json.Marshal(payload)
		req,_ := http.NewRequest("POST", webhook, bytes.NewReader(b))
		req.Header.Set("Content-Type","application/json")
		c := &http.Client{Timeout:15*time.Second}
		resp, err := c.Do(req); if err!=nil { return err }
		io.Copy(io.Discard, resp.Body); resp.Body.Close()
		if resp.StatusCode>=300 { return fmt.Errorf("discord status %d", resp.StatusCode) }
		time.Sleep(300*time.Millisecond)
	}
	return nil
}
func postTelegram(botToken, chatID, title string, lines []string) error {
	if botToken=="" || chatID=="" || len(lines)==0 { return nil }
	const maxLen = 3900
	header := title+"\n"
	cur := header
	var chunks []string
	for _, ln := range lines {
		if len(cur)+len(ln)+1 > maxLen { chunks = append(chunks, cur); cur = header }
		cur += ln+"\n"
	}
	if strings.TrimSpace(cur)!="" { chunks = append(chunks, cur) }
	api := "https://api.telegram.org/bot"+botToken+"/sendMessage"
	for _, msg := range chunks {
		payload := map[string]any{"chat_id":chatID,"text":msg,"parse_mode":"Markdown","disable_web_page_preview":true}
		b,_ := json.Marshal(payload)
		req,_ := http.NewRequest("POST", api, bytes.NewReader(b))
		req.Header.Set("Content-Type","application/json")
		c := &http.Client{Timeout:15*time.Second}
		resp, err := c.Do(req); if err!=nil { return err }
		io.Copy(io.Discard, resp.Body); resp.Body.Close()
		if resp.StatusCode>=300 { return fmt.Errorf("telegram status %d", resp.StatusCode) }
		time.Sleep(300*time.Millisecond)
	}
	return nil
}

// ---------- AI (optional) ----------
func getOpenAIKey() string {
	if s := strings.TrimSpace(os.Getenv("OPENAI_API_KEY")); s!="" { return s }
	if c,_ := loadConfig(); c!=nil { return strings.TrimSpace(c.OpenAIAPIKey) }
	return ""
}
func aiSummary(domain string, newSubs []string) (string, error) {
	key := getOpenAIKey()
	if key=="" { return "", nil }
	if len(newSubs)==0 { return "No new subdomains found.", nil }
	userMsg := fmt.Sprintf("Domain: %s\nNew subdomains (%d):\n- %s\n\nTask: 1) Group by obvious services (auth, api, dev, staging, admin, cdn, mail, vpn, grafana, kibana, git, test). 2) Flag likely high-value targets. 3) Suggest next checks (httpx, tls certs, title, tech stack, weak DNS). Output in concise bullets.", domain, len(newSubs), strings.Join(newSubs, "\n- "))
	payload := map[string]any{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{"role":"system","content":"You are a security assistant. Be concise and actionable."},
			{"role":"user","content":userMsg},
		},
		"temperature": 0.2,
	}
	body,_ := json.Marshal(payload)
	req,_ := http.NewRequest("POST","https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization","Bearer "+key)
	req.Header.Set("Content-Type","application/json")
	c := &http.Client{Timeout:30*time.Second}
	resp, err := c.Do(req); if err!=nil { return "", err }
	defer resp.Body.Close()
	if resp.StatusCode==429 { io.Copy(io.Discard, resp.Body); return "", nil }
	if resp.StatusCode>=300 { b,_ := io.ReadAll(resp.Body); return "", fmt.Errorf("OpenAI error: %s\n%s", resp.Status, string(b)) }
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string ` + "`json:\"content\"`" + `
			} ` + "`json:\"message\"`" + `
		} ` + "`json:\"choices\"`" + `
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err!=nil { return "", err }
	if len(parsed.Choices)==0 { return "", errors.New("no AI choices returned") }
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

// ---------- commands ----------
func cmdAdd(args []string) int {
	if len(args)<1 { fmt.Println("usage: domwatch add <domain>"); return 2 }
	domain := strings.ToLower(args[0])
	if err := ensureDirs(); err!=nil { fmt.Fprintln(os.Stderr, "error:", err); return 1 }
	p := filepath.Join(dataDir(), domain+".txt")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		if err := writeLines(p, []string{}); err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }
		fmt.Println("added:", domain)
	} else {
		fmt.Println("already exists:", domain)
	}
	df := filepath.Join(homeDir(), "domains.txt")
	old, _ := readLines(df)
	has := false
	for _, d := range old { if strings.EqualFold(strings.TrimSpace(d), domain) { has = true; break } }
	if !has { old = append(old, domain); old = uniqueSorted(old); _ = writeLines(df, old) }
	return 0
}

func scanOne(domain string, withAI bool) (int, error) {
	if err := ensureDirs(); err!=nil { return 0, err }
	oldList, err := readLines(filepath.Join(dataDir(), domain+".txt")); if err!=nil { return 0, err }
	nowList, err := runSubfinder(domain); if err!=nil { return 0, err }
	added, _ := diff(oldList, nowList)
	merged := uniqueSorted(append(oldList, nowList...))
	if err := writeLines(filepath.Join(dataDir(), domain+".txt"), merged); err!=nil { return 0, err }
	if len(added)>0 {
		lastNew := filepath.Join(dataDir(), fmt.Sprintf("%s_new_%d.txt", domain, time.Now().Unix()))
		_ = writeLines(lastNew, added)
	}
	fmt.Printf("Scan %s -> total:%d (new:%d, old:%d)\n", domain, len(merged), len(added), len(merged)-len(added))
	for _, s := range added { fmt.Println("[NEW]", s) }

	// notify
	if len(added)>0 {
		title := fmt.Sprintf("🆕 New subdomains for **%s** (%d) — %s", domain, len(added), time.Now().Format(time.RFC3339))
		var lines []string; for _, s := range added { lines = append(lines, "- `"+s+"`") }
		if d := getDiscordWebhook(); d!="" { if err := postDiscord(d, title, lines); err!=nil { fmt.Fprintln(os.Stderr,"Discord notify error:", err) } }
		if tb, tc := getTelegram(); tb!="" && tc!="" { if err := postTelegram(tb, tc, title, lines); err!=nil { fmt.Fprintln(os.Stderr,"Telegram notify error:", err) } }
	}

	if withAI {
		if summary, err := aiSummary(domain, added); err==nil && strings.TrimSpace(summary)!="" {
			fmt.Println("\n=== AI Summary ===")
			fmt.Println(summary)
		}
	}
	return len(added), nil
}

func cmdScan(args []string) int {
	if len(args)<1 { fmt.Println("usage: domwatch scan <domain>|--all [--ai]"); return 2 }
	withAI := false
	var domains []string
	for _, a := range args {
		if a=="--ai" { withAI = true; continue }
		if a=="--all" {
			list, _ := readLines(filepath.Join(homeDir(),"domains.txt"))
			if len(list)==0 { fmt.Println("no domains in domains.txt; add with: domwatch add example.com"); return 2 }
			domains = append(domains, list...)
		}
	}
	if len(domains)==0 && !strings.HasPrefix(args[0],"--") { domains = []string{args[0]} }
	if len(domains)==0 { fmt.Println("usage: domwatch scan <domain>|--all [--ai]"); return 2 }
	totalNew := 0
	if err := ensureSubfinder(); err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }
	for _, d := range domains {
		n, err := scanOne(strings.ToLower(d), withAI); if err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }
		totalNew += n
	}
	if totalNew==0 { fmt.Println("No new subdomains detected.") }
	return 0
}

func cmdList(args []string) int {
	if len(args)<1 { fmt.Println("usage: domwatch list <domain>"); return 2 }
	domain := strings.ToLower(args[0])
	lines, err := readLines(filepath.Join(dataDir(), domain+".txt")); if err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }
	for _, s := range lines { fmt.Println(s) }
	return 0
}

func cmdRemove(args []string) int {
	if len(args)<1 { fmt.Println("usage: domwatch remove <domain>"); return 2 }
	domain := strings.ToLower(args[0])
	df := filepath.Join(homeDir(),"domains.txt")
	lines, _ := readLines(df)
	var kept []string; for _, d := range lines { if !strings.EqualFold(strings.TrimSpace(d), domain) { kept = append(kept, d) } }
	_ = writeLines(df, uniqueSorted(kept))
	_ = os.Remove(filepath.Join(dataDir(), domain+".txt"))
	entries, _ := os.ReadDir(dataDir())
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, domain+"_new_") && strings.HasSuffix(name, ".txt") { _ = os.Remove(filepath.Join(dataDir(), name)) }
	}
	fmt.Println("removed:", domain)
	return 0
}

func cmdConfig(args []string) int {
	if len(args)==0 || args[0]=="show" {
		cfg,_ := loadConfig()
		fmt.Println("Home:", homeDir())
		fmt.Println("Config:", configPath())
		fmt.Println("discord_webhook_url:", mask(cfg.DiscordWebhookURL))
		fmt.Println("telegram_bot_token :", mask(cfg.TelegramBotToken))
		fmt.Println("telegram_chat_id   :", mask(cfg.TelegramChatID))
		fmt.Println("openai_api_key     :", mask(cfg.OpenAIAPIKey))
		return 0
	}
	switch args[0] {
	case "set-webhook":
		if len(args)<2 { fmt.Println("usage: domwatch config set-webhook <discord_url>"); return 2 }
		cfg,_ := loadConfig(); u := cleanWebhook(args[1]); if u=="" { fmt.Println("invalid webhook URL"); return 2 }
		cfg.DiscordWebhookURL=u; if err:=saveConfig(cfg); err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }
		fmt.Println("Saved webhook to", configPath())
	case "set-telegram":
		if len(args)<3 { fmt.Println("usage: domwatch config set-telegram <bot_token> <chat_id>"); return 2 }
		cfg,_ := loadConfig(); cfg.TelegramBotToken=strings.TrimSpace(args[1]); cfg.TelegramChatID=strings.TrimSpace(args[2]); if err:=saveConfig(cfg); err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }
		fmt.Println("Saved Telegram settings to", configPath())
	case "set-openai":
		if len(args)<2 { fmt.Println("usage: domwatch config set-openai <key>"); return 2 }
		cfg,_ := loadConfig(); cfg.OpenAIAPIKey=strings.TrimSpace(args[1]); if err:=saveConfig(cfg); err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }
		fmt.Println("Saved API key to", configPath())
	default:
		fmt.Println("usage: domwatch config [show|set-webhook <discord_url>|set-telegram <bot> <chat>|set-openai <key>]"); return 2
	}
	return 0
}

func cmdNotifyTest(args []string) int {
	if len(args)<1 { fmt.Println("usage: domwatch notify-test <domain>"); return 2 }
	domain := strings.ToLower(args[0])
	pattern := domain+"_new_"
	var newest string; var newestTS int64
	entries, _ := os.ReadDir(dataDir())
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, pattern) && strings.HasSuffix(name, ".txt") {
			var ts int64; fmt.Sscanf(strings.TrimSuffix(strings.TrimPrefix(name, pattern), ".txt"), "%d", &ts)
			if ts > newestTS { newestTS = ts; newest = filepath.Join(dataDir(), name) }
		}
	}
	var subs []string
	if newest != "" { subs,_ = readLines(newest) } else {
		all,_ := readLines(filepath.Join(dataDir(), domain+".txt"))
		if len(all)>10 { subs = all[:10] } else { subs = all }
	}
	if len(subs)==0 { fmt.Println("nothing to send"); return 0 }
	title := fmt.Sprintf("🔔 DomWatch test for **%s** — %s", domain, time.Now().Format(time.RFC3339))
	var lines []string; for _, s := range subs { lines = append(lines, "- `"+s+"`") }
	if d:=getDiscordWebhook(); d!="" { if err:=postDiscord(d,title,lines); err!=nil { fmt.Fprintln(os.Stderr,"Discord notify error:",err) } }
	if tb,tc := getTelegram(); tb!="" && tc!="" { if err:=postTelegram(tb,tc,title,lines); err!=nil { fmt.Fprintln(os.Stderr,"Telegram notify error:",err) } }
	fmt.Println("sent test notification")
	return 0
}

func cmdSetup(args []string) int {
	fmt.Println("== DomWatch setup ==")
	if err := ensureDirs(); err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }
	if err := ensureSubfinder(); err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }

	if !isInteractive() {
		fmt.Println("Non-interactive mode: use `domwatch config` commands to set notifiers.")
		return 0
	}
	cfg,_ := loadConfig()
	// Discord
	if cleanWebhook(cfg.DiscordWebhookURL)=="" {
		u, _ := prompt("Discord Webhook URL (or blank to skip): ")
		u = cleanWebhook(u); if u!="" { cfg.DiscordWebhookURL=u }
	}
	// Telegram
	if strings.TrimSpace(cfg.TelegramBotToken)=="" || strings.TrimSpace(cfg.TelegramChatID)=="" {
		tok,_ := prompt("Telegram Bot Token (blank to skip): ")
		if strings.TrimSpace(tok)!="" {
			chat,_ := prompt("Telegram Chat ID: ")
			if strings.TrimSpace(chat)!="" { cfg.TelegramBotToken=strings.TrimSpace(tok); cfg.TelegramChatID=strings.TrimSpace(chat) }
		}
	}
	if err := saveConfig(cfg); err!=nil { fmt.Fprintln(os.Stderr,"error:",err); return 1 }
	fmt.Println("Setup complete. Home:", homeDir())
	return 0
}

func prompt(q string) (string, error) { fmt.Print(q); r:=bufio.NewReader(os.Stdin); s,err:=r.ReadString('\n'); return strings.TrimSpace(s), err }

func mask(s string) string {
	s = strings.TrimSpace(s)
	if s=="" { return "(empty)" }
	if len(s)<=8 { return "********" }
	return s[:4]+"****"+s[len(s)-4:]
}
