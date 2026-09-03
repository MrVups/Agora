package main

import (
	"crypto/md5"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	stdhtml "html"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	DB_PATH        = envOrDefault("SUB_AGG_DB_PATH", "/opt/sub_aggregator/aggregator.db")
	SANAEI_DB_PATH = envOrDefault("SANAEI_DB_PATH", "/etc/x-ui/x-ui.db")
	MYSQL_USER     = envOrDefault("MYSQL_USER", "Admin")
	MYSQL_PASS     = os.Getenv("MYSQL_PASS")
	MYSQL_DB       = envOrDefault("MYSQL_DB", "mirzaprobot")
	MYSQL_HOST     = envOrDefault("MYSQL_HOST", "127.0.0.1:3306")
	SANAEI_PORT    = envOrDefault("SANAEI_PORT", "2096")
	LISTEN_PORT    = envOrDefault("SUB_AGG_LISTEN_PORT", ":8443")

	PANEL_TYPE            = os.Getenv("PANEL_TYPE")
	PASARGUARD_PORT       = envOrDefault("PASARGUARD_PORT", "8000")
	PASARGUARD_SUB_PATH   = envOrDefault("PASARGUARD_SUB_PATH", "/sub/")
	PASARGUARD_SCHEME     = envOrDefault("PASARGUARD_SCHEME", "http")
	PASARGUARD_ADMIN_USER = os.Getenv("PASARGUARD_ADMIN_USER")
	PASARGUARD_ADMIN_PASS = os.Getenv("PASARGUARD_ADMIN_PASS")

	BOT_INBOUND_FORMAT = envOrDefault("BOT_INBOUND_FORMAT", "plain")
)

func detectPanelType() string {
	if PANEL_TYPE != "" {
		log.Printf("🧩 نوع پنل صریحاً از تنظیمات خوانده شد: %s", PANEL_TYPE)
		return PANEL_TYPE
	}

	if _, err := os.Stat(SANAEI_DB_PATH); err == nil {
		log.Printf("🔍 فایل %s پیدا شد → نوع پنل به‌صورت خودکار: xui", SANAEI_DB_PATH)
		return "xui"
	}

	probeURL := fmt.Sprintf("%s://127.0.0.1:%s/", PASARGUARD_SCHEME, PASARGUARD_PORT)
	client := &http.Client{Timeout: 2 * time.Second}
	if resp, err := client.Get(probeURL); err == nil {
		resp.Body.Close()
		log.Printf("🔍 پاسخی از پورت %s گرفته شد → نوع پنل به‌صورت خودکار: pasarguard", PASARGUARD_PORT)
		return "pasarguard"
	}

	log.Printf("⚠️  نتوانستم نوع پنل را خودکار تشخیص بدهم. پیش‌فرض xui در نظر گرفته می‌شود.")
	return "xui"
}

var (
	db      *sql.DB
	xuiDB   *sql.DB
	mysqlDB *sql.DB
	dbLock  sync.Mutex
)

func initDB() {
	_ = os.MkdirAll(filepath.Dir(DB_PATH), 0755)
	var err error
	db, err = sql.Open("sqlite3", DB_PATH+"?_journal_mode=WAL")
	if err != nil {
		log.Fatalf("Failed to open SQLite DB: %v", err)
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS main_links (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT,
			url TEXT,
			target_inbounds TEXT DEFAULT 'all',
			is_active INTEGER DEFAULT 1,
			last_updated TEXT DEFAULT '-'
		);`,
		`CREATE TABLE IF NOT EXISTS category_schedules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			category_name TEXT,
			target_inbound TEXT,
			valid_from TEXT,
			valid_to TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS admin_users (
			username TEXT PRIMARY KEY,
			password TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS cached_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			inbound_id TEXT,
			raw_config TEXT
		);`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			log.Printf("DB Init Table Error: %v", err)
		}
	}
	seedOrMigrateAdminPassword()
}

func seedOrMigrateAdminPassword() {
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM admin_users").Scan(&count)
	if count == 0 {
		hashed, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Failed to hash default password: %v", err)
		}
		_, _ = db.Exec("INSERT INTO admin_users (username, password) VALUES (?, ?)", "admin", string(hashed))
		log.Printf("⚠️  کاربر ادمین پیش‌فرض ساخته شد (admin/admin). فوراً از کنسول پسورد رو عوض کنید.")
		return
	}
	var username, pass string
	if err := db.QueryRow("SELECT username, password FROM admin_users LIMIT 1").Scan(&username, &pass); err == nil {
		if !strings.HasPrefix(pass, "$2a$") && !strings.HasPrefix(pass, "$2b$") && !strings.HasPrefix(pass, "$2y$") {
			hashed, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
			if err == nil {
				_, _ = db.Exec("UPDATE admin_users SET password = ? WHERE username = ?", string(hashed), username)
				log.Printf("🔐 پسورد ادمین قدیمی (plaintext) پیدا شد و به‌صورت خودکار هش شد.")
			}
		}
	}
}

func initXUIDB() {
	var err error
	xuiDB, err = sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro&_journal_mode=WAL", SANAEI_DB_PATH))
	if err != nil {
		log.Printf("⚠️  اتصال read-only به x-ui.db برقرار نشد: %v (فیلتر per-inbound غیرفعال می‌ماند)", err)
		xuiDB = nil
		return
	}
	if err := xuiDB.Ping(); err != nil {
		log.Printf("⚠️  Ping به x-ui.db ناموفق بود: %v", err)
		xuiDB = nil
	}
}

type XUIRuntimeConfig struct {
	Path   string
	Port   string
	Domain string
}

var xuiConfigVal atomic.Value

func getXUIConfig() XUIRuntimeConfig {
	v := xuiConfigVal.Load()
	if v == nil {
		return XUIRuntimeConfig{Path: "/sub/", Port: SANAEI_PORT, Domain: ""}
	}
	return v.(XUIRuntimeConfig)
}

func loadXUIRuntimeConfig() {
	cfg := XUIRuntimeConfig{Path: "/sub/", Port: SANAEI_PORT, Domain: ""}
	if xuiDB != nil {
		rows, err := xuiDB.Query("SELECT key, value FROM settings WHERE key IN ('subPath', 'subPort', 'subDomain')")
		if err == nil {
			for rows.Next() {
				var k, v string
				if rows.Scan(&k, &v) == nil {
					if k == "subPath" && v != "" {
						if !strings.HasPrefix(v, "/") {
							v = "/" + v
						}
						if !strings.HasSuffix(v, "/") {
							v = v + "/"
						}
						cfg.Path = v
					}
					if k == "subPort" && v != "" {
						cfg.Port = v
					}
					if k == "subDomain" && v != "" {
						cfg.Domain = v
					}
				}
			}
			rows.Close()
		}
	}

	old := getXUIConfig()
	if old.Path != cfg.Path || old.Port != cfg.Port || old.Domain != cfg.Domain {
		log.Printf("🔄 تنظیمات ساب‌اسکریپشن x-ui: Path=%s Port=%s Domain=%s", cfg.Path, cfg.Port, cfg.Domain)
	}
	xuiConfigVal.Store(cfg)
}

func initMySQLDB() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?timeout=5s", MYSQL_USER, MYSQL_PASS, MYSQL_HOST, MYSQL_DB)
	var err error
	mysqlDB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("⚠️  اتصال به MySQL برقرار نشد: %v (سینک ربات غیرفعال می‌ماند)", err)
		mysqlDB = nil
		return
	}
	mysqlDB.SetMaxOpenConns(3)
	mysqlDB.SetConnMaxLifetime(5 * time.Minute)
	mysqlDB.Ping()
}

func isInfoOrFakeConfig(line string) bool {
	if line == "" {
		return true
	}
	if strings.Contains(line, "@0.0.0.0:") || strings.Contains(line, "://0.0.0.0:") || strings.Contains(line, "server=0.0.0.0") {
		return true
	}
	decoded, _ := url.QueryUnescape(line)
	lower := strings.ToLower(decoded)
	strictBanners := []string{"آپدیت کنید", "آیدی کانال", "عضو شوید", "@mushak_vpn", "ssssssjjjjjjjjldkrbdhdb"}
	for _, banner := range strictBanners {
		if strings.Contains(lower, banner) {
			return true
		}
	}
	return false
}

// 📌 Pipeline: Canonical Architecture Functions

func looksLikeHTMLResponse(body []byte, contentType string) bool {
	ct := strings.ToLower(contentType)
	trimmed := strings.TrimSpace(string(body))
	return strings.Contains(ct, "text/html") ||
		strings.HasPrefix(trimmed, "<!doctype html") ||
		strings.HasPrefix(trimmed, "<html")
}

func containsValidSubscriptionURI(text string) bool {
	lines := strings.Split(text, "\n")
	validProtocols := []string{"vless://", "vmess://", "ss://", "trojan://", "tuic://", "hysteria2://", "hysteria://", "wireguard://", "wg://", "tg://", "socks://", "http://"}
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		for _, proto := range validProtocols {
			if strings.HasPrefix(line, proto) {
				return true
			}
		}
	}
	return false
}

func isValidConfigLine(line string) bool {
	validProtocols := []string{"vless://", "vmess://", "ss://", "trojan://", "tuic://", "hysteria2://", "hysteria://", "wireguard://", "wg://", "tg://", "socks://", "http://"}
	for _, proto := range validProtocols {
		if strings.HasPrefix(line, proto) {
			return true
		}
	}
	return false
}

func normalizeSubscriptionText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}

	return strings.Join(out, "\n")
}

func decodeSubscriptionPayload(data string) (string, bool) {
	data = strings.TrimSpace(data)
	if data == "" {
		return "", false
	}

	var candidates []string
	candidates = append(candidates, data)

	if mod := len(data) % 4; mod != 0 {
		padded := data + strings.Repeat("=", 4-mod)
		candidates = append(candidates, padded)
	}

	for _, candidate := range candidates {
		decoded, err := base64.StdEncoding.DecodeString(candidate)
		if err != nil {
			continue
		}
		text := normalizeSubscriptionText(string(decoded))
		if containsValidSubscriptionURI(text) {
			return text, true
		}
	}

	return normalizeSubscriptionText(data), false
}

func copySubscriptionHeaders(dst, src http.Header) {
	for _, key := range []string{
		"Subscription-Userinfo",
		"Profile-Update-Interval",
		"Profile-Title",
		"Support-Url",
		"Profile-Web-Page-Url",
		"Announce",
		"Content-Disposition",
	} {
		values := src.Values(key)
		if len(values) == 0 {
			continue
		}
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func debugSubscriptionResponse(tag string, r *http.Request, resp *http.Response, body []byte) {
	if os.Getenv("SUB_AGG_DEBUG") != "1" {
		return
	}
	isBase64 := "false"
	if _, ok := decodeSubscriptionPayload(string(body)); ok {
		isBase64 = "true"
	}
	log.Printf(
		"[SUB-DEBUG][%s] UA=%q Status=%d Content-Type=%q BodyLen=%d Base64=%s",
		tag,
		r.Header.Get("User-Agent"),
		resp.StatusCode,
		resp.Header.Get("Content-Type"),
		len(body),
		isBase64,
	)
}

func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(strings.TrimSpace(text)))
	return hex.EncodeToString(hasher.Sum(nil))
}

func fetchAndCache() {
	dbLock.Lock()
	defer dbLock.Unlock()

	rows, err := db.Query("SELECT id, title, url, COALESCE(target_inbounds, 'all') FROM main_links WHERE COALESCE(is_active, 1) = 1")
	if err != nil {
		log.Printf("[CronFetch] DB Error: %v", err)
		return
	}
	type FetchItem struct {
		ID            int
		Title         string
		URL           string
		TargetInbound string
	}
	var links []FetchItem
	for rows.Next() {
		var item FetchItem
		if err := rows.Scan(&item.ID, &item.Title, &item.URL, &item.TargetInbound); err == nil {
			links = append(links, item)
		}
	}
	rows.Close()

	client := &http.Client{Timeout: 15 * time.Second}
	var allFetchedConfigs [][2]string
	seenHashes := make(map[string]bool)
	successful := 0

	for _, l := range links {
		req, _ := http.NewRequest("GET", strings.TrimSpace(l.URL), nil)
		req.Header.Set("User-Agent", "Go-Sub-Aggregator/1.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[CronFetch] خطای اتصال به '%s': %v", l.Title, err)
			continue
		}
		if resp.StatusCode != 200 {
			log.Printf("[CronFetch] لینک '%s' با کد %d پاسخ داد", l.Title, resp.StatusCode)
			resp.Body.Close()
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		payloadText, _ := decodeSubscriptionPayload(string(bodyBytes))
		lines := strings.Split(payloadText, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !isValidConfigLine(line) || isInfoOrFakeConfig(line) {
				continue
			}
			hashKey := l.TargetInbound + "_" + getMD5Hash(line)
			if seenHashes[hashKey] {
				continue
			}
			seenHashes[hashKey] = true
			allFetchedConfigs = append(allFetchedConfigs, [2]string{l.TargetInbound, line})
		}
		successful++
	}

	if len(allFetchedConfigs) == 0 && len(links) > 0 {
		log.Printf("[CronFetch] هشدار: هیچ کانفیگ معتبری از هیچ لینکی دریافت نشد. کش قبلی حفظ می‌شود.")
		return
	}

	db.Exec("DELETE FROM cached_configs")
	tx, err := db.Begin()
	if err != nil {
		log.Printf("[CronFetch] DB Tx Error: %v", err)
		return
	}
	stmt, _ := tx.Prepare("INSERT INTO cached_configs (inbound_id, raw_config) VALUES (?, ?)")
	for _, cfg := range allFetchedConfigs {
		stmt.Exec(cfg[0], cfg[1])
	}
	stmt.Close()
	tx.Commit()
	log.Printf("[CronFetch] کش به‌روزرسانی شد. %d/%d لینک موفق. %d کانفیگ یکتا.", successful, len(links), len(allFetchedConfigs))
}

func syncBotInbound() {
	if mysqlDB == nil {
		return
	}
	dbLock.Lock()
	rows, err := db.Query("SELECT category_name, target_inbound, valid_from, valid_to FROM category_schedules")
	if err != nil {
		dbLock.Unlock()
		return
	}
	type SchedItem struct{ Cat, Inb, VFrom, VTo string }
	var scheds []SchedItem
	for rows.Next() {
		var s SchedItem
		rows.Scan(&s.Cat, &s.Inb, &s.VFrom, &s.VTo)
		scheds = append(scheds, s)
	}
	rows.Close()
	dbLock.Unlock()

	today := time.Now().Format("2006-01-02")
	for _, s := range scheds {
		match := true
		if s.VFrom != "" && today < s.VFrom {
			match = false
		}
		if s.VTo != "" && today > s.VTo {
			match = false
		}
		if !match {
			continue
		}
		inboundValue := s.Inb
		if strings.EqualFold(BOT_INBOUND_FORMAT, "json_array") {
			inboundValue = fmt.Sprintf("[%s]", s.Inb)
		}
		_, err := mysqlDB.Exec("UPDATE product SET inbounds = ? WHERE category = ?", inboundValue, s.Cat)
		if err != nil {
			log.Printf("[SyncBot] خطا در به‌روزرسانی دسته '%s': %v", s.Cat, err)
		} else {
			log.Printf("[SyncBot] دسته '%s' → اینباند %s به‌روزرسانی شد", s.Cat, inboundValue)
		}
	}
}

func getBotCategories() []string {
	if mysqlDB == nil {
		return nil
	}
	rows, err := mysqlDB.Query(`SELECT DISTINCT category FROM product WHERE category IS NOT NULL AND category != ''`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var cats []string
	for rows.Next() {
		var c string
		if rows.Scan(&c) == nil {
			cats = append(cats, c)
		}
	}
	return cats
}

func getUserInboundID(subID string) int {
	if xuiDB == nil {
		return 1
	}
	var email string
	err := xuiDB.QueryRow("SELECT email FROM clients WHERE sub_id = ?", subID).Scan(&email)
	if err != nil || email == "" {
		return 1
	}
	var inboundID int
	err = xuiDB.QueryRow("SELECT inbound_id FROM client_traffics WHERE email = ?", email).Scan(&inboundID)
	if err != nil {
		return 1
	}
	return inboundID
}

func getCachedConfigsForInbound(inboundID int) []string {
	rows, err := db.Query("SELECT raw_config FROM cached_configs WHERE inbound_id = ? OR inbound_id = 'all'", strconv.Itoa(inboundID))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cfg string
		if rows.Scan(&cfg) == nil {
			out = append(out, cfg)
		}
	}
	return out
}

func normalizeURIPath(v string) string {
	if v == "" {
		return "/"
	}
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	if !strings.HasSuffix(v, "/") {
		v = v + "/"
	}
	return v
}

func getCachedConfigsForGroups(groupIDs []int) []string {
	if len(groupIDs) == 0 {
		return getCachedConfigsForInbound(-1)
	}
	placeholders := make([]string, 0, len(groupIDs)+1)
	args := make([]interface{}, 0, len(groupIDs)+1)
	for _, id := range groupIDs {
		placeholders = append(placeholders, "?")
		args = append(args, strconv.Itoa(id))
	}
	placeholders = append(placeholders, "?")
	args = append(args, "all")

	query := "SELECT raw_config FROM cached_configs WHERE inbound_id IN (" + strings.Join(placeholders, ",") + ")"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cfg string
		if rows.Scan(&cfg) == nil {
			out = append(out, cfg)
		}
	}
	return out
}

// 📌 پچ جدید: اضافه شدن فیلد Status برای خواندن وضعیت کاربر از پاسارگارد
type pasarGuardUserInfo struct {
	GroupIDs  []int  `json:"group_ids"`
	CreatedAt string `json:"created_at"`
	Status    string `json:"status"`
}

func fetchPasarGuardUserInfo(token string) *pasarGuardUserInfo {
	url := fmt.Sprintf("%s://127.0.0.1:%s%s%s/info", PASARGUARD_SCHEME, PASARGUARD_PORT, PASARGUARD_SUB_PATH, token)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[PasarGuard] خطا در گرفتن اطلاعات کاربر: %v", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	var info pasarGuardUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}
	return &info
}

func gregorianToJalali(gy, gm, gd int) (int, int, int) {
	gDaysInMonth := []int{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}
	var jy int
	if gy > 1600 {
		jy = 979
		gy -= 1600
	} else {
		jy = 0
		gy -= 621
	}
	var gy2 int
	if gm > 2 {
		gy2 = gy + 1
	} else {
		gy2 = gy
	}
	days := (365 * gy) + ((gy2 + 3) / 4) - ((gy2 + 99) / 100) + ((gy2 + 399) / 400) - 80 + gd + gDaysInMonth[gm-1]
	jy += 33 * (days / 12053)
	days %= 12053
	jy += 4 * (days / 1461)
	days %= 1461
	if days > 365 {
		jy += (days - 1) / 365
		days = (days - 1) % 365
	}
	var jm, jd int
	if days < 186 {
		jm = 1 + days/31
		jd = 1 + (days % 31)
	} else {
		jm = 7 + (days-186)/30
		jd = 1 + ((days - 186) % 30)
	}
	return jy, jm, jd
}

func jalaliDayOfPurchase(createdAt string) int {
	if createdAt == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05", createdAt)
		if err != nil {
			return 0
		}
	}
	_, _, jd := gregorianToJalali(t.Year(), int(t.Month()), t.Day())
	return jd
}

func getCachedConfigsForDay(day int) []string {
	if day <= 0 {
		return getCachedConfigsForInbound(-1)
	}
	rows, err := db.Query("SELECT raw_config FROM cached_configs WHERE inbound_id = ? OR inbound_id = 'all'", strconv.Itoa(day))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cfg string
		if rows.Scan(&cfg) == nil {
			out = append(out, cfg)
		}
	}
	return out
}

func injectExtraIntoPasarGuardHTML(htmlStr string, extraConfigs []string) string {
	if len(extraConfigs) == 0 {
		return htmlStr
	}
	marker := "<button\n                    class=\"copy-all-button\""
	idx := strings.Index(htmlStr, marker)
	if idx == -1 {
		return htmlStr
	}
	var sb strings.Builder
	for _, cfg := range extraConfigs {
		escAttr := stdhtml.EscapeString(cfg)
		escJS := strings.ReplaceAll(cfg, "\\", "\\\\")
		escJS = strings.ReplaceAll(escJS, "'", "\\'")
		sb.WriteString(`<div class="link-item">`)
		sb.WriteString(`<input type="text" class="link-input" value="`)
		sb.WriteString(escAttr)
		sb.WriteString(`" readonly />`)
		sb.WriteString(`<button class="copy-button" onclick="copyLink('`)
		sb.WriteString(escJS)
		sb.WriteString(`', this)">Copy</button>`)
		sb.WriteString(`<button class="qr-button" data-link="`)
		sb.WriteString(escAttr)
		sb.WriteString(`">QR Code</button>`)
		sb.WriteString(`</div>`)
	}
	return htmlStr[:idx] + sb.String() + htmlStr[idx:]
}

// 📌 Pipeline: PasarGuard Sub Handler
func handleSubPasarGuard(w http.ResponseWriter, r *http.Request, token string) {
	setNoCacheHeaders(w)
	if token == "" {
		http.NotFound(w, r)
		return
	}

	upstreamURL := fmt.Sprintf("%s://127.0.0.1:%s%s%s", PASARGUARD_SCHEME, PASARGUARD_PORT, PASARGUARD_SUB_PATH, token)
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", upstreamURL, nil)

	wantsHTML := strings.Contains(r.Header.Get("Accept"), "text/html") || r.URL.Query().Get("html") == "1"

	for k, v := range r.Header {
		if strings.ToLower(k) == "accept-encoding" {
			continue
		}
		req.Header[k] = v
	}
	req.Header.Set("Accept-Encoding", "identity")
	
	if !wantsHTML {
		req.Header.Set("Accept", "text/plain, application/octet-stream;q=0.9, */*;q=0.1")
		req.Header.Set("User-Agent", "Go-Sub-Aggregator/1.0")
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	debugSubscriptionResponse("PasarGuard", r, resp, bodyBytes)

	if resp.StatusCode != 200 {
		ct := resp.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/json"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		w.Write(bodyBytes)
		return
	}

	// 📌 پچ جدید: بررسی وضعیت کاربر قبل از واکشی کانفیگ‌های مادر
	userInfo := fetchPasarGuardUserInfo(token)
	var purchaseDay int
	userIsActive := true // پیش‌فرض فعال است

	if userInfo != nil {
		purchaseDay = jalaliDayOfPurchase(userInfo.CreatedAt)
		statusLower := strings.ToLower(strings.TrimSpace(userInfo.Status))
		// اگر کاربر منقضی یا غیرفعال شده بود، وضعیت را false می‌کنیم
		if statusLower == "expired" || statusLower == "disabled" || statusLower == "limited" {
			userIsActive = false
		}
	}

	var extraConfigs []string
	if userIsActive {
		extraConfigs = getCachedConfigsForDay(purchaseDay)
	}

	ct := resp.Header.Get("Content-Type")
	isHTML := looksLikeHTMLResponse(bodyBytes, ct)

	if isHTML {
		if ct == "" {
			ct = "text/html; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(injectExtraIntoPasarGuardHTML(string(bodyBytes), extraConfigs)))
		return
	}

	payloadText, wasBase64 := decodeSubscriptionPayload(string(bodyBytes))
	
	var configs []string
	if payloadText != "" {
		configs = strings.Split(payloadText, "\n")
	}
	
	// در صورت غیرفعال بودن کاربر، این آرایه خالی است و هیچ‌چیزی به خروجی پاسارگارد اضافه نمی‌شود
	configs = append(configs, extraConfigs...)
	
	finalPayload := normalizeSubscriptionText(strings.Join(configs, "\n"))
	
	copySubscriptionHeaders(w.Header(), resp.Header)
	
	if wasBase64 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(resp.StatusCode)
		encodedFinal := base64.StdEncoding.EncodeToString([]byte(finalPayload))
		w.Write([]byte(encodedFinal))
	} else {
		if ct == "" {
			ct = "text/plain; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(finalPayload))
	}
}

type pgGroupSimple struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

var (
	pgTokenCache   string
	pgTokenExpires time.Time
	pgTokenLock    sync.Mutex
)

func getPasarGuardAdminToken(forceRefresh bool) string {
	if PASARGUARD_ADMIN_USER == "" || PASARGUARD_ADMIN_PASS == "" {
		return ""
	}
	pgTokenLock.Lock()
	defer pgTokenLock.Unlock()

	if !forceRefresh && pgTokenCache != "" && time.Now().Before(pgTokenExpires) {
		return pgTokenCache
	}

	form := url.Values{}
	form.Set("username", PASARGUARD_ADMIN_USER)
	form.Set("password", PASARGUARD_ADMIN_PASS)

	loginURL := fmt.Sprintf("%s://127.0.0.1:%s/api/admin/token", PASARGUARD_SCHEME, PASARGUARD_PORT)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.PostForm(loginURL, form)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return ""
	}
	pgTokenCache = tok.AccessToken
	pgTokenExpires = time.Now().Add(20 * time.Hour)
	return pgTokenCache
}

func getPasarGuardGroups() []pgGroupSimple {
	token := getPasarGuardAdminToken(false)
	if token == "" {
		return nil
	}

	fetch := func(tok string) (*http.Response, error) {
		groupsURL := fmt.Sprintf("%s://127.0.0.1:%s/api/groups/simple?all=true", PASARGUARD_SCHEME, PASARGUARD_PORT)
		req, _ := http.NewRequest("GET", groupsURL, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		client := &http.Client{Timeout: 5 * time.Second}
		return client.Do(req)
	}

	resp, err := fetch(token)
	if err != nil {
		return nil
	}
	if resp.StatusCode == 401 {
		resp.Body.Close()
		token = getPasarGuardAdminToken(true)
		if token == "" {
			return nil
		}
		resp, err = fetch(token)
		if err != nil {
			return nil
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Groups []pgGroupSimple `json:"groups"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	return parsed.Groups
}

func checkBasicAuth(w http.ResponseWriter, r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	var dbUser, dbHash string
	err := db.QueryRow("SELECT username, password FROM admin_users LIMIT 1").Scan(&dbUser, &dbHash)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(dbUser)) == 1
	passOK := bcrypt.CompareHashAndPassword([]byte(dbHash), []byte(pass)) == nil
	if userOK && passOK {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return false
}

func basicAuthUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !checkBasicAuth(w, r) {
		return "", false
	}
	user, _, _ := r.BasicAuth()
	return user, true
}

type LinkRow struct {
	ID       int
	Title    string
	URL      string
	Inbounds string
	Active   bool
	Updated  string
}

type LinkGroup struct {
	Label string
	Links []LinkRow
}

type SchedRow struct {
	ID        int
	Category  string
	Inbound   string
	ValidFrom string
	ValidTo   string
}

type ConsoleData struct {
	Username     string
	Groups       []LinkGroup
	Scheds       []SchedRow
	Categories   []string
	IsPasarGuard bool
	PGGroups     []pgGroupSimple
	PanelLabel   string
	DayOptions   []int
}

const consoleTmpl = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<title>کنسول Go Sub-Aggregator</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css">
<link rel="stylesheet" href="https://unpkg.com/persian-datepicker@1.2.0/dist/css/persian-datepicker.min.css"/>
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://unpkg.com/persian-date@1.1.0/dist/persian-date.min.js"></script>
<script src="https://unpkg.com/persian-datepicker@1.2.0/dist/js/persian-datepicker.min.js"></script>
<style>
body { background-color: #f8f9fa; font-family: Tahoma, sans-serif; }
.card { border-radius: 12px; }
.pdate-input { background-color: #fff !important; cursor: pointer; }
</style>
</head>
<body class="container py-4">
<div class="d-flex justify-content-between align-items-center mb-4">
<h2>⚡ کنسول هوشمند Go Sub-Aggregator</h2>
<div>
<button class="btn btn-outline-dark btn-sm me-2" data-bs-toggle="modal" data-bs-target="#changeAuthModal">🔑 تغییر اطلاعات ورود</button>
<span class="badge bg-secondary me-2">پنل: {{.PanelLabel}}</span>
<span class="badge bg-dark">کاربر: {{.Username}}</span>
</div>
</div>

{{if not .IsPasarGuard}}
<div class="card p-4 mb-4 shadow-sm border-start border-4 border-primary">
<h4 class="mb-3">🤖 زمان‌بندی اینباند دسته‌بندی ربات</h4>
<form action="/aggr-console/sched/add" method="post" class="row g-3">
<div class="col-md-4">
<label class="form-label">دسته‌بندی</label>
<select name="category_name" class="form-select" required>
{{if .Categories}}{{range .Categories}}<option value="{{.}}">{{.}}</option>{{end}}{{else}}<option value="" disabled selected>هیچ دسته‌بندی‌ای یافت نشد (اتصال MySQL را بررسی کنید)</option>{{end}}
</select>
</div>
<div class="col-md-2">
<label class="form-label">Inbound ID</label>
<input type="text" name="target_inbound" class="form-control" placeholder="مثلا 1" required>
</div>
<div class="col-md-3">
<label class="form-label">از تاریخ (شمسی)</label>
<input type="text" name="valid_from" class="form-control pdate-input jalali-datepicker" placeholder="مثلا 1405/05/23" autocomplete="off">
</div>
<div class="col-md-3">
<label class="form-label">تا تاریخ (شمسی)</label>
<input type="text" name="valid_to" class="form-control pdate-input jalali-datepicker" placeholder="مثلا 1405/05/24" autocomplete="off">
</div>
<div class="col-md-12 text-end"><button type="submit" class="btn btn-primary">ثبت زمان‌بندی</button></div>
</form>

<table class="table table-sm mt-3">
<thead><tr><th>#</th><th>دسته</th><th>Inbound</th><th>بازه</th><th>عملیات</th></tr></thead>
<tbody>
{{range .Scheds}}
<tr>
<td>{{.ID}}</td><td>{{.Category}}</td><td>{{.Inbound}}</td>
<td>{{.ValidFrom}} تا {{.ValidTo}}</td>
<td><form method="post" action="/aggr-console/sched/delete/{{.ID}}" onsubmit="return confirm('حذف شود؟')" style="display:inline"><button type="submit" class="btn btn-sm btn-outline-danger">حذف</button></form></td>
</tr>
{{else}}
<tr><td colspan="5" class="text-center text-muted">زمان‌بندی ثبت نشده.</td></tr>
{{end}}
</tbody>
</table>
</div>
{{end}}

<div class="card p-4 mb-4 shadow-sm">
<h4 class="mb-3">🔗 ثبت گروهی لینک‌های مادر</h4>
<form action="/aggr-console/add" method="post" class="row g-3">
<div class="col-md-8"><input type="text" name="title" class="form-control" placeholder="عنوان" required></div>
<div class="col-md-4">
{{if .IsPasarGuard}}
  <select name="target_inbounds" class="form-select" required>
    <option value="all">همه (all)</option>
    {{range $d := .DayOptions}}<option value="{{$d}}">روز {{$d}} شمسی</option>{{end}}
  </select>
  <small class="text-muted">بر اساس روز شمسی ساخت اکانت کاربر انتخاب می‌شود.</small>
{{else}}
  <input type="text" name="target_inbounds" class="form-control" value="all" required placeholder="Inbound ID یا all">
{{end}}
</div>
<div class="col-md-12"><textarea name="urls" class="form-control" rows="3" placeholder="هر لینک در یک خط" required></textarea></div>
<div class="col-md-12 text-end"><button type="submit" class="btn btn-success px-4">ذخیره و آپدیت کش</button></div>
</form>
</div>

<h4 class="mb-3">📊 لینک‌های مادر بر اساس {{if .IsPasarGuard}}روز خرید (شمسی){{else}}اینباند{{end}}</h4>
{{range .Groups}}
<div class="card mb-3 border-start border-4 border-info">
<div class="card-header bg-light d-flex justify-content-between align-items-center">
<h5 class="mb-0">📌 {{.Label}}</h5>
<span class="badge bg-info text-dark">{{len .Links}} لینک</span>
</div>
<div class="card-body p-0">
<table class="table table-hover align-middle mb-0">
<thead><tr><th>#</th><th>عنوان</th><th>URL</th><th>وضعیت</th><th>بروزرسانی</th><th>عملیات</th></tr></thead>
<tbody>
{{range .Links}}
<tr>
<td>{{.ID}}</td>
<td><strong>{{.Title}}</strong></td>
<td><small class="text-break" style="max-width:280px;display:inline-block;">{{.URL}}</small></td>
<td>{{if .Active}}<span class="badge bg-success">فعال</span>{{else}}<span class="badge bg-secondary">غیرفعال</span>{{end}}</td>
<td><small>{{.Updated}}</small></td>
<td>
<button type="button" class="btn btn-sm btn-outline-primary me-1" onclick="openEditModal({{.ID}}, {{.Title}}, {{.URL}}, {{.Inbounds}})">ویرایش</button>
<form method="post" action="/aggr-console/toggle/{{.ID}}" style="display:inline"><button type="submit" class="btn btn-sm btn-outline-warning me-1">تغییر وضعیت</button></form>
<form method="post" action="/aggr-console/delete/{{.ID}}" onsubmit="return confirm('حذف شود؟')" style="display:inline"><button type="submit" class="btn btn-sm btn-outline-danger">حذف</button></form>
</td>
</tr>
{{end}}
</tbody>
</table>
</div>
</div>
{{else}}
<div class="alert alert-secondary text-center">هیچ لینکی ثبت نشده است.</div>
{{end}}

<div class="modal fade" id="editModal" tabindex="-1">
<div class="modal-dialog"><div class="modal-content">
<form action="/aggr-console/edit" method="post">
<div class="modal-header"><h5 class="modal-title">ویرایش لینک مادر</h5>
<button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body row g-3">
<input type="hidden" name="link_id" id="modal_link_id">
<div class="col-md-12"><label class="form-label">عنوان</label><input type="text" name="title" id="modal_title" class="form-control" required></div>
<div class="col-md-12"><label class="form-label">اینباند متصل (ID یا all)</label><input type="text" name="target_inbounds" id="modal_inbounds" class="form-control" required></div>
<div class="col-md-12"><label class="form-label">آدرس URL</label><input type="url" name="url" id="modal_url" class="form-control" required></div>
</div>
<div class="modal-footer">
<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">انصراف</button>
<button type="submit" class="btn primary">ذخیره تغییرات</button>
</div>
</form>
</div></div></div>

<div class="modal fade" id="changeAuthModal" tabindex="-1">
<div class="modal-dialog"><div class="modal-content">
<form action="/aggr-console/change-auth" method="post">
<div class="modal-header"><h5 class="modal-title">تغییر اطلاعات ورود</h5>
<button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body row g-3">
<div class="col-md-12"><label class="form-label">نام کاربری جدید</label><input type="text" name="new_username" class="form-control" required></div>
<div class="col-md-12"><label class="form-label">رمز عبور جدید</label><input type="password" name="new_password" class="form-control" required></div>
</div>
<div class="modal-footer">
<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">انصراف</button>
<button type="submit" class="btn btn-danger">ذخیره</button>
</div>
</form>
</div></div></div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
$(document).ready(function() {
	$('.jalali-datepicker').persianDatepicker({
		format: 'YYYY/MM/DD',
		autoClose: true,
		initialValue: false
	});
});
function openEditModal(id, title, url, inbounds) {
	document.getElementById('modal_link_id').value = id;
	document.getElementById('modal_title').value = title;
	document.getElementById('modal_url').value = url;
	document.getElementById('modal_inbounds').value = inbounds;
	var myModal = new bootstrap.Modal(document.getElementById('editModal'));
	myModal.show();
}
</script>
</body>
</html>`

var tmpl = template.Must(template.New("console").Parse(consoleTmpl))

func renderConsole(w http.ResponseWriter, username string) {
	rows, _ := db.Query("SELECT id, title, url, COALESCE(target_inbounds,'all'), COALESCE(is_active,1), COALESCE(last_updated,'-') FROM main_links ORDER BY id DESC")
	byGroup := map[string][]LinkRow{}
	if rows != nil {
		for rows.Next() {
			var l LinkRow
			var active int
			rows.Scan(&l.ID, &l.Title, &l.URL, &l.Inbounds, &active, &l.Updated)
			l.Active = active != 0
			byGroup[l.Inbounds] = append(byGroup[l.Inbounds], l)
		}
		rows.Close()
	}
	var groupKeys []string
	for k := range byGroup {
		groupKeys = append(groupKeys, k)
	}
	sort.Slice(groupKeys, func(i, j int) bool {
		if groupKeys[i] == "all" {
			return true
		}
		if groupKeys[j] == "all" {
			return false
		}
		return groupKeys[i] < groupKeys[j]
	})
	unitLabel := "اینباند"
	if strings.EqualFold(PANEL_TYPE, "pasarguard") {
		unitLabel = "روز"
	}
	var groups []LinkGroup
	for _, k := range groupKeys {
		label := unitLabel + " شماره " + k
		if strings.EqualFold(k, "all") {
			label = "عمومی (همه‌ی " + unitLabel + "‌ها)"
		}
		groups = append(groups, LinkGroup{Label: label, Links: byGroup[k]})
	}

	srows, _ := db.Query("SELECT id, category_name, target_inbound, COALESCE(valid_from,''), COALESCE(valid_to,'') FROM category_schedules ORDER BY id DESC")
	var scheds []SchedRow
	if srows != nil {
		for srows.Next() {
			var s SchedRow
			srows.Scan(&s.ID, &s.Category, &s.Inbound, &s.ValidFrom, &s.ValidTo)
			scheds = append(scheds, s)
		}
		srows.Close()
	}

	isPG := strings.EqualFold(PANEL_TYPE, "pasarguard")
	panelLabel := "x-ui"
	var pgGroups []pgGroupSimple
	var categories []string
	var dayOptions []int
	if isPG {
		panelLabel = "PasarGuard"
		pgGroups = getPasarGuardGroups()
		for d := 1; d <= 31; d++ {
			dayOptions = append(dayOptions, d)
		}
	} else {
		categories = getBotCategories()
	}

	data := ConsoleData{
		Username:     username,
		Groups:       groups,
		Scheds:       scheds,
		Categories:   categories,
		IsPasarGuard: isPG,
		PGGroups:     pgGroups,
		PanelLabel:   panelLabel,
		DayOptions:   dayOptions,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func checkCSRF(r *http.Request) bool {
	host := r.Host
	if host == "" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		return strings.Contains(o, host)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return strings.Contains(ref, host)
	}
	return false
}

func handleConsole(w http.ResponseWriter, r *http.Request) {
	username, ok := basicAuthUser(w, r)
	if !ok {
		return
	}

	if r.Method == "POST" && !checkCSRF(r) {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return
	}

	switch {
	case r.Method == "POST" && r.URL.Path == "/aggr-console/add":
		title := r.FormValue("title")
		urls := r.FormValue("urls")
		inbounds := r.FormValue("target_inbounds")
		lines := strings.Split(urls, "\n")
		nowStr := time.Now().Format("2006-01-02 15:04")
		for idx, u := range lines {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			itemTitle := title
			if len(lines) > 1 {
				itemTitle = fmt.Sprintf("%s #%d", title, idx+1)
			}
			db.Exec("INSERT INTO main_links (title, url, target_inbounds, is_active, last_updated) VALUES (?, ?, ?, 1, ?)", itemTitle, u, inbounds, nowStr)
		}
		go fetchAndCache()
		http.Redirect(w, r, "/aggr-console", http.StatusSeeOther)

	case r.Method == "POST" && r.URL.Path == "/aggr-console/edit":
		id := r.FormValue("link_id")
		title := r.FormValue("title")
		urlVal := r.FormValue("url")
		inbounds := r.FormValue("target_inbounds")
		nowStr := time.Now().Format("2006-01-02 15:04")
		db.Exec("UPDATE main_links SET title=?, url=?, target_inbounds=?, last_updated=? WHERE id=?", title, urlVal, inbounds, nowStr, id)
		go fetchAndCache()
		http.Redirect(w, r, "/aggr-console", http.StatusSeeOther)

	case r.Method == "POST" && r.URL.Path == "/aggr-console/change-auth":
		newUser := strings.TrimSpace(r.FormValue("new_username"))
		newPass := strings.TrimSpace(r.FormValue("new_password"))
		if newUser == "" || newPass == "" {
			http.Error(w, "نام کاربری و رمز عبور نمی‌توانند خالی باشند", http.StatusBadRequest)
			return
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "خطا در پردازش رمز عبور", http.StatusInternalServerError)
			return
		}
		tx, err := db.Begin()
		if err != nil {
			http.Error(w, "خطا در دیتابیس", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec("DELETE FROM admin_users"); err != nil {
			tx.Rollback()
			http.Error(w, "خطا در دیتابیس", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec("INSERT INTO admin_users (username, password) VALUES (?, ?)", newUser, string(hashed)); err != nil {
			tx.Rollback()
			http.Error(w, "خطا در دیتابیس", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(); err != nil {
			http.Error(w, "خطا در دیتابیس", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/aggr-console", http.StatusSeeOther)

	case r.Method == "POST" && r.URL.Path == "/aggr-console/sched/add":
		cat := r.FormValue("category_name")
		inb := r.FormValue("target_inbound")
		vFromJalali := r.FormValue("valid_from")
		vToJalali := r.FormValue("valid_to")
		db.Exec("INSERT INTO category_schedules (category_name, target_inbound, valid_from, valid_to) VALUES (?, ?, ?, ?)", cat, inb, vFromJalali, vToJalali)
		go syncBotInbound()
		http.Redirect(w, r, "/aggr-console", http.StatusSeeOther)

	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/aggr-console/sched/delete/"):
		id := strings.TrimPrefix(r.URL.Path, "/aggr-console/sched/delete/")
		db.Exec("DELETE FROM category_schedules WHERE id = ?", id)
		http.Redirect(w, r, "/aggr-console", http.StatusSeeOther)

	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/aggr-console/toggle/"):
		id := strings.TrimPrefix(r.URL.Path, "/aggr-console/toggle/")
		db.Exec("UPDATE main_links SET is_active = NOT COALESCE(is_active,1) WHERE id = ?", id)
		go fetchAndCache()
		http.Redirect(w, r, "/aggr-console", http.StatusSeeOther)

	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/aggr-console/delete/"):
		id := strings.TrimPrefix(r.URL.Path, "/aggr-console/delete/")
		db.Exec("DELETE FROM main_links WHERE id = ?", id)
		go fetchAndCache()
		http.Redirect(w, r, "/aggr-console", http.StatusSeeOther)

	default:
		renderConsole(w, username)
	}
}

func injectExtraIntoSanaeiHTML(htmlStr string, extraConfigs []string) string {
	if len(extraConfigs) == 0 {
		return htmlStr
	}

	markerJSON := `"links":[`
	if idx := strings.Index(htmlStr, markerJSON); idx != -1 {
		insertPos := idx + len(markerJSON)
		var quoted []string
		for _, c := range extraConfigs {
			b, err := json.Marshal(c)
			if err == nil {
				quoted = append(quoted, string(b))
			}
		}
		formattedExtra := strings.Join(quoted, ",")
		if insertPos < len(htmlStr) && htmlStr[insertPos] != ']' {
			formattedExtra += ","
		}
		return htmlStr[:insertPos] + formattedExtra + htmlStr[insertPos:]
	}

	markerB64 := `id="raw-configs" style="display:none;">`
	if idx := strings.Index(htmlStr, markerB64); idx != -1 {
		insertPos := idx + len(markerB64)
		extraB64 := base64.StdEncoding.EncodeToString([]byte(strings.Join(extraConfigs, "\n")))
		return htmlStr[:insertPos] + extraB64 + "\n" + htmlStr[insertPos:]
	}

	return htmlStr
}

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
}

// 📌 Pipeline: x-ui Sub Handler
func handleSub(w http.ResponseWriter, r *http.Request, subID string) {
	setNoCacheHeaders(w)
	if subID == "" {
		http.NotFound(w, r)
		return
	}

	cfg := getXUIConfig()
	sanaeiURL := fmt.Sprintf("https://127.0.0.1:%s%s%s", cfg.Port, cfg.Path, subID)
	req, _ := http.NewRequest("GET", sanaeiURL, nil)

	wantsHTML := strings.Contains(r.Header.Get("Accept"), "text/html") || r.URL.Query().Get("html") == "1"

	for k, v := range r.Header {
		if strings.ToLower(k) == "accept-encoding" {
			continue
		}
		req.Header[k] = v
	}
	req.Header.Set("Accept-Encoding", "identity")
	
	if !wantsHTML {
		req.Header.Set("Accept", "text/plain, application/octet-stream;q=0.9, */*;q=0.1")
		req.Header.Set("User-Agent", "Go-Sub-Aggregator/1.0")
	}

	if cfg.Domain != "" {
		req.Host = cfg.Domain
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	debugSubscriptionResponse("x-ui", r, resp, bodyBytes)

	if resp.StatusCode != 200 {
		w.WriteHeader(resp.StatusCode)
		w.Write(bodyBytes)
		return
	}

	userInboundID := getUserInboundID(subID)
	extraConfigs := getCachedConfigsForInbound(userInboundID)

	ct := resp.Header.Get("Content-Type")
	isHTML := looksLikeHTMLResponse(bodyBytes, ct)

	if isHTML {
		if ct == "" {
			ct = "text/html; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(injectExtraIntoSanaeiHTML(string(bodyBytes), extraConfigs)))
		return
	}

	payloadText, wasBase64 := decodeSubscriptionPayload(string(bodyBytes))
	
	var configs []string
	if payloadText != "" {
		configs = strings.Split(payloadText, "\n")
	}
	configs = append(configs, extraConfigs...)
	
	finalPayload := normalizeSubscriptionText(strings.Join(configs, "\n"))
	
	copySubscriptionHeaders(w.Header(), resp.Header)
	
	if wasBase64 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(resp.StatusCode)
		encodedFinal := base64.StdEncoding.EncodeToString([]byte(finalPayload))
		w.Write([]byte(encodedFinal))
	} else {
		if ct == "" {
			ct = "text/plain; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(finalPayload))
	}
}

func masterHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/aggr-console" || strings.HasPrefix(r.URL.Path, "/aggr-console/") {
		handleConsole(w, r)
		return
	}

	if strings.EqualFold(PANEL_TYPE, "pasarguard") {
		pgPath := normalizeURIPath(PASARGUARD_SUB_PATH)
		if strings.HasPrefix(r.URL.Path, pgPath) {
			token := strings.TrimPrefix(r.URL.Path, pgPath)
			handleSubPasarGuard(w, r, token)
			return
		}
		http.NotFound(w, r)
		return
	}

	cfg := getXUIConfig()
	if strings.HasPrefix(r.URL.Path, cfg.Path) {
		subID := strings.TrimPrefix(r.URL.Path, cfg.Path)
		handleSub(w, r, subID)
		return
	}

	http.NotFound(w, r)
}

func cliResetAdminPassword() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: sub_aggregator_go_bin reset-admin-password <username> <new_password>")
		os.Exit(1)
	}
	username := os.Args[2]
	newPass := os.Args[3]

	if err := os.MkdirAll(filepath.Dir(DB_PATH), 0755); err != nil {
		fmt.Println("Failed to create DB directory:", err)
		os.Exit(1)
	}
	localDB, err := sql.Open("sqlite3", DB_PATH+"?_journal_mode=WAL")
	if err != nil {
		fmt.Println("Failed to open database:", err)
		os.Exit(1)
	}
	defer localDB.Close()

	localDB.Exec(`CREATE TABLE IF NOT EXISTS admin_users (username TEXT PRIMARY KEY, password TEXT)`)

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Failed to hash password:", err)
		os.Exit(1)
	}

	localDB.Exec("DELETE FROM admin_users")
	if _, err := localDB.Exec("INSERT INTO admin_users (username, password) VALUES (?, ?)", username, string(hashed)); err != nil {
		fmt.Println("Failed to write new password:", err)
		os.Exit(1)
	}

	fmt.Printf("OK: admin password for '%s' has been reset.\n", username)
	fmt.Println("If the service is running, no restart is needed — the change applies immediately.")
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "reset-admin-password":
			cliResetAdminPassword()
			return
		case "version":
			fmt.Println("sub-aggregator (build from source)")
			return
		}
	}

	initDB()
	initMySQLDB()

	PANEL_TYPE = detectPanelType()

	if strings.EqualFold(PANEL_TYPE, "pasarguard") {
		log.Printf("🧩 حالت پنل: PasarGuard (Port=%s Path=%s Scheme=%s)", PASARGUARD_PORT, normalizeURIPath(PASARGUARD_SUB_PATH), PASARGUARD_SCHEME)
	} else {
		log.Printf("🧩 حالت پنل: x-ui")
		initXUIDB()
	}

	fetchIntervalMin := 30
	if v := os.Getenv("SUB_AGG_FETCH_INTERVAL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			fetchIntervalMin = n
		}
	}
	log.Printf("⏱️  فاصله‌ی به‌روزرسانی خودکار کش کانفیگ‌ها: هر %d دقیقه", fetchIntervalMin)
	go func() {
		for {
			fetchAndCache()
			syncBotInbound()
			time.Sleep(time.Duration(fetchIntervalMin) * time.Minute)
		}
	}()

	if !strings.EqualFold(PANEL_TYPE, "pasarguard") {
		loadXUIRuntimeConfig()
		go func() {
			for {
				time.Sleep(2 * time.Minute)
				loadXUIRuntimeConfig()
			}
		}()
	}

	http.HandleFunc("/", masterHandler)

	socketPath := envOrDefault("SUB_AGG_SOCKET_PATH", "/run/sub_aggregator/aggregator.sock")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		log.Fatalf("ساخت پوشه‌ی سوکت (%s) ناموفق بود: %v", filepath.Dir(socketPath), err)
	}
	_ = os.Remove(socketPath) 

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("گوش دادن روی Unix Socket (%s) ناموفق بود: %v", socketPath, err)
	}
	
	if grp, err := user.LookupGroup("www-data"); err == nil {
		if gid, err2 := strconv.Atoi(grp.Gid); err2 == nil {
			if err3 := os.Chown(socketPath, -1, gid); err3 == nil {
				os.Chmod(socketPath, 0660)
			} else {
				log.Printf("⚠️  تغییر مالکیت گروه سوکت ناموفق بود، fallback به 0666: %v", err3)
				os.Chmod(socketPath, 0666)
			}
		} else {
			os.Chmod(socketPath, 0666)
		}
	} else {
		log.Printf("⚠️  گروه www-data پیدا نشد؛ مجوز سوکت روی 0666 باقی می‌ماند")
		os.Chmod(socketPath, 0666)
	}

	log.Printf("🚀 Go Sub-Aggregator از طریق Unix Socket در حال اجراست: %s", socketPath)
	log.Printf("   (بدون استفاده از پورت TCP — هرگز با اینباندهای x-ui یا هر سرویس دیگری تداخل پیدا نمی‌کند)")
	log.Fatal(http.Serve(listener, nil))
}