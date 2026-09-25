package main

import (
	"bytes"
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
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

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

	// 📌 پیکربندی Rate Limiter سراسری برای تماس‌های upstream به PasarGuard
	// (طبق همان الگوی envOrDefault موجود در پروژه)
	PASARGUARD_UPSTREAM_RATE_PER_SEC = envOrDefault("PASARGUARD_UPSTREAM_RATE_PER_SEC", "20")
	PASARGUARD_UPSTREAM_BURST        = envOrDefault("PASARGUARD_UPSTREAM_BURST", "40")

	// 📌 Rate Limiter و Semaphore مجزا برای مسیر داغ /sub (تا با
	// /info مصرف توکن مشترک را دوبرابر نکند؛ هر درخواست واقعی کاربر
	// می‌تواند هم /sub و هم /info را صدا بزند).
	PASARGUARD_SUB_RATE_PER_SEC   = envOrDefault("PASARGUARD_SUB_RATE_PER_SEC", "50")
	PASARGUARD_SUB_BURST          = envOrDefault("PASARGUARD_SUB_BURST", "100")
	PASARGUARD_SUB_MAX_CONCURRENT = envOrDefault("PASARGUARD_SUB_MAX_CONCURRENT", "100")

	// 📌 سقف اتصالات هم‌زمان SQLite (جلوگیری از باز شدن کانکشن نامحدود زیر بار)
	SUB_AGG_DB_MAX_OPEN_CONNS = envOrDefault("SUB_AGG_DB_MAX_OPEN_CONNS", "8")

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

	// اتصال به دیتابیس با فعال‌سازی امکانات Performance ابری و WAL Mode
	db, err = sql.Open(
		"sqlite3",
		DB_PATH+
			"?_journal_mode=WAL"+
			"&_synchronous=NORMAL"+
			"&_busy_timeout=5000"+
			"&_temp_store=MEMORY",
	)

	if err != nil {
		log.Fatalf("Failed to open SQLite DB: %v", err)
	}

	// 📌 سقف اتصالات هم‌زمان — بدون این، زیر بار سنگین database/sql می‌تواند
	// کانکشن‌های نامحدودی به یک فایل SQLite باز کند. WAL چند Reader هم‌زمان
	// را اجازه می‌دهد، پس عدد خیلی کوچک بی‌مورد است؛ ولی باید محدود باشد.
	maxConns := parseInt(SUB_AGG_DB_MAX_OPEN_CONNS, 8)
	if maxConns <= 0 {
		maxConns = 8
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)

	// ============================================================
	// SQLite Performance / Concurrency PRAGMA
	// ============================================================
	pragmaQueries := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA temp_store=MEMORY;`,
	}

	for _, pragma := range pragmaQueries {
		if _, err := db.Exec(pragma); err != nil {
			log.Printf("[SQLite] PRAGMA failed: %s -> %v", pragma, err)
		}
	}

	queries := []string{
		// ---- جداول اصلی سیستم شما ----
		`CREATE TABLE IF NOT EXISTS main_links (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT,
			url TEXT,
			target_inbounds TEXT DEFAULT 'all',
			is_active INTEGER DEFAULT 1,
			last_updated TEXT DEFAULT '-',
			pool_name TEXT NOT NULL DEFAULT '',
			rotation_hours INTEGER NOT NULL DEFAULT 0
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
			link_id INTEGER DEFAULT 0,
			inbound_id TEXT,
			raw_config TEXT
		);`,

		// ---- جداول اختصاصی سیستم فایروال ----
		`CREATE TABLE IF NOT EXISTS firewall_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`INSERT OR IGNORE INTO firewall_settings (key, value) VALUES 
			('firewall_enabled', '1'),
			('suspicion_threshold', '3'),
			('max_devices_per_token', '5'),
			('reset_window_hours', '24'),
			('gc_interval_hours', '6'),
			('inactive_retention_days', '30'),
			('warning_fake_config', ''),
			('block_fake_config', '');`,
		`CREATE TABLE IF NOT EXISTS ip_tracking_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			os_type TEXT NOT NULL,
			first_seen INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ip_tracking_token_seen ON ip_tracking_logs(token, first_seen);`,
		`CREATE INDEX IF NOT EXISTS idx_ip_tracking_first_seen ON ip_tracking_logs(first_seen);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_device ON ip_tracking_logs(token, ip_address, os_type);`,
		`CREATE TABLE IF NOT EXISTS token_status (
			token TEXT PRIMARY KEY,
			is_suspicious INTEGER NOT NULL DEFAULT 0,
			admin_warn_mode INTEGER NOT NULL DEFAULT 0,
			admin_burn_mode INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE INDEX IF NOT EXISTS idx_token_status_token ON token_status(token);`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			log.Printf("DB Init Table Error: %v", err)
		}
	}

	// 🛠️ BUG FIX & SAFE MIGRATION: Use int and ALTER TABLE to avoid losing any schema/data
	var linkIdCount int
	err = db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('cached_configs') WHERE name='link_id'").Scan(&linkIdCount)
	if err == nil && linkIdCount == 0 {
		log.Printf("[DBMigration] ساختار انبار قدیمی است. در حال بروزرسانی جدول کش به روش امن (ALTER TABLE)...")
		_, err = db.Exec("ALTER TABLE cached_configs ADD COLUMN link_id INTEGER DEFAULT 0")
		if err != nil {
			log.Printf("[DBMigration] ارور در اضافه کردن ستون: %v", err)
		} else {
			log.Printf("[DBMigration] ستون link_id با موفقیت به انبار اضافه شد.")
		}
	}

	migrateMainLinksPoolingSchema()
	migrateTokenStatusSchema()
	migrateIPTrackingLogsSchema()
	seedOrMigrateAdminPassword()
}

func migrateMainLinksPoolingSchema() {
	rows, err := db.Query("PRAGMA table_info(main_links)")
	if err != nil {
		log.Printf("[DBMigration] خواندن schema جدول main_links ناموفق بود: %v", err)
		return
	}
	defer rows.Close()

	existing := make(map[string]bool)
	for rows.Next() {
		var (
			cid      int
			name     string
			colType  string
			notNull  int
			defaultV sql.NullString
			primary  int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &primary); err != nil {
			log.Printf("[DBMigration] خواندن ستون main_links ناموفق بود: %v", err)
			return
		}
		existing[name] = true
	}

	migrations := []struct {
		name string
		stmt string
	}{
		{
			name: "pool_name",
			stmt: "ALTER TABLE main_links ADD COLUMN pool_name TEXT NOT NULL DEFAULT ''",
		},
		{
			name: "rotation_hours",
			stmt: "ALTER TABLE main_links ADD COLUMN rotation_hours INTEGER NOT NULL DEFAULT 0",
		},
	}

	for _, m := range migrations {
		if existing[m.name] {
			continue
		}
		if _, err := db.Exec(m.stmt); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
				continue
			}
			log.Printf("[DBMigration] افزودن ستون %s ناموفق بود: %v", m.name, err)
			continue
		}
		log.Printf("[DBMigration] ستون %s با موفقیت اضافه شد.", m.name)
	}
}

func migrateTokenStatusSchema() {
	rows, err := db.Query("PRAGMA table_info(token_status)")
	if err != nil {
		log.Printf("[DBMigration] خواندن schema جدول token_status ناموفق بود: %v", err)
		return
	}
	defer rows.Close()

	existing := make(map[string]bool)
	for rows.Next() {
		var (
			cid      int
			name     string
			colType  string
			notNull  int
			defaultV sql.NullString
			primary  int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &primary); err != nil {
			log.Printf("[DBMigration] خواندن ستون token_status ناموفق بود: %v", err)
			return
		}
		existing[name] = true
	}

	migrations := []struct {
		name string
		stmt string
	}{
		{
			name: "username",
			stmt: "ALTER TABLE token_status ADD COLUMN username TEXT DEFAULT ''",
		},
		{
			name: "last_active",
			stmt: "ALTER TABLE token_status ADD COLUMN last_active INTEGER DEFAULT 0",
		},
	}

	for _, m := range migrations {
		if existing[m.name] {
			continue
		}
		if _, err := db.Exec(m.stmt); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
				continue
			}
			log.Printf("[DBMigration] افزودن ستون %s به token_status ناموفق بود: %v", m.name, err)
			continue
		}
		log.Printf("[DBMigration] ستون %s با موفقیت به token_status اضافه شد.", m.name)
	}
}

func migrateIPTrackingLogsSchema() {
	rows, err := db.Query("PRAGMA table_info(ip_tracking_logs)")
	if err != nil {
		log.Printf("[DBMigration] خواندن schema جدول ip_tracking_logs ناموفق بود: %v", err)
		return
	}
	defer rows.Close()

	existing := make(map[string]bool)
	for rows.Next() {
		var (
			cid      int
			name     string
			colType  string
			notNull  int
			defaultV sql.NullString
			primary  int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &primary); err != nil {
			log.Printf("[DBMigration] خواندن ستون ip_tracking_logs ناموفق بود: %v", err)
			return
		}
		existing[name] = true
	}

	if existing["client_app"] {
		// 📌 ستون از قبل موجود است (نصب قبلی که این migration را قبلاً
		// با موفقیت اجرا کرده) — پرچم را true می‌کنیم.
		clientAppColumnAvailable.Store(true)
		return
	}

	if _, err := db.Exec("ALTER TABLE ip_tracking_logs ADD COLUMN client_app TEXT DEFAULT ''"); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			clientAppColumnAvailable.Store(true)
			return
		}
		// 📌 مهم: اگر ALTER ناموفق بود (و علتش duplicate column نبود)،
		// پرچم روی false می‌ماند — هیچ کوئری‌ای که به client_app ارجاع
		// می‌دهد اجرا نخواهد شد. منطق اصلی فایروال کاملاً دست‌نخورده و
		// فعال باقی می‌ماند؛ فقط قابلیت تله‌متری client_app غیرفعال است.
		log.Printf("[DBMigration] افزودن ستون client_app به ip_tracking_logs ناموفق بود: %v", err)
		return
	}
	log.Printf("[DBMigration] ستون client_app با موفقیت به ip_tracking_logs اضافه شد.")
	clientAppColumnAvailable.Store(true)
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

// ============================================================
// 📦 Sing-box JSON Compatibility Layer
// پنل‌های PasarGuard/Marzban بر اساس User-Agent واقعی کلاینت (که این
// aggregator عیناً به upstream پاس می‌دهد) فرمت پاسخ ساب‌اسکریپشن را
// تغییر می‌دهند: برای sing-box و کلاینت‌های خانواده‌ی SagerNet
// (SFA/SFI/SFD/SFM)، به‌جای لیست خط‌به‌خط لینک، یک کانفیگ کامل JSON
// native سینگ‌باکس برمی‌گردانند. این بخش تشخیص می‌دهد پاسخ JSON است یا
// نه و در صورت نیاز extraConfigs/هشدار ادمین/بلاک فایروال را به‌صورت
// outbound معتبر سینگ‌باکس داخل همان JSON تزریق می‌کند.
//
// کاملاً مستقل از منطق امنیتی/فایروال (firewall.go دست‌نخورده می‌ماند)
// و مستقل از هر تابع تله‌متری کلاینت (detectClientApp)؛ صرفاً یک لایه‌ی
// HTTP response-formatting در همین فایل است.
// ============================================================

func looksLikeJSONResponse(body []byte, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "application/json") {
		return true
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return false
	}
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return false
	}
	return json.Valid(body)
}

// decodeBase64Flexible چند حالت رایج base64 (استاندارد/URL-safe،
// با/بدون padding) را امتحان می‌کند — برای payload های vmess و ss لازم است.
func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	variants := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range variants {
		decoded, err := enc.DecodeString(s)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// toInt مقادیر عددی JSON را که ممکن است float64, string, یا int باشند
// به int تبدیل می‌کند. توجه: این تابع دیگر برای اعتبارسنجی پورت یا هر
// فیلد عددی حیاتی استفاده نمی‌شود (به‌جای آن toPortStrictFromJSON و
// toNonNegativeIntStrict که رد کردن مقادیر نامعتبر را تضمین می‌کنند)،
// و صرفاً برای سازگاری باقی نگه داشته شده است.
func toInt(v interface{}) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

// toBoolParam یک parser سخت‌گیرانه برای مقادیر بولی query-string است.
// دقیقاً همین ۶ مقدار (case-sensitive، بدون نرمال‌سازی case) پذیرفته
// می‌شوند: "1", "true", "yes" → true و "0", "false", "no" → false.
// هر مقدار دیگری (شامل "TRUE"، "False"، "wat"، "2"، رشته‌ی خالی و...) خطا
// برمی‌گرداند — دیگر هیچ مقداری silently به false coerce نمی‌شود. فقط
// فضای خالی ابتدا/انتهای رشته trim می‌شود؛ case دست‌نخورده می‌ماند.
func toBoolParam(v string) (bool, error) {
	v = strings.TrimSpace(v)
	switch v {
	case "1", "true", "yes":
		return true, nil
	case "0", "false", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %q", v)
	}
}

// validatePortRange فقط پورت‌های معتبر TCP/UDP (۱ تا ۶۵۵۳۵) را می‌پذیرد.
func validatePortRange(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port out of range: %d", port)
	}
	return nil
}

// parseStrictPort یک رشته‌ی پورت را دقیقاً به یک عدد صحیح در بازه‌ی
// معتبر تبدیل می‌کند. هیچ کوارس‌سازی/truncateی مجاز نیست: فقط ارقام
// ۰-۹ پذیرفته می‌شوند (بدون علامت، بدون فاصله، بدون اعشار).
func parseStrictPort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty port")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-numeric port: %q", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if err := validatePortRange(n); err != nil {
		return 0, err
	}
	return n, nil
}

// toPortStrictFromJSON یک مقدار JSON (float64 یا string، طبق رفتار
// encoding/json روی اعداد) را به‌عنوان پورت اعتبارسنجی می‌کند. مقادیر
// اعشاری غیرصحیح (مثل 443.5) یا خارج از بازه رد می‌شوند، نه truncate.
func toPortStrictFromJSON(v interface{}) (int, error) {
	switch t := v.(type) {
	case float64:
		if t != math.Trunc(t) {
			return 0, fmt.Errorf("port is not an integer: %v", t)
		}
		n := int(t)
		if err := validatePortRange(n); err != nil {
			return 0, err
		}
		return n, nil
	case string:
		return parseStrictPort(t)
	default:
		return 0, fmt.Errorf("invalid port type: %T", v)
	}
}

// toNonNegativeIntStrict برای فیلدهای عددی غیر-پورت (مثل vmess aid)
// استفاده می‌شود: باید عدد صحیح و غیرمنفی باشد.
func toNonNegativeIntStrict(v interface{}) (int, error) {
	switch t := v.(type) {
	case float64:
		if t != math.Trunc(t) {
			return 0, fmt.Errorf("not an integer: %v", t)
		}
		n := int(t)
		if n < 0 {
			return 0, fmt.Errorf("negative value: %d", n)
		}
		return n, nil
	case string:
		s := strings.TrimSpace(t)
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid non-negative integer: %q", t)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("invalid type: %T", v)
	}
}

func splitHostPortFromURL(u *url.URL) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	portStr := u.Port()
	if portStr == "" {
		return "", 0, fmt.Errorf("empty port")
	}
	port, err := parseStrictPort(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// hostPortWithDefault مشابه splitHostPortFromURL است، با این تفاوت که
// اگر پورت در URI ذکر نشده باشد، از defaultPort استفاده می‌کند (برای
// hysteria2 که طبق پروتکل پورت پیش‌فرض ۴۴۳ دارد). اگر پورت ذکر شده
// باشد، همچنان دقیقاً و سخت‌گیرانه اعتبارسنجی می‌شود.
func hostPortWithDefault(u *url.URL, defaultPort int) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	portStr := u.Port()
	if portStr == "" {
		if err := validatePortRange(defaultPort); err != nil {
			return "", 0, fmt.Errorf("empty port and no valid default")
		}
		return host, defaultPort, nil
	}
	port, err := parseStrictPort(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// buildTransportObject بر اساس پارامتر type (ws/grpc/http/h2) شیء
// transport مشترک بین vless/vmess/trojan را می‌سازد. سخت‌گیرانه است:
// اگر type صریحاً چیزی غیر از موارد پشتیبانی‌شده (یا خالی/tcp/raw که
// معادل عدم وجود transport است) باشد، خطا برمی‌گرداند — هرگز به‌صورت
// خاموش نادیده گرفته نمی‌شود.
func buildTransportObject(q url.Values) (map[string]interface{}, error) {
	netType := strings.ToLower(strings.TrimSpace(q.Get("type")))
	switch netType {
	case "":
		return nil, nil
	case "tcp", "raw":
		// معادل صریح عدم وجود transport (پیش‌فرض سینگ‌باکس)؛ خطا نیست.
		return nil, nil
	case "ws":
		t := map[string]interface{}{"type": "ws"}
		if path := q.Get("path"); path != "" {
			t["path"] = path
		}
		if host := q.Get("host"); host != "" {
			t["headers"] = map[string]interface{}{"Host": host}
		}
		return t, nil
	case "grpc":
		t := map[string]interface{}{"type": "grpc"}
		if sn := q.Get("serviceName"); sn != "" {
			t["service_name"] = sn
		}
		return t, nil
	case "http", "h2":
		t := map[string]interface{}{"type": "http"}
		if path := q.Get("path"); path != "" {
			t["path"] = path
		}
		if host := q.Get("host"); host != "" {
			t["host"] = []string{host}
		}
		return t, nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %q", netType)
	}
}

// uuidPattern فرمت canonical استاندارد UUID را اعتبارسنجی می‌کند
// (8-4-4-4-12 hexadecimal، بدون محدودیت روی version/variant bits) —
// طبق درخواست صریح، هر UUID معتبر پذیرفته می‌شود، نه فقط v4.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isValidUUID(s string) bool {
	return uuidPattern.MatchString(strings.TrimSpace(s))
}

// isValidRealityShortID طبق schema فعلی سینگ‌باکس، short_id باید یک رشته‌ی
// hexadecimal با طول زوج و حداکثر ۱۶ کاراکتر باشد (رشته‌ی خالی هم مجاز
// است و یعنی short_id مشخص نشده). هر مقدار دیگری (طول فرد، کاراکتر
// غیر-hex، یا طول بیش از ۱۶) رد می‌شود.
func isValidRealityShortID(s string) bool {
	if len(s) > 16 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isValidRealityPublicKey کلید عمومی X25519 مورد استفاده در Reality را
// اعتبارسنجی می‌کند: باید base64 معتبر (استاندارد یا URL-safe، با یا
// بدون padding) باشد که دقیقاً به ۳۲ بایت decode شود.
func isValidRealityPublicKey(s string) bool {
	decoded, err := decodeBase64Flexible(s)
	if err != nil {
		return false
	}
	return len(decoded) == 32
}

// vlessAllowedFlows: مقادیر مجاز فیلد "flow" طبق schema فعلی VLESS در
// سینگ‌باکس (خانواده‌ی XTLS-Vision). "" یعنی flow صریحاً مشخص نشده.
// هر مقدار دیگری صراحتاً رد می‌شود، نه silently پذیرفته.
var vlessAllowedFlows = map[string]bool{
	"":                 true,
	"xtls-rprx-vision": true,
}

func buildVlessOutbound(rawURI, tag string) (map[string]interface{}, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, "vless") {
		return nil, fmt.Errorf("not a vless uri")
	}
	uuid := u.User.Username()
	if !isValidUUID(uuid) {
		return nil, fmt.Errorf("vless: invalid uuid: %q", uuid)
	}
	host, port, err := splitHostPortFromURL(u)
	if err != nil {
		return nil, fmt.Errorf("vless: %v", err)
	}
	// 📌 Query Parsing سخت‌گیرانه: u.Query() خطای percent-encoding نامعتبر
	// را silently نادیده می‌گیرد. اینجا صراحتاً با ParseQuery چک می‌شود.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("vless: invalid query parameters: %v", err)
	}

	out := map[string]interface{}{
		"type":        "vless",
		"tag":         tag,
		"server":      host,
		"server_port": port,
		"uuid":        uuid,
	}
	flow := q.Get("flow")
	if !vlessAllowedFlows[flow] {
		return nil, fmt.Errorf("vless: unsupported flow: %q", flow)
	}
	if flow != "" {
		out["flow"] = flow
	}

	security := strings.ToLower(strings.TrimSpace(q.Get("security")))
	switch security {
	case "", "none":
		// بدون tls
	case "tls", "reality":
		tlsObj := map[string]interface{}{"enabled": true}
		if sni := q.Get("sni"); sni != "" {
			tlsObj["server_name"] = sni
		}
		// 📌 پارامتر بولی allowInsecure فقط وقتی صراحتاً در query موجود
		// باشد بررسی می‌شود (غیاب آن یعنی false ساکت، بدون خطا)؛ اما اگر
		// موجود باشد و مقدارش با toBoolParam سخت‌گیرانه مطابقت نداشته
		// باشد (مثلاً "TRUE" یا "wat")، کل تبدیل خطا می‌دهد.
		if raw, present := q["allowInsecure"]; present {
			insecureVal, err := toBoolParam(raw[0])
			if err != nil {
				return nil, fmt.Errorf("vless: allowInsecure: %v", err)
			}
			if insecureVal {
				tlsObj["insecure"] = true
			}
		}
		if fp := q.Get("fp"); fp != "" {
			tlsObj["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
		}
		if alpnRaw := q.Get("alpn"); alpnRaw != "" {
			var alpnList []string
			for _, a := range strings.Split(alpnRaw, ",") {
				a = strings.TrimSpace(a)
				if a != "" {
					alpnList = append(alpnList, a)
				}
			}
			if len(alpnList) > 0 {
				tlsObj["alpn"] = alpnList
			}
		}
		if security == "reality" {
			// 📌 Reality بدون pbk (public_key) یا sid (short_id) یک outbound
			// ساختاراً ناقص و غیرقابل‌اتصال تولید می‌کند — طبق الزام صریح،
			// این دو فیلد برای reality اجباری‌اند، نه اختیاری.
			pbk := q.Get("pbk")
			if pbk == "" {
				return nil, fmt.Errorf("vless: reality requires non-empty pbk (public_key)")
			}
			if !isValidRealityPublicKey(pbk) {
				return nil, fmt.Errorf("vless: reality: invalid public_key (pbk): %q", pbk)
			}
			sid, hasSid := q["sid"]
			if !hasSid || len(sid) == 0 {
				return nil, fmt.Errorf("vless: reality requires sid (short_id) parameter")
			}
			if !isValidRealityShortID(sid[0]) {
				return nil, fmt.Errorf("vless: reality: invalid short_id (sid): %q", sid[0])
			}
			reality := map[string]interface{}{
				"enabled":    true,
				"public_key": pbk,
				"short_id":   sid[0],
			}
			tlsObj["reality"] = reality
		}
		out["tls"] = tlsObj
	default:
		return nil, fmt.Errorf("vless: unsupported security type: %q", security)
	}

	transport, err := buildTransportObject(q)
	if err != nil {
		return nil, fmt.Errorf("vless: %v", err)
	}
	if transport != nil {
		out["transport"] = transport
	}

	return out, nil
}

// vmessSecurityMethods مقادیر مجاز فیلد "scy" در vmess JSON. هر مقدار
// دیگری صراحتاً خطا برمی‌گرداند (نه silently ignore).
var vmessSecurityMethods = map[string]bool{
	"":                       true,
	"auto":                   true,
	"aes-128-gcm":            true,
	"chacha20-poly1305":      true,
	"chacha20-ietf-poly1305": true,
	"none":                   true,
	"zero":                   true,
}

// vmessStringField یک فیلد اختیاری VMess را می‌خواند: اگر کلید اصلاً وجود
// نداشته باشد رشته‌ی خالی برمی‌گرداند (بدون خطا)؛ اگر وجود دارد ولی نوعش
// string نیست، خطا برمی‌گرداند — هرگز silently به مقدار پیش‌فرض تبدیل نمی‌شود.
func vmessStringField(m map[string]interface{}, key string) (string, error) {
	raw, exists := m[key]
	if !exists {
		return "", nil
	}
	s, isStr := raw.(string)
	if !isStr {
		return "", fmt.Errorf("field %q has wrong type: %T (expected string)", key, raw)
	}
	return s, nil
}

func buildVmessOutbound(rawURI, tag string) (map[string]interface{}, error) {
	if !strings.HasPrefix(strings.ToLower(rawURI), "vmess://") {
		return nil, fmt.Errorf("not a vmess uri")
	}
	payload := rawURI[len("vmess://"):]
	if idx := strings.Index(payload, "#"); idx != -1 {
		payload = payload[:idx]
	}
	decoded, err := decodeBase64Flexible(payload)
	if err != nil {
		return nil, fmt.Errorf("vmess: base64 decode failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(decoded, &m); err != nil {
		return nil, fmt.Errorf("vmess: json decode failed: %v", err)
	}

	// 📌 هر فیلد رشته‌ای صراحتاً با type assertion چک می‌شود؛ اگر کلید با
	// نوع اشتباه وجود داشته باشد (مثلاً "scy": 123)، کل تبدیل خطا می‌دهد —
	// هرگز silently به مقدار پیش‌فرض/خالی reinterpret نمی‌شود.
	host, err := vmessStringField(m, "add")
	if err != nil {
		return nil, fmt.Errorf("vmess: add: %v", err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("vmess: empty host")
	}

	idVal, err := vmessStringField(m, "id")
	if err != nil {
		return nil, fmt.Errorf("vmess: id: %v", err)
	}
	idVal = strings.TrimSpace(idVal)
	if !isValidUUID(idVal) {
		return nil, fmt.Errorf("vmess: invalid uuid/id: %q", idVal)
	}

	portVal, err := toPortStrictFromJSON(m["port"])
	if err != nil {
		return nil, fmt.Errorf("vmess: invalid port: %v", err)
	}

	security, err := vmessStringField(m, "scy")
	if err != nil {
		return nil, fmt.Errorf("vmess: scy: %v", err)
	}
	security = strings.ToLower(strings.TrimSpace(security))
	if !vmessSecurityMethods[security] {
		return nil, fmt.Errorf("vmess: unsupported security method: %q", security)
	}
	if security == "" {
		security = "auto"
	}

	out := map[string]interface{}{
		"type":        "vmess",
		"tag":         tag,
		"server":      host,
		"server_port": portVal,
		"uuid":        idVal,
		"security":    security,
	}
	if aidRaw, ok := m["aid"]; ok {
		aidVal, err := toNonNegativeIntStrict(aidRaw)
		if err != nil {
			return nil, fmt.Errorf("vmess: invalid aid: %v", err)
		}
		out["alter_id"] = aidVal
	}

	netType, err := vmessStringField(m, "net")
	if err != nil {
		return nil, fmt.Errorf("vmess: net: %v", err)
	}
	path, err := vmessStringField(m, "path")
	if err != nil {
		return nil, fmt.Errorf("vmess: path: %v", err)
	}
	hostHeader, err := vmessStringField(m, "host")
	if err != nil {
		return nil, fmt.Errorf("vmess: host: %v", err)
	}
	q := url.Values{}
	if netType != "" {
		q.Set("type", netType)
	}
	// 📌 معنای فیلد "path" وابسته به نوع transport است: برای ws/http همان
	// مسیر HTTP است، ولی برای net=grpc طبق قرارداد رایج vmess JSON (که
	// generatorهای اشتراک از آن استفاده می‌کنند)، "path" در واقع
	// serviceName گرفته‌شده‌است، نه یک path واقعی. نگاشت اشتباه به "path"
	// باعث می‌شد buildTransportObject این مقدار را برای grpc اصلاً
	// نبیند (چون grpc دنبال کلید serviceName می‌گردد) و serviceName
	// silently گم شود.
	if path != "" {
		if strings.EqualFold(netType, "grpc") {
			q.Set("serviceName", path)
		} else {
			q.Set("path", path)
		}
	}
	if hostHeader != "" {
		q.Set("host", hostHeader)
	}
	transport, err := buildTransportObject(q)
	if err != nil {
		return nil, fmt.Errorf("vmess: %v", err)
	}
	if transport != nil {
		out["transport"] = transport
	}

	tlsVal, err := vmessStringField(m, "tls")
	if err != nil {
		return nil, fmt.Errorf("vmess: tls: %v", err)
	}
	tlsVal = strings.ToLower(strings.TrimSpace(tlsVal))
	switch tlsVal {
	case "", "none":
		// بدون tls
	case "tls":
		sni, err := vmessStringField(m, "sni")
		if err != nil {
			return nil, fmt.Errorf("vmess: sni: %v", err)
		}
		tlsObj := map[string]interface{}{"enabled": true}
		if sni != "" {
			tlsObj["server_name"] = sni
		}
		// 📌 fp (uTLS fingerprint) و alpn: فیلدهای رایج در vmess JSON که
		// generatorهای اشتراک اضافه می‌کنند. طبق الزام صریح، این پارامترها
		// باید faithfully به schema سینگ‌باکس نگاشت شوند، نه silently drop.
		fp, err := vmessStringField(m, "fp")
		if err != nil {
			return nil, fmt.Errorf("vmess: fp: %v", err)
		}
		if fp != "" {
			tlsObj["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fp}
		}
		alpnRaw, err := vmessStringField(m, "alpn")
		if err != nil {
			return nil, fmt.Errorf("vmess: alpn: %v", err)
		}
		if alpnRaw != "" {
			var alpnList []string
			for _, a := range strings.Split(alpnRaw, ",") {
				a = strings.TrimSpace(a)
				if a != "" {
					alpnList = append(alpnList, a)
				}
			}
			if len(alpnList) > 0 {
				tlsObj["alpn"] = alpnList
			}
		}
		// 📌 insecure: بعضی generatorها این را به‌صورت رشته‌ی بولی ("0"/"1"/
		// "true"/"false"/...) در vmess JSON قرار می‌دهند. اگر کلید وجود
		// نداشته باشد صرفاً نادیده گرفته می‌شود؛ اگر وجود داشته باشد باید
		// دقیقاً با toBoolParam سخت‌گیرانه معتبر باشد وگرنه خطا.
		insecureRaw, err := vmessStringField(m, "insecure")
		if err != nil {
			return nil, fmt.Errorf("vmess: insecure: %v", err)
		}
		if insecureRaw != "" {
			insecureVal, err := toBoolParam(insecureRaw)
			if err != nil {
				return nil, fmt.Errorf("vmess: insecure: %v", err)
			}
			if insecureVal {
				tlsObj["insecure"] = true
			}
		}
		out["tls"] = tlsObj
	default:
		return nil, fmt.Errorf("vmess: unsupported tls value: %q", tlsVal)
	}

	return out, nil
}

func buildTrojanOutbound(rawURI, tag string) (map[string]interface{}, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, "trojan") {
		return nil, fmt.Errorf("not a trojan uri")
	}
	password := u.User.Username()
	if password == "" {
		return nil, fmt.Errorf("trojan: empty password")
	}
	host, port, err := splitHostPortFromURL(u)
	if err != nil {
		return nil, fmt.Errorf("trojan: %v", err)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("trojan: invalid query parameters: %v", err)
	}

	security := strings.ToLower(strings.TrimSpace(q.Get("security")))
	if security != "" && security != "tls" {
		return nil, fmt.Errorf("trojan: unsupported security type: %q", security)
	}

	tlsObj := map[string]interface{}{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tlsObj["server_name"] = sni
	}
	if raw, present := q["allowInsecure"]; present {
		insecureVal, err := toBoolParam(raw[0])
		if err != nil {
			return nil, fmt.Errorf("trojan: allowInsecure: %v", err)
		}
		if insecureVal {
			tlsObj["insecure"] = true
		}
	}

	out := map[string]interface{}{
		"type":        "trojan",
		"tag":         tag,
		"server":      host,
		"server_port": port,
		"password":    password,
		"tls":         tlsObj,
	}
	transport, err := buildTransportObject(q)
	if err != nil {
		return nil, fmt.Errorf("trojan: %v", err)
	}
	if transport != nil {
		out["transport"] = transport
	}
	return out, nil
}

// buildShadowsocksOutbound هر دو فرمت رایج ss:// را دقیق و بدون
// اشتباه‌گرفتن با یکدیگر پشتیبانی می‌کند:
//   - SIP002: ss://BASE64(method:password)@host:port  یا
//     ss://method:password@host:port (userinfo خام، با percent-encoding
//     احتمالی روی پسورد)
//   - Legacy تمام-base64: ss://BASE64(method:password@host:port)
//
// تشخیص بین این دو صرفاً بر اساس وجود یک '@' واقعی (literal) در متن خام
// بعد از ss:// است؛ اگر '@' وجود دارد یعنی فرم مدرن (SIP002)، وگرنه
// فرم قدیمی. پارامتر plugin پشتیبانی نمی‌شود و باعث خطا (نه drop خاموش)
// می‌شود تا معنای واقعی نود هرگز به‌اشتباه نمایش داده نشود.
// ssAllowedMethods: روش‌های رمزنگاری پشتیبانی‌شده توسط shadowsocks outbound
// سینگ‌باکس (schema فعلی پروژه). هر روش دیگری صراحتاً رد می‌شود.
var ssAllowedMethods = map[string]bool{
	"aes-128-gcm":                   true,
	"aes-192-gcm":                   true,
	"aes-256-gcm":                   true,
	"chacha20-ietf-poly1305":        true,
	"xchacha20-ietf-poly1305":       true,
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
	"none":                          true,
}

func buildShadowsocksOutbound(rawURI, tag string) (map[string]interface{}, error) {
	if !strings.HasPrefix(strings.ToLower(rawURI), "ss://") {
		return nil, fmt.Errorf("not a shadowsocks uri")
	}
	rest := rawURI[len("ss://"):]

	if idx := strings.Index(rest, "#"); idx != -1 {
		rest = rest[:idx]
	}

	var rawQuery string
	if idx := strings.Index(rest, "?"); idx != -1 {
		rawQuery = rest[idx+1:]
		rest = rest[:idx]
	}

	if rawQuery != "" {
		q, err := url.ParseQuery(rawQuery)
		if err != nil {
			return nil, fmt.Errorf("ss: invalid query parameters: %v", err)
		}
		if plugin := q.Get("plugin"); plugin != "" {
			return nil, fmt.Errorf("ss: unsupported plugin parameter: %q", plugin)
		}
	}

	var method, password, hostPort string

	// 📌 تشخیص فرمت (SIP002 مدرن در برابر legacy تمام-base64) صرفاً بر
	// اساس وجود یک '@' literal در رشته‌ی خام (قبل از هر گونه trim) است —
	// دقیقاً همان‌طور که قبلاً بود. تفاوت کلیدی: دیگر هیچ‌جا قبل از تشخیص
	// فرمت و decode، بر اساس '/' truncate نمی‌کنیم؛ '/' یک کاراکتر معتبر
	// Base64 است و می‌تواند داخل payload رمزنگاری‌شده (چه userinfo در فرم
	// مدرن، چه کل payload در فرم legacy) ظاهر شود.
	if atIdx := strings.LastIndex(rest, "@"); atIdx != -1 {
		// فرم مدرن SIP002: userinfo قبل از @، host:port[/path] بعد از آن.
		// trailing path (اگر باشد) فقط از قسمت بعد از @ حذف می‌شود — نه از
		// userinfo، چون '/' آنجا می‌تواند بخشی معتبر از base64 باشد.
		userInfoRaw := rest[:atIdx]
		afterAt := rest[atIdx+1:]
		if idx := strings.Index(afterAt, "/"); idx != -1 {
			afterAt = afterAt[:idx]
		}
		hostPort = afterAt
		if hostPort == "" {
			return nil, fmt.Errorf("ss: empty host:port")
		}

		userInfoDecoded, decErr := url.QueryUnescape(userInfoRaw)
		if decErr != nil {
			// 📌 خطای percent-encoding نامعتبر در userinfo دیگر silently
			// نادیده گرفته نمی‌شود (قبلاً fallback به رشته‌ی خام می‌کرد) —
			// طبق الزام صریح، این یک شکست atomic است.
			return nil, fmt.Errorf("ss: invalid percent-encoding in userinfo: %v", decErr)
		}

		if strings.Contains(userInfoDecoded, ":") {
			// userinfo خام "method:password" (بدون base64)
			parts := strings.SplitN(userInfoDecoded, ":", 2)
			method, password = parts[0], parts[1]
		} else {
			// userinfo به‌صورت base64(method:password) طبق SIP002
			decoded, err := decodeBase64Flexible(userInfoRaw)
			if err != nil {
				return nil, fmt.Errorf("ss: base64 userinfo decode failed: %v", err)
			}
			mp := strings.SplitN(string(decoded), ":", 2)
			if len(mp) != 2 {
				return nil, fmt.Errorf("ss: invalid decoded method:password")
			}
			method, password = mp[0], mp[1]
		}
	} else {
		// فرم قدیمی: کل payload (شامل هر '/' احتمالی) به‌صورت کامل و
		// بدون هیچ truncation قبل از decode پردازش می‌شود.
		decoded, err := decodeBase64Flexible(rest)
		if err != nil {
			return nil, fmt.Errorf("ss: legacy base64 decode failed: %v", err)
		}
		full := string(decoded)
		atIdx2 := strings.LastIndex(full, "@")
		if atIdx2 == -1 {
			return nil, fmt.Errorf("ss: legacy payload missing '@'")
		}
		methodPass := full[:atIdx2]
		hostPort = full[atIdx2+1:]
		mp := strings.SplitN(methodPass, ":", 2)
		if len(mp) != 2 {
			return nil, fmt.Errorf("ss: invalid legacy method:password")
		}
		method, password = mp[0], mp[1]
	}

	if method == "" || password == "" {
		return nil, fmt.Errorf("ss: empty method or password")
	}
	if !ssAllowedMethods[strings.ToLower(method)] {
		return nil, fmt.Errorf("ss: unsupported method: %q", method)
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("ss: invalid host:port: %v", err)
	}
	if host == "" {
		return nil, fmt.Errorf("ss: empty host")
	}
	port, err := parseStrictPort(portStr)
	if err != nil {
		return nil, fmt.Errorf("ss: %v", err)
	}

	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      host,
		"server_port": port,
		"method":      strings.ToLower(method),
		"password":    password,
	}, nil
}

// buildHysteria2Outbound کل بخش auth قبل از @ را (نه فقط username) به‌عنوان
// password در نظر می‌گیرد — اگر userinfo شامل ":" باشد (مثلاً user:pass)،
// هر دو بخش با ":" دوباره ترکیب می‌شوند تا هیچ بخشی از اطلاعات احراز هویت
// گم نشود. اگر پورت در URI ذکر نشده باشد، از پورت پیش‌فرض پروتکل (۴۴۳)
// استفاده می‌شود؛ اگر ذکر شده باشد، باز هم سخت‌گیرانه اعتبارسنجی می‌شود.
func buildHysteria2Outbound(rawURI, tag string) (map[string]interface{}, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, "hysteria2") && !strings.EqualFold(u.Scheme, "hy2") {
		return nil, fmt.Errorf("not a hysteria2 uri")
	}
	if u.User == nil {
		return nil, fmt.Errorf("hysteria2: missing auth")
	}
	auth := u.User.Username()
	if pass, hasPass := u.User.Password(); hasPass {
		auth = auth + ":" + pass
	}
	if auth == "" {
		return nil, fmt.Errorf("hysteria2: empty auth")
	}

	host, port, err := hostPortWithDefault(u, 443)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %v", err)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: invalid query parameters: %v", err)
	}

	tlsObj := map[string]interface{}{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tlsObj["server_name"] = sni
	}
	if insecureRaw := q.Get("insecure"); insecureRaw != "" {
		insecureVal, err := toBoolParam(insecureRaw)
		if err != nil {
			return nil, fmt.Errorf("hysteria2: insecure: %v", err)
		}
		tlsObj["insecure"] = insecureVal
	}
	if alpnRaw := q.Get("alpn"); alpnRaw != "" {
		var alpnList []string
		for _, a := range strings.Split(alpnRaw, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				alpnList = append(alpnList, a)
			}
		}
		if len(alpnList) > 0 {
			tlsObj["alpn"] = alpnList
		}
	}
	// 📌 pinSHA256 (پین کردن گواهی سرور بر اساس هش SHA256): schema فعلی
	// سینگ‌باکس (option/tls.go) هیچ فیلد معادلی برای این نوع pinning در
	// tls خروجی ندارد (فقط server_name/insecure/alpn/certificate/ech/
	// reality/utls پشتیبانی می‌شوند). طبق الزام صریح «map کامل یا خطا»،
	// چون معادل صادقانه‌ای وجود ندارد، این پارامتر با خطا رد می‌شود —
	// silently نادیده گرفته نمی‌شود.
	if pinRaw := q.Get("pinSHA256"); pinRaw != "" {
		return nil, fmt.Errorf("hysteria2: pinSHA256 is not representable in the target sing-box schema")
	}
	// 📌 ech: طبق قرارداد رایج لینک‌های hysteria2 (v2rayN/NekoBox و مشابه)،
	// مقدار پارامتر ech حاوی ECHConfigList به‌صورت base64 است. این مستقیماً
	// به فیلد رسمی سینگ‌باکس tls.ech.config نگاشت می‌شود
	// (option/tls.go: OutboundECHOptions.Config). اگر decode base64 آن
	// ناموفق باشد، خطا برمی‌گردد نه silently ignore.
	if echRaw := q.Get("ech"); echRaw != "" {
		if _, err := decodeBase64Flexible(echRaw); err != nil {
			return nil, fmt.Errorf("hysteria2: invalid ech config (expected base64 ECHConfigList): %v", err)
		}
		tlsObj["ech"] = map[string]interface{}{
			"enabled": true,
			"config":  []string{echRaw},
		}
	}

	out := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         tag,
		"server":      host,
		"server_port": port,
		"password":    auth,
		"tls":         tlsObj,
	}

	// 📌 obfs: طبق schema فعلی هدف (سینگ‌باکس Hysteria2)، تنها نوع obfs
	// پشتیبانی‌شده "salamander" است. هر مقدار دیگری صراحتاً رد می‌شود —
	// نه silently به یک outbound با obfs غیرمعتبر تبدیل می‌شود.
	obfsType := q.Get("obfs")
	obfsPass := q.Get("obfs-password")
	switch obfsType {
	case "":
		if obfsPass != "" {
			// obfs-password بدون obfs یک پارامتر معنادار است که silently
			// drop نمی‌شود.
			return nil, fmt.Errorf("hysteria2: obfs-password supplied without obfs type")
		}
	case "salamander":
		obfs := map[string]interface{}{"type": obfsType}
		if obfsPass != "" {
			obfs["password"] = obfsPass
		}
		out["obfs"] = obfs
	default:
		return nil, fmt.Errorf("hysteria2: unsupported obfs type: %q", obfsType)
	}

	return out, nil
}

// buildWireGuardOutbound
// ⚠️ فرمت wireguard:// استاندارد رسمی ندارد؛ این رایج‌ترین قرارداد
// اکوسیستم است. اگر لینک‌های واقعی پروژه فرمت دیگری دارند، ممکن است
// نیاز به تنظیم جزئی بعد از دیدن یک نمونه‌ی واقعی باشد.
// wgValidateAddress یک آیتم مقدار address (CIDR مثل "10.0.0.2/32" یا
// "fd00::2/128") را اعتبارسنجی می‌کند. طبق schema فعلی هدف سینگ‌باکس،
// local_address باید CIDR notation معتبر باشد؛ یک IP بدون prefix هم
// پذیرفته می‌شود (سینگ‌باکس خودش /32 یا /128 را فرض می‌کند).
func wgValidateAddress(a string) (string, error) {
	a = strings.TrimSpace(a)
	if a == "" {
		return "", fmt.Errorf("empty address entry")
	}
	if strings.Contains(a, "/") {
		if _, _, err := net.ParseCIDR(a); err != nil {
			return "", fmt.Errorf("invalid CIDR %q: %v", a, err)
		}
		return a, nil
	}
	if net.ParseIP(a) == nil {
		return "", fmt.Errorf("invalid IP address %q", a)
	}
	return a, nil
}

func buildWireGuardOutbound(rawURI, tag string) (map[string]interface{}, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, "wireguard") && !strings.EqualFold(u.Scheme, "wg") {
		return nil, fmt.Errorf("not a wireguard uri")
	}
	privateKey := u.User.Username()
	if privateKey == "" {
		return nil, fmt.Errorf("wireguard: missing private key")
	}
	host, port, err := splitHostPortFromURL(u)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %v", err)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("wireguard: invalid query parameters: %v", err)
	}

	publicKey := q.Get("publickey")
	if publicKey == "" {
		return nil, fmt.Errorf("wireguard: missing publickey")
	}

	out := map[string]interface{}{
		"type":            "wireguard",
		"tag":             tag,
		"server":          host,
		"server_port":     port,
		"private_key":     privateKey,
		"peer_public_key": publicKey,
	}

	if psk := q.Get("presharedkey"); psk != "" {
		out["pre_shared_key"] = psk
	}

	// 📌 address/local_address اجباری است: طبق schema هدف، بدون آن یک
	// WireGuard outbound ساختاراً ناقص و غیرقابل‌اتصال تولید می‌شود.
	// مقدار نامعتبر/غیرقابل‌پردازش (نه فقط خالی) باید خطا ایجاد کند.
	addr := q.Get("address")
	if addr == "" {
		return nil, fmt.Errorf("wireguard: missing address")
	}
	var addrs []string
	for _, a := range strings.Split(addr, ",") {
		validated, err := wgValidateAddress(a)
		if err != nil {
			return nil, fmt.Errorf("wireguard: address: %v", err)
		}
		addrs = append(addrs, validated)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("wireguard: address resolved to no valid entries")
	}
	out["local_address"] = addrs

	if mtuRaw := q.Get("mtu"); mtuRaw != "" {
		n, err := strconv.Atoi(strings.TrimSpace(mtuRaw))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("wireguard: invalid mtu: %q", mtuRaw)
		}
		out["mtu"] = n
	}
	if reserved := q.Get("reserved"); reserved != "" {
		var nums []int
		for _, rv := range strings.Split(reserved, ",") {
			rv = strings.TrimSpace(rv)
			if rv == "" {
				return nil, fmt.Errorf("wireguard: invalid reserved entry (empty)")
			}
			n, err := strconv.Atoi(rv)
			if err != nil || n < 0 || n > 255 {
				return nil, fmt.Errorf("wireguard: invalid reserved entry: %q", rv)
			}
			nums = append(nums, n)
		}
		out["reserved"] = nums
	}

	return out, nil
}

// convertURIToSingBoxOutbound دیسپچر مرکزی: بر اساس scheme، یکی از توابع
// build* را صدا می‌زند. هر خطای برگشتی از این تابع باعث fail-safe کامل
// عملیات تزریق می‌شود (نه skip آن یک آیتم).
func convertURIToSingBoxOutbound(uri, tag string) (map[string]interface{}, error) {
	lower := strings.ToLower(strings.TrimSpace(uri))
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return buildVlessOutbound(uri, tag)
	case strings.HasPrefix(lower, "vmess://"):
		return buildVmessOutbound(uri, tag)
	case strings.HasPrefix(lower, "trojan://"):
		return buildTrojanOutbound(uri, tag)
	case strings.HasPrefix(lower, "ss://"):
		return buildShadowsocksOutbound(uri, tag)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		return buildHysteria2Outbound(uri, tag)
	case strings.HasPrefix(lower, "wireguard://"), strings.HasPrefix(lower, "wg://"):
		return buildWireGuardOutbound(uri, tag)
	default:
		return nil, fmt.Errorf("unsupported scheme for sing-box conversion: %q", uri)
	}
}

// injectExtraIntoSingBoxJSON تنها محل تزریق extraConfigs/هشدار داخل
// JSON نیتیو سینگ‌باکس است.
//
// طراحی دو-فازی سخت‌گیرانه:
//   - فاز ۱ (Validate): parse کامل JSON، اعتبارسنجی ساختار root/outbounds،
//     اعتبارسنجی تمام outboundهای موجود (type assertion صریح روی هر عضو،
//     نه صرفاً روی گروه هدف)، جمع‌آوری تگ‌های موجود، اعتبارسنجی و تبدیل
//     تمام URIهای اضافی/هشدار، تولید تگ‌های جدید، و تشخیص هر نوع تصادم
//     تگ. هیچ mutation‌ای در این فاز رخ نمی‌دهد.
//   - فاز ۲ (Mutate): فقط بعد از موفقیت کامل فاز ۱، آرایه‌ی outbounds
//     نهایی ساخته و گروه selector/urltest هدف (در صورت وجود) به‌روزرسانی
//     می‌شود.
//
// Atomic Fail-Safe: هر شکستی در هر مرحله (parse، ساختار نامعتبر، assertion
// ناموفق، URI نامعتبر، تصادم تگ، marshal ناموفق، یا panic) دقیقاً باعث
// (nil, false) می‌شود — هرگز یک JSON نیمه‌تغییریافته برگردانده نمی‌شود و
// هرگز یک URI نامعتبر به‌سادگی skip نمی‌شود؛ کل عملیات fail-closed است.
// collectOutboundTagReferences تمام فیلدهای شناخته‌شده‌ی سینگ‌باکس که به یک
// تگ outbound ارجاع می‌دهند را به‌صورت بازگشتی در سراسر سند JSON جمع‌آوری
// می‌کند: "outbound" (مثلاً route.rules[*].outbound)، "detour" (در هر
// outbound یا endpoint که می‌تواند از طریق outbound دیگری تونل بزند)،
// "final" (مثلاً route.final)، "default" (پیش‌فرض یک گروه selector)، و هر
// آرایه‌ی رشته‌ای تحت کلید "outbounds" (اعضای selector/urltest). طبق الزام
// صریح، شناخت صریح فیلدهای سینگ‌باکس ترجیح دارد بر تفسیر هر رشته‌ی
// دلخواه به‌عنوان reference؛ اگر schema های آینده فیلد جدیدی اضافه کنند،
// باید اینجا اضافه شود. اگر مقدار هر یک از این کلیدهای شناخته‌شده از نوع
// موردانتظار (رشته، یا آرایه‌ی رشته) نباشد، false برمی‌گرداند تا فراخواننده
// عملیات را کاملاً fail-closed کند.
func collectOutboundTagReferences(node interface{}, refs map[string]bool) bool {
	switch v := node.(type) {
	case map[string]interface{}:
		for key, val := range v {
			switch key {
			case "outbound", "detour", "final", "default":
				s, isStr := val.(string)
				if !isStr {
					return false
				}
				if s != "" {
					refs[s] = true
				}
			case "outbounds":
				if arr, isArr := val.([]interface{}); isArr {
					for _, item := range arr {
						// اعضای رشته‌ای (selector/urltest) reference هستند؛ اعضای
						// object (خودِ آرایه‌ی اصلی outbounds در ریشه‌ی سند) اینجا
						// نادیده گرفته می‌شوند چون توسط حلقه‌ی type-safe موجود در
						// فاز ۱ جداگانه و سخت‌گیرانه پردازش می‌شوند.
						if s, isStr := item.(string); isStr && s != "" {
							refs[s] = true
						}
					}
				}
			}
			if !collectOutboundTagReferences(val, refs) {
				return false
			}
		}
	case []interface{}:
		for _, item := range v {
			if !collectOutboundTagReferences(item, refs) {
				return false
			}
		}
	}
	return true
}

func injectExtraIntoSingBoxJSON(body []byte, extraConfigs []string, warningCfg string) (out []byte, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[SingBoxInject] recovered panic: %v", r)
			out, ok = nil, false
		}
	}()

	// ============================================================
	// فاز ۱: Validate — بدون هیچ mutation روی root/outbounds اصلی
	// ============================================================

	// 📌 اعتبارسنجی UTF-8 قبل از هرگونه parse: بدنه‌ای که ساختار JSON آن
	// syntactically معتبر ولی حاوی بایت‌های نامعتبر UTF-8 باشد هم رد می‌شود.
	if !utf8.Valid(body) {
		return nil, false
	}

	// 📌 json.Decoder با UseNumber به‌جای json.Unmarshal مستقیم روی
	// interface{}: اعداد صحیح بزرگ در float64 دقت خود را از دست می‌دهند
	// (مثلاً یک عدد ۱۹ رقمی)؛ با UseNumber این مقادیر به‌صورت json.Number
	// (رشته‌ی خام) نگه داشته می‌شوند و در marshal نهایی بدون تغییر بازتولید
	// می‌شوند. dec.More() صراحتاً هر داده‌ی اضافی بعد از سند JSON کامل را رد
	// می‌کند — دقیقاً همان سخت‌گیری‌ای که json.Unmarshal به‌صورت ضمنی داشت.
	var root map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, false
	}
	if dec.More() {
		return nil, false
	}

	rawOutbounds, exists := root["outbounds"]
	if !exists {
		return nil, false
	}
	outbounds, isArray := rawOutbounds.([]interface{})
	if !isArray {
		return nil, false
	}

	existingTags := make(map[string]bool, len(outbounds))
	// reservedRefs: هر رشته‌ای که در هر جای سند به‌عنوان reference به یک تگ
	// outbound شناخته می‌شود — چه داخل آرایه‌ی outbounds هر selector/urltest،
	// چه route.final، چه route.rules[*].outbound، چه هر فیلد detour/default
	// در هر نقطه از سند. این‌ها هم باید مثل تگ‌های واقعی از تصادم با تگ‌های
	// تولیدی محافظت شوند، حتی اگر خودشان یک outbound موجود نباشند.
	reservedRefs := make(map[string]bool)
	if !collectOutboundTagReferences(root, reservedRefs) {
		// یک فیلد شناخته‌شده‌ی reference (outbound/detour/final/default) با
		// نوع غیرمنتظره (نه رشته) پیدا شد — نمی‌توانیم اثبات کنیم ادامه‌ی
		// عملیات ایمن است؛ کل عملیات fail-closed می‌شود.
		return nil, false
	}
	var targetGroupMap map[string]interface{}
	var targetGroupExistingTags []interface{}

	// 📌 هر outbound از نوع selector/urltest باید مستقل و کامل اعتبارسنجی
	// شود — نه فقط اولین موردی که پیدا می‌شود. یک selector/urltest معیوب
	// در هر نقطه‌ای از آرایه (حتی بعد از یک مورد معتبر) باعث fail-closed
	// کامل می‌شود.
	for _, ob := range outbounds {
		obMap, isMap := ob.(map[string]interface{})
		if !isMap {
			// یک outbound موجود ساختار غیرمنتظره دارد — نمی‌توانیم اثبات کنیم
			// دستکاری آن ایمن است؛ کل عملیات fail-closed می‌شود.
			return nil, false
		}

		if tagRaw, hasTag := obMap["tag"]; hasTag {
			tagStr, isStr := tagRaw.(string)
			if !isStr {
				return nil, false
			}
			existingTags[tagStr] = true
		}

		typeRaw, hasType := obMap["type"]
		if !hasType {
			continue
		}
		typeStr, isStr := typeRaw.(string)
		if !isStr {
			return nil, false
		}
		if typeStr != "selector" && typeStr != "urltest" {
			continue
		}

		groupOutboundsRaw, hasGroupOutbounds := obMap["outbounds"]
		if !hasGroupOutbounds {
			return nil, false
		}
		groupOutbounds, isGroupArray := groupOutboundsRaw.([]interface{})
		if !isGroupArray {
			return nil, false
		}
		for _, gt := range groupOutbounds {
			gtStr, isStr := gt.(string)
			if !isStr {
				return nil, false
			}
			reservedRefs[gtStr] = true
		}

		if targetGroupMap == nil {
			targetGroupMap = obMap
			targetGroupExistingTags = groupOutbounds
		}
	}

	type injectItem struct {
		uri string
		tag string
	}
	var items []injectItem

	warningCfg = strings.TrimSpace(warningCfg)
	if warningCfg != "" {
		items = append(items, injectItem{uri: warningCfg, tag: "agg-warning"})
	}
	extraIdx := 0
	for _, cfg := range extraConfigs {
		cfg = strings.TrimSpace(cfg)
		if cfg == "" {
			continue
		}
		extraIdx++
		items = append(items, injectItem{uri: cfg, tag: fmt.Sprintf("agg-extra-%d", extraIdx)})
	}

	if len(items) == 0 {
		return nil, false
	}

	generatedTagSet := make(map[string]bool, len(items))
	var generatedOutbounds []interface{}
	var generatedTags []string

	for _, item := range items {
		if existingTags[item.tag] || generatedTagSet[item.tag] || reservedRefs[item.tag] {
			// تصادم تگ با کانفیگ موجود کاربر یا یک reference داخل
			// selector/urltest — هرگز rename/overwrite نمی‌کنیم، کل
			// عملیات fail-closed می‌شود.
			return nil, false
		}
		outbound, err := convertURIToSingBoxOutbound(item.uri, item.tag)
		if err != nil {
			// یک URI نامعتبر هرگز باعث skip آن آیتم و ادامه‌ی بقیه نمی‌شود؛
			// طبق الزام Atomic Fail-Safe کل عملیات fail-closed می‌شود.
			log.Printf("[SingBoxInject] تبدیل کانفیگ به outbound ناموفق بود؛ عملیات کاملاً fail-safe شد: %v", err)
			return nil, false
		}
		generatedTagSet[item.tag] = true
		generatedOutbounds = append(generatedOutbounds, outbound)
		generatedTags = append(generatedTags, item.tag)
	}

	// ============================================================
	// فاز ۲: Mutate — فقط بعد از موفقیت کامل تمام اعتبارسنجی‌های فاز ۱
	// ============================================================

	newOutbounds := make([]interface{}, len(outbounds), len(outbounds)+len(generatedOutbounds))
	copy(newOutbounds, outbounds)
	newOutbounds = append(newOutbounds, generatedOutbounds...)
	root["outbounds"] = newOutbounds

	if targetGroupMap != nil {
		newGroupOutbounds := make([]interface{}, len(targetGroupExistingTags), len(targetGroupExistingTags)+len(generatedTags))
		copy(newGroupOutbounds, targetGroupExistingTags)
		for _, tag := range generatedTags {
			newGroupOutbounds = append(newGroupOutbounds, tag)
		}
		targetGroupMap["outbounds"] = newGroupOutbounds
	}

	final, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return final, true
}

// requestWantsJSONFormat کاملاً مستقل از detectClientApp (تله‌متری
// داشبورد ادمین) است — فقط برای تصمیم‌گیری فرمت پاسخ استفاده می‌شود.
func requestWantsJSONFormat(r *http.Request) bool {
	if r == nil {
		return false
	}
	ua := strings.ToLower(strings.TrimSpace(r.Header.Get("User-Agent")))
	if ua == "" {
		return false
	}
	markers := []string{"sing-box", "sfa", "sfi", "sfd", "sfm"}
	for _, m := range markers {
		if strings.Contains(ua, m) {
			return true
		}
	}
	return false
}

// formatBlockResponse رفتار فعلی (text/plain) را برای غیر-JSON دقیقاً
// حفظ می‌کند. برای کلاینت‌های سینگ‌باکس، blockConfig هرگز به‌عنوان یک
// URI پروکسی parse/convert نمی‌شود — همیشه فقط یک outbound "direct"
// ساده تولید می‌شود تا هیچ URI پروکسی/credential واقعی از طریق پیام
// بلاک درز نکند.
func formatBlockResponse(blockConfig string, wantsJSON bool) (contentType string, body []byte) {
	blockConfig = strings.TrimSpace(blockConfig)
	if blockConfig == "" {
		blockConfig = "SUBSCRIPTION_BLOCKED"
	}

	if !wantsJSON {
		return "text/plain; charset=utf-8", []byte(blockConfig)
	}

	// 📌 محافظت نشتی credential: در پاسخ JSON سخت‌گیرانه (کلاینت‌های
	// سینگ‌باکس)، blockConfig هرگز به هیچ شکلی — کامل یا جزئی — در پاسخ
	// نمایش داده نمی‌شود. قبلاً اینجا یک heuristic بر اساس وجود "://"
	// بود که فقط URIهای پروکسی را فیلتر می‌کرد؛ آن heuristic حذف شده،
	// چون blockConfig می‌تواند حاوی UUID/پسورد/توکن حتی بدون "://" هم
	// باشد (مثلاً وقتی کاربر متن آزاد وارد کرده). پاسخ JSON همیشه و
	// بدون قید و شرط دقیقاً همین رشته‌ی ثابت است.
	const jsonBlockTag = "⛔ SUBSCRIPTION_BLOCKED"

	outbound := map[string]interface{}{
		"type": "direct",
		"tag":  jsonBlockTag,
	}
	root := map[string]interface{}{
		"outbounds": []interface{}{outbound},
	}
	final, err := json.Marshal(root)
	if err != nil {
		// 📌 حتی در این مسیر خطای بسیار بعید marshal، هرگز به fallback
		// متنی حاوی blockConfig برنمی‌گردیم — کلاینت درخواست JSON کرده
		// و باید فقط پیام ثابت و بی‌خطر را ببیند، نه یک fallback که
		// می‌تواند secret را افشا کند.
		return "application/json; charset=utf-8", []byte(`{"outbounds":[{"type":"direct","tag":"` + jsonBlockTag + `"}]}`)
	}
	return "application/json; charset=utf-8", final
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

// 📌 Data Ingestion Layer: This acts as a dumb worker. It fetches everything every X minutes without executing rotation math.
var fetchAndCacheRunning atomic.Bool

func fetchAndCache() {
	// 📌 محافظت در برابر اجرای هم‌زمان: fetchAndCache هم توسط تیکر
	// پس‌زمینه و هم دستی (بعد از هر add/edit/toggle/delete در پنل ادمین)
	// صدا زده می‌شود. اگر یک اجرا هنوز در حال واکشی HTTP از upstreamهاست،
	// اجرای جدید به‌جای overlap کردن (که می‌تواند نتیجه‌ی تازه‌تر را با
	// نتیجه‌ی قدیمی‌تر بازنویسی کند) به‌سادگی نادیده گرفته می‌شود؛ ادیت‌های
	// جدید ادمین طبیعتاً در دور بعدی (تیکر یا فراخوانی دستی بعدی) اعمال می‌شوند.
	if !fetchAndCacheRunning.CompareAndSwap(false, true) {
		log.Printf("[CronFetch] یک اجرای قبلی هنوز در حال انجام است؛ این فراخوانی نادیده گرفته شد.")
		return
	}
	defer fetchAndCacheRunning.Store(false)

	type FetchItem struct {
		ID            int
		Title         string
		URL           string
		TargetInbound string
	}

	// ---- فاز ۱: خواندن لیست لینک‌ها — قفل فقط برای همین خواندن کوتاه ----
	dbLock.Lock()
	rows, err := db.Query("SELECT id, title, url, COALESCE(target_inbounds, 'all') FROM main_links WHERE COALESCE(is_active, 1) = 1")
	if err != nil {
		dbLock.Unlock()
		log.Printf("[CronFetch] DB Error: %v", err)
		return
	}
	var linksToFetch []FetchItem
	for rows.Next() {
		var item FetchItem
		if err := rows.Scan(&item.ID, &item.Title, &item.URL, &item.TargetInbound); err == nil {
			linksToFetch = append(linksToFetch, item)
		}
	}
	rows.Close()
	dbLock.Unlock()

	// ---- فاز ۲: واکشی HTTP از تمام لینک‌ها — کاملاً بدون قفل ----
	client := &http.Client{Timeout: 15 * time.Second}

	type ConfigItem struct {
		LinkID    int
		InboundID string
		Raw       string
	}
	var allFetchedConfigs []ConfigItem
	seenHashes := make(map[string]bool)
	successful := 0

	for _, l := range linksToFetch {
		req, reqErr := http.NewRequest("GET", strings.TrimSpace(l.URL), nil)
		if reqErr != nil {
			log.Printf("[CronFetch] URL نامعتبر برای '%s': %v", l.Title, reqErr)
			continue
		}

		// 🛡️ VPN CLIENT SPOOFING: جعل کردن درخواست به عنوان کلاینت V2rayNG برای استخراج کانفیگ خام از پنل‌های هوشمند
		req.Header.Set("User-Agent", "v2rayNG/1.8.12")
		// با عدم ارسال Accept هدرهای اضافی، دقیقاً مشابه رفتار کلاینت واقعی عمل می‌کنیم

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[CronFetch] خطای اتصال به '%s': %v", l.Title, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("[CronFetch] لینک '%s' با کد %d پاسخ داد", l.Title, resp.StatusCode)
			resp.Body.Close()
			continue
		}

		// 📌 محدودسازی حافظه: یک لینک مادر upstream که پاسخ بسیار حجیمی
		// برمی‌گرداند نباید کل حافظه‌ی پروسه را مصرف کند. طبق همان سقف و
		// همان منطق fail-safe در handleSub/handleSubPasarGuard، بدنه‌ی
		// بیش از حد مجاز کاملاً رد می‌شود (نه truncate و ادامه).
		bodyBytes, readErr := readBoundedBody(resp.Body, maxUpstreamSubscriptionBodyBytes)
		resp.Body.Close()
		if readErr != nil {
			log.Printf("[CronFetch] خطای خواندن پاسخ '%s': %v", l.Title, readErr)
			continue
		}

		payloadText, _ := decodeSubscriptionPayload(string(bodyBytes))
		lines := strings.Split(payloadText, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !isValidConfigLine(line) || isInfoOrFakeConfig(line) {
				continue
			}
			// جلوگیری از اختلال هش‌های تکراری با اضافه کردن LinkID به امضای کش
			hashKey := strconv.Itoa(l.ID) + "_" + l.TargetInbound + "_" + getMD5Hash(line)
			if seenHashes[hashKey] {
				continue
			}
			seenHashes[hashKey] = true
			allFetchedConfigs = append(allFetchedConfigs, ConfigItem{LinkID: l.ID, InboundID: l.TargetInbound, Raw: line})
		}
		successful++
	}

	if len(allFetchedConfigs) == 0 && len(linksToFetch) > 0 {
		log.Printf("[CronFetch] هشدار: هیچ کانفیگ معتبری در این دوره واکشی نشد. کش قبلی حفظ می‌شود.")
		return
	}

	// ---- فاز ۳: نوشتن اتمیک در DB — قفل فقط برای همین فاز ----
	dbLock.Lock()
	defer dbLock.Unlock()

	tx, err := db.Begin()
	if err != nil {
		log.Printf("[CronFetch] DB Tx Error: %v", err)
		return
	}

	// 📌 DELETE اکنون داخل همان تراکنش INSERTهاست: یا هر دو با هم commit
	// می‌شوند یا هیچ‌کدام — دیگر پنجره‌ای برای «کش خالی بین DELETE و
	// commit» در صورت کرش پروسه وجود ندارد.
	if _, err := tx.Exec("DELETE FROM cached_configs"); err != nil {
		tx.Rollback()
		log.Printf("[CronFetch] خطا در پاکسازی کش قبلی: %v", err)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO cached_configs (link_id, inbound_id, raw_config) VALUES (?, ?, ?)")
	if err != nil {
		tx.Rollback()
		log.Printf("[CronFetch] Prepare Error: %v", err)
		return
	}

	for _, cfg := range allFetchedConfigs {
		if _, err := stmt.Exec(cfg.LinkID, cfg.InboundID, cfg.Raw); err != nil {
			stmt.Close()
			tx.Rollback()
			log.Printf("[CronFetch] INSERT cached_configs Error: %v", err)
			return
		}
	}
	stmt.Close()

	if err := tx.Commit(); err != nil {
		log.Printf("[CronFetch] DB Commit Error: %v", err)
		return
	}

	log.Printf(
		"[CronFetch] کش به‌روزرسانی شد. %d/%d لینک فعال در انبار ذخیره شدند (%d کانفیگ کل).",
		successful,
		len(linksToFetch),
		len(allFetchedConfigs),
	)
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

// 📌 خواندن مستقیم و لوکال ایمیل/نام‌کاربری از x-ui.db (بدون هیچ تماس شبکه‌ای)
func getXUIUsername(subID string) string {
	if xuiDB == nil {
		return "-"
	}
	var email string
	if err := xuiDB.QueryRow("SELECT email FROM clients WHERE sub_id = ?", subID).Scan(&email); err != nil || email == "" {
		return "-"
	}
	return email
}

// 📌 Data Serving Layer: Evaluates dynamic load balancing on-the-fly when the user requests their configs
func getActiveLinkIDsForTargets(targets []string) []int {
	if len(targets) == 0 {
		return nil
	}

	placeholders := make([]string, len(targets))
	args := make([]interface{}, len(targets))
	for i, t := range targets {
		placeholders[i] = "?"
		args[i] = t
	}
	query := "SELECT id, COALESCE(pool_name, ''), COALESCE(rotation_hours, 0) FROM main_links WHERE COALESCE(is_active, 1) = 1 AND target_inbounds IN (" + strings.Join(placeholders, ",") + ")"

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("[DataServing] DB Query Error: %v", err)
		return nil
	}
	defer rows.Close()

	type linkMeta struct {
		ID           int
		RotationMins int
	}
	var standalone []int
	pools := make(map[string][]linkMeta)

	for rows.Next() {
		var id, rot int
		var pool string
		if err := rows.Scan(&id, &pool, &rot); err == nil {
			if pool == "" {
				standalone = append(standalone, id)
			} else {
				if rot <= 0 {
					rot = 1 // Fallback to 1 minute if user put 0
				}
				pools[pool] = append(pools[pool], linkMeta{ID: id, RotationMins: rot})
			}
		}
	}

	var activeIDs []int
	activeIDs = append(activeIDs, standalone...)

	currentUnixMinute := time.Now().Unix() / 60

	for _, poolLinks := range pools {
		sort.SliceStable(poolLinks, func(i, j int) bool {
			return poolLinks[i].ID < poolLinks[j].ID
		})

		maxRot := 1
		for _, l := range poolLinks {
			if l.RotationMins > maxRot {
				maxRot = l.RotationMins
			}
		}

		windowIndex := (currentUnixMinute / int64(maxRot)) % int64(len(poolLinks))
		selected := poolLinks[int(windowIndex)]
		activeIDs = append(activeIDs, selected.ID)
	}

	return activeIDs
}

func getCachedConfigsForActiveLinks(activeIDs []int) []string {
	if len(activeIDs) == 0 {
		return nil
	}

	placeholders := make([]string, len(activeIDs))
	args := make([]interface{}, len(activeIDs))
	for i, id := range activeIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	query := "SELECT raw_config FROM cached_configs WHERE link_id IN (" + strings.Join(placeholders, ",") + ")"

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("[DataServing] DB Query Error: %v", err)
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

func getCachedConfigsForInbound(inboundID int) []string {
	targets := []string{strconv.Itoa(inboundID), "all"}
	activeIDs := getActiveLinkIDsForTargets(targets)
	return getCachedConfigsForActiveLinks(activeIDs)
}

func getCachedConfigsForGroups(groupIDs []int) []string {
	if len(groupIDs) == 0 {
		return getCachedConfigsForInbound(-1)
	}
	targets := make([]string, 0, len(groupIDs)+1)
	for _, id := range groupIDs {
		targets = append(targets, strconv.Itoa(id))
	}
	targets = append(targets, "all")
	activeIDs := getActiveLinkIDsForTargets(targets)
	return getCachedConfigsForActiveLinks(activeIDs)
}

func getCachedConfigsForDay(day int) []string {
	if day <= 0 {
		return getCachedConfigsForInbound(-1)
	}
	targets := []string{strconv.Itoa(day), "all"}
	activeIDs := getActiveLinkIDsForTargets(targets)
	return getCachedConfigsForActiveLinks(activeIDs)
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

type pasarGuardUserInfo struct {
	GroupIDs  []int  `json:"group_ids"`
	CreatedAt string `json:"created_at"`
	Status    string `json:"status"`
	Username  string `json:"username"`
}

// 📌 کش TTL برای اطلاعات کاربر PasarGuard. از نسخه‌ی قبلی حفظ شده،
// فقط یک فیلد state و persistedValue برای پشتیبانی از مدل چهار-حالته
// (VALID/NO_USERNAME/INVALID_TOKEN/TRANSIENT) اضافه شده — بدون تغییر رفتار
// مسیر اصلی سرو ساب‌اسکریپشن (handleSubPasarGuard).
type cachedUserInfo struct {
	info  *pasarGuardUserInfo
	state pgUserState
	// persistedValue آخرین مقداری است که با موفقیت در DB نوشته شده (یا "" اگر
	// هنوز هیچ‌وقت نوشته نشده)؛ برای جلوگیری از نوشتن تکراری DB به‌ازای
	// نتیجه‌ی یکسان در هر بار تازه‌سازی کش استفاده می‌شود.
	persistedValue string
	expiresAt      time.Time
}

var (
	pgUserInfoCache     = make(map[string]cachedUserInfo)
	pgUserInfoCacheLock sync.RWMutex
)

// تابع واکشی اطلاعات با بررسی کش — امضای بیرونی حفظ شده تا مسیر
// handleSubPasarGuard بدون تغییر باقی بماند. اکنون داخلاً از
// resolvePasarGuardUser (چهار-حالته، پشت Circuit Breaker/Rate Limiter/
// Single-Flight) استفاده می‌کند.
func getPasarGuardUserInfoCached(token string) *pasarGuardUserInfo {
	return resolvePasarGuardUser(token).Info
}

// 📌 خواندن read-only از کش، بدون هیچ فراخوانی شبکه‌ای (برای مسیرهای رندر مثل پنل ادمین)
func getPasarGuardUserInfoIfCached(token string) *pasarGuardUserInfo {
	pgUserInfoCacheLock.RLock()
	defer pgUserInfoCacheLock.RUnlock()
	cached, exists := pgUserInfoCache[token]
	if !exists {
		return nil
	}
	return cached.info
}

// Garbage Collector: پاکسازی رم از دیتاهای قدیمی هر ۳۰ ثانیه
func startUserInfoCacheGC() {
	for {
		time.Sleep(30 * time.Second)
		now := time.Now()

		pgUserInfoCacheLock.Lock()
		for token, cached := range pgUserInfoCache {
			if now.After(cached.expiresAt) {
				delete(pgUserInfoCache, token)
			}
		}
		pgUserInfoCacheLock.Unlock()
	}
}

// fetchPasarGuardUserInfo امضای قبلی را حفظ می‌کند (سازگاری با فراخوانی‌های
// موجود)؛ اکنون فقط یک wrapper نازک روی نسخه‌ی طبقه‌بندی‌شده است.
func fetchPasarGuardUserInfo(token string) *pasarGuardUserInfo {
	_, info := fetchPasarGuardUserInfoClassified(token)
	return info
}

// fetchPasarGuardUserInfoClassified تنها جایی است که واقعاً به شبکه تماس
// می‌گیرد. نتیجه را از طریق classifyPasarGuardOutcome (تعریف‌شده در
// firewall.go) به یکی از چهار حالت صریح تبدیل می‌کند — این تنها محل
// تفسیر خطا/وضعیت HTTP در کل پروژه است.
func fetchPasarGuardUserInfoClassified(token string) (pgUserState, *pasarGuardUserInfo) {
	url := fmt.Sprintf("%s://127.0.0.1:%s%s%s/info", PASARGUARD_SCHEME, PASARGUARD_PORT, PASARGUARD_SUB_PATH, token)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return classifyPasarGuardOutcome(0, err, nil)
	}
	defer resp.Body.Close()

	// 📌 محدودسازی حافظه: پاسخ /info یک آبجکت کوچک است؛ اگر upstream بیش از
	// سقف مجاز پاسخ بدهد، این را یک شکست مبهم upstream در نظر می‌گیریم
	// (نه پردازش یک بدنه‌ی بریده به‌عنوان اطلاعات معتبر کاربر).
	body, bodyErr := readBoundedBody(resp.Body, maxUpstreamAPIBodyBytes)
	if bodyErr != nil {
		return classifyPasarGuardOutcome(resp.StatusCode, nil, nil)
	}
	if resp.StatusCode != 200 {
		return classifyPasarGuardOutcome(resp.StatusCode, nil, nil)
	}
	var info pasarGuardUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		// JSON بدشکل با وجود 200 → یک شکست مبهم upstream است، نه توکن نامعتبر.
		return classifyPasarGuardOutcome(resp.StatusCode, nil, nil)
	}
	return classifyPasarGuardOutcome(resp.StatusCode, nil, &info)
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
// maxUpstreamSubscriptionBodyBytes سقف امن اندازه‌ی بدنه‌ی پاسخ upstream
// (پنل PasarGuard/x-ui) که خوانده می‌شود — جلوگیری از تخصیص حافظه‌ی
// نامحدود در صورت پاسخ upstream غیرمنتظره‌ی بسیار حجیم. اگر پاسخ از این
// سقف فراتر رود، به‌جای تلاش برای JSON-parse یا decode یک سند ناقص/بریده،
// همان مسیر خطای موجود («Subscription upstream error») برگردانده می‌شود.
const maxUpstreamSubscriptionBodyBytes = 10 * 1024 * 1024 // 10 MiB

// maxUpstreamAPIBodyBytes سقف امن برای پاسخ‌های API کوچک‌تر upstream
// (PasarGuard /info، /api/groups/simple، /api/admin/token) — این پاسخ‌ها
// طبق قرارداد باید JSON کوچک باشند؛ هر چیزی فراتر از این سقف مشکوک است و
// به‌جای پردازش یک بدنه‌ی احتمالاً بریده، صریحاً fail می‌شود.
const maxUpstreamAPIBodyBytes = 2 * 1024 * 1024 // 2 MiB

// readBoundedBody یک io.Reader را حداکثر تا maxBytes می‌خواند و اگر بدنه
// از این سقف فراتر رفته باشد (یعنی بایت اضافی +۱ هم موفق به خواندن شود)،
// صریحاً خطا برمی‌گرداند — نه truncate خاموش و ادامه‌ی کار با یک بدنه‌ی
// ناقص.
func readBoundedBody(r io.Reader, maxBytes int64) ([]byte, error) {
	limited, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(limited)) > maxBytes {
		return nil, fmt.Errorf("response body exceeds max allowed size (%d bytes)", maxBytes)
	}
	return limited, nil
}

func handleSubPasarGuard(w http.ResponseWriter, r *http.Request, token string) {
	setNoCacheHeaders(w)
	if token == "" {
		http.NotFound(w, r)
		return
	}

	// ============================================================
	// 🛡️ Firewall Hook
	// MUST run before contacting PasarGuard upstream.
	// ============================================================
	firewallDecision := FirewallCheck(r, token)
	if !firewallDecision.Allow {
		ct, body := formatBlockResponse(firewallDecision.BlockConfig, requestWantsJSONFormat(r))
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	upstreamURL := fmt.Sprintf("%s://127.0.0.1:%s%s%s", PASARGUARD_SCHEME, PASARGUARD_PORT, PASARGUARD_SUB_PATH, token)
	client := &http.Client{Timeout: 8 * time.Second}
	// 📌 خطای NewRequest دیگر نادیده گرفته نمی‌شود: این یک باگ مستقل بود
	// (nil-pointer panic روی حلقه‌ی کپی هدر در ادامه) — کاملاً مجزا از
	// موضوع Circuit Breaker، چون این خط قبل از هر تعاملی با breaker اجرا می‌شود.
	req, err := http.NewRequest("GET", upstreamURL, nil)
	if err != nil {
		log.Printf("[PasarGuard] ساخت درخواست upstream ناموفق بود: %v", err)
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}

	wantsHTML := strings.Contains(r.Header.Get("Accept"), "text/html") || r.URL.Query().Get("html") == "1"

	for k, v := range r.Header {
		if strings.ToLower(k) == "accept-encoding" {
			continue
		}
		req.Header[k] = v
	}
	req.Header.Set("Accept-Encoding", "identity")

	// 🛡️ USER-AGENT PASSTHROUGH & SPOOFING
	clientUA := r.Header.Get("User-Agent")
	if strings.TrimSpace(clientUA) == "" {
		clientUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", clientUA)

	if !wantsHTML {
		req.Header.Set("Accept", "text/plain, application/octet-stream;q=0.9, */*;q=0.1")
	}

	// ============================================================
	// 🛡️ محافظت مسیر داغ /sub: Circuit Breaker مشترک با /info + Rate
	// Limiter مجزا + Semaphore هم‌زمانی. هر سه رد شدن دقیقاً همان پاسخ
	// موجود «Subscription upstream error» را برمی‌گردانند — یعنی رفتار
	// قابل‌مشاهده برای کلاینت نهایی نسبت به قبل تغییری نکرده، فقط سریع‌تر
	// fail می‌شویم وقتی از قبل می‌دانیم upstream ناسالم/پرفشار است.
	// ============================================================
	if !pgCircuitBreaker.Allow() {
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}
	// 📌 Exception-Safe Ownership Cleanup: از همین‌جا به بعد، اگر تابع از
	// هر مسیری (return عادی یا یک panic پیش‌بینی‌نشده در آینده) خارج شود
	// بدون این‌که RecordResult واقعی صدا زده باشد، این defer به‌طور خودکار
	// "حق تماس" گرفته‌شده از Allow() را آزاد می‌کند — جلوی قفل‌شدن ابدی
	// Half-Open را می‌گیرد، حتی اگر کد آینده یک panic جدید معرفی کند.
	consumed := false
	defer func() {
		if !consumed {
			pgCircuitBreaker.ReleaseWithoutResult()
		}
	}()

	if !pgSubRateLimiter.Allow() {
		// رد شدن محلی است، نه شکست upstream؛ defer بالا "حق تماس" را آزاد می‌کند.
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}
	select {
	case pgSubConcurrency <- struct{}{}:
		defer func() { <-pgSubConcurrency }()
	default:
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		pgCircuitBreaker.RecordResult(false)
		consumed = true
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}
	// 📌 فقط خطای شبکه یا 5xx شکست زیرساختی محسوب می‌شود؛ هر status code
	// دیگر (شامل 4xx که می‌تواند معنای معتبر کسب‌وکاری داشته باشد) upstream
	// را سالم می‌داند — رفتار پاس‌شدن پاسخ به کاربر نهایی (چند خط پایین‌تر) دست‌نخورده می‌ماند.
	pgCircuitBreaker.RecordResult(!isPgUpstreamInfraFailure(nil, resp.StatusCode))
	consumed = true
	defer resp.Body.Close()

	// 📌 محدودسازی اندازه‌ی خواندن بدنه: اگر پاسخ upstream بیش از سقف مجاز
	// باشد، به‌جای پردازش یک بدنه‌ی بریده/ناقص (که می‌تواند JSON نامعتبر یا
	// base64 نیمه‌کاره تولید کند)، صریحاً fail می‌شویم — نه truncate خاموش.
	bodyBytes, bodyErr := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamSubscriptionBodyBytes+1))
	if bodyErr != nil {
		log.Printf("[PasarGuard] خواندن پاسخ upstream ناموفق بود: %v", bodyErr)
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}
	if len(bodyBytes) > maxUpstreamSubscriptionBodyBytes {
		log.Printf("[PasarGuard] پاسخ upstream بیش از سقف مجاز (%d بایت) بود؛ رد شد", len(bodyBytes))
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}
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

	// 📌 استفاده از تابع کش شده به جای فراخوانی مستقیم
	userInfo := getPasarGuardUserInfoCached(token)
	var purchaseDay int
	userIsActive := true

	if userInfo != nil {
		purchaseDay = jalaliDayOfPurchase(userInfo.CreatedAt)
		statusLower := strings.ToLower(strings.TrimSpace(userInfo.Status))
		if statusLower == "expired" || statusLower == "disabled" || statusLower == "limited" {
			userIsActive = false
		}
	}

	var extraConfigs []string
	if userIsActive {
		extraConfigs = getCachedConfigsForDay(purchaseDay)
	}

	var warningCfg string
	if firewallDecision.AdminWarn {
		warningCfg = strings.TrimSpace(firewallDecision.WarningConfig)
	}

	htmlExtraConfigs := extraConfigs
	if warningCfg != "" {
		htmlExtraConfigs = append([]string{warningCfg}, extraConfigs...)
	}

	ct := resp.Header.Get("Content-Type")
	isHTML := looksLikeHTMLResponse(bodyBytes, ct)

	if isHTML {
		if ct == "" {
			ct = "text/html; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(injectExtraIntoPasarGuardHTML(string(bodyBytes), htmlExtraConfigs)))
		return
	}

	if looksLikeJSONResponse(bodyBytes, ct) {
		if injected, ok := injectExtraIntoSingBoxJSON(bodyBytes, extraConfigs, warningCfg); ok {
			bodyBytes = injected
		}
		if ct == "" {
			ct = "application/json; charset=utf-8"
		}
		copySubscriptionHeaders(w.Header(), resp.Header)
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		w.Write(bodyBytes)
		return
	}

	payloadText, wasBase64 := decodeSubscriptionPayload(string(bodyBytes))

	var configs []string
	if payloadText != "" {
		configs = strings.Split(payloadText, "\n")
	}

	configs = append(configs, extraConfigs...)
	if warningCfg != "" {
		configs = append([]string{warningCfg}, configs...)
	}

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
	if !forceRefresh && pgTokenCache != "" && time.Now().Before(pgTokenExpires) {
		cached := pgTokenCache
		pgTokenLock.Unlock()
		return cached
	}
	pgTokenLock.Unlock()

	// 📌 به‌جای نگه‌داشتن pgTokenLock در طول کل تماس شبکه‌ای (که چند
	// درخواست هم‌زمان را بی‌دلیل تا ۵ ثانیه سریالایز می‌کرد)، از
	// Single-Flight موجود استفاده می‌کنیم: حداکثر یک تماس واقعی upstream
	// هم‌زمان برای گرفتن توکن ادمین در جریان است.
	v, err := pgAdminTokenSF.Do("pg-admin-token", func() (interface{}, error) {
		// Double-checked locking: شاید leader قبلی همین الان توکن را تازه کرده باشد.
		pgTokenLock.Lock()
		if pgTokenCache != "" && time.Now().Before(pgTokenExpires) {
			cached := pgTokenCache
			pgTokenLock.Unlock()
			return cached, nil
		}
		pgTokenLock.Unlock()

		form := url.Values{}
		form.Set("username", PASARGUARD_ADMIN_USER)
		form.Set("password", PASARGUARD_ADMIN_PASS)

		loginURL := fmt.Sprintf("%s://127.0.0.1:%s/api/admin/token", PASARGUARD_SCHEME, PASARGUARD_PORT)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.PostForm(loginURL, form)
		if err != nil {
			return "", nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", nil
		}
		body, bodyErr := readBoundedBody(resp.Body, maxUpstreamAPIBodyBytes)
		if bodyErr != nil {
			return "", nil
		}
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
			return "", nil
		}

		pgTokenLock.Lock()
		pgTokenCache = tok.AccessToken
		pgTokenExpires = time.Now().Add(20 * time.Hour)
		pgTokenLock.Unlock()

		return tok.AccessToken, nil
	})
	if err != nil {
		return ""
	}
	token, ok := v.(string)
	if !ok {
		return ""
	}
	return token
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

	body, bodyErr := readBoundedBody(resp.Body, maxUpstreamAPIBodyBytes)
	if bodyErr != nil {
		return nil
	}
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
	ID            int
	Title         string
	URL           string
	Inbounds      string
	PoolName      string
	RotationHours int
	Active        bool
	Updated       string
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

// 🛡️ Struct های مربوط به پنل Firewall
type FirewallSuspiciousRow struct {
	Token       string
	Suspicious  bool
	AdminWarn   bool
	AdminBurn   bool
	DeviceCount int
	Username    string
}

type FirewallConsoleData struct {
	Settings     FirewallSettings
	Suspicious   []FirewallSuspiciousRow
	CurrentPage  int
	TotalPages   int
	TotalRecords int
	SearchQuery  string
	HasPrevPage  bool
	HasNextPage  bool
	PrevPage     int
	NextPage     int
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
	Firewall     FirewallConsoleData // 🛡️ اضافه شدن فایروال به Data
}

// 🛡️ توابع Helper پنل فایروال
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

const firewallDashboardPageSize = 50
const firewallSearchMaxLen = 200
const firewallCountCacheTTL = 5 * time.Second
const firewallCountCacheLimit = 200
const firewallMaxPage = 100000

// 📌 کش کوتاه‌مدت COUNT(*) — چون این کوئری با هر جست‌وجوی متفاوت هزینه‌ی
// جداگانه دارد، و زیر یک burst بازدید پنل ادمین می‌تواند تکراری/پرهزینه شود.
type firewallCountCacheItem struct {
	Count  int
	Expire time.Time
}

var firewallCountCacheMu sync.RWMutex
var firewallCountCache = make(map[string]firewallCountCacheItem)

func getSuspiciousCount(searchPattern string) int {
	now := time.Now()
	firewallCountCacheMu.RLock()
	item, ok := firewallCountCache[searchPattern]
	firewallCountCacheMu.RUnlock()
	if ok && now.Before(item.Expire) {
		return item.Count
	}

	// 📌 Single-Flight: اگر ۵۰ ادمین هم‌زمان دقیقاً همین جست‌وجو را وقتی
	// کش تازه منقضی شده انجام دهند، فقط یک COUNT(*) واقعی روی SQLite
	// اجرا می‌شود، نه ۵۰ کوئری هم‌زمان.
	v, err := firewallCountSF.Do(searchPattern, func() (interface{}, error) {
		refreshNow := time.Now()

		// Double-checked locking: شاید leader قبلی همین الان کش را پر کرده باشد.
		firewallCountCacheMu.RLock()
		if item, ok := firewallCountCache[searchPattern]; ok && refreshNow.Before(item.Expire) {
			firewallCountCacheMu.RUnlock()
			return item.Count, nil
		}
		firewallCountCacheMu.RUnlock()

		var count int
		if db != nil {
			_ = db.QueryRow(`
				SELECT COUNT(*) FROM token_status
				WHERE is_suspicious = 1 AND (token LIKE ? OR COALESCE(username,'') LIKE ?)
			`, searchPattern, searchPattern).Scan(&count)
		}

		firewallCountCacheMu.Lock()
		if len(firewallCountCache) >= firewallCountCacheLimit {
			sampledEvict(firewallCountCache, func(v firewallCountCacheItem) time.Time { return v.Expire })
		}
		firewallCountCache[searchPattern] = firewallCountCacheItem{Count: count, Expire: refreshNow.Add(firewallCountCacheTTL)}
		firewallCountCacheMu.Unlock()

		return count, nil
	})
	if err != nil {
		return 0
	}
	count, ok2 := v.(int)
	if !ok2 {
		return 0
	}
	return count
}

// getSuspiciousFirewallTokens صفحه‌بندی‌شده و قابل‌جست‌وجو است: حداکثر
// firewallDashboardPageSize ردیف در هر بار، هرگز کل جدول را یک‌جا در
// حافظه نمی‌خواند. ورودی‌ها (طول جست‌وجو، شماره صفحه) قبل از ساخت کوئری
// نرمال‌سازی/محدود می‌شوند تا از مقادیر پاتولوژیک جلوگیری شود.
func getSuspiciousFirewallTokens(searchQuery string, page int) FirewallConsoleData {
	result := FirewallConsoleData{CurrentPage: 1, TotalPages: 1}

	searchQuery = strings.TrimSpace(searchQuery)
	if len(searchQuery) > firewallSearchMaxLen {
		searchQuery = searchQuery[:firewallSearchMaxLen]
	}
	result.SearchQuery = searchQuery

	if page < 1 {
		page = 1
	}
	if page > firewallMaxPage {
		page = firewallMaxPage
	}

	if db == nil {
		return result
	}

	pattern := "%" + searchQuery + "%"
	totalRecords := getSuspiciousCount(pattern)
	result.TotalRecords = totalRecords

	totalPages := 1
	if totalRecords > 0 {
		totalPages = (totalRecords + firewallDashboardPageSize - 1) / firewallDashboardPageSize
	}
	if page > totalPages {
		page = totalPages
	}
	result.CurrentPage = page
	result.TotalPages = totalPages
	offset := (page - 1) * firewallDashboardPageSize

	rows, err := db.Query(`
		SELECT 
			t.token, 
			t.is_suspicious, 
			t.admin_warn_mode, 
			t.admin_burn_mode, 
			COUNT(l.id),
			COALESCE(t.username, '')
		FROM token_status t
		LEFT JOIN ip_tracking_logs l ON t.token = l.token
		WHERE t.is_suspicious = 1 AND (t.token LIKE ? OR COALESCE(t.username,'') LIKE ?)
		GROUP BY t.token
		ORDER BY t.token ASC
		LIMIT ? OFFSET ?
	`, pattern, pattern, firewallDashboardPageSize, offset)
	if err != nil {
		log.Printf("[FirewallConsole] suspicious query failed: %v", err)
		return result
	}
	defer rows.Close()

	isPG := strings.EqualFold(PANEL_TYPE, "pasarguard")
	var suspicious []FirewallSuspiciousRow

	for rows.Next() {
		var token, savedUsername string
		var isSuspiciousFlag, warn, burn, deviceCount int

		if err := rows.Scan(&token, &isSuspiciousFlag, &warn, &burn, &deviceCount, &savedUsername); err != nil {
			continue
		}

		username := "-"
		if isPG {
			// 📌 Persistent Memoization: هرگز در مسیر رندر تماس شبکه‌ای زده نمی‌شود.
			// مقدار ذخیره‌شده در DB می‌تواند یک نام‌کاربری واقعی، یکی از دو
			// سنتینل حالت قطعی (بدون نام / نامعتبر)، یا خالی (هنوز lookup نشده) باشد.
			savedUsername = strings.TrimSpace(savedUsername)
			switch savedUsername {
			case "":
				username = "LAZY_LOAD"
			case pgSentinelNoUsername:
				username = "بدون نام‌کاربری"
			case pgSentinelInvalid:
				username = "❌ نامعتبر"
			default:
				username = savedUsername
			}
		} else {
			// x-ui: کوئری local روی xuiDB، بدون هیچ فراخوانی شبکه‌ای
			username = getXUIUsername(token)
		}

		suspicious = append(suspicious, FirewallSuspiciousRow{
			Token:       token,
			Suspicious:  isSuspiciousFlag != 0,
			AdminWarn:   warn != 0,
			AdminBurn:   burn != 0,
			DeviceCount: deviceCount,
			Username:    username,
		})
	}

	result.Suspicious = suspicious
	result.HasPrevPage = page > 1
	result.HasNextPage = page < totalPages
	if result.HasPrevPage {
		result.PrevPage = page - 1
	}
	if result.HasNextPage {
		result.NextPage = page + 1
	}
	return result
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

<!-- ============================================================
     FIREWALL SETTINGS
     ============================================================ -->
<div class="card p-4 mb-4 shadow-sm border-start border-4 border-danger" id="firewall">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h4 class="mb-1">🛡️ Firewall & Anti-Sharing IDS</h4>
            <small class="text-muted">
                کنترل اتصال، تشخیص دستگاه‌های جدید و مدیریت توکن‌های مشکوک
            </small>
        </div>
        {{if .Firewall.Settings.Enabled}}
            <span class="badge bg-success fs-6">فعال</span>
        {{else}}
            <span class="badge bg-secondary fs-6">خاموش</span>
        {{end}}
    </div>
    <form method="post" action="/aggr-console/firewall/settings" class="row g-3">
        <div class="col-md-3">
            <label class="form-label">وضعیت فایروال</label>
            <select name="firewall_enabled" class="form-select">
                {{if .Firewall.Settings.Enabled}}
                    <option value="1" selected>روشن</option>
                    <option value="0">خاموش</option>
                {{else}}
                    <option value="1">روشن</option>
                    <option value="0" selected>خاموش</option>
                {{end}}
            </select>
        </div>
        <div class="col-md-3">
            <label class="form-label">آستانه مشکوک بودن</label>
            <input type="number" name="suspicion_threshold" class="form-control" min="1" value="{{.Firewall.Settings.SuspicionThreshold}}" required>
        </div>
        <div class="col-md-3">
            <label class="form-label">سقف دستگاه</label>
            <input type="number" name="max_devices_per_token" class="form-control" min="2" value="{{.Firewall.Settings.MaxDevices}}" required>
            <small class="text-muted">باید بیشتر از آستانه مشکوک بودن باشد.</small>
        </div>
        <div class="col-md-3">
            <label class="form-label">بازه اعتبار اتصال (ساعت)</label>
            <input type="number" name="reset_window_hours" class="form-control" min="1" value="{{.Firewall.Settings.ResetWindowHours}}" required>
        </div>
        <div class="col-md-3">
            <label class="form-label">فاصله GC (ساعت)</label>
            <input type="number" name="gc_interval_hours" class="form-control" min="1" value="{{.Firewall.Settings.GCIntervalHours}}" required>
        </div>
        <div class="col-md-3">
            <label class="form-label">مدت زمان نگهداری توکن‌های غیرفعال (روز)</label>
            <input type="number" name="inactive_retention_days" class="form-control" min="1" value="{{.Firewall.Settings.InactiveRetentionDays}}" required>
        </div>
        <div class="col-md-6"></div>
        <div class="col-md-6">
            <label class="form-label">⚠️ کانفیگ هشدار مشکوک</label>
            <textarea name="warning_fake_config" class="form-control" rows="4" placeholder="کانفیگ نمایشی هشدار...">{{.Firewall.Settings.WarningFakeConfig}}</textarea>
        </div>
        <div class="col-md-6">
            <label class="form-label">🚫 کانفیگ انسداد کامل</label>
            <textarea name="block_fake_config" class="form-control" rows="4" placeholder="کانفیگ نمایشی هنگام Block...">{{.Firewall.Settings.BlockFakeConfig}}</textarea>
        </div>
        <div class="col-12 text-end">
            <button type="submit" class="btn btn-danger px-4">💾 ذخیره تنظیمات Firewall</button>
        </div>
    </form>
</div>

<!-- ============================================================
     SUSPICIOUS TOKENS DASHBOARD
     ============================================================ -->
<div class="card p-4 mb-4 shadow-sm border-start border-4 border-warning">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h4 class="mb-1">🚨 توکن‌های مشکوک</h4>
            <small class="text-muted">مدیریت فوری Warning و Burn بدون Reload صفحه</small>
        </div>
        <span class="badge bg-warning text-dark" id="firewall-count-badge">{{.Firewall.TotalRecords}} مورد</span>
    </div>
    <form method="get" action="/aggr-console#firewall" class="row g-2 mb-3">
        <div class="col-md-6">
            <input type="text" name="search" class="form-control" placeholder="جستجو بر اساس Token یا نام‌کاربری..." value="{{.Firewall.SearchQuery}}" maxlength="200">
        </div>
        <div class="col-md-2">
            <button type="submit" class="btn btn-outline-primary w-100">🔍 جستجو</button>
        </div>
        {{if .Firewall.SearchQuery}}
        <div class="col-md-2">
            <a href="/aggr-console#firewall" class="btn btn-outline-secondary w-100">پاک کردن</a>
        </div>
        {{end}}
    </form>
    <div id="firewall-alert" class="alert d-none" role="alert"></div>
    <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Token</th>
                    <th>نام کاربری</th>
                    <th>دستگاه‌ها</th>
                    <th>وضعیت</th>
                    <th>عملیات</th>
                </tr>
            </thead>
            <tbody>
            {{range $i, $row := .Firewall.Suspicious}}
                <tr id="firewall-row-{{$i}}">
                    <td><strong>{{$i | printf "%d"}}</strong></td>
                    <td><code style="word-break:break-all;">{{$row.Token}}</code></td>
                    <td>
                        {{if eq $row.Username "LAZY_LOAD"}}
                            <span class="lazy-fetch text-muted" data-token="{{$row.Token}}">در حال واکشی...</span>
                        {{else}}
                            <span class="badge bg-light text-dark border">{{$row.Username}}</span>
                        {{end}}
                    </td>
                    <td><span class="badge bg-secondary">{{$row.DeviceCount}}</span></td>
                    <td class="firewall-status-cell">
                        {{if $row.AdminBurn}}
                            <span class="badge bg-danger">🔥 Burn</span>
                        {{else if $row.AdminWarn}}
                            <span class="badge bg-warning text-dark">⚠️ Warning</span>
                        {{else}}
                            <span class="badge bg-warning text-dark">🚨 مشکوک</span>
                        {{end}}
                    </td>
                    <td>
                        <div class="btn-group" role="group">
                            <button type="button" class="btn btn-sm btn-outline-info" onclick="firewallShowHistory('{{js $row.Token}}')">🔍 جزئیات</button>
                            <button type="button" class="btn btn-sm btn-outline-warning" onclick="firewallWarn('{{js $row.Token}}', {{$i}})">⚠️ هشدار</button>
                            <button type="button" class="btn btn-sm btn-outline-danger" onclick="firewallBurn('{{js $row.Token}}', {{$i}})">🔥 قطع کامل</button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" onclick="firewallReset('{{js $row.Token}}', {{$i}})">♻️ بازنشانی</button>
                        </div>
                    </td>
                </tr>
            {{else}}
                <tr>
                    <td colspan="6" class="text-center text-muted py-4">✅ فعلاً توکن مشکوکی ثبت نشده است.</td>
                </tr>
            {{end}}
            </tbody>
        </table>
    </div>
    {{if gt .Firewall.TotalPages 1}}
    <nav class="mt-3">
        <ul class="pagination pagination-sm justify-content-center mb-0">
            {{if .Firewall.HasPrevPage}}
                <li class="page-item"><a class="page-link" href="/aggr-console?page={{.Firewall.PrevPage}}&search={{.Firewall.SearchQuery}}#firewall">قبلی</a></li>
            {{else}}
                <li class="page-item disabled"><span class="page-link">قبلی</span></li>
            {{end}}
            <li class="page-item disabled"><span class="page-link">صفحه {{.Firewall.CurrentPage}} از {{.Firewall.TotalPages}}</span></li>
            {{if .Firewall.HasNextPage}}
                <li class="page-item"><a class="page-link" href="/aggr-console?page={{.Firewall.NextPage}}&search={{.Firewall.SearchQuery}}#firewall">بعدی</a></li>
            {{else}}
                <li class="page-item disabled"><span class="page-link">بعدی</span></li>
            {{end}}
        </ul>
    </nav>
    {{end}}
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
<div class="col-md-6">
  <label class="form-label">نام دسته/استخر</label>
  <input type="text" name="pool_name" class="form-control" placeholder="اختیاری؛ مثلاً Pool-A">
  <small class="text-muted">لینک‌هایی با نام و اینباند یکسان در یک استخر قرار می‌گیرند.</small>
</div>
<div class="col-md-6">
  <label class="form-label">زمان چرخش (به دقیقه)</label>
  <input type="number" name="rotation_hours" class="form-control" value="0" min="0" step="1" placeholder="مثلا 300 برای 5 ساعت">
  <small class="text-muted">۰ یعنی استفاده از مقدار پیش‌فرض ۱ دقیقه.</small>
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
<thead><tr><th>#</th><th>عنوان</th><th>URL</th><th>استخر</th><th>چرخش (دقیقه)</th><th>وضعیت</th><th>بروزرسانی</th><th>عملیات</th></tr></thead>
<tbody>
{{range .Links}}
<tr>
<td>{{.ID}}</td>
<td><strong>{{.Title}}</strong></td>
<td><small class="text-break" style="max-width:280px;display:inline-block;">{{.URL}}</small></td>
<td>
{{if .PoolName}}
  <span class="badge bg-primary">{{.PoolName}}</span>
{{else}}
  <span class="text-muted">مستقل</span>
{{end}}
</td>
<td>
{{if .PoolName}}
  <span class="badge bg-info text-dark">{{.RotationHours}} دقیقه</span>
{{else}}
  <span class="text-muted">—</span>
{{end}}
</td>
<td>{{if .Active}}<span class="badge bg-success">فعال</span>{{else}}<span class="badge bg-secondary">غیرفعال</span>{{end}}</td>
<td><small>{{.Updated}}</small></td>
<td>
<button type="button" class="btn btn-sm btn-outline-primary me-1" onclick="openEditModal({{.ID}}, {{.Title}}, {{.URL}}, {{.Inbounds}}, {{.PoolName}}, {{.RotationHours}})">ویرایش</button>
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
<div class="col-md-6"><label class="form-label">نام دسته/استخر</label><input type="text" name="pool_name" id="modal_pool_name" class="form-control" placeholder="اختیاری"></div>
<div class="col-md-6"><label class="form-label">زمان چرخش (به دقیقه)</label><input type="number" name="rotation_hours" id="modal_rotation_hours" class="form-control" min="0" step="1" value="0"></div>
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

<div class="modal fade" id="deviceHistoryModal" tabindex="-1">
<div class="modal-dialog modal-lg"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title">🔍 جزئیات اتصالات توکن</h5>
<button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body">
<table class="table table-sm table-striped mb-0">
<thead><tr><th>IP</th><th>سیستم‌عامل</th><th>کلاینت</th><th>اولین اتصال</th></tr></thead>
<tbody id="deviceHistoryBody"></tbody>
</table>
</div>
<div class="modal-footer">
<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">بستن</button>
</div>
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
function openEditModal(id, title, url, inbounds, poolName, rotationHours) {
	document.getElementById('modal_link_id').value = id;
	document.getElementById('modal_title').value = title;
	document.getElementById('modal_url').value = url;
	document.getElementById('modal_inbounds').value = inbounds;
	document.getElementById('modal_pool_name').value = poolName || '';
	document.getElementById('modal_rotation_hours').value = Number.isFinite(Number(rotationHours)) ? Number(rotationHours) : 0;
	var myModal = new bootstrap.Modal(document.getElementById('editModal'));
	myModal.show();
}

// ============================================================
// AJAX Functions for Firewall Dashboard
// ============================================================
function showFirewallAlert(message, success) {
    const box = document.getElementById('firewall-alert');
    if (!box) return;
    box.classList.remove('d-none');
    box.className = 'alert ' + (success ? 'alert-success' : 'alert-danger');
    box.textContent = message;
    window.clearTimeout(window.firewallAlertTimer);
    window.firewallAlertTimer = window.setTimeout(function () {
        box.classList.add('d-none');
    }, 3500);
}

function updateFirewallCount(delta) {
    const badge = document.getElementById('firewall-count-badge');
    if (!badge) return;
    const match = badge.textContent.match(/\d+/);
    const current = match ? parseInt(match[0], 10) : 0;
    badge.textContent = Math.max(0, current + delta) + ' مورد';
}

function escapeHtml(str) {
    if (str === undefined || str === null) return '';
    return String(str).replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
}

async function firewallPost(url, token, rowIndex, mode) {
    const formData = new URLSearchParams();
    formData.set('token', token);
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
            body: formData.toString()
        });
        const text = await response.text();
        if (!response.ok) throw new Error(text || 'Request failed');
        let data = null;
        try { data = JSON.parse(text); } catch (_) {}
        if (!data || !data.ok) throw new Error('عملیات توسط سرور تأیید نشد.');

        if (mode === 'reset') {
            const row = document.getElementById('firewall-row-' + rowIndex);
            if (row) row.remove();
            updateFirewallCount(-1);
            showFirewallAlert('اتصالات این توکن بازنشانی و از لیست مشکوک حذف شد.', true);
            return;
        }

        const row = document.getElementById('firewall-row-' + rowIndex);
        if (row) {
            const statusCell = row.querySelector('.firewall-status-cell');
            if (statusCell) {
                if (mode === 'burn') {
                    statusCell.innerHTML = '<span class="badge bg-danger">🔥 Burn</span>';
                } else if (mode === 'warn') {
                    statusCell.innerHTML = data.state
                        ? '<span class="badge bg-warning text-dark">⚠️ Warning</span>'
                        : '<span class="badge bg-warning text-dark">🚨 مشکوک</span>';
                }
            }
        }

        const msg = mode === 'burn'
            ? 'اتصالات این توکن کاملاً قطع شد.'
            : (data.state ? 'حالت هشدار برای این توکن فعال شد.' : 'حالت هشدار برای این توکن غیرفعال شد.');
        showFirewallAlert(msg, true);
    } catch (error) {
        console.error('[Firewall]', error);
        showFirewallAlert('اجرای عملیات ناموفق بود.', false);
    }
}

function firewallWarn(token, rowIndex) {
    if (!confirm('وضعیت هشدار برای این توکن تغییر کند؟')) return;
    firewallPost('/aggr-console/firewall/warn', token, rowIndex, 'warn');
}

function firewallBurn(token, rowIndex) {
    if (!confirm('آیا از قطع کامل اتصالات این توکن مطمئن هستید؟')) return;
    firewallPost('/aggr-console/firewall/burn', token, rowIndex, 'burn');
}

function firewallReset(token, rowIndex) {
    if (!confirm('اتصالات و وضعیت این توکن کاملاً بازنشانی شود؟ این عمل توکن را از لیست مشکوک حذف می‌کند.')) return;
    firewallPost('/aggr-console/firewall/reset', token, rowIndex, 'reset');
}

async function firewallShowHistory(token) {
    const modalBody = document.getElementById('deviceHistoryBody');
    modalBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">در حال بارگذاری...</td></tr>';
    var myModal = new bootstrap.Modal(document.getElementById('deviceHistoryModal'));
    myModal.show();
    try {
        const response = await fetch('/aggr-console/firewall/history?token=' + encodeURIComponent(token));
        if (!response.ok) throw new Error('failed');
        const devices = await response.json();
        if (!devices || devices.length === 0) {
            modalBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">دستگاهی ثبت نشده است.</td></tr>';
            return;
        }
        modalBody.innerHTML = devices.map(function (d) {
            return '<tr><td>' + escapeHtml(d.IP) + '</td><td>' + escapeHtml(d.OS) + '</td><td>' + escapeHtml(d.ClientApp) + '</td><td>' + escapeHtml(d.FirstSeen) + '</td></tr>';
        }).join('');
    } catch (e) {
        modalBody.innerHTML = '<tr><td colspan="4" class="text-center text-danger">خطا در بارگذاری اطلاعات.</td></tr>';
    }
}

// 📌 Lazy-Load نام‌کاربری پاسارگارد: صفحه فوراً رندر می‌شود، سپس همه‌ی
// ردیف‌های نیازمند lookup واکشی می‌شوند. نرخ واقعی تماس با PasarGuard
// توسط Rate Limiter/Circuit Breaker سمت سرور کنترل می‌شود، نه با تاخیر
// جاوااسکریپتی. صفحه‌بندی سمت سرور از قبل تعداد ردیف‌های هر صفحه را به
// حداکثر ۵۰ محدود کرده، اما برای اطمینان مضاعف (extreme safety)، در
// صورت وجود بیش از حد مجاز batch سمت سرور، اینجا هم به تکه‌های ۵۰تایی
// تقسیم و به‌صورت متوالی (نه موازی) پردازش می‌شود.
(async function () {
    var elements = Array.prototype.slice.call(document.querySelectorAll('.lazy-fetch'));
    if (elements.length === 0) return;

    var BATCH_MAX = 50;

    function applyResult(el, item) {
        if (!item) {
            el.textContent = '-';
            el.classList.remove('lazy-fetch');
            return;
        }
        if (item.state === 'VALID' && item.username) {
            el.outerHTML = '<span class="badge bg-light text-dark border">' + escapeHtml(item.username) + '</span>';
        } else if (item.state === 'NO_USERNAME') {
            el.outerHTML = '<span class="badge bg-light text-dark border">بدون نام‌کاربری</span>';
        } else if (item.state === 'INVALID_TOKEN') {
            el.outerHTML = '<span class="badge bg-danger">❌ نامعتبر</span>';
        } else {
            // TRANSIENT: شکست موقت upstream/rate-limit؛ با رفرش بعدی صفحه دوباره تلاش می‌شود.
            el.textContent = '-';
            el.classList.remove('lazy-fetch');
        }
    }

    for (var start = 0; start < elements.length; start += BATCH_MAX) {
        var chunk = elements.slice(start, start + BATCH_MAX);
        var tokens = chunk.map(function (el) { return el.getAttribute('data-token') || ''; });
        try {
            var res = await fetch('/aggr-console/firewall/userinfo-batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tokens: tokens })
            });
            var data = res.ok ? await res.json() : null;
            var results = (data && data.results) || [];
            chunk.forEach(function (el, i) { applyResult(el, results[i]); });
        } catch (e) {
            chunk.forEach(function (el) {
                el.textContent = '-';
                el.classList.remove('lazy-fetch');
            });
        }
    }
})();
</script>
</body>
</html>`

// normalizeInboundKey cleans a target_inbounds value before numeric comparison.
// Values typed/pasted on Persian keyboards or copied from RTL sources (Telegram,
// Word, etc.) often carry invisible bidi/format characters (RLM/LRM/ALM/BOM) or
// use Persian/Arabic-Indic digits instead of ASCII digits. strconv.Atoi fails
// silently on both, which is what was causing the sort to fall back to
// lexicographic string comparison even though every value "looked" numeric.
func normalizeInboundKey(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Cf, r): // bidi/format marks: RLM, LRM, ALM, BOM, etc.
			continue
		case r >= '۰' && r <= '۹': // Persian (Extended Arabic-Indic) digits U+06F0-06F9
			b.WriteRune('0' + (r - '۰'))
		case r >= '٠' && r <= '٩': // Arabic-Indic digits U+0660-0669
			b.WriteRune('0' + (r - '٠'))
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

var tmpl = template.Must(template.New("console").Parse(consoleTmpl))

func renderConsole(w http.ResponseWriter, r *http.Request, username string) {
	rows, _ := db.Query("SELECT id, title, url, COALESCE(target_inbounds,'all'), COALESCE(pool_name,''), COALESCE(rotation_hours,0), COALESCE(is_active,1), COALESCE(last_updated,'-') FROM main_links ORDER BY id DESC")
	byGroup := map[string][]LinkRow{}
	if rows != nil {
		for rows.Next() {
			var l LinkRow
			var active int
			if err := rows.Scan(&l.ID, &l.Title, &l.URL, &l.Inbounds, &l.PoolName, &l.RotationHours, &active, &l.Updated); err != nil {
				continue
			}
			l.Active = active != 0
			byGroup[l.Inbounds] = append(byGroup[l.Inbounds], l)
		}
		rows.Close()
	}
	var groupKeys []string
	for k := range byGroup {
		groupKeys = append(groupKeys, k)
	}
	sort.SliceStable(groupKeys, func(i, j int) bool {
		ki, kj := groupKeys[i], groupKeys[j]
		if strings.EqualFold(strings.TrimSpace(ki), "all") {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(kj), "all") {
			return false
		}
		// تلاش برای تبدیل به عدد و مرتب‌سازی ریاضی
		// (پاک‌سازی کاراکترهای نامرئی/جهت‌ساز و ارقام فارسی/عربی قبل از تبدیل)
		numI, errI := strconv.Atoi(normalizeInboundKey(ki))
		numJ, errJ := strconv.Atoi(normalizeInboundKey(kj))
		if errI == nil && errJ == nil {
			return numI < numJ
		}
		// اگر عدد نبودند، همان مرتب‌سازی متنی قبلی
		return ki < kj
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

	// 🛡️ ایجاد داده‌های مربوط به فایروال برای تزریق به پنل HTML
	// (پارامترهای page/search نرمال‌سازی/محدودسازی‌شان داخل خودِ
	// getSuspiciousFirewallTokens انجام می‌شود)
	searchQuery := r.URL.Query().Get("search")
	page, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page")))
	firewallData := getSuspiciousFirewallTokens(searchQuery, page)
	firewallData.Settings = getFirewallSettings()

	data := ConsoleData{
		Username:     username,
		Groups:       groups,
		Scheds:       scheds,
		Categories:   categories,
		IsPasarGuard: isPG,
		PGGroups:     pgGroups,
		PanelLabel:   panelLabel,
		DayOptions:   dayOptions,
		Firewall:     firewallData,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func checkCSRF(r *http.Request) bool {
	requestHost := strings.TrimSpace(r.Host)
	if requestHost == "" {
		return false
	}

	if parsedHost, err := url.Parse("http://" + requestHost); err == nil && parsedHost.Hostname() != "" {
		requestHost = strings.ToLower(parsedHost.Hostname())
	} else {
		requestHost = strings.ToLower(strings.TrimSpace(requestHost))
	}
	if requestHost == "" {
		return false
	}

	originMatches := func(raw string) bool {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return false
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return false
		}
		hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if hostname == requestHost {
			return true
		}
		return strings.HasSuffix(hostname, "."+requestHost)
	}

	if o := r.Header.Get("Origin"); o != "" {
		return originMatches(o)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return originMatches(ref)
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
	// ============================================================
	// 🛡️ API Endpoints for Firewall
	// ============================================================
	case r.Method == "POST" && r.URL.Path == "/aggr-console/firewall/settings":
		enabled := parseBool(r.FormValue("firewall_enabled"))
		suspicionThreshold := parseInt(r.FormValue("suspicion_threshold"), 3)
		maxDevices := parseInt(r.FormValue("max_devices_per_token"), 5)
		resetWindowHours := parseInt(r.FormValue("reset_window_hours"), 24)
		gcIntervalHours := parseInt(r.FormValue("gc_interval_hours"), 6)
		inactiveRetentionDays := parseInt(r.FormValue("inactive_retention_days"), 30)

		if maxDevices <= suspicionThreshold {
			http.Error(w, "سقف دستگاه باید بیشتر از آستانه مشکوک بودن باشد", http.StatusBadRequest)
			return
		}

		warningConfig := strings.TrimSpace(r.FormValue("warning_fake_config"))
		blockConfig := strings.TrimSpace(r.FormValue("block_fake_config"))

		settings := map[string]string{
			"firewall_enabled":        strconv.Itoa(boolToInt(enabled)),
			"suspicion_threshold":     strconv.Itoa(suspicionThreshold),
			"max_devices_per_token":   strconv.Itoa(maxDevices),
			"reset_window_hours":      strconv.Itoa(resetWindowHours),
			"gc_interval_hours":       strconv.Itoa(gcIntervalHours),
			"inactive_retention_days": strconv.Itoa(inactiveRetentionDays),
			"warning_fake_config":     warningConfig,
			"block_fake_config":       blockConfig,
		}

		tx, err := db.Begin()
		if err != nil {
			log.Printf("[FirewallConsole] begin settings transaction failed: %v", err)
			http.Error(w, "خطا در دیتابیس", http.StatusInternalServerError)
			return
		}

		settingsSaved := true
		for key, value := range settings {
			if _, err := tx.Exec(`
				INSERT INTO firewall_settings(key, value)
				VALUES (?, ?)
				ON CONFLICT(key) DO UPDATE SET value = excluded.value
			`, key, value); err != nil {
				log.Printf("[FirewallConsole] save setting %s failed: %v", key, err)
				settingsSaved = false
				break
			}
		}

		if !settingsSaved {
			_ = tx.Rollback()
			http.Error(w, "خطا در ذخیره تنظیمات Firewall", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			log.Printf("[FirewallConsole] commit settings transaction failed: %v", err)
			http.Error(w, "خطا در دیتابیس", http.StatusInternalServerError)
			return
		}

		InvalidateFirewallSettingsCache()
		http.Redirect(w, r, "/aggr-console#firewall", http.StatusSeeOther)

	case r.Method == "POST" && r.URL.Path == "/aggr-console/firewall/warn":
		token := strings.TrimSpace(r.FormValue("token"))
		if token == "" {
			http.Error(w, "token is required", http.StatusBadRequest)
			return
		}
		newState, err := toggleFirewallWarning(token)
		if err != nil {
			http.Error(w, "خطا در تغییر حالت هشدار", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":true,"mode":"warn","state":%v}`, newState)))

	case r.Method == "POST" && r.URL.Path == "/aggr-console/firewall/reset":
		token := strings.TrimSpace(r.FormValue("token"))
		if token == "" {
			http.Error(w, "token is required", http.StatusBadRequest)
			return
		}
		if err := resetFirewallToken(token); err != nil {
			http.Error(w, "خطا در بازنشانی اتصالات", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"ok":true,"mode":"reset"}`))

	case r.Method == "GET" && r.URL.Path == "/aggr-console/firewall/history":
		token := strings.TrimSpace(r.URL.Query().Get("token"))
		if token == "" {
			http.Error(w, "token is required", http.StatusBadRequest)
			return
		}
		devices := getFirewallTokenDevices(token)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(devices); err != nil {
			log.Printf("[FirewallConsole] history encode failed: %v", err)
		}

	case r.Method == "POST" && r.URL.Path == "/aggr-console/firewall/userinfo-batch":
		const maxBatchTokens = 50
		const maxTokenLen = 256

		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var req struct {
			Tokens []string `json:"tokens"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.Tokens) == 0 {
			http.Error(w, "tokens is required", http.StatusBadRequest)
			return
		}
		if len(req.Tokens) > maxBatchTokens {
			http.Error(w, "too many tokens in one batch", http.StatusBadRequest)
			return
		}

		type userinfoResult struct {
			State    string `json:"state"`
			Username string `json:"username,omitempty"`
		}
		results := make([]userinfoResult, len(req.Tokens))

		var wg sync.WaitGroup
		for i, rawToken := range req.Tokens {
			token := strings.TrimSpace(rawToken)
			if token == "" || len(token) > maxTokenLen {
				// ورودی نامعتبر یک آیتم، کل batch را fail نمی‌کند.
				results[i] = userinfoResult{State: string(pgUserStateTransient)}
				continue
			}
			wg.Add(1)
			go func(idx int, tok string) {
				defer wg.Done()
				// 📌 دفاع لایه‌دوم: حتی بعد از اصلاح sfGroup برای عدم
				// دوباره-panic زدن، این گوروتین خام مستقل یک recover
				// مخصوص خودش هم دارد تا هر مسیر آینده‌ای که ممکن است
				// بدون عبور از sfGroup اینجا اضافه شود هم ایمن بماند.
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[FirewallConsole] recovered panic in userinfo-batch worker: %v", r)
						results[idx] = userinfoResult{State: string(pgUserStateTransient)}
					}
				}()
				// 📌 resolvePasarGuardUser خودش Single-Flight/Circuit-Breaker/
				// Rate-Limiter را اعمال می‌کند؛ توکن‌های تکراری در همین batch
				// (یا حتی در batchهای هم‌زمان دیگر ادمین‌ها) به‌طور خودکار
				// در همان‌جا collapse می‌شوند، نیازی به دی‌دوپ محلی نیست.
				res := resolvePasarGuardUser(tok)
				results[idx] = userinfoResult{State: string(res.State), Username: res.Username}
			}(i, token)
		}
		wg.Wait()

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(struct {
			Results []userinfoResult `json:"results"`
		}{Results: results})

	case r.Method == "POST" && r.URL.Path == "/aggr-console/firewall/burn":
		token := strings.TrimSpace(r.FormValue("token"))
		if token == "" {
			http.Error(w, "token is required", http.StatusBadRequest)
			return
		}
		if err := setFirewallBurn(token, true); err != nil {
			http.Error(w, "خطا در قطع کامل اتصالات", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"ok":true,"mode":"burn"}`))

	// ============================================================
	// سایر Endpoints
	// ============================================================
	case r.Method == "POST" && r.URL.Path == "/aggr-console/add":
		title := strings.TrimSpace(r.FormValue("title"))
		urls := r.FormValue("urls")
		inbounds := strings.TrimSpace(r.FormValue("target_inbounds"))
		if !strings.EqualFold(inbounds, "all") {
			inbounds = normalizeInboundKey(inbounds)
		}
		poolName := strings.TrimSpace(r.FormValue("pool_name"))
		rotationHours := 0
		if raw := strings.TrimSpace(r.FormValue("rotation_hours")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				http.Error(w, "زمان چرخش باید یک عدد صحیح بزرگ‌تر یا مساوی صفر باشد (به دقیقه)", http.StatusBadRequest)
				return
			}
			rotationHours = parsed
		}
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
			if _, err := db.Exec(
				"INSERT INTO main_links (title, url, target_inbounds, pool_name, rotation_hours, is_active, last_updated) VALUES (?, ?, ?, ?, ?, 1, ?)",
				itemTitle, u, inbounds, poolName, rotationHours, nowStr,
			); err != nil {
				log.Printf("[Console] افزودن لینک ناموفق بود: %v", err)
			}
		}
		go fetchAndCache()
		http.Redirect(w, r, "/aggr-console", http.StatusSeeOther)

	case r.Method == "POST" && r.URL.Path == "/aggr-console/edit":
		id := strings.TrimSpace(r.FormValue("link_id"))
		title := strings.TrimSpace(r.FormValue("title"))
		urlVal := strings.TrimSpace(r.FormValue("url"))
		inbounds := strings.TrimSpace(r.FormValue("target_inbounds"))
		if !strings.EqualFold(inbounds, "all") {
			inbounds = normalizeInboundKey(inbounds)
		}
		poolName := strings.TrimSpace(r.FormValue("pool_name"))
		rotationHours := 0
		if raw := strings.TrimSpace(r.FormValue("rotation_hours")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				http.Error(w, "زمان چرخش باید یک عدد صحیح بزرگ‌تر یا مساوی صفر باشد (به دقیقه)", http.StatusBadRequest)
				return
			}
			rotationHours = parsed
		}
		nowStr := time.Now().Format("2006-01-02 15:04")
		if _, err := db.Exec(
			"UPDATE main_links SET title=?, url=?, target_inbounds=?, pool_name=?, rotation_hours=?, last_updated=? WHERE id=?",
			title, urlVal, inbounds, poolName, rotationHours, nowStr, id,
		); err != nil {
			log.Printf("[Console] ویرایش لینک ناموفق بود: %v", err)
		}
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
		renderConsole(w, r, username)
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

	// ============================================================
	// 🛡️ Firewall Hook
	// MUST run before contacting Upstream.
	// ============================================================
	firewallDecision := FirewallCheck(r, subID)
	if !firewallDecision.Allow {
		ct, body := formatBlockResponse(firewallDecision.BlockConfig, requestWantsJSONFormat(r))
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	cfg := getXUIConfig()
	sanaeiURL := fmt.Sprintf("https://127.0.0.1:%s%s%s", cfg.Port, cfg.Path, subID)
	// 📌 خطای NewRequest دیگر نادیده گرفته نمی‌شود: نادیده‌گرفتن آن یعنی
	// دسترسی به req نامعتبر (nil) در ادامه‌ی تابع (nil-pointer panic روی
	// req.Header). مسیر موفق کاملاً بدون تغییر باقی می‌ماند.
	req, reqErr := http.NewRequest("GET", sanaeiURL, nil)
	if reqErr != nil {
		log.Printf("[XUI] ساخت درخواست upstream ناموفق بود: %v", reqErr)
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}

	wantsHTML := strings.Contains(r.Header.Get("Accept"), "text/html") || r.URL.Query().Get("html") == "1"

	for k, v := range r.Header {
		if strings.ToLower(k) == "accept-encoding" {
			continue
		}
		req.Header[k] = v
	}
	req.Header.Set("Accept-Encoding", "identity")

	// 🛡️ USER-AGENT PASSTHROUGH & SPOOFING
	clientUA := r.Header.Get("User-Agent")
	if strings.TrimSpace(clientUA) == "" {
		clientUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", clientUA)

	if !wantsHTML {
		req.Header.Set("Accept", "text/plain, application/octet-stream;q=0.9, */*;q=0.1")
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

	// 📌 محدودسازی اندازه‌ی خواندن بدنه (همان سقف و همان منطق fail-safe
	// استفاده‌شده در handleSubPasarGuard): یک بدنه‌ی بریده/ناقص هرگز
	// به‌عنوان ساب‌اسکریپشن کامل پردازش نمی‌شود.
	bodyBytes, bodyErr := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamSubscriptionBodyBytes+1))
	if bodyErr != nil {
		log.Printf("[XUI] خواندن پاسخ upstream ناموفق بود: %v", bodyErr)
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}
	if len(bodyBytes) > maxUpstreamSubscriptionBodyBytes {
		log.Printf("[XUI] پاسخ upstream بیش از سقف مجاز (%d بایت) بود؛ رد شد", len(bodyBytes))
		http.Error(w, "Subscription upstream error", http.StatusBadGateway)
		return
	}
	debugSubscriptionResponse("x-ui", r, resp, bodyBytes)

	if resp.StatusCode != 200 {
		w.WriteHeader(resp.StatusCode)
		w.Write(bodyBytes)
		return
	}

	userInboundID := getUserInboundID(subID)
	extraConfigs := getCachedConfigsForInbound(userInboundID)

	var warningCfg string
	if firewallDecision.AdminWarn {
		warningCfg = strings.TrimSpace(firewallDecision.WarningConfig)
	}

	// 🛡️ برای نمای HTML، هشدار اولین آیتم بلوک تزریق‌شونده است
	htmlExtraConfigs := extraConfigs
	if warningCfg != "" {
		htmlExtraConfigs = append([]string{warningCfg}, extraConfigs...)
	}

	ct := resp.Header.Get("Content-Type")
	isHTML := looksLikeHTMLResponse(bodyBytes, ct)

	if isHTML {
		if ct == "" {
			ct = "text/html; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(injectExtraIntoSanaeiHTML(string(bodyBytes), htmlExtraConfigs)))
		return
	}

	if looksLikeJSONResponse(bodyBytes, ct) {
		if injected, ok := injectExtraIntoSingBoxJSON(bodyBytes, extraConfigs, warningCfg); ok {
			bodyBytes = injected
		}
		if ct == "" {
			ct = "application/json; charset=utf-8"
		}
		copySubscriptionHeaders(w.Header(), resp.Header)
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		w.Write(bodyBytes)
		return
	}

	payloadText, wasBase64 := decodeSubscriptionPayload(string(bodyBytes))

	var configs []string
	if payloadText != "" {
		configs = strings.Split(payloadText, "\n")
	}
	configs = append(configs, extraConfigs...)
	if warningCfg != "" {
		configs = append([]string{warningCfg}, configs...)
	}

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
	localDB, err := sql.Open(
		"sqlite3",
		DB_PATH+
			"?_journal_mode=WAL"+
			"&_synchronous=NORMAL"+
			"&_busy_timeout=5000"+
			"&_temp_store=MEMORY",
	)
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

	// 🔐 Anti-Sharing Firewall background collector
	StartFirewallGC()
	log.Printf("🛡️ Firewall Anti-Sharing GC started.")

	PANEL_TYPE = detectPanelType()

	if strings.EqualFold(PANEL_TYPE, "pasarguard") {
		log.Printf("🧩 حالت پنل: PasarGuard (Port=%s Path=%s Scheme=%s)", PASARGUARD_PORT, normalizeURIPath(PASARGUARD_SUB_PATH), PASARGUARD_SCHEME)

		// 📌 پچ جدید: راه‌اندازی Garbage Collector برای پاکسازی خودکار رم
		go startUserInfoCacheGC()
		log.Printf("🧹 پردازشگر پاکسازی حافظه موقت (Garbage Collector) با موفقیت فعال شد.")

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
