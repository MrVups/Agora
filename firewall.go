package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	firewallSettingsTTL         = 5 * time.Second
	firewallStatusTTL           = 2 * time.Second
	firewallWriterBuffer        = 4096
	firewallStatusWriterBuffer  = 1024
	firewallCacheLimit          = 50000
	firewallDefaultResetHours   = 24
	firewallDefaultGCInterval   = 6
	firewallDefaultInactiveDays = 30
	firewallGCTickInterval      = 1 * time.Minute
	firewallGCUpdateChunkSize   = 500
	firewallSampledEvictK       = 5
)

type FirewallSettings struct {
	Enabled               bool
	SuspicionThreshold    int
	MaxDevices            int
	ResetWindowHours      int
	GCIntervalHours       int
	InactiveRetentionDays int
	WarningFakeConfig     string
	BlockFakeConfig       string
}

type FirewallDecision struct {
	Allow         bool
	Suspicious    bool
	AdminWarn     bool
	AdminBurn     bool
	WarningConfig string
	BlockConfig   string
}

type firewallStatus struct {
	Suspicious bool
	Warn       bool
	Burn       bool
}

type FirewallDeviceLogRow struct {
	IP        string
	OS        string
	ClientApp string
	FirstSeen string
}

type firewallStatusCacheItem struct {
	Status   firewallStatus
	Expire   time.Time
	LastUsed time.Time
}

// ============================================================
// 🧮 Sampled Random Eviction (Approximated LRU, K=5)
// به‌جای اسکن کامل O(N) نقشه زیر قفل، فقط K کاندید (بر اساس ترتیب
// pseudo-random پیمایش map در Go) بررسی می‌شود و قدیمی‌ترین از بین
// همان‌ها حذف می‌گردد. این یک تابع generic است تا هم برای
// firewallStatusCache و هم firewallLastTouchAt بدون تکرار کد استفاده شود.
// ============================================================
func sampledEvict[V any](m map[string]V, timestampOf func(V) time.Time) {
	oldestKey := ""
	var oldestTime time.Time
	sampled := 0
	for key, val := range m {
		t := timestampOf(val)
		if oldestKey == "" || t.Before(oldestTime) {
			oldestKey = key
			oldestTime = t
		}
		sampled++
		if sampled >= firewallSampledEvictK {
			break
		}
	}
	if oldestKey != "" {
		delete(m, oldestKey)
	}
}

// ============================================================
// 🔁 Single-Flight عمومی و قابل‌استفاده‌ی مجدد
// نسخه‌ی داخلی و سبک، بدون وابستگی جدید (معادل golang.org/x/sync/singleflight).
// کلیدها بلافاصله بعد از تکمیل فراخوانی حذف می‌شوند — رشد نامحدود حافظه ممکن نیست.
// دو نمونه‌ی مستقل از این نوع در ادامه ساخته می‌شود: یکی برای رفرش
// firewallStatus (محلی/DB) و یکی برای resolvePasarGuardUser (upstream) —
// این دو عملیات منطقاً متفاوتند و نباید کلید یکسان به اشتراک بگذارند،
// اما هر دو باید duplicate concurrent load را برای یک توکن collapse کنند.
// ============================================================
type sfCall struct {
	wg  sync.WaitGroup
	val interface{}
	err error
}

type sfGroup struct {
	mu    sync.Mutex
	calls map[string]*sfCall
}

func (g *sfGroup) Do(key string, fn func() (interface{}, error)) (interface{}, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*sfCall)
	}
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := new(sfCall)
	c.wg.Add(1)
	g.calls[key] = c
	g.mu.Unlock()

	// 📌 محافظت در برابر panic: fn() ممکن است از داخل گوروتین‌های خامی
	// صدا زده شود که خودشان recover مستقل ندارند (مثل worker‌های
	// /userinfo-batch). اگر اینجا دوباره panic بزنیم، کل پروسه کرش
	// می‌کند. پس panic هرگز دوباره raise نمی‌شود؛ به یک خطای معمولی
	// تبدیل و بلند لاگ می‌شود (بدون افشای key، چون معمولاً همان توکن
	// خام است) تا هم waiterها امن آزاد شوند و هم مشکل واقعی رهگیری‌پذیر بماند.
	func() {
		defer func() {
			if r := recover(); r != nil {
				c.err = fmt.Errorf("singleflight: recovered panic: %v", r)
				log.Printf("[SingleFlight] PANIC RECOVERED (not re-raised): %v\n%s", r, debug.Stack())
			}
		}()
		c.val, c.err = fn()
	}()

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	c.wg.Done()

	return c.val, c.err
}

var firewallStatusSF = &sfGroup{}
var pgUserInfoSF = &sfGroup{}
var firewallCountSF = &sfGroup{}
var pgAdminTokenSF = &sfGroup{}

// ============================================================
// 🔌 Circuit Breaker سراسری برای تمام تماس‌های upstream به PasarGuard
// (شامل هم مسیر اصلی سرو ساب‌اسکریپشن و هم داشبورد ادمین).
// فقط شکست‌های واقعی زیرساختی (شبکه/timeout/5xx) شمارش می‌شوند؛
// نتایج قطعی (VALID/NO_USERNAME/INVALID_TOKEN) هرگز شکست محسوب نمی‌شوند.
// ============================================================
type circuitState int

const (
	circuitClosed circuitState = iota
	circuitOpen
	circuitHalfOpen
)

const (
	circuitFailureThreshold = 5
	circuitOpenDuration     = 30 * time.Second
)

type circuitBreaker struct {
	mu               sync.Mutex
	state            circuitState
	failureCount     int
	openUntil        time.Time
	halfOpenInFlight bool
}

// Allow گزارش می‌دهد که آیا اجازه‌ی تماس واقعی upstream وجود دارد.
// در حالت Half-Open، فقط یک پروب هم‌زمان مجاز است؛ فراخوان‌کننده که
// true دریافت می‌کند، موظف است در ادامه RecordResult را صدا بزند.
func (cb *circuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case circuitOpen:
		if time.Now().Before(cb.openUntil) {
			return false
		}
		cb.state = circuitHalfOpen
		cb.halfOpenInFlight = true
		return true
	case circuitHalfOpen:
		if cb.halfOpenInFlight {
			return false
		}
		cb.halfOpenInFlight = true
		return true
	default: // circuitClosed
		return true
	}
}

func (cb *circuitBreaker) RecordResult(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.halfOpenInFlight = false
	if success {
		cb.state = circuitClosed
		cb.failureCount = 0
		return
	}
	cb.failureCount++
	if cb.state == circuitHalfOpen || cb.failureCount >= circuitFailureThreshold {
		cb.state = circuitOpen
		cb.openUntil = time.Now().Add(circuitOpenDuration)
		cb.failureCount = 0
	}
}

// ReleaseWithoutResult "حق تماس" گرفته‌شده از یک Allow()==true را آزاد
// می‌کند بدون این‌که آن را موفقیت یا شکست upstream حساب کند. برای زمانی
// است که Allow() اجازه داد ولی خودمان (نه upstream) تصمیم گرفتیم اصلاً
// تماس نزنیم — مثلاً چون Rate Limiter یا Semaphore محلی رد کرد. بدون این،
// اگر این رد شدن دقیقاً در حالت Half-Open رخ دهد، halfOpenInFlight برای
// همیشه true می‌ماند و breaker تا ابد قفل می‌شود (چون هیچ تماس بعدی اجازه‌ی
// عبور نمی‌گیرد تا probe بعدی را انجام دهد). برخلاف RecordResult، این تابع
// state و failureCount را دست‌نخورده می‌گذارد چون هیچ اطلاعاتی درباره‌ی
// سلامت واقعی upstream به دست نیامده.
func (cb *circuitBreaker) ReleaseWithoutResult() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.halfOpenInFlight = false
}

var pgCircuitBreaker = &circuitBreaker{}

// ============================================================
// 🪣 Token-Bucket سراسری برای محدودسازی نرخ واقعی تماس با PasarGuard،
// مستقل از تعداد تب مرورگر/ادمین همزمان — محافظت واقعی در سمت سرور،
// نه صرفاً throttle جاوااسکریپتی که قابل دور زدن است.
// ============================================================
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
}

func newTokenBucket(ratePerSec, burst float64) *tokenBucket {
	if ratePerSec <= 0 {
		ratePerSec = 20
	}
	if burst <= 0 {
		burst = ratePerSec * 2
	}
	return &tokenBucket{tokens: burst, maxTokens: burst, refillRate: ratePerSec, lastRefill: time.Now()}
}

func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func envFloatOrDefault(v string, def float64) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || f <= 0 {
		return def
	}
	return f
}

var pgUpstreamRateLimiter = newTokenBucket(
	envFloatOrDefault(PASARGUARD_UPSTREAM_RATE_PER_SEC, 20),
	envFloatOrDefault(PASARGUARD_UPSTREAM_BURST, 40),
)

// ============================================================
// 🚦 محافظت مسیر داغ /sub (سنگین‌ترین و پرترافیک‌ترین endpoint).
// Circuit Breaker با /info به‌صورت *مشترک* استفاده می‌شود (چون سیگنال
// «آیا upstream سالم است» برای هر دو یکی است)، ولی Rate Limiter مجزاست
// تا مصرف توکن یک درخواست واقعی کاربر (که هم /sub و هم /info را صدا
// می‌زند) دوبرابر یک bucket مشترک را خالی نکند. Semaphore هم‌زمانی یک
// محافظت مکمل و مستقل است: Rate Limiter فقط نرخ *شروع* درخواست‌های جدید
// را محدود می‌کند، نه تعداد درخواست‌های در حال انتظار برای یک upstream
// کُند (نه لزوماً خراب).
// ============================================================
var pgSubRateLimiter = newTokenBucket(
	envFloatOrDefault(PASARGUARD_SUB_RATE_PER_SEC, 50),
	envFloatOrDefault(PASARGUARD_SUB_BURST, 100),
)

var pgSubConcurrency = make(chan struct{}, func() int {
	n := parseInt(PASARGUARD_SUB_MAX_CONCURRENT, 100)
	if n <= 0 {
		n = 100
	}
	return n
}())

// isPgUpstreamInfraFailure مشخص می‌کند که آیا یک پاسخ/خطای upstream یک
// شکست زیرساختی واقعی محسوب می‌شود (برای Circuit Breaker) — فقط
// خطای شبکه/DNS/timeout و 5xx. هر status code دیگر (شامل 4xx که می‌تواند
// معنای معتبر کسب‌وکاری مثل «سابسکریپشن منقضی» داشته باشد) هرگز شکست
// زیرساختی محسوب نمی‌شود و رفتار پاس‌شدن به کاربر نهایی را تغییر نمی‌دهد.
func isPgUpstreamInfraFailure(err error, statusCode int) bool {
	if err != nil {
		return true
	}
	return statusCode >= 500
}

// ============================================================
// 🚦 مدل صریح چهار-حالته برای نتیجه‌ی lookup کاربر PasarGuard.
// این تنها محل تفسیر پاسخ/خطای upstream در کل پروژه است.
// ============================================================
type pgUserState string

const (
	pgUserStateValid      pgUserState = "VALID"
	pgUserStateNoUsername pgUserState = "NO_USERNAME"
	pgUserStateInvalid    pgUserState = "INVALID_TOKEN"
	pgUserStateTransient  pgUserState = "TRANSIENT"
)

// سنتینل‌های ماندگار در همان ستون موجود token_status.username — بدون
// تغییر Schema. یک نام‌کاربری واقعی هرگز دقیقاً برابر این رشته‌ها نخواهد بود.
const (
	pgSentinelNoUsername = "__NO_USERNAME__"
	pgSentinelInvalid    = "__INVALID_TOKEN__"
)

const pgTransientCacheTTL = 15 * time.Second
const pgConfidentCacheTTL = 30 * time.Second

// classifyPasarGuardOutcome تنها تابع تفسیر وضعیت HTTP/خطای شبکه در کل
// پروژه است. هیچ محل دیگری نباید مستقیماً statusCode یا err را تفسیر کند.
//
// قوانین:
//   - خطای شبکه/DNS/timeout/context cancellation → TRANSIENT
//   - 200 + JSON معتبر با username غیرخالی → VALID
//   - 200 + JSON معتبر با username خالی → NO_USERNAME
//   - 200 + JSON بدشکل (info==nil) → TRANSIENT (مبهم، هرگز INVALID_TOKEN نیست)
//   - 401/403/404 → INVALID_TOKEN (تنها حالت‌های قطعی شکست احراز هویت/عدم وجود)
//   - 5xx، 429، یا هر کد غیرمنتظره‌ی دیگر → TRANSIENT
func classifyPasarGuardOutcome(statusCode int, err error, info *pasarGuardUserInfo) (pgUserState, *pasarGuardUserInfo) {
	if err != nil {
		return pgUserStateTransient, nil
	}
	switch {
	case statusCode == http.StatusOK && info != nil:
		if strings.TrimSpace(info.Username) == "" {
			return pgUserStateNoUsername, info
		}
		return pgUserStateValid, info
	case statusCode == http.StatusOK && info == nil:
		return pgUserStateTransient, nil
	case statusCode == http.StatusUnauthorized,
		statusCode == http.StatusForbidden,
		statusCode == http.StatusNotFound:
		return pgUserStateInvalid, nil
	default:
		// شامل 5xx، 429 (rate limit خودِ upstream)، و هر کد غیرمنتظره‌ی دیگر.
		return pgUserStateTransient, nil
	}
}

// ============================================================
// 💾 نوشتن Async/Batched نتایج قطعی (VALID/NO_USERNAME/INVALID_TOKEN)
// دقیقاً با همان الگوی صف+pending-map+ticker موجود پروژه
// (firewallStatusQueue/firewallPendingSuspicious) بازسازی شده — نه یک
// انتزاع جدید. TRANSIENT هرگز به این صف نمی‌رسد.
// ============================================================
type pgStateWriteEvent struct {
	Token    string
	State    pgUserState
	Username string
}

var pgStateWriteQueue chan pgStateWriteEvent
var pgStateWriteOnce sync.Once

var pgPendingWritesMu sync.Mutex
var pgPendingWrites = make(map[string]pgStateWriteEvent)
var pgQueuedWrites = make(map[string]struct{})

func startPgStateWriter() {
	pgStateWriteOnce.Do(func() {
		pgStateWriteQueue = make(chan pgStateWriteEvent, firewallStatusWriterBuffer)
		go func() {
			for event := range pgStateWriteQueue {
				err := writePgUserState(event)
				pgPendingWritesMu.Lock()
				delete(pgQueuedWrites, event.Token)
				if err == nil {
					// 📌 Compare-and-Delete: فقط اگر مقدار pending هنوز دقیقاً
					// همان eventی است که همین الان نوشتیم حذفش می‌کنیم. اگر در
					// همین حین یک event جدیدتر جایگزین شده باشد (Lost Update)،
					// آن را دست‌نخورده می‌گذاریم؛ چون چند خط بالاتر
					// pgQueuedWrites همین الان پاک شد، تیکر ۵۰۰ms بعدی
					// (flushPendingPgStateWrites) آن مقدار جدیدتر را با
					// موفقیت دوباره صف می‌کند.
					if current, ok := pgPendingWrites[event.Token]; ok && current == event {
						delete(pgPendingWrites, event.Token)
					}
				}
				pgPendingWritesMu.Unlock()
				if err != nil {
					// توکن خام هرگز لاگ نمی‌شود.
					log.Printf("[PasarGuard] persisting user state failed: %v", err)
				}
			}
		}()

		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for range ticker.C {
				flushPendingPgStateWrites()
			}
		}()
	})
}

func enqueuePgStateWrite(event pgStateWriteEvent) {
	if db == nil || strings.TrimSpace(event.Token) == "" {
		return
	}
	startPgStateWriter()

	pgPendingWritesMu.Lock()
	pgPendingWrites[event.Token] = event
	pgPendingWritesMu.Unlock()

	queuePendingPgStateWrite(event.Token)
}

func queuePendingPgStateWrite(token string) {
	pgPendingWritesMu.Lock()
	event, pending := pgPendingWrites[token]
	if !pending {
		pgPendingWritesMu.Unlock()
		return
	}
	if _, queued := pgQueuedWrites[token]; queued {
		pgPendingWritesMu.Unlock()
		return
	}
	pgQueuedWrites[token] = struct{}{}
	pgPendingWritesMu.Unlock()

	select {
	case pgStateWriteQueue <- event:
	default:
		pgPendingWritesMu.Lock()
		delete(pgQueuedWrites, token)
		pgPendingWritesMu.Unlock()
	}
}

func flushPendingPgStateWrites() {
	pgPendingWritesMu.Lock()
	pending := make([]string, 0, len(pgPendingWrites))
	for token := range pgPendingWrites {
		pending = append(pending, token)
	}
	pgPendingWritesMu.Unlock()

	for _, token := range pending {
		queuePendingPgStateWrite(token)
	}
}

func writePgUserState(event pgStateWriteEvent) error {
	if db == nil {
		return sql.ErrConnDone
	}
	var value string
	switch event.State {
	case pgUserStateValid:
		value = event.Username
	case pgUserStateNoUsername:
		value = pgSentinelNoUsername
	case pgUserStateInvalid:
		value = pgSentinelInvalid
	default:
		// TRANSIENT هرگز نباید به اینجا برسد؛ محافظت دفاعی.
		return nil
	}
	_, err := db.Exec(`
		INSERT INTO token_status(token, is_suspicious, admin_warn_mode, admin_burn_mode, username)
		VALUES (?, 0, 0, 0, ?)
		ON CONFLICT(token) DO UPDATE SET username = excluded.username
	`, event.Token, value)
	return err
}

// pgLookupResult نتیجه‌ی یکپارچه‌ی resolvePasarGuardUser است.
type pgLookupResult struct {
	State    pgUserState
	Username string
	Info     *pasarGuardUserInfo
}

func pgPersistValueFor(state pgUserState, username string) string {
	switch state {
	case pgUserStateValid:
		return username
	case pgUserStateNoUsername:
		return pgSentinelNoUsername
	case pgUserStateInvalid:
		return pgSentinelInvalid
	default:
		return ""
	}
}

// resolvePasarGuardUser تنها نقطه‌ی ورودی برای هر نوع lookup کاربر
// PasarGuard در کل پروژه است (هم مسیر داغ سرو ساب‌اسکریپشن، هم داشبورد
// ادمین/Lazy-Load). این تابع:
//  1. ابتدا کش TTL درون‌حافظه‌ای را چک می‌کند (بدون I/O).
//  2. در صورت miss، از طریق Single-Flight (کلید=توکن) اطمینان می‌دهد که
//     حداکثر یک تماس واقعی upstream برای هر توکن هم‌زمان در جریان باشد.
//  3. قبل از تماس واقعی، Circuit Breaker و Rate Limiter سراسری را چک
//     می‌کند؛ رد شدن توسط هرکدام همیشه TRANSIENT برمی‌گرداند، هرگز
//     INVALID_TOKEN.
//  4. فقط نتایج قطعی (VALID/NO_USERNAME/INVALID_TOKEN) و فقط در صورت
//     تغییر نسبت به آخرین مقدار ماندگارشده، به‌صورت async/batched در DB
//     نوشته می‌شوند. شکست نوشتن DB هرگز نتیجه‌ی برگشتی به فراخوان را
//     تغییر نمی‌دهد.
func resolvePasarGuardUser(token string) pgLookupResult {
	token = strings.TrimSpace(token)
	if token == "" {
		return pgLookupResult{State: pgUserStateTransient}
	}

	now := time.Now()
	pgUserInfoCacheLock.RLock()
	cached, hit := pgUserInfoCache[token]
	pgUserInfoCacheLock.RUnlock()
	if hit && now.Before(cached.expiresAt) {
		return pgLookupResult{State: cached.state, Username: pgUsernameFromCache(cached), Info: cached.info}
	}

	v, err := pgUserInfoSF.Do(token, func() (interface{}, error) {
		return pgDoResolve(token), nil
	})
	if err != nil {
		return pgLookupResult{State: pgUserStateTransient}
	}
	result, ok := v.(pgLookupResult)
	if !ok {
		return pgLookupResult{State: pgUserStateTransient}
	}
	return result
}

func pgUsernameFromCache(c cachedUserInfo) string {
	if c.state == pgUserStateValid && c.info != nil {
		return c.info.Username
	}
	return ""
}

// pgDoResolve تنها از داخل Single-Flight (پس حداکثر یک اجرای هم‌زمان
// به‌ازای هر توکن) فراخوانی می‌شود؛ تماس واقعی upstream، ثبت نتیجه در
// Circuit Breaker، به‌روزرسانی کش، و صف‌کردن نوشتن DB را انجام می‌دهد.
func pgDoResolve(token string) pgLookupResult {
	// یک بار دیگر کش را چک می‌کنیم (ممکن است leader قبلی همین لحظه پر کرده باشد).
	now := time.Now()
	pgUserInfoCacheLock.RLock()
	prev, hadPrev := pgUserInfoCache[token]
	pgUserInfoCacheLock.RUnlock()
	if hadPrev && now.Before(prev.expiresAt) {
		return pgLookupResult{State: prev.state, Username: pgUsernameFromCache(prev), Info: prev.info}
	}

	var state pgUserState
	var info *pasarGuardUserInfo

	if !pgCircuitBreaker.Allow() {
		state, info = pgUserStateTransient, nil
	} else {
		// 📌 Exception-Safe Ownership Cleanup: از همین‌جا به بعد، اگر این
		// بلوک از هر مسیری (return عادی یا یک panic پیش‌بینی‌نشده در
		// آینده) خارج شود بدون این‌که RecordResult واقعی صدا زده باشد،
		// این defer به‌طور خودکار "حق تماس" گرفته‌شده از Allow() را آزاد
		// می‌کند. این جلوی قفل‌شدن ابدی Half-Open را می‌گیرد.
		consumed := false
		defer func() {
			if !consumed {
				pgCircuitBreaker.ReleaseWithoutResult()
			}
		}()

		if !pgUpstreamRateLimiter.Allow() {
			state, info = pgUserStateTransient, nil
			// رد شدن توسط Rate Limiter یک شکست زیرساختی upstream نیست؛
			// defer بالا به‌جای ما "حق تماس" را آزاد می‌کند.
		} else {
			state, info = fetchPasarGuardUserInfoClassified(token)
			pgCircuitBreaker.RecordResult(state != pgUserStateTransient)
			consumed = true
		}
	}

	username := ""
	if state == pgUserStateValid && info != nil {
		username = info.Username
	}

	ttl := pgConfidentCacheTTL
	persistedValue := prev.persistedValue
	if state == pgUserStateTransient {
		ttl = pgTransientCacheTTL
	} else {
		newValue := pgPersistValueFor(state, username)
		if !hadPrev || prev.persistedValue != newValue {
			enqueuePgStateWrite(pgStateWriteEvent{Token: token, State: state, Username: username})
		}
		persistedValue = newValue
	}

	pgUserInfoCacheLock.Lock()
	if len(pgUserInfoCache) >= firewallCacheLimit {
		sampledEvict(pgUserInfoCache, func(v cachedUserInfo) time.Time {
			return v.expiresAt
		})
	}
	pgUserInfoCache[token] = cachedUserInfo{
		info:           info,
		state:          state,
		persistedValue: persistedValue,
		expiresAt:      time.Now().Add(ttl),
	}
	pgUserInfoCacheLock.Unlock()

	return pgLookupResult{State: state, Username: username, Info: info}
}

var firewallSettingsMu sync.RWMutex
var firewallSettingsCache FirewallSettings
var firewallSettingsExpires time.Time

var firewallStatusMu sync.RWMutex
var firewallStatusCache = make(map[string]firewallStatusCacheItem)

var firewallReservationMu sync.Mutex
var firewallPendingSlots = make(map[string]int)
var firewallPendingDevices = make(map[string]int)

// ============================================================
// 🕰️ Per-Token Generation/Epoch
// جلوگیری از Resurrection: وقتی resetFirewallToken یک توکن را کاملاً پاک
// می‌کند، ممکن است یک رویداد async قدیمی‌تر (در firewallDeviceQueue یا
// firewallStatusQueue) که قبل از reset ساخته شده، چند میلی‌ثانیه بعد از
// reset پردازش شود و همان چیزی که پاک شد را دوباره بنویسد. هر توکن یک
// شماره‌ی نسل (generation) دارد که resetFirewallToken آن را +۱ می‌کند؛
// رویدادها generation را در لحظه‌ی *ساخته‌شدن* ثبت می‌کنند و worker قبل
// از اعمال نوشتن، آن را با generation فعلی توکن مقایسه می‌کند.
//
// ⚠️ این نقشه عمداً هرگز evict نمی‌شود. اگر یک entry حذف شود و بعداً دوباره
// برای همان توکن ساخته شود، currentTokenGeneration به‌اشتباه صفر برمی‌گرداند
// — یعنی یک event قدیمی با generation=0 (از قبل از هر reset) دوباره با
// generation فعلی «صفرِ بازسازی‌شده» برابر می‌شود و داده‌ی پاک‌شده Resurrect
// می‌شود. صحت این نقشه از محدودبودن مصرف حافظه‌اش مهم‌تر است؛ چون فقط با
// اکشن دستی ادمین (نه ترافیک مهاجم) رشد می‌کند، این ریسک پذیرفته‌شده است.
// ============================================================
type tokenGenerationEntry struct {
	Gen        uint64
	LastBumped time.Time
}

var firewallGenerationMu sync.Mutex
var firewallGeneration = make(map[string]tokenGenerationEntry)

func currentTokenGeneration(token string) uint64 {
	firewallGenerationMu.Lock()
	defer firewallGenerationMu.Unlock()
	return firewallGeneration[token].Gen
}

func bumpTokenGeneration(token string) uint64 {
	firewallGenerationMu.Lock()
	defer firewallGenerationMu.Unlock()
	entry := firewallGeneration[token]
	entry.Gen++
	entry.LastBumped = time.Now()
	firewallGeneration[token] = entry
	return entry.Gen
}

type firewallDeviceEvent struct {
	Token string
	IP    string
	OS    string
	// ClientApp صرفاً تله‌متری است — هرگز در firewallDeviceKey، uniqueness،
	// یا هیچ منطق enforcement/تصمیم امنیتی استفاده نمی‌شود.
	ClientApp string
	// Generation در لحظه‌ی ساخته‌شدن این event ثبت می‌شود (نه در لحظه‌ی
	// پردازش). اگر تا آن‌موقع resetFirewallToken اجرا شده باشد، generation
	// فعلی توکن از این مقدار جلوتر خواهد بود و worker این event را نادیده می‌گیرد.
	Generation uint64
}

var firewallDeviceQueue chan firewallDeviceEvent
var firewallDeviceOnce sync.Once

// ============================================================
// 🔒 firewallDBWriteMu
// نکته: بدون این قفل، بین چک‌کردن generation و اجرای db.Exec یک پنجره‌ی
// race باز است — اگر resetFirewallToken دقیقاً در همین فاصله اجرا شود
// (generation را +۱ کند و رکورد را پاک/ریست کند)، worker همچنان با
// generation قدیمیِ از‌قبل-تأییدشده به نوشتن ادامه می‌دهد و داده‌ی
// عمداً پاک‌شده را Resurrect می‌کند. با این قفل، «چک generation + نوشتن
// DB» در workerها و «bump generation + نوشتن DB» در resetFirewallToken
// نسبت به هم غیرقابل‌تقسیم (atomic) می‌شوند — این پنجره کاملاً بسته می‌شود.
// ============================================================
var firewallDBWriteMu sync.Mutex

func startFirewallDeviceWriter() {
	firewallDeviceOnce.Do(func() {
		firewallDeviceQueue = make(chan firewallDeviceEvent, firewallWriterBuffer)
		go func() {
			for event := range firewallDeviceQueue {
				firewallDBWriteMu.Lock()
				if currentTokenGeneration(event.Token) != event.Generation {
					// یک reset بین ساخته‌شدن و پردازش این event رخ داده؛
					// نوشتن آن یعنی Resurrection داده‌ی عمداً پاک‌شده.
					firewallDBWriteMu.Unlock()
					releaseFirewallDeviceReservation(event.Token, event.IP, event.OS)
					continue
				}
				now := time.Now().Unix()
				// 📌 client_app صرفاً تله‌متری است؛ اگر migration آن ستون
				// ناموفق بوده، هرگز کوئری‌ای که به آن ارجاع می‌دهد اجرا
				// نمی‌شود — دقیقاً همان INSERT قبلی، بدون تغییر.
				var err error
				if clientAppColumnAvailable.Load() {
					_, err = db.Exec(`
						INSERT OR IGNORE INTO ip_tracking_logs(token,ip_address,os_type,first_seen,client_app)
						VALUES (?,?,?,?,?)
					`, event.Token, event.IP, event.OS, now, event.ClientApp)
				} else {
					_, err = db.Exec(`
						INSERT OR IGNORE INTO ip_tracking_logs(token,ip_address,os_type,first_seen)
						VALUES (?,?,?,?)
					`, event.Token, event.IP, event.OS, now)
				}
				if err != nil {
					log.Printf("[Firewall] device insert failed: %v", err)
				}
				if _, err := db.Exec(`
					INSERT INTO token_status(token, is_suspicious, admin_warn_mode, admin_burn_mode, last_active)
					VALUES (?, 0, 0, 0, ?)
					ON CONFLICT(token) DO UPDATE SET last_active = excluded.last_active
				`, event.Token, now); err != nil {
					log.Printf("[Firewall] last_active update failed: %v", err)
				}
				firewallDBWriteMu.Unlock()
				releaseFirewallDeviceReservation(event.Token, event.IP, event.OS)
			}
		}()
	})
}

func firewallDeviceKey(token, ip, osType string) string {
	return token + "\x00" + ip + "\x00" + osType
}

// ============================================================
// 🧹 last_active Touch: هر اتصال (نه فقط دستگاه جدید) این مقدار
// را async و throttled به‌روز می‌کند تا GC فقط توکن‌های واقعاً
// «روح» (بدون هیچ اتصالی) را پاک کند، نه توکن‌های فعال با دستگاه ثابت.
// ============================================================
const firewallTouchThrottle = 5 * time.Minute

var firewallTouchQueue chan string
var firewallTouchOnce sync.Once

var firewallLastTouchMu sync.RWMutex
var firewallLastTouchAt = make(map[string]time.Time)

func startFirewallTouchWriter() {
	firewallTouchOnce.Do(func() {
		firewallTouchQueue = make(chan string, firewallWriterBuffer)
		go func() {
			for token := range firewallTouchQueue {
				// 📌 این نوشتن هم اکنون زیر firewallDBWriteMu سریالایز می‌شود.
				// این برای صحت GC حیاتی است: GC (پردازش inactiveTokens) قبل
				// از حذف یک ردیف، last_active را زیر همین قفل دوباره
				// re-validate می‌کند؛ اگر این writer از این قفل عبور نکند،
				// می‌تواند دقیقاً در وسط پنجره‌ی validate-تا-commit یک
				// last_active تازه بنویسد که GC هرگز نمی‌بیند.
				firewallDBWriteMu.Lock()
				if _, err := db.Exec(`
					INSERT INTO token_status(token, is_suspicious, admin_warn_mode, admin_burn_mode, last_active)
					VALUES (?, 0, 0, 0, ?)
					ON CONFLICT(token) DO UPDATE SET last_active = excluded.last_active
				`, token, time.Now().Unix()); err != nil {
					log.Printf("[Firewall] last_active touch write failed: %v", err)
				}
				firewallDBWriteMu.Unlock()
			}
		}()
	})
}

func touchFirewallLastActive(token string) {
	if db == nil {
		return
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}

	now := time.Now()

	// مسیر سریع: فقط RLock — اکثر ترافیک مشروع (توکن اخیراً touch شده)
	// از همین‌جا بدون هیچ قفل انحصاری برمی‌گردد.
	firewallLastTouchMu.RLock()
	last, ok := firewallLastTouchAt[token]
	firewallLastTouchMu.RUnlock()
	if ok && now.Sub(last) < firewallTouchThrottle {
		return
	}

	// مسیر کند: نیاز به جهش‌دادن نقشه، پس Lock انحصاری می‌گیریم و
	// شرط را دوباره زیر آن چک می‌کنیم (double-checked locking).
	firewallLastTouchMu.Lock()
	if last, ok := firewallLastTouchAt[token]; ok && now.Sub(last) < firewallTouchThrottle {
		firewallLastTouchMu.Unlock()
		return
	}
	if len(firewallLastTouchAt) >= firewallCacheLimit {
		sampledEvict(firewallLastTouchAt, func(t time.Time) time.Time { return t })
	}
	firewallLastTouchAt[token] = now
	firewallLastTouchMu.Unlock()

	startFirewallTouchWriter()
	select {
	case firewallTouchQueue <- token:
	default:
		// صف پر است؛ throttle window در دور بعدی دوباره تلاش می‌کند، رکورد گم نمی‌شود چون last_active فقط برای GC حیاتی است نه امنیت
	}
}

func reserveFirewallDevice(token, ip, osType string, currentCount, maxDevices int, exists bool) (allowed bool, newlyReserved bool) {
	if exists {
		return true, false
	}

	key := firewallDeviceKey(token, ip, osType)

	firewallReservationMu.Lock()
	defer firewallReservationMu.Unlock()

	if firewallPendingDevices[key] > 0 {
		return true, false
	}

	effectiveCount := currentCount + firewallPendingSlots[token]
	if effectiveCount >= maxDevices {
		return false, false
	}

	firewallPendingSlots[token]++
	firewallPendingDevices[key]++
	return true, true
}

func releaseFirewallDeviceReservation(token, ip, osType string) {
	key := firewallDeviceKey(token, ip, osType)
	firewallReservationMu.Lock()
	defer firewallReservationMu.Unlock()

	if firewallPendingDevices[key] > 0 {
		delete(firewallPendingDevices, key)
		if firewallPendingSlots[token] > 0 {
			firewallPendingSlots[token]--
		}
		if firewallPendingSlots[token] <= 0 {
			delete(firewallPendingSlots, token)
		}
	}
}

func queueFirewallDevice(event firewallDeviceEvent) bool {
	startFirewallDeviceWriter()
	select {
	case firewallDeviceQueue <- event:
		return true
	default:
		return false
	}
}

func FirewallCheck(r *http.Request, token string) FirewallDecision {
	settings := getFirewallSettings()
	result := FirewallDecision{
		Allow:         true,
		WarningConfig: settings.WarningFakeConfig,
		BlockConfig:   settings.BlockFakeConfig,
	}

	if !settings.Enabled {
		return result
	}

	// 📌 last_active باید «آخرین اتصال از هر نوع» را نشان دهد، نه فقط دستگاه‌های جدید.
	// این فراخوانی throttled و کاملاً async است؛ هیچ تأخیری به مسیر اصلی اضافه نمی‌کند.
	touchFirewallLastActive(token)

	status := getFirewallStatus(token)
	result.Suspicious = status.Suspicious
	result.AdminWarn = status.Warn
	result.AdminBurn = status.Burn

	if status.Burn {
		result.Allow = false
		return result
	}

	ip := extractClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	osType := detectClientOS(userAgent)
	// 📌 clientApp صرفاً تله‌متری است — عمداً به checkFirewallDevice/
	// reserveFirewallDevice/firewallDeviceKey داده نمی‌شود تا معنای
	// uniqueness/MaxDevices دست‌نخورده بماند.
	clientApp := detectClientApp(userAgent)
	if ip == "" {
		return result
	}

	count, exists, err := checkFirewallDevice(token, ip, osType, settings.ResetWindowHours)
	if err != nil {
		log.Printf("[Firewall] device check failed for token=%q: %v; fail-open", token, err)
		return result
	}

	if !exists {
		allowed, newlyReserved := reserveFirewallDevice(token, ip, osType, count, settings.MaxDevices, exists)
		if !allowed {
			result.Allow = false
			return result
		}
		if newlyReserved {
			if !queueFirewallDevice(firewallDeviceEvent{Token: token, IP: ip, OS: osType, ClientApp: clientApp, Generation: currentTokenGeneration(token)}) {
				releaseFirewallDeviceReservation(token, ip, osType)
				result.Allow = false
				return result
			}
		}
	}

	firewallReservationMu.Lock()
	pendingSlots := firewallPendingSlots[token]
	firewallReservationMu.Unlock()

	effectiveCount := count + pendingSlots
	if !status.Suspicious && effectiveCount >= settings.SuspicionThreshold {
		asyncMarkSuspicious(token)
		result.Suspicious = true
	}

	return result
}

func getFirewallSettings() FirewallSettings {
	now := time.Now()
	firewallSettingsMu.RLock()
	cached := firewallSettingsCache
	expires := firewallSettingsExpires
	firewallSettingsMu.RUnlock()

	if now.Before(expires) {
		return cached
	}

	settings := FirewallSettings{
		Enabled:               true,
		SuspicionThreshold:    3,
		MaxDevices:            5,
		ResetWindowHours:      firewallDefaultResetHours,
		GCIntervalHours:       firewallDefaultGCInterval,
		InactiveRetentionDays: firewallDefaultInactiveDays,
	}

	if db == nil {
		return settings
	}

	rows, err := db.Query("SELECT key, value FROM firewall_settings")
	if err == nil {
		for rows.Next() {
			var key, value string
			if err := rows.Scan(&key, &value); err != nil {
				continue
			}
			switch key {
			case "firewall_enabled":
				settings.Enabled = parseBool(value)
			case "suspicion_threshold":
				settings.SuspicionThreshold = parseInt(value, settings.SuspicionThreshold)
			case "max_devices_per_token":
				settings.MaxDevices = parseInt(value, settings.MaxDevices)
			case "reset_window_hours":
				settings.ResetWindowHours = parseInt(value, settings.ResetWindowHours)
			case "gc_interval_hours":
				settings.GCIntervalHours = parseInt(value, settings.GCIntervalHours)
			case "inactive_retention_days":
				settings.InactiveRetentionDays = parseInt(value, settings.InactiveRetentionDays)
			case "warning_fake_config":
				settings.WarningFakeConfig = value
			case "block_fake_config":
				settings.BlockFakeConfig = value
			}
		}
		rows.Close()
	}

	if settings.SuspicionThreshold <= 0 {
		settings.SuspicionThreshold = 3
	}
	if settings.MaxDevices <= settings.SuspicionThreshold {
		settings.MaxDevices = settings.SuspicionThreshold + 1
	}
	if settings.ResetWindowHours <= 0 {
		settings.ResetWindowHours = firewallDefaultResetHours
	}
	if settings.GCIntervalHours <= 0 {
		settings.GCIntervalHours = firewallDefaultGCInterval
	}
	if settings.InactiveRetentionDays <= 0 {
		settings.InactiveRetentionDays = firewallDefaultInactiveDays
	}

	firewallSettingsMu.Lock()
	firewallSettingsCache = settings
	firewallSettingsExpires = now.Add(firewallSettingsTTL)
	firewallSettingsMu.Unlock()

	return settings
}

func InvalidateFirewallSettingsCache() {
	firewallSettingsMu.Lock()
	firewallSettingsExpires = time.Time{}
	firewallSettingsMu.Unlock()
}

func parseBool(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func parseInt(v string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func getFirewallStatus(token string) firewallStatus {
	now := time.Now()
	firewallStatusMu.RLock()
	item, ok := firewallStatusCache[token]
	firewallStatusMu.RUnlock()
	if ok && now.Before(item.Expire) {
		return item.Status
	}

	// Single-Flight: چند درخواست هم‌زمان برای همان توکن که کش‌شان همین
	// الان منقضی شده، فقط یک بار DB را می‌خوانند، نه یکی به‌ازای هرکدام.
	v, err := firewallStatusSF.Do(token, func() (interface{}, error) {
		refreshNow := time.Now()

		// یک بار دیگر کش را چک می‌کنیم؛ ممکن است leader قبلی همین الان پر کرده باشد.
		firewallStatusMu.RLock()
		if item, ok := firewallStatusCache[token]; ok && refreshNow.Before(item.Expire) {
			firewallStatusMu.RUnlock()
			return item.Status, nil
		}
		firewallStatusMu.RUnlock()

		var status firewallStatus
		if db != nil {
			err := db.QueryRow(`
				SELECT is_suspicious, admin_warn_mode, admin_burn_mode
				FROM token_status
				WHERE token = ?
			`, token).Scan(&status.Suspicious, &status.Warn, &status.Burn)
			if err != nil {
				status = firewallStatus{}
			}
		}

		firewallStatusMu.Lock()
		if len(firewallStatusCache) >= firewallCacheLimit {
			sampledEvict(firewallStatusCache, func(v firewallStatusCacheItem) time.Time {
				return v.LastUsed
			})
		}
		firewallStatusCache[token] = firewallStatusCacheItem{
			Status:   status,
			Expire:   refreshNow.Add(firewallStatusTTL),
			LastUsed: refreshNow,
		}
		firewallStatusMu.Unlock()

		return status, nil
	})
	if err != nil {
		return firewallStatus{}
	}
	result, ok := v.(firewallStatus)
	if !ok {
		return firewallStatus{}
	}
	return result
}

func invalidateFirewallStatus(token string) {
	firewallStatusMu.Lock()
	delete(firewallStatusCache, token)
	firewallStatusMu.Unlock()
}

func checkFirewallDevice(token, ip, osType string, resetHours int) (count int, exists bool, err error) {
	if db == nil {
		return 0, false, sql.ErrConnDone
	}
	cutoff := time.Now().Add(-time.Duration(resetHours) * time.Hour).Unix()
	var existsInt sql.NullInt64
	err = db.QueryRow(`
		SELECT COUNT(*),
		       MAX(CASE WHEN ip_address = ? AND os_type = ? THEN 1 ELSE 0 END)
		FROM ip_tracking_logs
		WHERE token = ? AND first_seen >= ?
	`, ip, osType, token, cutoff).Scan(&count, &existsInt)
	if err != nil {
		return 0, false, err
	}
	return count, existsInt.Valid && existsInt.Int64 != 0, nil
}

type firewallSuspiciousEvent struct {
	Token      string
	Generation uint64
}

var firewallStatusQueue chan firewallSuspiciousEvent
var firewallStatusOnce sync.Once

var firewallPendingSuspiciousMu sync.Mutex

// 📌 مقدار این نقشه دیگر صرفاً struct{} (presence) نیست: generationی که در
// لحظه‌ی *تصمیم* (داخل asyncMarkSuspicious) گرفته شده را نگه می‌دارد. این
// برای مسیر retry (flushPendingFirewallSuspicious) حیاتی است — بدون آن،
// یک retry مجبور می‌شد generation را دوباره از currentTokenGeneration
// بخواند که دقیقاً همان race شرح‌داده‌شده در ممیزی را روی مسیر retry
// بازتولید می‌کند.
var firewallPendingSuspicious = make(map[string]uint64)
var firewallQueuedSuspicious = make(map[string]struct{})

func startFirewallStatusWriter() {
	firewallStatusOnce.Do(func() {
		firewallStatusQueue = make(chan firewallSuspiciousEvent, firewallStatusWriterBuffer)
		go func() {
			for event := range firewallStatusQueue {
				firewallDBWriteMu.Lock()
				if currentTokenGeneration(event.Token) != event.Generation {
					// یک reset بین صف‌شدن و پردازش این event رخ داده؛
					// نوشتن is_suspicious=1 یعنی Resurrection وضعیت پاک‌شده.
					firewallDBWriteMu.Unlock()
					firewallPendingSuspiciousMu.Lock()
					delete(firewallQueuedSuspicious, event.Token)
					// 📌 فقط اگر pending هنوز دقیقاً همین generation قدیمی را
					// نشان می‌دهد حذفش می‌کنیم. اگر در همین حین یک تصمیم
					// جدیدتر (generation بزرگ‌تر) ثبت شده باشد، این event
					// قدیمی حق ندارد آن را پاک/بی‌اثر کند — باید برای
					// flushPendingFirewallSuspicious بعدی دست‌نخورده بماند.
					if storedGen, exists := firewallPendingSuspicious[event.Token]; exists && storedGen == event.Generation {
						delete(firewallPendingSuspicious, event.Token)
					}
					firewallPendingSuspiciousMu.Unlock()
					continue
				}
				err := writeSuspiciousStatus(event.Token)
				firewallDBWriteMu.Unlock()

				firewallPendingSuspiciousMu.Lock()
				delete(firewallQueuedSuspicious, event.Token)
				if err == nil {
					// 📌 همان محافظت: یک نوشتن موفق برای این generation نباید
					// یک تصمیم جدیدتر که در همین حین pending شده را پاک کند.
					if storedGen, exists := firewallPendingSuspicious[event.Token]; exists && storedGen == event.Generation {
						delete(firewallPendingSuspicious, event.Token)
					}
				}
				firewallPendingSuspiciousMu.Unlock()

				if err != nil {
					log.Printf("[Firewall] suspicious status write failed for token=%q: %v", event.Token, err)
				}
				invalidateFirewallStatus(event.Token)
			}
		}()

		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for range ticker.C {
				flushPendingFirewallSuspicious()
			}
		}()
	})
}

func asyncMarkSuspicious(token string) {
	if strings.TrimSpace(token) == "" || db == nil {
		return
	}
	// 📌 Generation باید در همین‌جا — نزدیک‌ترین ممکن به لحظه‌ی واقعی
	// تصمیم‌گیری در FirewallCheck — خوانده و *ذخیره* شود، نه بعداً هنگام
	// صف‌بندی یا retry دوباره خوانده شود. وگرنه یک reset هم‌زمان می‌تواند
	// این event را (حتی در یک retry دقایق بعد) با generation جدید
	// اشتباهاً مهر بزند.
	gen := currentTokenGeneration(token)

	invalidateFirewallStatus(token)
	startFirewallStatusWriter()

	// 📌 Compare-and-Update: اگر یک entry pending قدیمی‌تر (generation
	// کوچک‌تر) از قبل وجود دارد، آن را با generation جدیدتر جایگزین
	// می‌کنیم به‌جای این‌که فقط به‌خاطر وجود یک entry قدیمی، این تصمیم
	// جدیدتر را کاملاً نادیده بگیریم. اگر storedGen از قبل >= gen باشد
	// (یعنی یک تصمیم مساوی یا جدیدتر از این هم از قبل pending است)، نیازی
	// به کاری نیست.
	firewallPendingSuspiciousMu.Lock()
	if storedGen, exists := firewallPendingSuspicious[token]; exists {
		if storedGen >= gen {
			firewallPendingSuspiciousMu.Unlock()
			return
		}
	}
	firewallPendingSuspicious[token] = gen
	firewallPendingSuspiciousMu.Unlock()

	queuePendingFirewallSuspicious(token, gen)
}

func queuePendingFirewallSuspicious(token string, gen uint64) {
	firewallPendingSuspiciousMu.Lock()
	if _, pending := firewallPendingSuspicious[token]; !pending {
		firewallPendingSuspiciousMu.Unlock()
		return
	}
	if _, queued := firewallQueuedSuspicious[token]; queued {
		firewallPendingSuspiciousMu.Unlock()
		return
	}
	firewallQueuedSuspicious[token] = struct{}{}
	firewallPendingSuspiciousMu.Unlock()

	// 📌 gen پارامتر ورودی است — همان مقداری که در لحظه‌ی تصمیم (یا در
	// retryهای بعدی، همان مقدار اصلی ذخیره‌شده در firewallPendingSuspicious)
	// گرفته شده. اینجا هرگز currentTokenGeneration دوباره خوانده نمی‌شود.
	select {
	case firewallStatusQueue <- firewallSuspiciousEvent{Token: token, Generation: gen}:
	default:
		firewallPendingSuspiciousMu.Lock()
		delete(firewallQueuedSuspicious, token)
		firewallPendingSuspiciousMu.Unlock()
	}
}

func flushPendingFirewallSuspicious() {
	firewallPendingSuspiciousMu.Lock()
	pending := make(map[string]uint64, len(firewallPendingSuspicious))
	for token, gen := range firewallPendingSuspicious {
		pending[token] = gen
	}
	firewallPendingSuspiciousMu.Unlock()

	for token, gen := range pending {
		// 📌 gen همان مقدار *اصلی* ذخیره‌شده در نقشه است، نه یک خواندن تازه —
		// این دقیقاً همان چیزی است که مسیر retry را ایمن می‌کند.
		queuePendingFirewallSuspicious(token, gen)
	}
}

func writeSuspiciousStatus(token string) error {
	_, err := db.Exec(`
		INSERT INTO token_status(token,is_suspicious,admin_warn_mode,admin_burn_mode)
		VALUES (?,1,0,0)
		ON CONFLICT(token) DO UPDATE SET is_suspicious=1
	`, token)
	return err
}

func setFirewallWarning(token string, enabled bool) error {
	return setFirewallFlag(token, "admin_warn_mode", enabled)
}

func setFirewallBurn(token string, enabled bool) error {
	return setFirewallFlag(token, "admin_burn_mode", enabled)
}

func setFirewallFlag(token, flag string, enabled bool) error {
	if db == nil {
		return sql.ErrConnDone
	}
	if strings.TrimSpace(token) == "" {
		return sql.ErrNoRows
	}
	if flag != "admin_warn_mode" && flag != "admin_burn_mode" && flag != "is_suspicious" {
		return sql.ErrNoRows
	}
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO token_status(token,is_suspicious,admin_warn_mode,admin_burn_mode)
		VALUES (?,0,0,0)
	`, token); err != nil {
		return err
	}
	value := 0
	if enabled {
		value = 1
	}
	_, err := db.Exec("UPDATE token_status SET "+flag+" = ? WHERE token = ?", value, token)
	if err == nil {
		invalidateFirewallStatus(token)
	}
	return err
}

func toggleFirewallWarning(token string) (bool, error) {
	if db == nil {
		return false, sql.ErrConnDone
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return false, sql.ErrNoRows
	}

	if _, err := db.Exec(`
		INSERT OR IGNORE INTO token_status(token,is_suspicious,admin_warn_mode,admin_burn_mode)
		VALUES (?,0,0,0)
	`, token); err != nil {
		return false, err
	}

	var current int
	if err := db.QueryRow("SELECT admin_warn_mode FROM token_status WHERE token = ?", token).Scan(&current); err != nil {
		return false, err
	}

	newState := current == 0
	if err := setFirewallWarning(token, newState); err != nil {
		return false, err
	}
	return newState, nil
}

func resetFirewallToken(token string) error {
	if db == nil {
		return sql.ErrConnDone
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return sql.ErrNoRows
	}

	// 📌 firewallDBWriteMu اینجا هم گرفته می‌شود تا «bump generation +
	// نوشتن DB» نسبت به «چک generation + نوشتن DB» در workerهای async
	// (device/status) غیرقابل‌تقسیم باشد. بدون این قفل مشترک، بین چک
	// generation در worker و اجرای db.Exec آن، دقیقاً همین‌جا می‌توانست
	// reset اجرا شود و worker همچنان با generation قدیمیِ از‌قبل-تأییدشده
	// بنویسد (Resurrection). با این قفل، این دو دیگر هرگز interleave نمی‌شوند.
	firewallDBWriteMu.Lock()
	defer firewallDBWriteMu.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	if _, err := tx.Exec("DELETE FROM ip_tracking_logs WHERE token = ?", token); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`
		UPDATE token_status
		SET is_suspicious = 0, admin_warn_mode = 0, admin_burn_mode = 0
		WHERE token = ?
	`, token); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// 📌 Generation فقط بعد از commit موفق bump می‌شود — نه قبلش. اگر قبل
	// از commit bump می‌شد و تراکنش (به هر دلیلی: db.Begin، Exec، یا خودِ
	// Commit؛ مثلاً یک SQLITE_BUSY گذرا) شکست می‌خورد، generation به‌اشتباه
	// جلو رفته بود بدون این‌که DB واقعاً reset شده باشد (Generation Drift)
	// — یعنی رویدادهای کاملاً معتبر و قدیمی برای همیشه به‌اشتباه rejected
	// می‌شدند، درحالی‌که هیچ reset واقعی رخ نداده بود. چون این bump هنوز
	// زیر همان firewallDBWriteMu انجام می‌شود (قفل تا پایان تابع باز
	// نمی‌شود)، تضمین mutual-exclusion در برابر workerها کاملاً حفظ می‌ماند
	// — هیچ گوروتین دیگری نمی‌تواند بین commit و همین bump چیزی را چک یا
	// بنویسد، چون برای آن هم به همین قفل نیاز دارد.
	bumpTokenGeneration(token)

	invalidateFirewallStatus(token)
	return nil
}

func getFirewallTokenDevices(token string) []FirewallDeviceLogRow {
	if db == nil {
		return nil
	}
	// 📌 اگر migration ستون client_app ناموفق بوده، هرگز کوئری‌ای که به
	// آن ارجاع می‌دهد اجرا نمی‌شود — همان SELECT قبلی، بدون تغییر.
	query := `SELECT ip_address, os_type, '', first_seen FROM ip_tracking_logs WHERE token = ? ORDER BY first_seen DESC`
	if clientAppColumnAvailable.Load() {
		query = `SELECT ip_address, os_type, COALESCE(client_app, ''), first_seen FROM ip_tracking_logs WHERE token = ? ORDER BY first_seen DESC`
	}
	rows, err := db.Query(query, token)
	if err != nil {
		log.Printf("[FirewallConsole] device history query failed: %v", err)
		return nil
	}
	defer rows.Close()

	var out []FirewallDeviceLogRow
	for rows.Next() {
		var ip, osType, clientApp string
		var firstSeen int64
		if err := rows.Scan(&ip, &osType, &clientApp, &firstSeen); err == nil {
			// 📌 تمایز صریح بین «قدیمی/بدون داده» (ستون خالی — یا چون
			// migration انجام نشده، یا چون ردیف قبل از این ویژگی ثبت شده)
			// و «Unknown» واقعی (یعنی تشخیص واقعاً اجرا شد ولی الگویی
			// پیدا نکرد). این دو معنای متفاوتی دارند.
			display := clientApp
			if display == "" {
				display = "نامشخص (قدیمی)"
			}
			out = append(out, FirewallDeviceLogRow{
				IP:        ip,
				OS:        osType,
				ClientApp: display,
				FirstSeen: time.Unix(firstSeen, 0).Format("2006-01-02 15:04:05"),
			})
		}
	}
	return out
}

func extractClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	candidates := []string{
		r.Header.Get("CF-Connecting-IP"),
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		candidates = append(candidates, strings.TrimSpace(strings.Split(xff, ",")[0]))
	}
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		candidates = append(candidates, host)
	} else {
		candidates = append(candidates, strings.TrimSpace(r.RemoteAddr))
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if ip := net.ParseIP(candidate); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func detectClientOS(userAgent string) string {
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	switch {
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"), strings.Contains(ua, "ios"):
		return "iOS"
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "macintosh"), strings.Contains(ua, "mac os"):
		return "macOS"
	case strings.Contains(ua, "linux"):
		return "Linux"
	case strings.Contains(ua, "mozilla"), strings.Contains(ua, "chrome"), strings.Contains(ua, "safari"), strings.Contains(ua, "firefox"):
		return "Browser"
	default:
		return "Browser"
	}
}

// clientAppColumnAvailable مشخص می‌کند که آیا ستون client_app با موفقیت
// migrate شده یا نه. تا وقتی این پرچم false است، هیچ INSERT/SELECTی نباید
// به ستون client_app ارجاع بدهد — تا یک migration ناموفق باعث خطای
// runtime روی نصب‌های موجود نشود.
var clientAppColumnAvailable atomic.Bool

// ============================================================
// 📊 تشخیص کلاینت واقعی (client_app) — صرفاً تله‌متری، هرگز در تصمیم
// امنیتی استفاده نمی‌شود. User-Agent کاملاً توسط کلاینت کنترل و
// قابل‌جعل است؛ این تابع فقط یک برچسب best-effort برای داشبورد ادمین
// تولید می‌کند.
//
// طراحی: یک جدول قوانین *ترتیبی* (نه switch/case پراکنده). اولین
// تطابق برنده است. ترتیب صراحتاً اولویت را کدگذاری می‌کند:
//
//	۱. کلاینت‌های پروکسی/ساب‌اسکریپشن شناخته‌شده (چون بسیاری از آن‌ها
//	   توکن‌های مرورگر را هم در UA خود می‌گذارند، باید قبل از لایه‌ی
//	   مرورگر چک شوند).
//	۲. در داخل خودِ این لایه، نام‌های طولانی‌تر/خاص‌تر قبل از نام‌های
//	   کوتاه‌تری که substring آن‌ها هستند چک می‌شوند (مثلاً "v2rayNG"
//	   قبل از "v2rayN"، چون "v2rayng" خودش شامل "v2rayn" است).
//	۳. مرورگرهای مبتنی بر Chromium (Edge/Opera) قبل از Chrome، چون
//	   هر دو توکن "chrome/" را هم به‌عنوان سازگاری دارند.
//	۴. Safari آخرین مورد بین مرورگرهاست، چون تقریباً همه‌ی UAهای
//	   موبایل (حتی Chrome/Firefox موبایل) توکن "safari/" را هم دارند.
//
// نسخه‌ها عمداً از مقدار canonical حذف می‌شوند (v2rayNG/1.8.12 → v2rayNG).
// ============================================================
type clientAppRule struct {
	Name     string
	Matchers []string
}

var clientAppDetectionRules = []clientAppRule{
	// --- کلاینت‌های پروکسی/ساب‌اسکریپشن (قبل از هر چیز دیگر) ---
	{Name: "v2rayNG", Matchers: []string{"v2rayng"}},
	{Name: "v2box", Matchers: []string{"v2box"}},
	{Name: "Hiddify", Matchers: []string{"hiddify"}},
	{Name: "Streisand", Matchers: []string{"streisand"}},
	{Name: "NekoBox", Matchers: []string{"nekobox", "nekoray"}},
	// clash-verge/clash-verge-rev بر پایه‌ی هسته‌ی mihomo کار می‌کنند؛
	// قبل از قانون عمومی‌تر "Clash" چک می‌شوند چون "clash" را هم به‌عنوان
	// substring دارند.
	{Name: "Clash Meta / Mihomo", Matchers: []string{"clashmeta", "mihomo", "clash-verge-rev", "clash-verge"}},
	{Name: "Clash", Matchers: []string{"clash"}},
	{Name: "Sing-box", Matchers: []string{"sing-box", "singbox"}},
	{Name: "Shadowrocket", Matchers: []string{"shadowrocket"}},
	{Name: "Surge", Matchers: []string{"surge"}},
	{Name: "Quantumult X", Matchers: []string{"quantumult"}},
	{Name: "Stash", Matchers: []string{"stash"}},
	{Name: "v2rayN", Matchers: []string{"v2rayn"}}, // بعد از v2rayNG، به‌خاطر تداخل substring

	// --- مرورگرهای شناخته‌شده (فقط اگر هیچ‌کدام از بالا match نکرد) ---
	{Name: "Edge", Matchers: []string{"edg/", "edga/", "edgios/"}},
	{Name: "Opera", Matchers: []string{"opr/", "opios/", "opt/"}},
	{Name: "Firefox", Matchers: []string{"firefox/", "fxios/"}},
	{Name: "Chrome", Matchers: []string{"chrome/", "crios/"}},
	{Name: "Safari", Matchers: []string{"safari/"}}, // آخرین مورد: توکن مشترک اکثر UAهای موبایل
}

// detectClientApp هرگز حدس نمی‌زند: اگر هیچ قانون صریحی match نکند،
// همیشه "Unknown" برمی‌گردد — حتی اگر UA الگوی عمومی مرورگرمانند
// (مثلاً "Mozilla/5.0") داشته باشد. یک هیورستیک قبلی که چنین مواردی را
// حدس می‌زد ("Browser (Other)") عمداً حذف شد چون این تابع تله‌متری
// best-effort است، نه یک طبقه‌بند احتمالاتی؛ شواهد ناکافی هرگز نباید به
// یک هویت ساختگی تبدیل شود.
func detectClientApp(userAgent string) string {
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	if ua == "" {
		return "Unknown"
	}
	for _, rule := range clientAppDetectionRules {
		for _, m := range rule.Matchers {
			if strings.Contains(ua, m) {
				return rule.Name
			}
		}
	}
	return "Unknown"
}

var firewallGCOnce sync.Once

func StartFirewallGC() {
	firewallGCOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(firewallGCTickInterval)
			defer ticker.Stop()

			var lastRun time.Time
			for {
				if lastRun.IsZero() {
					lastRun = time.Now()
				}
				select {
				case now := <-ticker.C:
					settings := getFirewallSettings()
					interval := time.Duration(settings.GCIntervalHours) * time.Hour
					if now.Sub(lastRun) >= interval {
						runFirewallGC()
						lastRun = now
					}
				}
			}
		}()
	})
}

// gcQueryTokens یک کوئری ساده و auto-commit (بدون تراکنش نگه‌داشته‌شده)
// اجرا می‌کند — برای فاز شناسایی اولیه‌ی کاندیدها، بدون قفل و بدون
// نگه‌داشتن snapshot طولانی.
func gcQueryTokens(query string, arg int64) []string {
	rows, err := db.Query(query, arg)
	if err != nil {
		log.Printf("[FirewallGC] candidate query failed: %v", err)
		return nil
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err == nil {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func gcBuildInClause(tokens []string) (string, []any) {
	placeholders := make([]string, len(tokens))
	args := make([]any, len(tokens))
	for i, token := range tokens {
		placeholders[i] = "?"
		args[i] = token
	}
	return strings.Join(placeholders, ","), args
}

// gcMutateExpiredChunk چرخه‌ی کامل «Lock -> validate -> Bump -> BeginTx ->
// Mutate -> Commit -> Unlock» را برای یک chunk از expiredTokens اجرا
// می‌کند. قفل هرگز بیشتر از طول عمر همین تابع نگه داشته نمی‌شود (defer
// محدود به scope همین تابع است، نه کل GC run).
func gcMutateExpiredChunk(chunk []string, cutoff int64) ([]string, bool) {
	if len(chunk) == 0 {
		return nil, false
	}

	firewallDBWriteMu.Lock()
	defer firewallDBWriteMu.Unlock()

	// identify/validate: چون first_seen هرگز update نمی‌شود (فقط insert)،
	// این چک عمدتاً محافظت دفاعی است، ولی هزینه‌اش ناچیز است و دقیقاً طبق
	// توالی درخواستی («Lock -> identify/validate -> ... -> Bump») حفظ می‌شود.
	inClause, inArgs := gcBuildInClause(chunk)
	validateArgs := append(append([]any{}, inArgs...), cutoff)
	validated := gcQueryTokensWithArgs(
		"SELECT DISTINCT token FROM ip_tracking_logs WHERE token IN ("+inClause+") AND first_seen < ?",
		validateArgs,
	)
	if len(validated) == 0 {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[FirewallGC] begin chunk transaction failed: %v", err)
		return nil, false
	}
	defer tx.Rollback()

	vClause, vArgs := gcBuildInClause(validated)
	deleteArgs := append(append([]any{}, vArgs...), cutoff)
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM ip_tracking_logs WHERE token IN ("+vClause+") AND first_seen < ?",
		deleteArgs...,
	); err != nil {
		log.Printf("[FirewallGC] chunk log delete failed: %v", err)
		return nil, false
	}

	if _, err := tx.ExecContext(ctx,
		"UPDATE token_status SET is_suspicious = 0, admin_warn_mode = 0, admin_burn_mode = 0 WHERE token IN ("+vClause+")",
		vArgs...,
	); err != nil {
		log.Printf("[FirewallGC] chunk status reset failed: %v", err)
		return nil, false
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[FirewallGC] chunk commit failed: %v", err)
		return nil, false
	}

	// 📌 Generation فقط بعد از commit موفق bump می‌شود (نه قبل از BeginTx).
	// اگر قبل bump می‌شد و تراکنش با یک SQLITE_BUSY گذرا یا هر خطای دیگر
	// شکست می‌خورد، generation به‌اشتباه جلو رفته بود بدون تغییر واقعی در
	// DB (Generation Drift) — رویدادهای کاملاً معتبر بعداً برای همیشه
	// نادیده گرفته می‌شدند. چون bump هنوز زیر همان firewallDBWriteMu است
	// (قفل تا پایان تابع باز نمی‌شود)، هیچ worker دیگری نمی‌تواند بین
	// commit و این bump چیزی چک/بنویسد.
	for _, token := range validated {
		bumpTokenGeneration(token)
	}

	return validated, true
}

// gcMutateInactiveChunk همان چرخه را برای inactiveTokens اجرا می‌کند.
// نکته‌ی حیاتی: برخلاف first_seen، last_active یک فیلد *قابل‌تغییر* است
// (توسط firewallTouchQueue/firewallDeviceQueue به‌روزرسانی می‌شود). به
// همین دلیل شرط last_active < inactiveCutoff داخل همان تراکنش کوتاه
// دوباره چک می‌شود؛ چون هر دو writer آن فیلد اکنون زیر همین
// firewallDBWriteMu سریالایز هستند، هیچ نوشتن هم‌زمانی نمی‌تواند بین
// validate و DELETE این تابع «قایم» بماند.
func gcMutateInactiveChunk(chunk []string, inactiveCutoff int64) ([]string, bool) {
	if len(chunk) == 0 {
		return nil, false
	}

	firewallDBWriteMu.Lock()
	defer firewallDBWriteMu.Unlock()

	inClause, inArgs := gcBuildInClause(chunk)
	validateArgs := append(append([]any{}, inArgs...), inactiveCutoff)
	validated := gcQueryTokensWithArgs(
		"SELECT token FROM token_status WHERE token IN ("+inClause+") AND last_active > 0 AND last_active < ?",
		validateArgs,
	)
	if len(validated) == 0 {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[FirewallGC] begin inactive chunk transaction failed: %v", err)
		return nil, false
	}
	defer tx.Rollback()

	vClause, vArgs := gcBuildInClause(validated)
	deleteArgs := append(append([]any{}, vArgs...), inactiveCutoff)
	// 📌 محافظت دفاعی: شرط last_active دوباره همین‌جا چک می‌شود. چون
	// touchFirewallLastActive اکنون خودش هم زیر همین firewallDBWriteMu
	// سریالایز است، و این قفل از validate بالا تا همین لحظه پیوسته نگه
	// داشته شده، عملاً هیچ نوشتنی نمی‌تواند بین آن دو فاصله بیفتد — این
	// چک صرفاً یک لایه‌ی دوم اطمینان است، نه نیاز اساسی.
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM token_status WHERE token IN ("+vClause+") AND last_active > 0 AND last_active < ?",
		deleteArgs...,
	); err != nil {
		log.Printf("[FirewallGC] inactive chunk delete failed: %v", err)
		return nil, false
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[FirewallGC] inactive chunk commit failed: %v", err)
		return nil, false
	}

	// 📌 Generation فقط بعد از commit موفق bump می‌شود (نه قبل از BeginTx)
	// — همان دلیل gcMutateExpiredChunk: جلوگیری از Generation Drift اگر
	// تراکنش شکست بخورد. چون firewallDBWriteMu از validate تا همین‌جا
	// پیوسته نگه داشته شده، مجموعه‌ی validated دقیقاً همان چیزی است که
	// واقعاً حذف شد — bump کردن همه‌ی آن‌ها اینجا صحیح است.
	for _, token := range validated {
		bumpTokenGeneration(token)
	}

	return validated, true
}

func gcQueryTokensWithArgs(query string, args []any) []string {
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("[FirewallGC] chunk validation query failed: %v", err)
		return nil
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err == nil {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

// runFirewallGC — Per-Chunk Transaction Isolation:
// هر chunk چرخه‌ی کامل و مستقل «Lock -> identify/validate -> Bump ->
// BeginTx -> Mutate -> Commit -> Unlock» خودش را دارد (نه یک تراکنش/قفل
// واحد برای کل اجرای GC). این هم مشکل Lock Convoy (قفل نگه‌داشته‌شده روی
// هزاران توکن) را می‌بندد، هم پنجره‌ی snapshot کهنه‌ی SQLite را به‌اندازه‌ی
// یک chunk (نه کل GC run) محدود می‌کند.
func runFirewallGC() {
	if db == nil {
		return
	}

	settings := getFirewallSettings()
	cutoff := time.Now().Add(-time.Duration(settings.ResetWindowHours) * time.Hour).Unix()
	inactiveCutoff := time.Now().Unix() - int64(settings.InactiveRetentionDays)*86400

	// فاز شناسایی: بدون قفل، بدون تراکنش نگه‌داشته‌شده — فقط برای تعیین
	// مرزهای chunk. اعتبارسنجی واقعی و تصمیم‌گیرنده داخل هر chunk، زیر
	// قفل، دوباره انجام می‌شود.
	expiredCandidates := gcQueryTokens("SELECT DISTINCT token FROM ip_tracking_logs WHERE first_seen < ?", cutoff)
	inactiveCandidates := gcQueryTokens("SELECT token FROM token_status WHERE last_active > 0 AND last_active < ?", inactiveCutoff)

	for start := 0; start < len(expiredCandidates); start += firewallGCUpdateChunkSize {
		end := start + firewallGCUpdateChunkSize
		if end > len(expiredCandidates) {
			end = len(expiredCandidates)
		}
		validated, ok := gcMutateExpiredChunk(expiredCandidates[start:end], cutoff)
		if !ok {
			continue
		}
		for _, token := range validated {
			invalidateFirewallStatus(token)
		}
	}

	// ============================================================
	// 🧹 Modular GC: حذف کامل توکن‌های "روح" (Ghost) که برای مدت
	// تنظیم‌شده در InactiveRetentionDays هیچ اتصال جدیدی نداشته‌اند
	// (شامل توکن‌های Burn/Warn شده - سیاست تأییدشده: پاک‌سازی بی‌قیدوشرط)
	// ============================================================
	for start := 0; start < len(inactiveCandidates); start += firewallGCUpdateChunkSize {
		end := start + firewallGCUpdateChunkSize
		if end > len(inactiveCandidates) {
			end = len(inactiveCandidates)
		}
		validated, ok := gcMutateInactiveChunk(inactiveCandidates[start:end], inactiveCutoff)
		if !ok {
			continue
		}
		for _, token := range validated {
			invalidateFirewallStatus(token)
		}
	}
}
