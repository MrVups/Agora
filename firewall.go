package main

import (
	"context"
	"database/sql"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	firewallSettingsTTL        = 5 * time.Second
	firewallStatusTTL          = 2 * time.Second
	firewallWriterBuffer       = 4096
	firewallStatusWriterBuffer = 1024
	firewallCacheLimit         = 5000
	firewallDefaultResetHours  = 24
	firewallDefaultGCInterval  = 6
	firewallGCTickInterval     = 1 * time.Minute
	firewallGCUpdateChunkSize  = 500
)

type FirewallSettings struct {
	Enabled            bool
	SuspicionThreshold int
	MaxDevices         int
	ResetWindowHours   int
	GCIntervalHours    int
	WarningFakeConfig  string
	BlockFakeConfig    string
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

type firewallStatusCacheItem struct {
	Status   firewallStatus
	Expire   time.Time
	LastUsed time.Time
}

var firewallSettingsMu sync.RWMutex
var firewallSettingsCache FirewallSettings
var firewallSettingsExpires time.Time

var firewallStatusMu sync.RWMutex
var firewallStatusCache = make(map[string]firewallStatusCacheItem)

var firewallReservationMu sync.Mutex
var firewallPendingSlots = make(map[string]int)
var firewallPendingDevices = make(map[string]int)

type firewallDeviceEvent struct {
	Token string
	IP    string
	OS    string
}

var firewallDeviceQueue chan firewallDeviceEvent
var firewallDeviceOnce sync.Once

func startFirewallDeviceWriter() {
	firewallDeviceOnce.Do(func() {
		firewallDeviceQueue = make(chan firewallDeviceEvent, firewallWriterBuffer)
		go func() {
			for event := range firewallDeviceQueue {
				_, err := db.Exec(`
					INSERT OR IGNORE INTO ip_tracking_logs(token,ip_address,os_type,first_seen)
					VALUES (?,?,?,?)
				`, event.Token, event.IP, event.OS, time.Now().Unix())
				if err != nil {
					log.Printf("[Firewall] device insert failed: %v", err)
				}
				releaseFirewallDeviceReservation(event.Token, event.IP, event.OS)
			}
		}()
	})
}

func firewallDeviceKey(token, ip, osType string) string {
	return token + "\x00" + ip + "\x00" + osType
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

	status := getFirewallStatus(token)
	result.Suspicious = status.Suspicious
	result.AdminWarn = status.Warn
	result.AdminBurn = status.Burn

	if status.Burn {
		result.Allow = false
		return result
	}

	ip := extractClientIP(r)
	osType := detectClientOS(r.Header.Get("User-Agent"))
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
			if !queueFirewallDevice(firewallDeviceEvent{Token: token, IP: ip, OS: osType}) {
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
		Enabled:            true,
		SuspicionThreshold: 3,
		MaxDevices:         5,
		ResetWindowHours:   firewallDefaultResetHours,
		GCIntervalHours:    firewallDefaultGCInterval,
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
		oldestToken := ""
		var oldest time.Time
		for k, v := range firewallStatusCache {
			if oldestToken == "" || v.LastUsed.Before(oldest) {
				oldestToken = k
				oldest = v.LastUsed
			}
		}
		if oldestToken != "" {
			delete(firewallStatusCache, oldestToken)
		}
	}
	firewallStatusCache[token] = firewallStatusCacheItem{
		Status:   status,
		Expire:   now.Add(firewallStatusTTL),
		LastUsed: now,
	}
	firewallStatusMu.Unlock()
	return status
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
	Token string
}

var firewallStatusQueue chan firewallSuspiciousEvent
var firewallStatusOnce sync.Once

var firewallPendingSuspiciousMu sync.Mutex
var firewallPendingSuspicious = make(map[string]struct{})
var firewallQueuedSuspicious = make(map[string]struct{})

func startFirewallStatusWriter() {
	firewallStatusOnce.Do(func() {
		firewallStatusQueue = make(chan firewallSuspiciousEvent, firewallStatusWriterBuffer)
		go func() {
			for event := range firewallStatusQueue {
				err := writeSuspiciousStatus(event.Token)
				firewallPendingSuspiciousMu.Lock()
				delete(firewallQueuedSuspicious, event.Token)
				if err == nil {
					delete(firewallPendingSuspicious, event.Token)
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
	invalidateFirewallStatus(token)
	startFirewallStatusWriter()

	firewallPendingSuspiciousMu.Lock()
	if _, exists := firewallPendingSuspicious[token]; exists {
		firewallPendingSuspiciousMu.Unlock()
		return
	}
	firewallPendingSuspicious[token] = struct{}{}
	firewallPendingSuspiciousMu.Unlock()

	queuePendingFirewallSuspicious(token)
}

func queuePendingFirewallSuspicious(token string) {
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

	select {
	case firewallStatusQueue <- firewallSuspiciousEvent{Token: token}:
	default:
		firewallPendingSuspiciousMu.Lock()
		delete(firewallQueuedSuspicious, token)
		firewallPendingSuspiciousMu.Unlock()
	}
}

func flushPendingFirewallSuspicious() {
	firewallPendingSuspiciousMu.Lock()
	pending := make([]string, 0, len(firewallPendingSuspicious))
	for token := range firewallPendingSuspicious {
		pending = append(pending, token)
	}
	firewallPendingSuspiciousMu.Unlock()

	for _, token := range pending {
		queuePendingFirewallSuspicious(token)
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

func runFirewallGC() {
	if db == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[FirewallGC] begin transaction failed: %v", err)
		return
	}
	defer tx.Rollback()

	cutoff := time.Now().Add(-time.Duration(getFirewallSettings().ResetWindowHours) * time.Hour).Unix()
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT token
		FROM ip_tracking_logs
		WHERE first_seen < ?
	`, cutoff)
	if err != nil {
		log.Printf("[FirewallGC] token select failed: %v", err)
		return
	}

	var expiredTokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err == nil {
			expiredTokens = append(expiredTokens, token)
		}
	}
	rows.Close()

	if _, err := tx.ExecContext(ctx, "DELETE FROM ip_tracking_logs WHERE first_seen < ?", cutoff); err != nil {
		log.Printf("[FirewallGC] delete failed: %v", err)
		return
	}

	for start := 0; start < len(expiredTokens); start += firewallGCUpdateChunkSize {
		end := start + firewallGCUpdateChunkSize
		if end > len(expiredTokens) {
			end = len(expiredTokens)
		}
		chunk := expiredTokens[start:end]
		placeholders := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for i, token := range chunk {
			placeholders[i] = "?"
			args[i] = token
		}
		query := "UPDATE token_status SET is_suspicious = 0, admin_warn_mode = 0, admin_burn_mode = 0 WHERE token IN (" + strings.Join(placeholders, ",") + ")"
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			log.Printf("[FirewallGC] status reset failed: %v", err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[FirewallGC] commit failed: %v", err)
		return
	}

	for _, token := range expiredTokens {
		invalidateFirewallStatus(token)
	}
}
