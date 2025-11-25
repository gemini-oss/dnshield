//go:build darwin
// +build darwin

// DNShield Watchdog
//
// Optional LaunchDaemon that monitors /etc/hosts for blocked-domain bypass attempts.
package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gemini/dnshield/internal/cfpref"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type watchdog struct {
	logPrefix            string
	pollInterval         int
	removalCommentFormat string
	rulesDBPath          string
	removeBlockedEntries bool
}

var ErrPrefValueNotFound = errors.New("no value found for key")

const (
	hostsFilePath         = "/etc/hosts"
	sqlite3Binary         = "/usr/bin/sqlite3"
	preferenceDomain      = "com.dnshield.watchdog"
	removePrefKey         = "RemoveBlockBypassEntries"
	ruleDBPathKey         = "RulesDBPath"
	removalCommentKey     = "RemovalComment"
	loggerPrefixKey       = "LoggerPrefix"
	pollIntervalKey       = "PollInterval"
	telemetryEnabledKey   = "TelemetryEnabled"
	telemetryHECTokenKey  = "TelemetryHECToken"
	telemetryServerURLKey = "TelemetryServerURL"
	useJSONLoggingKey     = "UseJSONLogging"
	logFilePathKey        = "LogFilePath"
)

var ( // default values if not set on the preference domain.
	logPrefix         = "[dnshield-watchdog]"
	pollInterval      = 3 * time.Second
	removalCommentFmt = "# Removed by DNShield Watchdog %s: %s"
	rulesDBPath       = "/var/db/dnshield/rules.db"
	wd                *watchdog
	telemetry         *TelemetryClient
	dbMonitor         *DatabaseMonitor
	useJSONLogging    bool
	logFilePath       = "/var/log/dnshield/watchdog.log"
)

var timeNow = time.Now

type blockedSet struct {
	exact     map[string]struct{}
	wildcards []string
	regexps   []*regexp.Regexp
}

func main() {
	if err := execute(); err != nil {
		log.Fatal().Err(err).Msg("fatal error")
	}
}

func execute() error {
	wd = &watchdog{}

	// Load all preferences
	loadPreferences()

	// Initialize zerolog based on configuration
	initializeZerolog()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start database monitoring if enabled
	if useJSONLogging {
		dbMonitor = NewDatabaseMonitor(wd.rulesDBPath)
		dbMonitor.Start(ctx)
	}

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

func newBlockedSet() *blockedSet {
	return &blockedSet{
		exact: make(map[string]struct{}),
	}
}

func (b *blockedSet) add(domain string, ruleType int) {
	if domain == "" {
		return
	}

	normalized := strings.ToLower(strings.TrimSpace(domain))
	switch ruleType {
	case 0: // Exact
		b.exact[normalized] = struct{}{}
	case 1: // Wildcard (stored as *.example.com)
		if strings.HasPrefix(normalized, "*.") {
			b.wildcards = append(b.wildcards, strings.TrimPrefix(normalized, "*."))
		} else {
			// Treat malformed wildcard as suffix entry
			b.wildcards = append(b.wildcards, normalized)
		}
	default: // Regex or other
		re, err := regexp.Compile(normalized)
		if err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("failed to compile regex rule")
			return
		}
		b.regexps = append(b.regexps, re)
	}
}

func (b *blockedSet) matches(host string) bool {
	if host == "" {
		return false
	}

	lower := strings.ToLower(host)

	if _, ok := b.exact[lower]; ok {
		return true
	}

	for _, suffix := range b.wildcards {
		if lower == suffix {
			return true
		}
		if strings.HasSuffix(lower, "."+suffix) {
			return true
		}
	}

	for _, re := range b.regexps {
		if re.MatchString(host) {
			return true
		}
	}

	return false
}

func (b *blockedSet) isEmpty() bool {
	return len(b.exact) == 0 && len(b.wildcards) == 0 && len(b.regexps) == 0
}

func (b *blockedSet) count() int {
	return len(b.exact) + len(b.wildcards) + len(b.regexps)
}

type lineInfo struct {
	original  string
	updated   string
	ip        string
	lineIndex int
	offending []string
	changed   bool
}

func run(ctx context.Context) error {
	initialContent, err := os.ReadFile(hostsFilePath)
	if err != nil {
		return fmt.Errorf("read hosts file: %w", err)
	}

	hashedContent := initialContent
	if sanitized, sanitizeErr := handleHostsChange(ctx, initialContent); sanitizeErr != nil {
		log.Error().Err(sanitizeErr).Msg("initial hosts inspection failed")
	} else {
		hashedContent = sanitized
	}

	lastHash := hashBytes(hashedContent)
	log.Info().Msg("watchdog started; monitoring /etc/hosts for bypass attempts")

	if kqErr := monitorWithKqueue(ctx, &lastHash); kqErr != nil {
		log.Warn().Err(kqErr).Msg("kqueue monitoring unavailable, falling back to polling")
		return monitorWithPolling(ctx, &lastHash)
	}
	return nil
}

func processHostsChange(ctx context.Context, lastHash *[32]byte) error {
	data, err := os.ReadFile(hostsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	newHash := hashBytes(data)
	if newHash == *lastHash {
		return nil
	}

	finalContent, err := handleHostsChange(ctx, data)
	if err != nil {
		*lastHash = newHash
		return err
	}

	*lastHash = hashBytes(finalContent)
	return nil
}

func handleHostsChange(ctx context.Context, content []byte) ([]byte, error) {
	blocked, err := loadBlockedSet(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to load blocked domains")
	}

	if blocked == nil || blocked.isEmpty() {
		log.Info().Msg("hosts file changed but no blocked-domain rules are available; skipping enforcement")
		return content, nil
	}

	lines := strings.Split(string(content), "\n")
	hadTrailingNewline := len(content) > 0 && content[len(content)-1] == '\n'

	lineInfos := make([]lineInfo, len(lines))
	var offendingLines []lineInfo
	for idx, line := range lines {
		info := analyzeLine(line, idx, blocked, wd.removeBlockedEntries)
		lineInfos[idx] = info
		if len(info.offending) > 0 {
			offendingLines = append(offendingLines, info)
		}
	}

	if len(offendingLines) == 0 {
		log.Info().Msg("hosts file modified; no blocked-domain entries detected")
		return content, nil
	}

	if !wd.removeBlockedEntries {
		for _, info := range offendingLines {
			log.Warn().
				Bool("detected", true).
				Bool("removed", false).
				Int("line_number", info.lineIndex+1).
				Str("ip_address", info.ip).
				Strs("domains", info.offending).
				Str("event_type", "bypass_attempt").
				Msgf("detected blocked-domain override on line %d (%s): %s",
					info.lineIndex+1, info.ip, strings.Join(info.offending, ", "))
		}
		return content, nil
	}

	for _, info := range offendingLines {
		if info.changed {
			log.Info().
				Bool("detected", true).
				Bool("removed", true).
				Int("line_number", info.lineIndex+1).
				Str("ip_address", info.ip).
				Strs("domains", info.offending).
				Str("event_type", "bypass_attempt").
				Msgf("removed blocked-domain override on line %d: %s",
					info.lineIndex+1, strings.Join(info.offending, ", "))
		} else {
			log.Info().
				Int("line_number", info.lineIndex+1).
				Msg("blocked-domain override detected but no change was required")
		}
	}

	updatedLines := make([]string, len(lineInfos))
	changed := false
	for idx, info := range lineInfos {
		updatedLines[idx] = info.updated
		if info.changed {
			changed = true
		}
	}

	if !changed {
		return content, nil
	}

	finalString := strings.Join(updatedLines, "\n")
	if hadTrailingNewline && !strings.HasSuffix(finalString, "\n") {
		finalString += "\n"
	}

	if writeErr := writeHostsFile(finalString); writeErr != nil {
		return nil, fmt.Errorf("write sanitized hosts file: %w", writeErr)
	}

	return []byte(finalString), nil
}

func analyzeLine(line string, idx int, blocked *blockedSet, remove bool) lineInfo {
	info := lineInfo{
		original:  line,
		updated:   line,
		lineIndex: idx,
	}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return info
	}

	comment := ""
	content := line
	if hash := strings.Index(line, "#"); hash >= 0 {
		content = line[:hash]
		comment = line[hash:]
	}

	fields := strings.Fields(content)
	if len(fields) < 2 {
		return info
	}

	ip := fields[0]
	hosts := fields[1:]
	info.ip = ip

	var filtered []string
	for _, host := range hosts {
		if blocked.matches(host) {
			info.offending = append(info.offending, host)
			continue
		}
		filtered = append(filtered, host)
	}

	if len(info.offending) == 0 {
		return info
	}

	if !remove {
		return info
	}

	if len(filtered) > 0 {
		info.updated = rebuildHostsLine(ip, filtered, comment)
		info.changed = info.updated != info.original
		return info
	}

	timestamp := timeNow().UTC().Format(time.RFC3339)
	info.updated = fmt.Sprintf(removalCommentFmt, timestamp, strings.Join(info.offending, ", "))
	info.changed = info.updated != info.original
	return info
}

func rebuildHostsLine(ip string, hosts []string, comment string) string {
	base := strings.TrimSpace(ip)
	if base == "" {
		return strings.TrimSpace(comment)
	}

	if len(hosts) > 0 {
		base = fmt.Sprintf("%s\t%s", base, strings.Join(hosts, "\t"))
	}

	comment = strings.TrimRight(comment, "\r\n")
	if comment != "" {
		if !strings.HasPrefix(comment, "#") {
			comment = "# " + strings.TrimSpace(comment)
		}
		// Ensure we maintain a single space before the comment.
		base = strings.TrimRight(base, " \t")
		comment = " " + strings.TrimSpace(comment)
		return base + comment
	}

	return base
}

func writeHostsFile(content string) error {
	info, err := os.Stat(hostsFilePath)
	if err != nil {
		return err
	}

	dir := filepath.Dir(hostsFilePath)
	tmp, err := os.CreateTemp(dir, "dnshield-hosts-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, writeErr := tmp.WriteString(content); writeErr != nil {
		tmp.Close()
		return writeErr
	}

	if chmodErr := tmp.Chmod(info.Mode()); chmodErr != nil {
		tmp.Close()
		return chmodErr
	}

	if syncErr := tmp.Sync(); syncErr != nil {
		tmp.Close()
		return syncErr
	}

	if closeErr := tmp.Close(); closeErr != nil {
		return closeErr
	}

	return os.Rename(tmpName, hostsFilePath)
}

func loadBlockedSet(ctx context.Context) (*blockedSet, error) {
	if _, err := os.Stat(rulesDBPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Warn().Str("db_path", rulesDBPath).Msg("rule database not found; continuing with empty set")
			return newBlockedSet(), nil
		}
		return nil, err
	}

	cmd := exec.CommandContext(ctx, sqlite3Binary, "-readonly", "-separator", "|", rulesDBPath,
		"SELECT domain,type FROM dns_rules WHERE action = 0;")
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			if stderr != "" {
				log.Error().Str("stderr", stderr).Msg("sqlite3 reported an error")
			}
		}
		return nil, err
	}

	set := newBlockedSet()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		domain := strings.TrimSpace(parts[0])
		typeValue := strings.TrimSpace(parts[1])
		ruleType, atoiErr := strconv.Atoi(typeValue)
		if atoiErr != nil {
			log.Warn().
				Str("type_value", typeValue).
				Str("domain", domain).
				Msg("unexpected rule type value")
			continue
		}
		set.add(domain, ruleType)
	}

	log.Info().
		Int("rule_count", set.count()).
		Str("db_path", rulesDBPath).
		Bool("success", true).
		Str("event_type", "rule_load").
		Msgf("loaded %d blocked-domain rule(s) from %s", set.count(), rulesDBPath)

	return set, nil
}

// telemetryHook sends log events to telemetry service.
type telemetryHook struct {
	client *TelemetryClient
}

func (h telemetryHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	if h.client != nil && level >= zerolog.InfoLevel {
		// Create a log entry that matches the expected structure
		entry := map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"level":     level.String(),
			"message":   msg,
			"component": "dnshield-watchdog",
		}

		// Send to telemetry asynchronously
		go func() {
			if err := h.client.SendEvent(entry); err != nil {
				// Don't log telemetry errors to avoid recursion
				fmt.Fprintf(os.Stderr, "Failed to send telemetry: %v\n", err)
			}
		}()
	}
}

func initializeZerolog() {
	// Set global log level
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if useJSONLogging {
		// JSON output is the default for zerolog
		if logFilePath != "" && logFilePath != "-" {
			// Ensure log directory exists
			logDir := filepath.Dir(logFilePath)
			if err := os.MkdirAll(logDir, 0o755); err != nil {
				log.Fatal().Err(err).Msg("failed to create log directory")
			}

			file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to open log file")
			}

			// Set up JSON logger writing to file
			log.Logger = zerolog.New(file).With().
				Timestamp().
				Str("component", "dnshield-watchdog").
				Logger()
		} else {
			// JSON output to stdout
			log.Logger = zerolog.New(os.Stdout).With().
				Timestamp().
				Str("component", "dnshield-watchdog").
				Logger()
		}
	} else {
		// Console output for non-JSON mode
		output := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
			FormatLevel: func(i interface{}) string {
				return fmt.Sprintf("%s %-6s", wd.logPrefix, i)
			},
		}
		log.Logger = zerolog.New(output).With().
			Timestamp().
			Str("component", "dnshield-watchdog").
			Logger()
	}

	// Add telemetry hook if configured
	if telemetry != nil {
		log.Logger = log.Logger.Hook(telemetryHook{client: telemetry})
	}
}

//nolint:gocyclo,cyclop // Preference loading intentionally aggregates many related checks to keep configuration logic centralized.
func loadPreferences() {
	wd.logPrefix = logPrefix
	wd.pollInterval = int(pollInterval / time.Second)
	wd.removalCommentFormat = removalCommentFmt
	wd.rulesDBPath = rulesDBPath
	wd.removeBlockedEntries = false

	logPrefErr := func(key string, err error) {
		if err != nil && !errors.Is(err, ErrPrefValueNotFound) {
			log.Error().Err(err).Str("key", key).Msg("error reading preference")
		} else if errors.Is(err, ErrPrefValueNotFound) {
			log.Debug().Str("key", key).Msg("no value found for preference key")
		}
	}

	if v, err := readPreference(loggerPrefixKey); err == nil {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			wd.logPrefix = strings.TrimSpace(s) + " "
		}
	} else {
		logPrefErr(loggerPrefixKey, err)
	}

	// PollInterval (int seconds; allow int, int64, float64, string)
	if v, err := readPreference(pollIntervalKey); err == nil {
		switch n := v.(type) {
		case int:
			wd.pollInterval = n
		case int64:
			wd.pollInterval = int(n)
		case float64:
			wd.pollInterval = int(n)
		case string:
			if i, e := strconv.Atoi(strings.TrimSpace(n)); e == nil {
				wd.pollInterval = i
			}
		}
	} else {
		logPrefErr(pollIntervalKey, err)
	}

	// RemoveBlockBypassEntries (bool; allow bool, string)
	if v, err := readPreference(removePrefKey); err == nil {
		switch b := v.(type) {
		case bool:
			wd.removeBlockedEntries = b
		case string:
			if parsed, e := strconv.ParseBool(strings.TrimSpace(b)); e == nil {
				wd.removeBlockedEntries = parsed
			}
		}
	} else {
		logPrefErr(removePrefKey, err)
	}

	// RulesDBPath (string)
	if v, err := readPreference(ruleDBPathKey); err == nil {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			wd.rulesDBPath = s
		}
	} else {
		logPrefErr(ruleDBPathKey, err)
	}

	// RemovalComment (string)
	if v, err := readPreference(removalCommentKey); err == nil {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			wd.removalCommentFormat = s
		}
	} else {
		logPrefErr(removalCommentKey, err)
	}

	// Mirror back into globals
	logPrefix = wd.logPrefix
	rulesDBPath = wd.rulesDBPath
	removalCommentFmt = wd.removalCommentFormat
	if wd.pollInterval > 0 {
		pollInterval = time.Duration(wd.pollInterval) * time.Second
	}

	if v, err := readPreference(useJSONLoggingKey); err == nil {
		switch b := v.(type) {
		case bool:
			useJSONLogging = b
		case string:
			if parsed, e := strconv.ParseBool(strings.TrimSpace(b)); e == nil {
				useJSONLogging = parsed
			}
		}
	} else {
		logPrefErr(useJSONLoggingKey, err)
	}

	// LogFilePath (string)
	if v, err := readPreference(logFilePathKey); err == nil {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			logFilePath = strings.TrimSpace(s)
		}
	} else {
		logPrefErr(logFilePathKey, err)
	}

	// TelemetryEnabled and related settings
	telemetryEnabled := false
	if v, err := readPreference(telemetryEnabledKey); err == nil {
		switch b := v.(type) {
		case bool:
			telemetryEnabled = b
		case string:
			if parsed, e := strconv.ParseBool(strings.TrimSpace(b)); e == nil {
				telemetryEnabled = parsed
			}
		}
	} else {
		logPrefErr(telemetryEnabledKey, err)
	}

	if telemetryEnabled {
		var hecToken, serverURL string

		// TelemetryHECToken (string)
		if v, err := readPreference(telemetryHECTokenKey); err == nil {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				hecToken = strings.TrimSpace(s)
			}
		} else {
			logPrefErr(telemetryHECTokenKey, err)
		}

		// TelemetryServerURL (string)
		if v, err := readPreference(telemetryServerURLKey); err == nil {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				serverURL = strings.TrimSpace(s)
			}
		} else {
			logPrefErr(telemetryServerURLKey, err)
		}

		// Initialize telemetry client if we have both token and URL
		if hecToken != "" && serverURL != "" {
			hostname, _ := os.Hostname()
			telemetry = NewTelemetryClient(serverURL, hecToken, hostname)
		}
	}
}

func readPreference(prefKey string) (any, error) {
	value, valueType := cfpref.CFPreferencesCopyAppValueAndType(prefKey, preferenceDomain)
	if value != nil {
		var strValue string
		switch v := value.(type) {
		case string:
			strValue = v
		case int:
			strValue = strconv.Itoa(v)
		case int64:
			strValue = strconv.FormatInt(v, 10)
		case float64:
			strValue = strconv.FormatInt(int64(v), 10)
		default:
			log.Debug().
				Str("key", prefKey).
				Str("type", fmt.Sprintf("%T", value)).
				Str("cfpref_type", valueType).
				Msg("unexpected type for preference")
		}
		if strValue != "" {
			os.Setenv(prefKey, strValue)
		}
		return value, nil
	}
	return nil, ErrPrefValueNotFound
}

func hashBytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func monitorWithPolling(ctx context.Context, lastHash *[32]byte) error {
	ticker := time.NewTicker(time.Duration(wd.pollInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("shutting down (context canceled)")
			return ctx.Err()
		case <-ticker.C:
			if err := processHostsChange(ctx, lastHash); err != nil {
				log.Error().Err(err).Msg("error processing hosts change")
			}
		}
	}
}

func monitorWithKqueue(ctx context.Context, lastHash *[32]byte) error {
	fd, err := openHostsFile()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	kq, err := syscall.Kqueue()
	if err != nil {
		return err
	}
	defer syscall.Close(kq)

	// File descriptors are non-negative integers, safe to convert
	var fdIdent uint64
	if fd >= 0 {
		fdIdent = uint64(fd)
	} else {
		return fmt.Errorf("invalid file descriptor: %d", fd)
	}

	event := syscall.Kevent_t{
		Ident:  fdIdent,
		Filter: syscall.EVFILT_VNODE,
		Flags:  syscall.EV_ADD | syscall.EV_CLEAR,
		Fflags: syscall.NOTE_WRITE | syscall.NOTE_DELETE | syscall.NOTE_EXTEND |
			syscall.NOTE_ATTRIB | syscall.NOTE_RENAME | syscall.NOTE_REVOKE,
	}

	if _, keventErr := syscall.Kevent(kq, []syscall.Kevent_t{event}, nil, nil); keventErr != nil {
		return fmt.Errorf("register kevent: %w", keventErr)
	}

	events := make([]syscall.Kevent_t, 1)
	timeout := syscall.NsecToTimespec(int64(500 * time.Millisecond))

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("shutting down (context canceled)")
			return ctx.Err()
		default:
		}

		n, keventWaitErr := syscall.Kevent(kq, nil, events, &timeout)
		if keventWaitErr != nil {
			if errors.Is(keventWaitErr, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("kevent wait: %w", keventWaitErr)
		}

		if n == 0 {
			continue
		}

		ev := events[0]
		if ev.Flags&syscall.EV_ERROR != 0 {
			return fmt.Errorf("kevent error flag set (data=%d)", ev.Data)
		}

		if ev.Fflags&(syscall.NOTE_DELETE|syscall.NOTE_RENAME|syscall.NOTE_REVOKE) != 0 {
			syscall.Close(fd)
			var openErr error
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				fd, openErr = openHostsFile()
				if openErr == nil {
					break
				}
				log.Info().Err(openErr).Msg("waiting for hosts file to reappear")
				time.Sleep(100 * time.Millisecond)
			}

			if fd >= 0 {
				event.Ident = uint64(fd)
			} else {
				return fmt.Errorf("invalid file descriptor after reopen: %d", fd)
			}
			if _, reregErr := syscall.Kevent(kq, []syscall.Kevent_t{event}, nil, nil); reregErr != nil {
				return fmt.Errorf("re-register kevent: %w", reregErr)
			}
			if procErr := processHostsChange(ctx, lastHash); procErr != nil {
				log.Error().Err(procErr).Msg("error processing hosts change after reopen")
			}
			continue
		}

		if ev.Fflags&(syscall.NOTE_WRITE|syscall.NOTE_EXTEND|syscall.NOTE_ATTRIB) == 0 {
			continue
		}

		time.Sleep(100 * time.Millisecond)

		if procErr := processHostsChange(ctx, lastHash); procErr != nil {
			log.Error().Err(procErr).Msg("error processing hosts change")
		}
	}
}

func openHostsFile() (int, error) {
	fd, err := syscall.Open(hostsFilePath, syscall.O_EVTONLY, 0)
	if err != nil {
		return -1, fmt.Errorf("open hosts file: %w", err)
	}
	return fd, nil
}
