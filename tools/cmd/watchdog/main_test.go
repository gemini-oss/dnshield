//go:build darwin
// +build darwin

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestMain(m *testing.M) {
	// Disable logging for tests.
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func TestBlockedSetMatches(t *testing.T) {
	// Temporarily set logging to discard for this test
	oldLogger := log.Logger
	log.Logger = zerolog.New(os.Stderr).Level(zerolog.Disabled)
	defer func() { log.Logger = oldLogger }()

	set := newBlockedSet()
	set.add("bad.example", 0)       // exact
	set.add("*.wildcard.com", 1)    // wildcard
	set.add(`evil\d+\.net`, 2)      // regex
	set.add("invalid[regex", 2)     // malformed regex should be ignored
	set.add("*.SubWildCard.Com", 1) // case-insensitive wildcard
	set.add("ANOTHER.EXAMPLE", 0)   // ensure case insensitive exact
	set.add(`ANOTHER\d+\.net`, 2)   // uppercase regex

	tests := []struct {
		host     string
		expected bool
	}{
		{"bad.example", true},
		{"BAD.EXAMPLE", true}, // case insensitive exact
		{"sub.wildcard.com", true},
		{"deep.sub.wildcard.com", true},
		{"wildcard.com", true}, // wildcard should match root
		{"subwildcard.com", true},
		{"evil123.net", true},
		{"notevil.net", false},
		{"another.example", true},
		{"another999.net", true},
		{"completely.safe", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := set.matches(tt.host); got != tt.expected {
				t.Fatalf("matches(%q) = %v, want %v", tt.host, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeLine_NoRemoval(t *testing.T) {
	set := newBlockedSet()
	set.exact["blocked.com"] = struct{}{}

	line := "127.0.0.1 blocked.com allowed.com"
	info := analyzeLine(line, 0, set, false)

	if !strings.Contains(strings.Join(info.offending, ","), "blocked.com") {
		t.Fatalf("expected offending list to contain blocked.com, got %v", info.offending)
	}
	if info.changed {
		t.Fatalf("expected no change when removal disabled")
	}
	if info.updated != line {
		t.Fatalf("expected updated line to remain unchanged, got %q", info.updated)
	}
}

func TestAnalyzeLine_RemovePartialLine(t *testing.T) {
	set := newBlockedSet()
	set.exact["blocked.com"] = struct{}{}
	set.exact["another.com"] = struct{}{}

	line := "127.0.0.1 blocked.com allowed.com another.com # inline comment"
	info := analyzeLine(line, 2, set, true)

	if !strings.Contains(strings.Join(info.offending, ","), "blocked.com") {
		t.Fatalf("expected offending list to contain blocked.com, got %v", info.offending)
	}
	if !info.changed {
		t.Fatalf("expected line to be modified when removal enabled")
	}
	if strings.Contains(info.updated, "blocked.com") || strings.Contains(info.updated, "another.com") {
		t.Fatalf("expected blocked domains to be removed, got %q", info.updated)
	}
	if !strings.Contains(info.updated, "allowed.com") {
		t.Fatalf("expected allowed domains to remain, got %q", info.updated)
	}
	if !strings.Contains(info.updated, "# inline comment") {
		t.Fatalf("expected inline comment to be preserved, got %q", info.updated)
	}
	if !strings.Contains(info.updated, "\tallowed.com") {
		t.Fatalf("expected sanitized hosts to be tab delimited, got %q", info.updated)
	}
}

func TestAnalyzeLine_RemoveEntireLine(t *testing.T) {
	defer func(prev func() time.Time) {
		timeNow = prev
	}(timeNow)
	fixedTime := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	timeNow = func() time.Time { return fixedTime }

	set := newBlockedSet()
	set.exact["blocked.com"] = struct{}{}

	line := "0.0.0.0 blocked.com"
	info := analyzeLine(line, 5, set, true)

	if !info.changed {
		t.Fatalf("expected line to be replaced with audit comment")
	}
	if !strings.HasPrefix(info.updated, "# Removed by DNShield Watchdog 2025-01-02T03:04:05Z") {
		t.Fatalf("unexpected audit comment: %q", info.updated)
	}
	if strings.Contains(info.updated, "blocked.com") && !strings.HasSuffix(info.updated, "blocked.com") {
		t.Fatalf("expected domain only in audit metadata, got %q", info.updated)
	}
}

func TestRebuildHostsLine(t *testing.T) {
	got := rebuildHostsLine("127.0.0.1", []string{"alpha.com", "beta.com"}, "# comment preserved")
	want := "127.0.0.1\talpha.com\tbeta.com # comment preserved"
	if got != want {
		t.Fatalf("unexpected rebuilt hosts line: got %q want %q", got, want)
	}

	// No hosts -> should return trimmed comment
	if result := rebuildHostsLine("", nil, "# only comment"); result != "# only comment" {
		t.Fatalf("expected comment-only return, got %q", result)
	}

	// Comment lacking hash should be normalized
	got = rebuildHostsLine("127.0.0.1", []string{"alpha.com"}, "trailing comment")
	want = "127.0.0.1\talpha.com # trailing comment"
	if got != want {
		t.Fatalf("comment normalization failed: got %q want %q", got, want)
	}
}
