//go:build darwin
// +build darwin

package main

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// LogDatabaseEvent logs database-related events with structured fields.
func LogDatabaseEvent(event string, dbPath string, exists bool) {
	logEvent := func(evt *zerolog.Event) {
		evt.
			Str("db_event", event).
			Str("db_path", dbPath).
			Bool("db_exists", exists).
			Str("event_type", "database_event").
			Msg("database state change detected")
	}

	if !exists && event != "initialized" {
		logEvent(log.Warn())
		return
	}

	logEvent(log.Info())
}

// LogRuleLoad logs rule loading events with structured fields.
func LogRuleLoad(count int, dbPath string, success bool) {
	if success {
		log.Info().
			Int("rule_count", count).
			Str("db_path", dbPath).
			Bool("success", success).
			Str("event_type", "rule_load").
			Msg("loaded blocked-domain rule(s)")
	} else {
		log.Error().
			Str("db_path", dbPath).
			Bool("success", success).
			Str("event_type", "rule_load").
			Msg("failed to load rules")
	}
}
