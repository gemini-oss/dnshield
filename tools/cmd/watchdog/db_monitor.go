//go:build darwin
// +build darwin

package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// DatabaseMonitor watches for database file changes.
type DatabaseMonitor struct {
	dbPath        string
	lastState     *DBState
	mu            sync.RWMutex
	checkInterval time.Duration
}

// DBState represents the state of the database file.
type DBState struct {
	Exists   bool
	Size     int64
	ModTime  time.Time
	Checksum string
}

// NewDatabaseMonitor creates a new database monitor.
func NewDatabaseMonitor(dbPath string) *DatabaseMonitor {
	return &DatabaseMonitor{
		dbPath:        dbPath,
		checkInterval: 5 * time.Second,
	}
}

// Start begins monitoring the database.
func (dm *DatabaseMonitor) Start(ctx context.Context) {
	// Initial state check
	dm.checkState()

	// Start monitoring loop
	go dm.monitorLoop(ctx)
}

// monitorLoop continuously monitors the database file.
func (dm *DatabaseMonitor) monitorLoop(ctx context.Context) {
	ticker := time.NewTicker(dm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dm.checkState()
		}
	}
}

// checkState checks the current state of the database file.
func (dm *DatabaseMonitor) checkState() {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	newState := dm.getCurrentState()

	// First check or state changed
	if dm.lastState == nil {
		dm.handleStateChange(nil, newState)
		dm.lastState = newState
		return
	}

	// Check for changes
	if dm.hasStateChanged(dm.lastState, newState) {
		dm.handleStateChange(dm.lastState, newState)
		dm.lastState = newState
	}
}

// getCurrentState gets the current database file state.
func (dm *DatabaseMonitor) getCurrentState() *DBState {
	info, err := os.Stat(dm.dbPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &DBState{
				Exists: false,
			}
		}
		// Other error, treat as not existing
		return &DBState{
			Exists: false,
		}
	}

	return &DBState{
		Exists:  true,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
}

// hasStateChanged determines if the database state has changed.
func (dm *DatabaseMonitor) hasStateChanged(old, ns *DBState) bool {
	if old.Exists != ns.Exists {
		return true
	}

	if !ns.Exists {
		return false
	}

	// Check for size or modification time changes
	if old.Size != ns.Size || !old.ModTime.Equal(ns.ModTime) {
		return true
	}

	return false
}

// handleStateChange handles database state changes.
func (dm *DatabaseMonitor) handleStateChange(old, newState *DBState) {
	if old == nil {
		// Initial state
		if newState.Exists {
			LogDatabaseEvent("initialized", dm.dbPath, true)
		} else {
			LogDatabaseEvent("not_found", dm.dbPath, false)
		}
		return
	}

	// Database was deleted
	if old.Exists && !newState.Exists {
		LogDatabaseEvent("removed", dm.dbPath, false)
		log.Warn().
			Str("db_path", dm.dbPath).
			Str("event_type", "database_removed").
			Str("severity", "high").
			Msg("Database file has been removed")
		return
	}

	// Database was created
	if !old.Exists && newState.Exists {
		LogDatabaseEvent("created", dm.dbPath, true)
		log.Info().
			Str("db_path", dm.dbPath).
			Int64("db_size", newState.Size).
			Str("event_type", "database_created").
			Msg("Database file has been created")
		return
	}

	// Database was modified
	if old.Size != newState.Size {
		LogDatabaseEvent("modified", dm.dbPath, true)
		log.Info().
			Str("db_path", dm.dbPath).
			Int64("old_size", old.Size).
			Int64("new_size", newState.Size).
			Int64("size_diff", newState.Size-old.Size).
			Str("event_type", "database_modified").
			Msg("Database file has been modified")
	}
}

// WatchDatabase monitors database file using kqueue (macOS).
func (dm *DatabaseMonitor) WatchDatabase(ctx context.Context) error {
	kq, err := syscall.Kqueue()
	if err != nil {
		return err
	}
	defer syscall.Close(kq)

	// Open the database file
	fd, err := syscall.Open(dm.dbPath, syscall.O_RDONLY, 0)
	if err != nil {
		// File doesn't exist yet, fall back to polling
		return dm.pollDatabase(ctx)
	}
	defer syscall.Close(fd)

	// Set up the kevent
	kev := syscall.Kevent_t{
		Ident:  uint64(uintptr(fd)),
		Filter: syscall.EVFILT_VNODE,
		Flags:  syscall.EV_ADD | syscall.EV_CLEAR,
		Fflags: syscall.NOTE_DELETE | syscall.NOTE_WRITE | syscall.NOTE_RENAME | syscall.NOTE_ATTRIB,
		Data:   0,
		Udata:  nil,
	}

	// Register the event
	n, err := syscall.Kevent(kq, []syscall.Kevent_t{kev}, nil, nil)
	if err != nil || n == -1 {
		return err
	}

	events := make([]syscall.Kevent_t, 1)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Wait for events with timeout
			n, err := syscall.Kevent(kq, nil, events, &syscall.Timespec{Sec: 1})
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				return err
			}

			if n > 0 {
				event := events[0]
				dm.handleKqueueEvent(event)
			}
		}
	}
}

// handleKqueueEvent handles kqueue events for database monitoring.
func (dm *DatabaseMonitor) handleKqueueEvent(event syscall.Kevent_t) {
	if event.Fflags&syscall.NOTE_DELETE != 0 {
		LogDatabaseEvent("deleted", dm.dbPath, false)
	}
	if event.Fflags&syscall.NOTE_WRITE != 0 {
		dm.checkState()
	}
	if event.Fflags&syscall.NOTE_RENAME != 0 {
		LogDatabaseEvent("renamed", dm.dbPath, false)
	}
	if event.Fflags&syscall.NOTE_ATTRIB != 0 {
		dm.checkState()
	}
}

// pollDatabase falls back to polling when kqueue is not available.
func (dm *DatabaseMonitor) pollDatabase(ctx context.Context) error {
	ticker := time.NewTicker(dm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			dm.checkState()
		}
	}
}

// GetPath returns the database path being monitored.
func (dm *DatabaseMonitor) GetPath() string {
	return dm.dbPath
}

// IsHealthy checks if the database is currently accessible.
func (dm *DatabaseMonitor) IsHealthy() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if dm.lastState == nil {
		return false
	}

	return dm.lastState.Exists && dm.lastState.Size > 0
}
