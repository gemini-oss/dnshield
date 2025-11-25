//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// HECEvent represents a Splunk HEC event.
type HECEvent struct {
	Time       float64                `json:"time"`
	Event      interface{}            `json:"event"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	SourceType string                 `json:"sourcetype,omitempty"`
	Index      string                 `json:"index,omitempty"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
}

// TelemetryClient handles sending logs to Splunk HEC.
type TelemetryClient struct {
	serverURL  string
	hecToken   string
	httpClient *http.Client
	hostname   string
}

// NewTelemetryClient creates a new telemetry client.
func NewTelemetryClient(serverURL, hecToken, hostname string) *TelemetryClient {
	return &TelemetryClient{
		serverURL: serverURL,
		hecToken:  hecToken,
		hostname:  hostname,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // Splunk HEC endpoint
				},
			},
		},
	}
}

// SendEvent sends a single event to Splunk HEC.
func (t *TelemetryClient) SendEvent(event interface{}) error {
	if t.serverURL == "" || t.hecToken == "" {
		return errors.New("telemetry not configured")
	}

	hecEvent := HECEvent{
		Time:       float64(time.Now().Unix()),
		Event:      event,
		Host:       t.hostname,
		Source:     "dnshield-watchdog",
		SourceType: "_json",
		Fields: map[string]interface{}{
			"component": "watchdog",
			"service":   "dnshield",
		},
	}

	jsonData, err := json.Marshal(hecEvent)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, t.serverURL+"/services/collector/event", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Splunk "+t.hecToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// SendBatch sends multiple events to Splunk HEC.
func (t *TelemetryClient) SendBatch(events []interface{}) error {
	if t.serverURL == "" || t.hecToken == "" {
		return errors.New("telemetry not configured")
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)

	for _, event := range events {
		hecEvent := HECEvent{
			Time:       float64(time.Now().Unix()),
			Event:      event,
			Host:       t.hostname,
			Source:     "dnshield-watchdog",
			SourceType: "_json",
			Fields: map[string]interface{}{
				"component": "watchdog",
				"service":   "dnshield",
			},
		}

		if err := encoder.Encode(hecEvent); err != nil {
			return fmt.Errorf("failed to encode event: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, t.serverURL+"/services/collector/event", &buffer)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Splunk "+t.hecToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send batch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
