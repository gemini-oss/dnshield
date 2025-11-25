package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

func main() {
	nesi := "/opt/dnshield/nesi"

	type Result struct {
		DNShieldProxy string `json:"dnshield_proxy"`
	}

	// Default result
	res := Result{DNShieldProxy: "disabled"}

	// Check existence
	if _, err := os.Stat(nesi); err != nil {
		res.DNShieldProxy = "nesi_not_installed"
		printJSON(res)
		return
	}

	// Execute: nesi -identifier "com.dnshield.app" -type dnsProxy -stdout-enabled
	cmd := exec.Command(nesi,
		"-identifier", "com.dnshield.app",
		"-type", "dnsProxy",
		"-stdout-enabled",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &bytes.Buffer{}      // ignore stderr for status
	if err := cmd.Run(); err != nil { // if execution fails, keep "disabled"
		printJSON(res)
		return
	}

	status := strings.TrimSpace(out.String())
	switch status {
	case "true":
		res.DNShieldProxy = "enabled"
	default:
		res.DNShieldProxy = "disabled"
	}

	printJSON(res)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "")
	_ = enc.Encode(v)
}
