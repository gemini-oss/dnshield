//go:build darwin
// +build darwin

package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gemini/dnshield/internal/cfpref"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v66/github"
	"golang.org/x/oauth2"
)

type Config struct {
	Port         string
	ManifestsDir string
	BaseDir      string
}

type AppConfig struct {
	RepoPath string `json:"repo_path"`
}

type ConfigRequest struct {
	RepoPath string `json:"repo_path"`
}

type PathSuggestion struct {
	Path        string `json:"path"`
	Valid       bool   `json:"valid"`
	Description string `json:"description"`
}

type DomainRequest struct {
	Action       string   `json:"action"` // "add", "remove", "create"
	ManifestName string   `json:"manifest_name"`
	Domains      []string `json:"domains"`
	Category     string   `json:"category,omitempty"`  // for new manifests: "global", "domain", "group", "phishing", "team"
	RuleType     string   `json:"rule_type,omitempty"` // ruleTypeAllow or ruleTypeBlock
}

type GitHubAppConfig struct {
	AppID          int64
	InstallationID int64
	PrivateKey     string
	APIBase        string
	DefaultOwner   string
	DefaultRepo    string
	ClientID       string
	ClientSecret   string
}

type PRRequest struct {
	Owner         string     `json:"owner"`
	Repo          string     `json:"repo"`
	BaseBranch    string     `json:"base_branch"`
	FeaturePrefix string     `json:"feature_prefix"`
	CommitMessage string     `json:"commit_message"`
	PRTitle       string     `json:"pr_title"`
	PRBody        string     `json:"pr_body"`
	Files         []FileSpec `json:"files"`
}

type FileSpec struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"content_base64"`
}

type PRResponse struct {
	Branch    string `json:"branch"`
	CommitSHA string `json:"commit_sha"`
	PRNumber  int    `json:"pr_number"`
	PRURL     string `json:"pr_url"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

type TokenService struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey
	cacheToken     string
	cacheExpiry    time.Time
	apiBase        string
}

type SearchRequest struct {
	Type  string `json:"type"`
	Query string `json:"query"`
}

type SearchResult struct {
	Found    bool      `json:"found"`
	Type     string    `json:"type,omitempty"`
	Name     string    `json:"name,omitempty"`
	File     string    `json:"file,omitempty"`
	Serial   string    `json:"serial,omitempty"`
	Machines []Machine `json:"machines,omitempty"`
}

type Machine struct {
	Serial   string `json:"serial"`
	Hostname string `json:"hostname"`
	File     string `json:"file"`
}

func writeJSON(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

type ManifestData struct {
	Manifests []string               `json:"manifests"`
	Raw       map[string]interface{} `json:"raw,omitempty"`
}

type ManifestItem struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

type UpdateRequest struct {
	Manifests []string `json:"manifests"`
}

type LegacyPRRequest struct {
	Branch      string                 `json:"branch"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	File        string                 `json:"file"`
	Changes     map[string]interface{} `json:"changes"`
}

type LegacyPRResponse struct {
	Success bool   `json:"success"`
	Branch  string `json:"branch,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Embed static files
//
//go:embed frontend/*
var staticFiles embed.FS

var (
	config             Config
	appConfig          AppConfig
	ghAppConfig        *GitHubAppConfig
	tokenService       *TokenService
	userMapping        = make(map[string][]Machine)       // Changed to store multiple machines per user
	inheritedManifests = make(map[string]map[string]bool) // Cache inherited manifests
	prefDomain         = "com.dnshield.manifest-editor"
	sessions           = make(map[string]*UserSession)
	csrfStates         = make(map[string]string) // state -> sessionID
)

const (
	defaultGitHubAPIBase = "https://api.github.com"
	ruleTypeAllow        = "allow"
	ruleTypeBlock        = "block"
)

// Lightweight session storage for local tool use.
type UserSession struct {
	AccessToken string
	Login       string
	Name        string
	ExpiresAt   time.Time
}

func init() { //nolint:gochecknoinits // Manifest editor preloads configuration before main to configure handlers.
	// Load environment variables
	loadEnvFile()

	// Initialize GitHub App configuration
	if err := initGitHubAppConfig(); err != nil {
		log.Printf("Warning: GitHub App not configured: %v", err)
	}

	// Load saved repository path first
	if err := loadAppConfig(); err == nil && appConfig.RepoPath != "" {
		// Use saved path if it's still valid
		if isValidRepoPath(appConfig.RepoPath) {
			config = Config{
				Port:         "7777",
				BaseDir:      appConfig.RepoPath,
				ManifestsDir: filepath.Join(appConfig.RepoPath, "manifests"),
			}
			return
		}
	}

	// No valid saved path - will require user to select one
	config = Config{
		Port:         "7777",
		BaseDir:      "",
		ManifestsDir: "",
	}
}

// getConfigPath returns the path to the app configuration file.
func getConfigPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	configDir := filepath.Join(usr.HomeDir, ".config", "dnshield-manifest-editor")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return "", err
	}

	return filepath.Join(configDir, "config.json"), nil
}

// loadAppConfig loads the application configuration from file.
func loadAppConfig() error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &appConfig)
}

// saveAppConfig saves the application configuration to file.
func saveAppConfig() error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(appConfig, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0o600)
}

// isValidRepoPath checks if the given path contains a valid DNShield repository.
func isValidRepoPath(path string) bool {
	if path == "" {
		return false
	}

	// Check if manifests directory exists
	manifestsPath := filepath.Join(path, "manifests")
	if info, err := os.Stat(manifestsPath); err != nil || !info.IsDir() {
		return false
	}

	// Check if it's a git repository
	gitPath := filepath.Join(path, ".git")
	if info, err := os.Stat(gitPath); err != nil || !info.IsDir() {
		return false
	}

	return true
}

func main() {
	// Setup routes
	http.HandleFunc("/api/search", corsMiddleware(requireConfig(handleSearch)))
	http.HandleFunc("/api/manifests/", corsMiddleware(requireConfig(handleManifests)))
	http.HandleFunc("/api/manifests/available", corsMiddleware(requireConfig(handleAvailableManifests)))
	http.HandleFunc("/api/manifest/view/", corsMiddleware(requireConfig(handleViewManifest)))
	http.HandleFunc("/api/domains", corsMiddleware(requireConfig(handleDomains)))
	http.HandleFunc("/api/pull-request", corsMiddleware(requireConfig(handlePullRequest)))
	http.HandleFunc("/api/pr-from-json-edits", corsMiddleware(requireConfig(handleGitHubPR)))
	// Auth endpoints
	http.HandleFunc("/api/auth/status", corsMiddleware(handleAuthStatus))
	http.HandleFunc("/api/auth/login", corsMiddleware(handleAuthLogin))
	http.HandleFunc("/api/auth/callback", corsMiddleware(handleAuthCallback))
	http.HandleFunc("/api/auth/logout", corsMiddleware(handleAuthLogout))
	http.HandleFunc("/api/config", corsMiddleware(handleConfig))
	http.HandleFunc("/api/health", corsMiddleware(handleHealth))

	// Serve embedded static files
	staticFS, err := fs.Sub(staticFiles, "frontend")
	if err != nil {
		log.Fatal("Failed to create static file system:", err)
	}
	http.Handle("/", http.FileServer(http.FS(staticFS)))

	fmt.Printf("DNShield Manifest Editor Server\n")
	if config.BaseDir != "" {
		fmt.Printf("Base directory: %s\n", config.BaseDir)
		fmt.Printf("Manifests directory: %s\n", config.ManifestsDir)
	} else {
		fmt.Printf("Repository path not configured - setup required\n")
	}
	fmt.Printf("Server running at: http://localhost:%s\n", config.Port)
	fmt.Printf("Open http://localhost:%s/ in your browser\n", config.Port)

	server := &http.Server{
		Addr:              ":" + config.Port,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

func corsMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler(w, r)
	}
}

// ----- Auth Handlers (GitHub App on behalf of a user) -----.
func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	sess := currentSession(r)
	if sess != nil && sess.AccessToken != "" {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, map[string]any{"authenticated": true, "user": sess.Login})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]any{"authenticated": false})
}

func handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if ghAppConfig == nil || ghAppConfig.ClientID == "" || ghAppConfig.ClientSecret == "" {
		http.Error(w, "GitHub App OAuth not configured", http.StatusServiceUnavailable)
		return
	}
	sid := ensureSession(w, r)
	state := randString(24)
	csrfStates[state] = sid
	redirectURL := oauthRedirectURL(r)
	q := url.Values{}
	q.Set("client_id", ghAppConfig.ClientID)
	q.Set("redirect_uri", redirectURL)
	q.Set("scope", "repo")
	q.Set("state", state)
	q.Set("allow_signup", "false")
	authURL := oauthBaseURL() + "/login/oauth/authorize?" + q.Encode()
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if ghAppConfig == nil || ghAppConfig.ClientID == "" || ghAppConfig.ClientSecret == "" {
		http.Error(w, "GitHub App OAuth not configured", http.StatusServiceUnavailable)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing code/state", http.StatusBadRequest)
		return
	}
	sid, ok := csrfStates[state]
	if !ok {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	delete(csrfStates, state)

	form := url.Values{}
	form.Set("client_id", ghAppConfig.ClientID)
	form.Set("client_secret", ghAppConfig.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", oauthRedirectURL(r))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, oauthBaseURL()+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "OAuth exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &tokenResp)
	if tokenResp.AccessToken == "" {
		http.Error(w, "OAuth exchange error: "+tokenResp.Error+" "+tokenResp.ErrorDesc, http.StatusBadGateway)
		return
	}

	gh := github.NewClient(nil).WithAuthToken(tokenResp.AccessToken)
	if ghAppConfig.APIBase != defaultGitHubAPIBase && ghAppConfig.APIBase != "" {
		gh, _ = gh.WithEnterpriseURLs(ghAppConfig.APIBase, ghAppConfig.APIBase)
	}
	user, _, err := gh.Users.Get(r.Context(), "")
	if err != nil {
		http.Error(w, "Failed to fetch user profile", http.StatusBadGateway)
		return
	}
	sessions[sid] = &UserSession{AccessToken: tokenResp.AccessToken, Login: user.GetLogin(), Name: user.GetName(), ExpiresAt: time.Now().Add(8 * time.Hour)}
	http.Redirect(w, r, "/", http.StatusFound)
}

// oauthBaseURL returns the base host for OAuth endpoints based on APIBase.
func oauthBaseURL() string {
	base := ghAppConfig.APIBase
	if base == "" || base == defaultGitHubAPIBase {
		return "https://github.com"
	}
	// Derive host from API base (trim trailing "/api" or "/api/v3")
	if u, err := url.Parse(base); err == nil {
		// Remove "/api" or "/api/v3" from path
		p := strings.TrimSuffix(strings.TrimSuffix(u.Scheme+"://"+u.Host+u.Path, "/api/v3"), "/api")
		if p != "" {
			return p
		}
		return u.Scheme + "://" + u.Host
	}
	return "https://github.com"
}

// oauthRedirectURL returns the redirect URI to use for OAuth callback
// Order of precedence: env override -> request host/proto -> localhost:PORT.
func oauthRedirectURL(r *http.Request) string {
	if v := os.Getenv("GH_APP_REDIRECT_URL"); v != "" {
		return v
	}
	if v := os.Getenv("GH_REDIRECT_URL"); v != "" {
		return v
	}
	if v := os.Getenv("GITHUB_REDIRECT_URL"); v != "" {
		return v
	}

	host := r.Host
	if host == "" {
		host = "localhost:" + config.Port
	}
	scheme := "http"
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return fmt.Sprintf("%s://%s/api/auth/callback", scheme, host)
}

func handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("me_session"); err == nil {
		delete(sessions, c.Value)
		http.SetCookie(w, &http.Cookie{Name: "me_session", Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1})
	}
	w.WriteHeader(http.StatusNoContent)
}

// Session helpers.
func ensureSession(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("me_session"); err == nil && c.Value != "" {
		return c.Value
	}
	sid := randString(32)
	http.SetCookie(w, &http.Cookie{Name: "me_session", Value: sid, Path: "/", HttpOnly: true})
	return sid
}

func currentSession(r *http.Request) *UserSession {
	c, err := r.Cookie("me_session")
	if err != nil {
		return nil
	}
	return sessions[c.Value]
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

func loadUserMapping() {
	if len(userMapping) > 0 {
		return
	}

	// Gather machine manifest files from both top-level and manifests/machines/
	topLevelFiles, _ := filepath.Glob(filepath.Join(config.ManifestsDir, "*.json"))
	machinesFiles, _ := filepath.Glob(filepath.Join(config.ManifestsDir, "machines", "*.json"))
	files := append([]string{}, topLevelFiles...)
	files = append(files, machinesFiles...)

	for _, file := range files {
		filename := filepath.Base(file)
		if filename == "default.json" || filename == "global-allowlist.json" ||
			filename == "global-blocklist.json" || filename == "site_default.json" {
			continue
		}

		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var manifest map[string]interface{}
		if err := json.Unmarshal(data, &manifest); err != nil {
			continue
		}

		// Determine serial (file base name without extension)
		serial := strings.TrimSuffix(filename, ".json")
		// Determine repo-relative path for API (e.g., "machines/C02ABC1234.json" or "C02ABC1234.json")
		relPath, _ := filepath.Rel(config.ManifestsDir, file)

		// Try to extract user from metadata.description
		// Format: "... (hostname: xxx, user: email@domain.com)"
		if metadata, ok := manifest["metadata"].(map[string]interface{}); ok {
			if description, ok := metadata["description"].(string); ok {
				var hostname string
				var userEmail string

				// Extract hostname
				hostnameStart := strings.Index(description, "hostname: ")
				if hostnameStart != -1 {
					hostnameStart += 10 // length of "hostname: "
					hostnameEnd := strings.IndexByte(description[hostnameStart:], ',')
					if hostnameEnd != -1 {
						hostname = description[hostnameStart : hostnameStart+hostnameEnd]
					}
				}

				// Extract user from description using pattern matching
				userStart := strings.Index(description, "user: ")
				if userStart != -1 {
					userStart += 6 // length of "user: "
					userEnd := strings.IndexByte(description[userStart:], ')')
					if userEnd != -1 {
						userEmail = description[userStart : userStart+userEnd]

						// Extract username from email (part before @)
						username := userEmail
						if atIdx := strings.Index(userEmail, "@"); atIdx != -1 {
							username = userEmail[:atIdx]
						}

						machine := Machine{
							Serial:   serial,
							Hostname: hostname,
							File:     relPath,
						}

						// Store both username and full email
						userMapping[strings.ToLower(username)] = append(userMapping[strings.ToLower(username)], machine)
						if username != userEmail {
							userMapping[strings.ToLower(userEmail)] = append(userMapping[strings.ToLower(userEmail)], machine)
						}
					}
				}
			}
		}
	}
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := searchEntity(req.Type, req.Query)
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, result)
}

func searchEntity(entityType, query string) SearchResult {
	query = strings.ToLower(strings.TrimSpace(query))

	switch entityType {
	case "user":
		loadUserMapping()

		// Exact match
		if machines, ok := userMapping[query]; ok && len(machines) > 0 {
			// If multiple machines, return them all
			if len(machines) > 1 {
				return SearchResult{
					Found:    true,
					Type:     "user",
					Name:     query,
					Machines: machines,
				}
			}
			// Single machine - return as before for backward compatibility
			return SearchResult{
				Found:  true,
				Type:   "user",
				Name:   query,
				File:   machines[0].File,
				Serial: machines[0].Serial,
			}
		}

		// Partial match
		for username, machines := range userMapping {
			if strings.Contains(username, query) && len(machines) > 0 {
				if len(machines) > 1 {
					return SearchResult{
						Found:    true,
						Type:     "user",
						Name:     username,
						Machines: machines,
					}
				}
				return SearchResult{
					Found:  true,
					Type:   "user",
					Name:   username,
					File:   machines[0].File,
					Serial: machines[0].Serial,
				}
			}
		}

		// Check if query is a serial (look under manifests/machines first, then top-level)
		serialUpper := strings.ToUpper(query)
		manifestFileMachines := filepath.Join(config.ManifestsDir, "machines", serialUpper+".json")
		if _, err := os.Stat(manifestFileMachines); err == nil {
			return SearchResult{
				Found:  true,
				Type:   "user",
				File:   filepath.ToSlash(filepath.Join("machines", serialUpper+".json")),
				Serial: serialUpper,
			}
		}
		manifestFileTop := filepath.Join(config.ManifestsDir, serialUpper+".json")
		if _, err := os.Stat(manifestFileTop); err == nil {
			return SearchResult{
				Found:  true,
				Type:   "user",
				File:   serialUpper + ".json",
				Serial: serialUpper,
			}
		}

	case "machine":
		serial := strings.ToUpper(query)
		// Prefer manifests/machines/<serial>.json if present
		manifestFileMachines := filepath.Join(config.ManifestsDir, "machines", serial+".json")
		if _, err := os.Stat(manifestFileMachines); err == nil {
			return SearchResult{
				Found:  true,
				Type:   "machine",
				Serial: serial,
				File:   filepath.ToSlash(filepath.Join("machines", serial+".json")),
			}
		}
		// Fallback to top-level for backward compatibility
		manifestFileTop := filepath.Join(config.ManifestsDir, serial+".json")
		if _, err := os.Stat(manifestFileTop); err == nil {
			return SearchResult{
				Found:  true,
				Type:   "machine",
				Serial: serial,
				File:   serial + ".json",
			}
		}

	case "group":
		// Check group manifests
		groupFile := filepath.Join(config.ManifestsDir, "includes", "group", query+".json")
		if _, err := os.Stat(groupFile); err == nil {
			return SearchResult{
				Found: true,
				Type:  "group",
				Name:  query,
				File:  "includes/group/" + query + ".json",
			}
		}

		// Check team manifests
		teamFile := filepath.Join(config.ManifestsDir, "includes", "team", query+".json")
		if _, err := os.Stat(teamFile); err == nil {
			return SearchResult{
				Found: true,
				Type:  "group",
				Name:  query,
				File:  "includes/team/" + query + ".json",
			}
		}
	}

	return SearchResult{Found: false}
}

func handleManifests(w http.ResponseWriter, r *http.Request) {
	// Extract file path from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/manifests/")

	switch r.Method {
	case http.MethodGet:
		content := getManifestContent(path)
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, content)

	case http.MethodPut:
		var req UpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if saveManifest(path, req.Manifests) {
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]bool{"success": true})
		} else {
			http.Error(w, "Failed to save", http.StatusInternalServerError)
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getManifestContent(filePath string) ManifestData {
	fullPath := filepath.Join(config.ManifestsDir, filePath)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		return ManifestData{Manifests: []string{}}
	}

	var rawData map[string]interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		return ManifestData{Manifests: []string{}}
	}

	manifests := []string{}

	// Handle included_manifests
	if included, ok := rawData["included_manifests"].([]interface{}); ok {
		for _, m := range included {
			if str, ok := m.(string); ok {
				manifests = append(manifests, cleanManifestName(str))
			}
		}
	}

	// Handle catalogs
	if catalogs, ok := rawData["catalogs"].([]interface{}); ok {
		for _, catalog := range catalogs {
			if str, ok := catalog.(string); ok {
				manifests = append(manifests, cleanManifestName(str))
			} else if cat, ok := catalog.(map[string]interface{}); ok {
				if name, ok := cat["name"].(string); ok {
					manifests = append(manifests, cleanManifestName(name))
				}
			}
		}
	}

	// Calculate all inherited manifests (including nested)
	allInherited := getAllInheritedManifests(manifests)
	inheritedManifests[filePath] = allInherited

	return ManifestData{
		Manifests: manifests,
		Raw:       rawData,
	}
}

// Recursively get all manifests that are inherited (including nested).
func getAllInheritedManifests(directManifests []string) map[string]bool {
	inherited := make(map[string]bool)
	visited := make(map[string]bool)

	var resolve func(string)
	resolve = func(manifestName string) {
		if visited[manifestName] {
			return
		}
		visited[manifestName] = true
		inherited[manifestName] = true

		// Load the manifest file and get its includes
		manifestPath := determineManifestPath(manifestName)
		fullPath := filepath.Join(config.ManifestsDir, manifestPath)

		data, err := os.ReadFile(fullPath)
		if err != nil {
			return
		}

		var manifest map[string]interface{}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return
		}

		// Check for included_manifests
		if included, ok := manifest["included_manifests"].([]interface{}); ok {
			for _, m := range included {
				if str, ok := m.(string); ok {
					childName := cleanManifestName(str)
					inherited[childName] = true
					resolve(childName)
				}
			}
		}

		// Check for catalogs
		if catalogs, ok := manifest["catalogs"].([]interface{}); ok {
			for _, catalog := range catalogs {
				if str, ok := catalog.(string); ok {
					childName := cleanManifestName(str)
					inherited[childName] = true
					resolve(childName)
				}
			}
		}
	}

	for _, manifest := range directManifests {
		resolve(manifest)
	}

	return inherited
}

// Determine the file path for a manifest based on its name (for reading files).
func determineManifestPath(manifest string) string {
	// Check if it's already a path
	if strings.Contains(manifest, "/") {
		// Ensure it has .json extension for file reading
		if !strings.HasSuffix(manifest, ".json") {
			return manifest + ".json"
		}
		return manifest
	}

	// Check standard locations
	if manifest == "global-allowlist" || manifest == "global-blocklist" {
		return manifest + ".json"
	}

	// Try to determine based on naming patterns - add .json for file reading
	catalogPath := determineCatalogPath(manifest)
	if !strings.HasSuffix(catalogPath, ".json") {
		catalogPath += ".json"
	}
	return catalogPath
}

func cleanManifestName(name string) string {
	name = strings.TrimSuffix(name, ".json")
	name = strings.ReplaceAll(name, "includes/", "")
	if strings.Contains(name, "/") {
		parts := strings.Split(name, "/")
		name = parts[len(parts)-1]
	}
	return name
}

func saveManifest(filePath string, manifests []string) bool {
	fullPath := filepath.Join(config.ManifestsDir, filePath)

	// Read existing file
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return false
	}

	var rawData map[string]interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		return false
	}

	// Build updated catalogs
	updatedCatalogs := []string{}
	for _, manifest := range manifests {
		catalogPath := determineCatalogPath(manifest)
		updatedCatalogs = append(updatedCatalogs, catalogPath)
	}

	// Update the data
	if _, ok := rawData["catalogs"]; ok {
		rawData["catalogs"] = updatedCatalogs
	} else if _, ok := rawData["included_manifests"]; ok {
		rawData["included_manifests"] = updatedCatalogs
	}

	// Write back
	output, err := json.MarshalIndent(rawData, "", "  ")
	if err != nil {
		return false
	}

	return os.WriteFile(fullPath, append(output, '\n'), 0o644) == nil //nolint:gosec // manifests remain world-readable within repository checkout
}

func determineCatalogPath(manifest string) string {
	// Remove .json extension if present
	manifest = strings.TrimSuffix(manifest, ".json")

	// Dynamically search for the manifest in the filesystem
	categories := []string{"team", "global", "phishing", "group", "domain"}
	for _, category := range categories {
		manifestPath := filepath.Join(config.ManifestsDir, "includes", category, manifest+".json")
		if _, err := os.Stat(manifestPath); err == nil {
			return fmt.Sprintf("includes/%s/%s", category, manifest)
		}
	}

	// Fallback
	switch {
	case strings.HasPrefix(manifest, "fte-"):
		return "includes/team/" + manifest
	case manifest == "global-allowlist" || manifest == "global-blocklist" ||
		manifest == "ai" || manifest == "vpns" || manifest == "typo-squatting-domains" ||
		manifest == "allowlist" || manifest == "blocklist":
		return "includes/global/" + manifest
	case strings.Contains(strings.ToLower(manifest), "phish") ||
		strings.Contains(strings.ToLower(manifest), "urlhaus"):
		return "includes/phishing/" + manifest
	case manifest == "social-media-allow":
		return "includes/group/" + manifest
	case manifest == "okta-allowlist" || manifest == "telegram-allowlist" ||
		manifest == "twingate-allowlist":
		return "includes/domain/" + manifest
	default:
		return "includes/" + manifest
	}
}

func handleAvailableManifests(w http.ResponseWriter, r *http.Request) {
	// Get the entity file from query params to know what's already inherited
	entityFile := r.URL.Query().Get("entity")

	manifests := getAvailableManifests()

	// If we have inherited manifests for this entity, filter them out
	if entityFile != "" && len(inheritedManifests[entityFile]) > 0 {
		filtered := []ManifestItem{}
		inherited := inheritedManifests[entityFile]
		currentManifests := getManifestContent(entityFile).Manifests

		// Create a map of current team assignments for filtering
		currentTeams := make(map[string]bool)
		for _, m := range currentManifests {
			if strings.HasPrefix(m, "fte-") {
				currentTeams[m] = true
			}
		}

		for _, manifest := range manifests {
			// Skip if already inherited
			if inherited[manifest.Name] {
				continue
			}

			// Skip team manifests that user isn't already assigned to
			if manifest.Type == "team" && !currentTeams[manifest.Name] {
				continue
			}

			filtered = append(filtered, manifest)
		}
		manifests = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string][]ManifestItem{"manifests": manifests})
}

func getAvailableManifests() []ManifestItem {
	manifests := []ManifestItem{}

	categories := []string{"global", "domain", "group", "phishing", "team"}
	for _, category := range categories {
		categoryDir := filepath.Join(config.ManifestsDir, "includes", category)
		files, err := filepath.Glob(filepath.Join(categoryDir, "*.json"))
		if err != nil {
			continue
		}

		for _, file := range files {
			name := strings.TrimSuffix(filepath.Base(file), ".json")
			manifests = append(manifests, ManifestItem{
				Name: name,
				Type: category,
				Path: fmt.Sprintf("includes/%s/%s", category, name),
			})
		}
	}

	return manifests
}

func handlePullRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LegacyPRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := createPullRequest(req.Branch, req.Title, req.Description, req.File)
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, result)
}

func createPullRequest(branch, title, description, filePath string) LegacyPRResponse {
	// Change to repo directory
	if err := os.Chdir(config.BaseDir); err != nil {
		return LegacyPRResponse{Success: false, Error: err.Error()}
	}

	// Check if gh CLI is available first
	if !isGHInstalled() {
		return LegacyPRResponse{
			Success: false,
			Error:   "GitHub CLI (gh) is required but not installed. " + getGHInstallMessage(),
		}
	}

	// Check if we have uncommitted changes for the specific file
	cmd := exec.CommandContext(context.Background(), "git", "status", "--porcelain", filepath.Join("manifests", filePath)) //nolint:gosec // command arguments are controlled and limited to git operations within the repository
	statusOutput, _ := cmd.Output()
	if len(statusOutput) == 0 {
		return LegacyPRResponse{
			Success: false,
			Error:   "No changes detected in the file. Please make sure you've saved changes first.",
		}
	}

	// Create and switch to new branch, add changes, then use gh pr create
	manifestPath := filepath.Join("manifests", filePath)

	// Create new branch from main
	cmd = exec.CommandContext(context.Background(), "git", "checkout", "-b", branch)
	if err := cmd.Run(); err != nil {
		return LegacyPRResponse{Success: false, Error: "Failed to create branch"}
	}

	// Add and commit the file changes
	cmd = exec.CommandContext(context.Background(), "git", "add", manifestPath)
	if err := cmd.Run(); err != nil {
		return LegacyPRResponse{Success: false, Error: "Failed to stage changes"}
	}

	cmd = exec.CommandContext(context.Background(), "git", "commit", "-m", title)
	if err := cmd.Run(); err != nil {
		return LegacyPRResponse{Success: false, Error: "Failed to commit changes"}
	}

	// Use gh pr create which will push the branch and create PR
	cmd = exec.CommandContext(context.Background(), "gh", "pr", "create",
		"--title", title,
		"--body", description,
		"--base", "main",
	)

	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err == nil {
		// Success! Extract PR URL from output and mark as ready
		prURL := outputStr

		// Convert from draft to ready
		cmd = exec.CommandContext(context.Background(), "gh", "pr", "ready", prURL)
		if err := cmd.Run(); err != nil {
			log.Printf("failed to mark pull request ready: %v", err)
		}

		return LegacyPRResponse{
			Success: true,
			Branch:  branch,
			Message: fmt.Sprintf("Pull request created successfully! View at: %s", prURL),
		}
	}

	// Handle various gh pr create error cases
	if strings.Contains(outputStr, "auth") || strings.Contains(outputStr, "authenticate") {
		return LegacyPRResponse{
			Success: false,
			Error:   "GitHub CLI needs authentication. Run: gh auth login",
		}
	}

	if strings.Contains(outputStr, "already exists") {
		return LegacyPRResponse{
			Success: false,
			Error:   fmt.Sprintf("Branch '%s' or PR already exists. Use a different branch name.", branch),
		}
	}

	// Generic error with full output for debugging
	return LegacyPRResponse{
		Success: false,
		Error:   fmt.Sprintf("Failed to create PR. gh error: %s", outputStr),
	}
}

// Check if GitHub CLI is installed.
func isGHInstalled() bool {
	cmd := exec.CommandContext(context.Background(), "which", "gh")
	err := cmd.Run()
	return err == nil
}

// Get installation message for GitHub CLI.
func getGHInstallMessage() string {
	// Detect OS for platform-specific instructions
	cmd := exec.CommandContext(context.Background(), "uname", "-s")
	output, err := cmd.Output()
	osName := "Linux"
	if err == nil {
		osName = strings.TrimSpace(string(output))
	}

	switch osName {
	case "Darwin": // macOS
		return "Tip: Install GitHub CLI for automatic PR creation:\n" +
			"   brew install gh\n" +
			"   gh auth login\n" +
			"   More info: https://cli.github.com/manual/installation"
	case "Linux":
		return "Tip: Install GitHub CLI for automatic PR creation:\n" +
			"   • Debian/Ubuntu: sudo apt install gh\n" +
			"   • Fedora: sudo dnf install gh\n" +
			"   • Arch: sudo pacman -S github-cli\n" +
			"   Then run: gh auth login\n" +
			"   More info: https://cli.github.com/manual/installation"
	default:
		return "Tip: Install GitHub CLI for automatic PR creation:\n" +
			"   Download from: https://cli.github.com\n" +
			"   Then run: gh auth login"
	}
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Return current configuration status with suggestions
		suggestions := generatePathSuggestions()
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, map[string]interface{}{
			"configured":  config.BaseDir != "",
			"repo_path":   config.BaseDir,
			"suggestions": suggestions,
		})

	case http.MethodPost:
		// Set repository path
		var req ConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Validate the path
		if !isValidRepoPath(req.RepoPath) {
			http.Error(w, "Invalid repository path - must contain 'manifests' directory and be a git repository", http.StatusBadRequest)
			return
		}

		// Update configuration
		appConfig.RepoPath = req.RepoPath
		config.BaseDir = req.RepoPath
		config.ManifestsDir = filepath.Join(req.RepoPath, "manifests")

		// Save to config file
		if err := saveAppConfig(); err != nil {
			log.Printf("Warning: Failed to save config: %v", err)
		}

		// Clear cached data since we're switching repositories
		userMapping = make(map[string][]Machine)
		inheritedManifests = make(map[string]map[string]bool)

		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, map[string]interface{}{
			"success":   true,
			"repo_path": req.RepoPath,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.Action {
	case "create":
		ruleType := req.RuleType
		if ruleType == "" {
			// Default to block if not specified
			ruleType = ruleTypeBlock
			if strings.Contains(strings.ToLower(req.ManifestName), ruleTypeAllow) {
				ruleType = ruleTypeAllow
			}
		}
		result := createManifest(req.ManifestName, req.Category, req.Domains, ruleType)
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, result)
	case "add":
		result := addDomainsToManifest(req.ManifestName, req.Domains, req.RuleType)
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, result)
	case "remove":
		result := removeDomainsFromManifest(req.ManifestName, req.Domains)
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, result)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
	}
}

func handleViewManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract manifest name from URL path
	manifestName := strings.TrimPrefix(r.URL.Path, "/api/manifest/view/")
	if manifestName == "" {
		http.Error(w, "Manifest name required", http.StatusBadRequest)
		return
	}

	result := getManifestDetails(manifestName)
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, result)
}

func handleGitHubPR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if GitHub App is configured
	if ghAppConfig == nil || tokenService == nil {
		http.Error(w, "GitHub App not configured", http.StatusServiceUnavailable)
		return
	}

	// Require user login for PR creation
	sess := currentSession(r)
	if sess == nil || sess.AccessToken == "" {
		http.Error(w, "Authentication required. Please sign in via GitHub.", http.StatusUnauthorized)
		return
	}

	var req PRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Use defaults if not provided
	if req.Owner == "" {
		req.Owner = ghAppConfig.DefaultOwner
	}
	if req.Repo == "" {
		req.Repo = ghAppConfig.DefaultRepo
	}
	if req.BaseBranch == "" {
		req.BaseBranch = "main"
	}
	if req.FeaturePrefix == "" {
		req.FeaturePrefix = "feature"
	}

	// Inject user token into context so actions are done on behalf of the user
	ctx := withUserToken(r.Context(), sess.AccessToken)
	result := createGitHubPR(ctx, req)
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, result)
}

func createGitHubPR(ctx context.Context, req PRRequest) PRResponse {
	log.Printf("[PR] Starting GitHub PR creation for %s/%s", req.Owner, req.Repo)

	// Initialize services
	clientFactory := &GitHubClientFactory{tokenService: tokenService}
	repoService := &RepoService{clientFactory: clientFactory}

	// Generate unique feature branch name
	featureBranch := generateFeatureBranchName(req.FeaturePrefix, "manifest-editor")
	log.Printf("[PR] Generated feature branch name: %s", featureBranch)

	// Get base branch SHA
	log.Printf("[PR] Getting base branch SHA for %s", req.BaseBranch)
	baseSHA, err := repoService.GetBaseRef(ctx, req.Owner, req.Repo, req.BaseBranch)
	if err != nil {
		log.Printf("[PR] ERROR: Failed to get base branch: %v", err)
		return PRResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get base branch: %v", err),
		}
	}
	log.Printf("[PR] Base branch SHA: %s", baseSHA)

	// Create feature branch
	log.Printf("[PR] Creating feature branch: %s", featureBranch)
	if err := repoService.CreateBranch(ctx, req.Owner, req.Repo, featureBranch, baseSHA); err != nil {
		log.Printf("[PR] ERROR: Failed to create branch: %v", err)
		return PRResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create branch: %v", err),
		}
	}
	log.Printf("[PR] Feature branch created successfully")

	// Commit files atomically
	log.Printf("[PR] Committing %d files atomically", len(req.Files))
	for i, file := range req.Files {
		log.Printf("[PR] File %d: %s (%d bytes base64)", i+1, file.Path, len(file.ContentBase64))
	}

	// Use App installation token for commit operations to obtain GitHub-signed (Verified) commits
	ctxCommit := withCommitWithApp(ctx, true)
	commitSHA, err := repoService.CommitFilesAtomic(ctxCommit, req.Owner, req.Repo, featureBranch, baseSHA, req.Files, req.CommitMessage)
	if err != nil {
		log.Printf("[PR] ERROR: Failed to commit files: %v", err)
		return PRResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to commit files: %v", err),
		}
	}
	log.Printf("[PR] Commit created successfully: %s", commitSHA)

	// Create pull request as the authenticated user (on-behalf-of) using the user token
	log.Printf("[PR] Creating pull request: %s -> %s", featureBranch, req.BaseBranch)
	prNumber, prURL, err := repoService.OpenPR(ctx, req.Owner, req.Repo, req.PRTitle, req.PRBody, featureBranch, req.BaseBranch)
	if err != nil {
		log.Printf("[PR] ERROR: Failed to create pull request: %v", err)
		return PRResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create pull request: %v", err),
		}
	}
	log.Printf("[PR] Pull request created successfully: #%d - %s", prNumber, prURL)

	return PRResponse{
		Success:   true,
		Branch:    featureBranch,
		CommitSHA: commitSHA,
		PRNumber:  prNumber,
		PRURL:     prURL,
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// requireConfig is a middleware that ensures repository is configured.
func requireConfig(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if config.BaseDir == "" {
			http.Error(w, "Repository path not configured", http.StatusBadRequest)
			return
		}
		handler(w, r)
	}
}

// generatePathSuggestions detects git repository using git rev-parse.
func generatePathSuggestions() []PathSuggestion {
	suggestions := []PathSuggestion{}

	// Try to detect git repository from current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return suggestions
	}

	// Change to the current working directory and run git rev-parse
	cmd := exec.CommandContext(context.Background(), "git", "rev-parse", "--show-toplevel")
	cmd.Dir = cwd
	output, err := cmd.Output()

	if err == nil {
		// Git repository detected
		repoRoot := strings.TrimSpace(string(output))
		if repoRoot != "" {
			valid := isValidRepoPath(repoRoot)
			var description string
			switch {
			case valid:
				description = "Valid DNShield repository detected"
			default:
				if _, statErr := os.Stat(filepath.Join(repoRoot, "manifests")); errors.Is(statErr, fs.ErrNotExist) {
					description = "Git repository found, but missing manifests directory"
				} else {
					description = "Git repository found, but not a DNShield repository"
				}
			}

			suggestions = append(suggestions, PathSuggestion{
				Path:        repoRoot,
				Valid:       valid,
				Description: description,
			})
		}
	}

	return suggestions
}

// loadEnvFile loads environment variables from .env file and macOS preferences.
func loadEnvFile() {
	// First load from .env file
	loadEnvFromFile()

	// Then load from macOS preferences (overrides .env if present)
	loadEnvFromPreferences()
}

// loadEnvFromFile loads from .env file.
func loadEnvFromFile() {
	file, err := os.Open(".env")
	if err != nil {
		return // .env file is optional
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		if len(value) >= 2 {
			if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
				(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
				value = value[1 : len(value)-1]
			}
		}

		os.Setenv(key, value)
	}
}

// loadEnvFromPreferences loads from macOS preferences domain using cfpref.
func loadEnvFromPreferences() {
	// List of environment variables to check in preferences
	envVars := []string{
		"GH_CLIENT_ID",
		"GH_APP_CLIENT_ID",
		"GH_CLIENT_SECRET",
		"GH_APP_CLIENT_SECRET",
		"GH_APP_ID",
		"GH_INSTALLATION_ID",
		"GH_APP_PRIVATE_KEY",
		"GITHUB_API_BASE",
		"GITHUB_DEFAULT_OWNER",
		"GITHUB_DEFAULT_REPO",
	}

	for _, envVar := range envVars {
		// Try to read from preferences using cfpref with type information
		value, valueType := cfpref.CFPreferencesCopyAppValueAndType(envVar, prefDomain)
		if value != nil {
			var strValue string

			// Handle different types that might be stored in preferences
			switch v := value.(type) {
			case string:
				strValue = v
			case int:
				strValue = strconv.Itoa(v)
			case int64:
				strValue = strconv.FormatInt(v, 10)
			case float64:
				// Sometimes numbers come back as float64
				strValue = strconv.FormatInt(int64(v), 10)
			default:
				log.Printf("[ENV] Unexpected type for %s: %T (cfpref type: %s)", envVar, value, valueType)
				continue
			}

			if strValue != "" {
				os.Setenv(envVar, strValue)
				log.Printf("[ENV] Loaded %s from macOS preferences (cfpref type: %s, go type: %T, value: %s)", envVar, valueType, value, strValue)
			}
		}
	}
}

// initGitHubAppConfig initializes GitHub App configuration from environment.
func initGitHubAppConfig() error {
	appIDStr := os.Getenv("GH_APP_ID")
	if appIDStr == "" {
		return errors.New("GH_APP_ID not set")
	}

	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid GH_APP_ID: %w", err)
	}

	installationIDStr := os.Getenv("GH_INSTALLATION_ID")
	if installationIDStr == "" {
		return errors.New("GH_INSTALLATION_ID not set")
	}

	installationID, err := strconv.ParseInt(installationIDStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid GH_INSTALLATION_ID: %w", err)
	}

	privateKeyData := os.Getenv("GH_APP_PRIVATE_KEY")
	if privateKeyData == "" || privateKeyData == "REPLACE_WITH_YOUR_ACTUAL_PRIVATE_KEY" {
		return errors.New("GH_APP_PRIVATE_KEY not set or placeholder value")
	}

	// Check if it's a SHA256 format (not PEM) - skip GitHub App setup
	if strings.HasPrefix(privateKeyData, "SHA256:") {
		return errors.New("private key appears to be SSH format (SHA256:) - GitHub App requires PEM format private key (base64 encoded)")
	}

	var privateKeyPEM []byte

	// Try to decode as base64 first
	if decoded, err := base64.StdEncoding.DecodeString(privateKeyData); err == nil {
		privateKeyPEM = decoded
	} else {
		// If base64 decode fails, assume it's already PEM format
		privateKeyPEM = []byte(privateKeyData)
	}

	// Parse the private key (PEM format)
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return errors.New("failed to parse private key PEM - ensure it's in PEM format (base64 encoded) starting with -----BEGIN")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format as fallback
		if pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes); err2 == nil {
			if rsaKey, ok := pkcs8Key.(*rsa.PrivateKey); ok {
				privateKey = rsaKey
			} else {
				return errors.New("private key is not RSA format")
			}
		} else {
			return fmt.Errorf("failed to parse private key: %w (also tried PKCS8: %s)", err, err2.Error())
		}
	}

	apiBase := os.Getenv("GITHUB_API_BASE")
	if apiBase == "" {
		apiBase = defaultGitHubAPIBase
	}

	defaultOwner := os.Getenv("GITHUB_DEFAULT_OWNER")
	if defaultOwner == "" {
		defaultOwner = "your-org"
	}

	defaultRepo := os.Getenv("GITHUB_DEFAULT_REPO")
	if defaultRepo == "" {
		defaultRepo = "dnshield"
	}

	// Optional: GitHub App OAuth client credentials for user login
	// Support multiple env var names for convenience
	clientID := os.Getenv("GH_APP_CLIENT_ID")
	if clientID == "" {
		clientID = os.Getenv("GH_CLIENT_ID")
	}
	clientSecret := os.Getenv("GH_APP_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = os.Getenv("GH_CLIENT_SECRET")
	}

	ghAppConfig = &GitHubAppConfig{
		AppID:          appID,
		InstallationID: installationID,
		PrivateKey:     string(privateKeyPEM),
		APIBase:        apiBase,
		DefaultOwner:   defaultOwner,
		DefaultRepo:    defaultRepo,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
	}

	// Initialize token service
	tokenService = &TokenService{
		appID:          appID,
		installationID: installationID,
		privateKey:     privateKey,
		apiBase:        apiBase,
	}

	return nil
}

// appJWT creates a JWT for GitHub App authentication.
func (ts *TokenService) appJWT() (string, error) {
	now := time.Now()

	// Set iat 60 seconds in the past to protect against clock drift
	// Set exp no more than 10 minutes in the future
	claims := jwt.MapClaims{
		"iss": ts.appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(ts.privateKey)
}

// InstallationToken gets or refreshes the installation access token.
func (ts *TokenService) InstallationToken(ctx context.Context) (string, error) {
	// Return cached token if still valid (with 1 minute buffer)
	if time.Now().Before(ts.cacheExpiry.Add(-1*time.Minute)) && ts.cacheToken != "" {
		log.Printf("[TOKEN] Using cached installation token (expires: %s)", ts.cacheExpiry.Format(time.RFC3339))
		return ts.cacheToken, nil
	}

	log.Printf("[TOKEN] Creating new JWT for app ID: %d", ts.appID)
	// Create JWT for authentication
	jwtToken, err := ts.appJWT()
	if err != nil {
		log.Printf("[TOKEN] ERROR: Failed to create JWT: %v", err)
		return "", fmt.Errorf("failed to create JWT: %w", err)
	}
	log.Printf("[TOKEN] JWT created successfully (length: %d)", len(jwtToken))

	// Create GitHub client with JWT auth
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: jwtToken,
			}),
		},
	})

	client := github.NewClient(nil).WithAuthToken(jwtToken)
	if ts.apiBase != defaultGitHubAPIBase {
		client, _ = client.WithEnterpriseURLs(ts.apiBase, ts.apiBase)
	}

	// Get installation access token
	log.Printf("[TOKEN] Requesting installation token for installation: %d", ts.installationID)
	token, resp, err := client.Apps.CreateInstallationToken(ctx, ts.installationID, &github.InstallationTokenOptions{})
	if err != nil {
		log.Printf("[TOKEN] ERROR: Failed to get installation token (status: %d): %v", resp.StatusCode, err)
		return "", fmt.Errorf("failed to get installation token: %w", err)
	}

	// Cache the token
	ts.cacheToken = token.GetToken()
	ts.cacheExpiry = token.GetExpiresAt().Time
	log.Printf("[TOKEN] Installation token cached successfully (expires: %s)", ts.cacheExpiry.Format(time.RFC3339))

	return ts.cacheToken, nil
}

// GitHubClientFactory creates authenticated GitHub clients.
type GitHubClientFactory struct {
	tokenService *TokenService
}

// NewClient creates a new GitHub client with installation token.
func (factory *GitHubClientFactory) NewClient(ctx context.Context) (*github.Client, error) {
	// If this request forces App token (for Verified commits), use installation token regardless of user token
	if forceApp, ok := ctx.Value(ctxCommitWithAppKey{}).(bool); ok && forceApp {
		token, err := factory.tokenService.InstallationToken(ctx)
		if err != nil {
			return nil, err
		}
		client := github.NewClient(nil).WithAuthToken(token)
		if factory.tokenService.apiBase != defaultGitHubAPIBase {
			client, _ = client.WithEnterpriseURLs(factory.tokenService.apiBase, factory.tokenService.apiBase)
		}
		return client, nil
	}

	// Otherwise, prefer user token (on behalf of the user)
	if tok, ok := ctx.Value(ctxUserTokenKey{}).(string); ok && tok != "" {
		client := github.NewClient(nil).WithAuthToken(tok)
		if factory.tokenService.apiBase != defaultGitHubAPIBase {
			client, _ = client.WithEnterpriseURLs(factory.tokenService.apiBase, factory.tokenService.apiBase)
		}
		return client, nil
	}

	// Fallback to installation token
	token, err := factory.tokenService.InstallationToken(ctx)
	if err != nil {
		return nil, err
	}

	client := github.NewClient(nil).WithAuthToken(token)
	if factory.tokenService.apiBase != defaultGitHubAPIBase {
		client, _ = client.WithEnterpriseURLs(factory.tokenService.apiBase, factory.tokenService.apiBase)
	}

	return client, nil
}

// Context key for injecting user access token.
type ctxUserTokenKey struct{}

func withUserToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxUserTokenKey{}, token)
}

// Context key for forcing use of App installation token (e.g., to obtain GitHub-verified commits).
type ctxCommitWithAppKey struct{}

func withCommitWithApp(ctx context.Context, force bool) context.Context {
	return context.WithValue(ctx, ctxCommitWithAppKey{}, force)
}

// RepoService handles repository operations.
type RepoService struct {
	clientFactory *GitHubClientFactory
}

// GetBaseRef returns the base branch commit SHA.
func (rs *RepoService) GetBaseRef(ctx context.Context, owner, repo, baseBranch string) (string, error) {
	client, err := rs.clientFactory.NewClient(ctx)
	if err != nil {
		return "", err
	}

	ref, _, err := client.Git.GetRef(ctx, owner, repo, "heads/"+baseBranch)
	if err != nil {
		return "", fmt.Errorf("failed to get base ref: %w", err)
	}

	return ref.Object.GetSHA(), nil
}

// CreateBranch creates a new feature branch from base SHA.
func (rs *RepoService) CreateBranch(ctx context.Context, owner, repo, featureBranch, baseSHA string) error {
	client, err := rs.clientFactory.NewClient(ctx)
	if err != nil {
		return err
	}

	ref := &github.Reference{
		Ref: github.String("refs/heads/" + featureBranch),
		Object: &github.GitObject{
			SHA: github.String(baseSHA),
		},
	}

	_, _, err = client.Git.CreateRef(ctx, owner, repo, ref)
	if err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	return nil
}

// CommitFilesAtomic creates blobs, tree, commit, and updates ref atomically.
func (rs *RepoService) CommitFilesAtomic(ctx context.Context, owner, repo, featureBranch, baseSHA string, files []FileSpec, message string) (string, error) {
	log.Printf("[COMMIT] Starting atomic commit for %s/%s on branch %s", owner, repo, featureBranch)

	client, err := rs.clientFactory.NewClient(ctx)
	if err != nil {
		log.Printf("[COMMIT] ERROR: Failed to create GitHub client: %v", err)
		return "", err
	}
	log.Printf("[COMMIT] GitHub client created successfully")

	// Get base commit to get base tree SHA
	log.Printf("[COMMIT] Getting base commit: %s", baseSHA)
	baseCommit, _, err := client.Git.GetCommit(ctx, owner, repo, baseSHA)
	if err != nil {
		log.Printf("[COMMIT] ERROR: Failed to get base commit: %v", err)
		return "", fmt.Errorf("failed to get base commit: %w", err)
	}
	log.Printf("[COMMIT] Base commit tree SHA: %s", baseCommit.Tree.GetSHA())

	// Create blobs for all files
	var treeEntries []*github.TreeEntry
	log.Printf("[COMMIT] Creating %d blobs", len(files))

	for i, file := range files {
		log.Printf("[COMMIT] Creating blob %d/%d for file: %s", i+1, len(files), file.Path)

		// Create blob
		blob, resp, err := client.Git.CreateBlob(ctx, owner, repo, &github.Blob{
			Content:  github.String(file.ContentBase64),
			Encoding: github.String("base64"),
		})
		if err != nil {
			log.Printf("[COMMIT] ERROR: Failed to create blob for %s (status: %d): %v", file.Path, resp.StatusCode, err)
			return "", fmt.Errorf("failed to create blob for %s: %w", file.Path, err)
		}
		log.Printf("[COMMIT] Blob created for %s: %s", file.Path, blob.GetSHA())

		// Add tree entry
		treeEntries = append(treeEntries, &github.TreeEntry{
			Path: github.String(file.Path),
			Mode: github.String("100644"),
			Type: github.String("blob"),
			SHA:  github.String(blob.GetSHA()),
		})
	}

	// Create tree
	log.Printf("[COMMIT] Creating tree with base tree: %s", baseCommit.Tree.GetSHA())
	tree, resp, err := client.Git.CreateTree(ctx, owner, repo, baseCommit.Tree.GetSHA(), treeEntries)
	if err != nil {
		log.Printf("[COMMIT] ERROR: Failed to create tree (status: %d): %v", resp.StatusCode, err)
		return "", fmt.Errorf("failed to create tree: %w", err)
	}
	log.Printf("[COMMIT] Tree created successfully: %s", tree.GetSHA())

	// Create commit
	log.Printf("[COMMIT] Creating commit with message: %s", message)
	commit, resp, err := client.Git.CreateCommit(ctx, owner, repo, &github.Commit{
		Message: github.String(message),
		Tree:    tree,
		Parents: []*github.Commit{baseCommit},
	}, &github.CreateCommitOptions{})
	if err != nil {
		log.Printf("[COMMIT] ERROR: Failed to create commit (status: %d): %v", resp.StatusCode, err)
		return "", fmt.Errorf("failed to create commit: %w", err)
	}
	log.Printf("[COMMIT] Commit created successfully: %s", commit.GetSHA())

	// Update branch ref
	log.Printf("[COMMIT] Updating branch ref: refs/heads/%s", featureBranch)
	ref := &github.Reference{
		Ref: github.String("refs/heads/" + featureBranch),
		Object: &github.GitObject{
			SHA: commit.SHA,
		},
	}

	_, resp, err = client.Git.UpdateRef(ctx, owner, repo, ref, false)
	if err != nil {
		log.Printf("[COMMIT] ERROR: Failed to update ref (status: %d): %v", resp.StatusCode, err)
		return "", fmt.Errorf("failed to update ref: %w", err)
	}
	log.Printf("[COMMIT] Branch ref updated successfully")

	return commit.GetSHA(), nil
}

// OpenPR creates a pull request.
func (rs *RepoService) OpenPR(ctx context.Context, owner, repo, title, body, head, base string) (int, string, error) {
	client, err := rs.clientFactory.NewClient(ctx)
	if err != nil {
		return 0, "", err
	}

	pr, _, err := client.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
		Title: github.String(title),
		Head:  github.String(head),
		Base:  github.String(base),
		Body:  github.String(body),
	})
	if err != nil {
		return 0, "", fmt.Errorf("failed to create pull request: %w", err)
	}

	return pr.GetNumber(), pr.GetHTMLURL(), nil
}

// generateFeatureBranchName creates a unique feature branch name.
func generateFeatureBranchName(prefix, userHandle string) string {
	timestamp := time.Now().Format("2006-01-02-150405")
	if userHandle == "" {
		userHandle = "user"
	}
	return fmt.Sprintf("%s/%s/%s", prefix, userHandle, timestamp)
}

// createManifest creates a new manifest file with domains.
func createManifest(manifestName, category string, domains []string, ruleType string) map[string]interface{} {
	// Determine the file path based on category
	var filePath string
	switch category {
	case "global", "domain", "group", "phishing", "team":
		filePath = filepath.Join(config.ManifestsDir, "includes", category, manifestName+".json")
	default:
		filePath = filepath.Join(config.ManifestsDir, "includes", manifestName+".json")
	}

	// Check if file already exists
	if _, err := os.Stat(filePath); err == nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Manifest already exists",
		}
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create directory: " + err.Error(),
		}
	}

	// Validate rule type
	if ruleType != ruleTypeAllow && ruleType != ruleTypeBlock {
		ruleType = ruleTypeBlock // default to block if invalid
	}

	// Create the manifest structure with proper DNShield format
	manifest := map[string]interface{}{
		"manifest_version":   "1.0",
		"identifier":         manifestName,
		"display_name":       manifestName,
		"included_manifests": []string{},
		"managed_rules": map[string]interface{}{
			ruleType: domains,
		},
		"metadata": map[string]interface{}{
			"author":        "Manifest Editor",
			"description":   "Created via Manifest Editor",
			"last_modified": time.Now().Format(time.RFC3339),
			"source":        "",
			"rule_count": map[string]interface{}{
				ruleTypeAllow: func() int {
					if ruleType == ruleTypeAllow {
						return len(domains)
					}
					return 0
				}(),
				ruleTypeBlock: func() int {
					if ruleType == ruleTypeBlock {
						return len(domains)
					}
					return 0
				}(),
			},
		},
	}

	// Write the file
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to marshal JSON: " + err.Error(),
		}
	}

	if err := os.WriteFile(filePath, append(data, '\n'), 0o644); err != nil { //nolint:gosec // manifest files checked into git with standard permissions
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to write file: " + err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"message": "Manifest created successfully",
		"path":    filePath,
	}
}

func manifestFilePath(manifestName string) (string, error) {
	categories := []string{"global", "domain", "group", "phishing", "team"}
	for _, category := range categories {
		testPath := filepath.Join(config.ManifestsDir, "includes", category, manifestName+".json")
		if _, err := os.Stat(testPath); err == nil {
			return testPath, nil
		}
	}

	manifestPath := determineManifestPath(manifestName)
	fullPath := filepath.Join(config.ManifestsDir, manifestPath)
	if _, err := os.Stat(fullPath); err != nil {
		return "", fmt.Errorf("manifest %s not found", manifestName)
	}

	return fullPath, nil
}

func loadManifest(path string) (map[string]interface{}, error) {
	manifest, _, err := loadManifestWithRaw(path)
	return manifest, err
}

func loadManifestWithRaw(path string) (map[string]interface{}, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest map[string]interface{}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return manifest, data, nil
}

func prepareManagedRules(manifest map[string]interface{}, manifestName, requestedRuleType string) (map[string]interface{}, string, []string, error) {
	value, exists := manifest["managed_rules"]
	if !exists {
		managedRules := map[string]interface{}{
			ruleTypeAllow: []string{},
			ruleTypeBlock: []string{},
		}
		manifest["managed_rules"] = managedRules
		return managedRules, determineRuleType(manifestName, requestedRuleType), []string{}, nil
	}

	managedRules, ok := value.(map[string]interface{})
	if !ok {
		return nil, "", nil, errors.New("manifest has invalid managed_rules structure")
	}

	if allowList, ok := managedRules[ruleTypeAllow]; ok {
		allowDomains := toStringSlice(allowList)
		if len(allowDomains) > 0 {
			return managedRules, ruleTypeAllow, allowDomains, nil
		}
	}

	if blockList, ok := managedRules[ruleTypeBlock]; ok {
		blockDomains := toStringSlice(blockList)
		if len(blockDomains) > 0 {
			return managedRules, ruleTypeBlock, blockDomains, nil
		}
	}

	managedRules[ruleTypeAllow] = []string{}
	managedRules[ruleTypeBlock] = []string{}

	return managedRules, determineRuleType(manifestName, requestedRuleType), []string{}, nil
}

func determineRuleType(manifestName, requested string) string {
	if requested == ruleTypeAllow || requested == ruleTypeBlock {
		return requested
	}
	if strings.Contains(strings.ToLower(manifestName), ruleTypeAllow) {
		return ruleTypeAllow
	}
	return ruleTypeBlock
}

func toStringSlice(value interface{}) []string {
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}

	results := make([]string, 0, len(items))
	for _, item := range items {
		if str, ok := item.(string); ok {
			results = append(results, str)
		}
	}

	return results
}

func mergeDomains(existing, candidates []string) ([]string, []string) {
	domainSet := make(map[string]struct{}, len(existing))
	merged := make([]string, 0, len(existing)+len(candidates))
	merged = append(merged, existing...)

	for _, domain := range existing {
		domainSet[domain] = struct{}{}
	}

	added := make([]string, 0, len(candidates))
	for _, domain := range candidates {
		if _, found := domainSet[domain]; found {
			continue
		}
		merged = append(merged, domain)
		added = append(added, domain)
		domainSet[domain] = struct{}{}
	}

	return merged, added
}

func filterDomains(existing, toRemove []string) ([]string, []string) {
	if len(toRemove) == 0 {
		return existing, []string{}
	}

	removeSet := make(map[string]struct{}, len(toRemove))
	for _, domain := range toRemove {
		removeSet[domain] = struct{}{}
	}

	remaining := make([]string, 0, len(existing))
	removed := make([]string, 0, len(toRemove))
	for _, domain := range existing {
		if _, ok := removeSet[domain]; ok {
			removed = append(removed, domain)
			continue
		}
		remaining = append(remaining, domain)
	}

	return remaining, removed
}

func updateRuleMetadata(manifest map[string]interface{}, ruleType string, domains []string) {
	metadata, ok := manifest["metadata"].(map[string]interface{})
	if !ok {
		metadata = map[string]interface{}{}
		manifest["metadata"] = metadata
	}

	ruleCount, ok := metadata["rule_count"].(map[string]interface{})
	if !ok {
		ruleCount = map[string]interface{}{
			ruleTypeAllow: 0,
			ruleTypeBlock: 0,
		}
		metadata["rule_count"] = ruleCount
	}

	ruleCount[ruleType] = len(domains)
	metadata["last_modified"] = time.Now().Format(time.RFC3339)
}

func writeManifest(path string, manifest map[string]interface{}) error {
	output, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	if err := os.WriteFile(path, append(output, '\n'), 0o644); err != nil { //nolint:gosec // manifest files should retain repository permissions
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// addDomainsToManifest adds domains to an existing manifest.
func addDomainsToManifest(manifestName string, domains []string, requestedRuleType string) map[string]interface{} {
	fullPath, err := manifestFilePath(manifestName)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	manifest, err := loadManifest(fullPath)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	managedRules, ruleType, existingDomains, err := prepareManagedRules(manifest, manifestName, requestedRuleType)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	updatedDomains, addedDomains := mergeDomains(existingDomains, domains)
	if len(addedDomains) == 0 {
		return map[string]interface{}{
			"success":       true,
			"message":       "No new domains to add",
			"added_domains": []string{},
			"total_domains": len(existingDomains),
		}
	}

	managedRules[ruleType] = updatedDomains
	updateRuleMetadata(manifest, ruleType, updatedDomains)

	if err := writeManifest(fullPath, manifest); err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success":       true,
		"message":       fmt.Sprintf("Added %d domains to %s", len(addedDomains), manifestName),
		"added_domains": addedDomains,
		"total_domains": len(updatedDomains),
	}
}

// removeDomainsFromManifest removes domains from an existing manifest.
func removeDomainsFromManifest(manifestName string, domains []string) map[string]interface{} {
	fullPath, err := manifestFilePath(manifestName)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	manifest, err := loadManifest(fullPath)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	managedRules, ruleType, existingDomains, err := prepareManagedRules(manifest, manifestName, "")
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	remaining, removed := filterDomains(existingDomains, domains)
	if len(removed) == 0 {
		return map[string]interface{}{
			"success":         true,
			"message":         "No matching domains found",
			"removed_domains": []string{},
			"total_domains":   len(existingDomains),
		}
	}

	managedRules[ruleType] = remaining
	updateRuleMetadata(manifest, ruleType, remaining)

	if err := writeManifest(fullPath, manifest); err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success":         true,
		"message":         fmt.Sprintf("Removed %d domains from %s", len(removed), manifestName),
		"removed_domains": removed,
		"total_domains":   len(remaining),
	}
}

// getManifestDetails retrieves detailed information about a manifest.
func getManifestDetails(manifestName string) map[string]interface{} {
	fullPath, err := manifestFilePath(manifestName)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	manifest, data, err := loadManifestWithRaw(fullPath)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	// Extract domains from different formats
	var domains []string

	// New format: rules.domains
	if rules, ok := manifest["rules"].(map[string]interface{}); ok {
		if domainList, ok := rules["domains"].([]interface{}); ok {
			for _, domain := range domainList {
				if domainStr, ok := domain.(string); ok {
					domains = append(domains, domainStr)
				}
			}
		}
	}

	// Old format: managed_rules.allow or managed_rules.block
	if len(domains) == 0 {
		if managedRules, ok := manifest["managed_rules"].(map[string]interface{}); ok {
			// Try allow list first
			if allowList, ok := managedRules[ruleTypeAllow].([]interface{}); ok {
				for _, domain := range allowList {
					if domainStr, ok := domain.(string); ok {
						domains = append(domains, domainStr)
					}
				}
			}
			// Then try block list
			if len(domains) == 0 {
				if blockList, ok := managedRules[ruleTypeBlock].([]interface{}); ok {
					for _, domain := range blockList {
						if domainStr, ok := domain.(string); ok {
							domains = append(domains, domainStr)
						}
					}
				}
			}
		}
	}

	// Extract metadata
	var metadata map[string]interface{}
	if meta, ok := manifest["metadata"].(map[string]interface{}); ok {
		metadata = meta
	}

	// Get file info
	fileInfo, _ := os.Stat(fullPath)
	var lastModified string
	if fileInfo != nil {
		lastModified = fileInfo.ModTime().Format(time.RFC3339)
	}

	return map[string]interface{}{
		"success":       true,
		"name":          manifestName,
		"path":          fullPath,
		"domains":       domains,
		"domain_count":  len(domains),
		"metadata":      metadata,
		"last_modified": lastModified,
		"raw_content":   string(data),
	}
}
