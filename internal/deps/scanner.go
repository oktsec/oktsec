package deps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Scanner checks dependency manifests for supply chain risks.
type Scanner struct {
	httpClient *http.Client
	semaphore  chan struct{}
}

// NewScanner creates a Scanner with the given HTTP client.
// If client is nil, a default client with 10s timeout is used.
func NewScanner(client *http.Client) *Scanner {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Scanner{
		httpClient: client,
		semaphore:  make(chan struct{}, 5), // max 5 concurrent OSV requests
	}
}

// ScanResult holds the full output of a dependency scan.
type ScanResult struct {
	Path      string    `json:"path"`
	Manifests []Manifest `json:"manifests"`
	Findings  []Finding  `json:"findings"`
	Risk      string     `json:"risk"` // "clean", "low", "medium", "high", "critical"
}

// Manifest describes a discovered dependency file.
type Manifest struct {
	File     string `json:"file"`
	Packages int    `json:"packages"`
	Unpinned int    `json:"unpinned,omitempty"`
}

// Finding is a single issue found during the scan.
type Finding struct {
	Severity string `json:"severity"`          // "critical", "warning", "info"
	Message  string `json:"message"`
	Package  string `json:"package,omitempty"`
	Version  string `json:"version,omitempty"`
	VulnID   string `json:"vuln_id,omitempty"`
}

// PackageRef is a single dependency parsed from a manifest.
type PackageRef struct {
	Name      string
	Version   string
	Ecosystem string // "PyPI", "npm", "Go"
	Pinned    bool
}

// osvQuery is the request body for the OSV.dev API.
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvResponse is the response from the OSV.dev API.
type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

const osvEndpoint = "https://api.osv.dev/v1/query"

// Scan scans the given directory for dependency manifests and checks them.
func (s *Scanner) Scan(dir string) (*ScanResult, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("path not found: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", dir)
	}

	result := &ScanResult{
		Path:      dir,
		Manifests: []Manifest{},
		Findings:  []Finding{},
	}

	var allPkgs []PackageRef

	// Parse each supported manifest type
	type manifestParser struct {
		file      string
		lockfiles []string
		parser    func(string) ([]PackageRef, error)
	}

	parsers := []manifestParser{
		{"requirements.txt", []string{"Pipfile.lock"}, parseRequirementsTxt},
		{"package.json", []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}, parsePackageJSON},
		{"go.mod", []string{"go.sum"}, parseGoMod},
	}

	for _, mp := range parsers {
		path := filepath.Join(dir, mp.file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		pkgs, err := mp.parser(path)
		if err != nil {
			result.Findings = append(result.Findings, Finding{
				Severity: "warning",
				Message:  fmt.Sprintf("Failed to parse %s: %v", mp.file, err),
			})
			continue
		}

		unpinned := 0
		for _, p := range pkgs {
			if !p.Pinned {
				unpinned++
			}
		}

		result.Manifests = append(result.Manifests, Manifest{
			File:     mp.file,
			Packages: len(pkgs),
			Unpinned: unpinned,
		})
		allPkgs = append(allPkgs, pkgs...)

		// Check lockfile presence
		hasLock := false
		for _, lf := range mp.lockfiles {
			if _, err := os.Stat(filepath.Join(dir, lf)); err == nil {
				hasLock = true
				break
			}
		}
		if !hasLock {
			result.Findings = append(result.Findings, Finding{
				Severity: "warning",
				Message:  fmt.Sprintf("No lockfile found for %s", mp.file),
			})
		}
	}

	if len(result.Manifests) == 0 {
		result.Risk = "clean"
		return result, nil
	}

	// Check dependency count
	totalPkgs := len(allPkgs)
	if totalPkgs >= 300 {
		result.Findings = append(result.Findings, Finding{
			Severity: "warning",
			Message:  fmt.Sprintf("Very high dependency count (%d packages) — increased supply chain risk", totalPkgs),
		})
	} else if totalPkgs >= 100 {
		result.Findings = append(result.Findings, Finding{
			Severity: "warning",
			Message:  fmt.Sprintf("High dependency count (%d packages)", totalPkgs),
		})
	} else if totalPkgs >= 20 {
		result.Findings = append(result.Findings, Finding{
			Severity: "info",
			Message:  fmt.Sprintf("Moderate dependency count (%d packages)", totalPkgs),
		})
	}

	// Check version pinning
	totalUnpinned := 0
	for _, p := range allPkgs {
		if !p.Pinned {
			totalUnpinned++
		}
	}
	if totalPkgs > 0 {
		pct := (totalUnpinned * 100) / totalPkgs
		if pct > 50 {
			result.Findings = append(result.Findings, Finding{
				Severity: "warning",
				Message:  fmt.Sprintf("%d%% of dependencies use unpinned versions", pct),
			})
		}
	}

	// Query OSV for packages with pinned versions
	pinnedPkgs := make([]PackageRef, 0)
	for _, p := range allPkgs {
		if p.Version != "" && p.Pinned {
			pinnedPkgs = append(pinnedPkgs, p)
		}
	}

	osvFindings := s.checkOSVBatch(pinnedPkgs)
	result.Findings = append(result.Findings, osvFindings...)

	result.Risk = ComputeRisk(result.Findings)
	return result, nil
}

// checkOSVBatch queries OSV.dev for a batch of packages with concurrency control.
func (s *Scanner) checkOSVBatch(pkgs []PackageRef) []Finding {
	var (
		mu       sync.Mutex
		findings []Finding
		wg       sync.WaitGroup
	)

	for _, pkg := range pkgs {
		wg.Add(1)
		go func(p PackageRef) {
			defer wg.Done()

			// Acquire semaphore
			s.semaphore <- struct{}{}
			defer func() { <-s.semaphore }()

			vulns, err := s.checkOSV(p)
			if err != nil {
				mu.Lock()
				findings = append(findings, Finding{
					Severity: "warning",
					Message:  fmt.Sprintf("OSV lookup failed for %s: %v", p.Name, err),
					Package:  p.Name,
					Version:  p.Version,
				})
				mu.Unlock()
				return
			}

			mu.Lock()
			for _, v := range vulns {
				summary := v.Summary
				if summary == "" {
					summary = "Known vulnerability"
				}
				findings = append(findings, Finding{
					Severity: "critical",
					Message:  summary,
					Package:  p.Name,
					Version:  p.Version,
					VulnID:   v.ID,
				})
			}
			mu.Unlock()
		}(pkg)
	}

	wg.Wait()
	return findings
}

// checkOSV queries the OSV.dev API for vulnerabilities affecting a single package.
func (s *Scanner) checkOSV(pkg PackageRef) ([]osvVuln, error) {
	q := osvQuery{
		Package: osvPackage{
			Name:      pkg.Name,
			Ecosystem: pkg.Ecosystem,
		},
		Version: pkg.Version,
	}

	body, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}

	resp, err := s.httpClient.Post(osvEndpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("OSV request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("reading OSV response: %w", err)
	}

	var result osvResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
	}

	return result.Vulns, nil
}

// ComputeRisk determines the overall risk level from a set of findings.
func ComputeRisk(findings []Finding) string {
	for _, f := range findings {
		if f.Severity == "critical" {
			return "critical"
		}
	}
	warnings := 0
	for _, f := range findings {
		if f.Severity == "warning" {
			warnings++
		}
	}
	if warnings >= 3 {
		return "high"
	}
	if warnings >= 1 {
		return "medium"
	}
	return "clean"
}

// --- Manifest parsers ---

var requirementLineRe = regexp.MustCompile(`^([a-zA-Z0-9_.-]+)\s*(==|>=|~=|!=|<=|>|<)\s*([0-9a-zA-Z.*+-]+)`)

func parseRequirementsTxt(path string) ([]PackageRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkgs []PackageRef
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := requirementLineRe.FindStringSubmatch(line)
		if m == nil {
			// Bare package name (no version specifier)
			name := strings.TrimSpace(line)
			if name != "" && !strings.Contains(name, " ") {
				pkgs = append(pkgs, PackageRef{
					Name:      name,
					Ecosystem: "PyPI",
					Pinned:    false,
				})
			}
			continue
		}
		pinned := m[2] == "=="
		pkgs = append(pkgs, PackageRef{
			Name:      m[1],
			Version:   m[3],
			Ecosystem: "PyPI",
			Pinned:    pinned,
		})
	}
	return pkgs, nil
}

func parsePackageJSON(path string) ([]PackageRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}

	var refs []PackageRef
	addDeps := func(deps map[string]string) {
		for name, ver := range deps {
			ver = strings.TrimSpace(ver)
			pinned := true
			cleanVer := ver
			if strings.HasPrefix(ver, "^") || strings.HasPrefix(ver, "~") || strings.HasPrefix(ver, ">") || strings.HasPrefix(ver, "<") || ver == "*" || ver == "latest" {
				pinned = false
				cleanVer = strings.TrimLeft(ver, "^~>=<")
			}
			refs = append(refs, PackageRef{
				Name:      name,
				Version:   cleanVer,
				Ecosystem: "npm",
				Pinned:    pinned,
			})
		}
	}

	addDeps(pkg.Dependencies)
	addDeps(pkg.DevDependencies)
	return refs, nil
}

var goModRequireRe = regexp.MustCompile(`^\s*([^\s]+)\s+(v[0-9][^\s]*)`)

func parseGoMod(path string) ([]PackageRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkgs []PackageRef
	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "require (") || trimmed == "require (" {
			inRequire = true
			continue
		}
		if inRequire && trimmed == ")" {
			inRequire = false
			continue
		}

		// Single-line require
		if strings.HasPrefix(trimmed, "require ") && !strings.Contains(trimmed, "(") {
			after := strings.TrimPrefix(trimmed, "require ")
			m := goModRequireRe.FindStringSubmatch(after)
			if m != nil {
				pkgs = append(pkgs, PackageRef{
					Name:      m[1],
					Version:   m[2],
					Ecosystem: "Go",
					Pinned:    true, // Go modules are always pinned
				})
			}
			continue
		}

		if inRequire {
			// Skip indirect dependencies comment check — still parse them
			cleanLine := trimmed
			if idx := strings.Index(cleanLine, "//"); idx >= 0 {
				cleanLine = strings.TrimSpace(cleanLine[:idx])
			}
			m := goModRequireRe.FindStringSubmatch(cleanLine)
			if m != nil {
				pkgs = append(pkgs, PackageRef{
					Name:      m[1],
					Version:   m[2],
					Ecosystem: "Go",
					Pinned:    true,
				})
			}
		}
	}

	return pkgs, nil
}
