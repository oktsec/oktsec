package deps

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Manifest parser tests ---

func TestParseRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	content := `# This is a comment
flask==2.3.1
requests>=2.28.0
numpy~=1.24.0
pandas==2.0.3
boto3

-r extra-requirements.txt
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(content), 0644))

	pkgs, err := parseRequirementsTxt(filepath.Join(dir, "requirements.txt"))
	require.NoError(t, err)
	assert.Len(t, pkgs, 5)

	// flask is pinned
	assert.Equal(t, "flask", pkgs[0].Name)
	assert.Equal(t, "2.3.1", pkgs[0].Version)
	assert.Equal(t, "PyPI", pkgs[0].Ecosystem)
	assert.True(t, pkgs[0].Pinned)

	// requests is unpinned (>=)
	assert.Equal(t, "requests", pkgs[1].Name)
	assert.Equal(t, "2.28.0", pkgs[1].Version)
	assert.False(t, pkgs[1].Pinned)

	// numpy is unpinned (~=)
	assert.Equal(t, "numpy", pkgs[2].Name)
	assert.False(t, pkgs[2].Pinned)

	// pandas is pinned
	assert.Equal(t, "pandas", pkgs[3].Name)
	assert.True(t, pkgs[3].Pinned)

	// boto3 has no version (bare name)
	assert.Equal(t, "boto3", pkgs[4].Name)
	assert.Equal(t, "", pkgs[4].Version)
	assert.False(t, pkgs[4].Pinned)
}

func TestParseRequirementsTxtEmpty(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("# empty\n\n"), 0644))

	pkgs, err := parseRequirementsTxt(filepath.Join(dir, "requirements.txt"))
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func TestParsePackageJSON(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "name": "my-mcp-server",
  "dependencies": {
    "express": "4.18.2",
    "axios": "^1.4.0",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0644))

	pkgs, err := parsePackageJSON(filepath.Join(dir, "package.json"))
	require.NoError(t, err)
	assert.Len(t, pkgs, 4)

	// Build a map for easier assertion (order is not guaranteed with maps)
	byName := map[string]PackageRef{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	assert.True(t, byName["express"].Pinned)
	assert.Equal(t, "4.18.2", byName["express"].Version)
	assert.Equal(t, "npm", byName["express"].Ecosystem)

	assert.False(t, byName["axios"].Pinned)
	assert.False(t, byName["lodash"].Pinned)
	assert.False(t, byName["jest"].Pinned)
}

func TestParseGoMod(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/my-server

go 1.22.0

require (
	github.com/spf13/cobra v1.8.0
	github.com/stretchr/testify v1.9.0
	golang.org/x/sync v0.6.0 // indirect
)

require github.com/single/dep v0.1.0
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0644))

	pkgs, err := parseGoMod(filepath.Join(dir, "go.mod"))
	require.NoError(t, err)
	assert.Len(t, pkgs, 4)

	assert.Equal(t, "github.com/spf13/cobra", pkgs[0].Name)
	assert.Equal(t, "v1.8.0", pkgs[0].Version)
	assert.Equal(t, "Go", pkgs[0].Ecosystem)
	assert.True(t, pkgs[0].Pinned)

	assert.Equal(t, "golang.org/x/sync", pkgs[2].Name)
	assert.Equal(t, "v0.6.0", pkgs[2].Version)

	// Single-line require
	assert.Equal(t, "github.com/single/dep", pkgs[3].Name)
	assert.Equal(t, "v0.1.0", pkgs[3].Version)
}

func TestParseGoModEmpty(t *testing.T) {
	dir := t.TempDir()
	content := `module example.com/my-server

go 1.22.0
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0644))

	pkgs, err := parseGoMod(filepath.Join(dir, "go.mod"))
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

// --- Risk computation tests ---

func TestComputeRisk(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     string
	}{
		{
			name:     "no findings",
			findings: nil,
			want:     "clean",
		},
		{
			name: "info only",
			findings: []Finding{
				{Severity: "info", Message: "moderate count"},
			},
			want: "clean",
		},
		{
			name: "single warning",
			findings: []Finding{
				{Severity: "warning", Message: "no lockfile"},
			},
			want: "medium",
		},
		{
			name: "two warnings",
			findings: []Finding{
				{Severity: "warning", Message: "no lockfile"},
				{Severity: "warning", Message: "high count"},
			},
			want: "medium",
		},
		{
			name: "three warnings",
			findings: []Finding{
				{Severity: "warning", Message: "no lockfile"},
				{Severity: "warning", Message: "high count"},
				{Severity: "warning", Message: "unpinned versions"},
			},
			want: "high",
		},
		{
			name: "critical finding",
			findings: []Finding{
				{Severity: "critical", Message: "known vuln", Package: "bad-pkg", VulnID: "PYSEC-2026-001"},
			},
			want: "critical",
		},
		{
			name: "critical overrides warnings",
			findings: []Finding{
				{Severity: "warning", Message: "no lockfile"},
				{Severity: "critical", Message: "known vuln"},
			},
			want: "critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ComputeRisk(tt.findings))
		})
	}
}

// --- Dependency count threshold tests ---

func TestDependencyCountThresholds(t *testing.T) {
	tests := []struct {
		count    int
		wantSev  string // expected severity, "" if no finding
		wantFrag string // substring expected in message
	}{
		{19, "", ""},
		{50, "info", "Moderate dependency count"},
		{150, "warning", "High dependency count"},
		{350, "warning", "Very high dependency count"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("count_%d", tt.count), func(t *testing.T) {
			dir := t.TempDir()

			// Create a requirements.txt with the right number of packages
			var lines []string
			for i := 0; i < tt.count; i++ {
				lines = append(lines, fmt.Sprintf("pkg%d==1.0.0", i))
			}
			require.NoError(t, os.WriteFile(
				filepath.Join(dir, "requirements.txt"),
				[]byte(strings.Join(lines, "\n")),
				0644,
			))
			// Add lockfile so we don't get a lockfile warning
			require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte("{}"), 0644))

			// Use a mock OSV server that returns no vulns
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"vulns": []}`))
			}))
			defer srv.Close()

			scanner := NewScanner(srv.Client())
			// Override the OSV endpoint by using a custom transport
			scanner.httpClient = &http.Client{
				Timeout:   10 * time.Second,
				Transport: &rewriteTransport{base: http.DefaultTransport, target: srv.URL},
			}

			result, err := scanner.Scan(dir)
			require.NoError(t, err)

			if tt.wantSev == "" {
				// No dependency count finding expected
				for _, f := range result.Findings {
					assert.NotContains(t, f.Message, "dependency count", "unexpected finding: %s", f.Message)
				}
			} else {
				found := false
				for _, f := range result.Findings {
					if strings.Contains(f.Message, "dependency count") {
						assert.Equal(t, tt.wantSev, f.Severity)
						assert.Contains(t, f.Message, tt.wantFrag)
						found = true
						break
					}
				}
				assert.True(t, found, "expected a dependency count finding")
			}
		})
	}
}

// --- Lockfile presence tests ---

func TestLockfileWarning(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.3.1\n"), 0644))
	// No Pipfile.lock

	srv := newMockOSVServer(nil)
	defer srv.Close()

	scanner := newScannerWithMockOSV(srv)
	result, err := scanner.Scan(dir)
	require.NoError(t, err)

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "No lockfile") {
			assert.Equal(t, "warning", f.Severity)
			found = true
			break
		}
	}
	assert.True(t, found, "expected lockfile warning")
}

func TestNoLockfileWarningWhenPresent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.3.1\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte("{}"), 0644))

	srv := newMockOSVServer(nil)
	defer srv.Close()

	scanner := newScannerWithMockOSV(srv)
	result, err := scanner.Scan(dir)
	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotContains(t, f.Message, "No lockfile")
	}
}

// --- OSV integration tests (mocked) ---

func TestOSVVulnerabilityDetection(t *testing.T) {
	vulns := map[string][]osvVuln{
		"flask": {
			{ID: "PYSEC-2026-001", Summary: "Remote code execution in Flask"},
		},
	}

	srv := newMockOSVServer(vulns)
	defer srv.Close()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.3.1\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte("{}"), 0644))

	scanner := newScannerWithMockOSV(srv)
	result, err := scanner.Scan(dir)
	require.NoError(t, err)

	var criticalFindings []Finding
	for _, f := range result.Findings {
		if f.Severity == "critical" {
			criticalFindings = append(criticalFindings, f)
		}
	}
	require.Len(t, criticalFindings, 1)
	assert.Equal(t, "flask", criticalFindings[0].Package)
	assert.Equal(t, "2.3.1", criticalFindings[0].Version)
	assert.Equal(t, "PYSEC-2026-001", criticalFindings[0].VulnID)
	assert.Equal(t, "critical", result.Risk)
}

func TestOSVNetworkError(t *testing.T) {
	// Server that always returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.3.1\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte("{}"), 0644))

	scanner := newScannerWithMockOSV(srv)
	result, err := scanner.Scan(dir)
	require.NoError(t, err)

	// Should produce a warning, not fail
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "OSV lookup failed") {
			assert.Equal(t, "warning", f.Severity)
			found = true
			break
		}
	}
	assert.True(t, found, "expected OSV failure warning")
	// Risk should not be critical since the lookup failed (not confirmed vuln)
	assert.NotEqual(t, "critical", result.Risk)
}

// --- Empty directory ---

func TestEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	scanner := NewScanner(nil)
	result, err := scanner.Scan(dir)
	require.NoError(t, err)

	assert.Empty(t, result.Manifests)
	assert.Empty(t, result.Findings)
	assert.Equal(t, "clean", result.Risk)
}

// --- JSON output format ---

func TestScanResultJSON(t *testing.T) {
	result := ScanResult{
		Path: "/path/to/server",
		Manifests: []Manifest{
			{File: "requirements.txt", Packages: 47, Unpinned: 12},
		},
		Findings: []Finding{
			{Severity: "critical", Message: "Known vulnerability", Package: "litellm", Version: "1.82.8", VulnID: "PYSEC-2026-XXXX"},
			{Severity: "warning", Message: "No lockfile found for requirements.txt"},
		},
		Risk: "critical",
	}

	b, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(b, &decoded))

	assert.Equal(t, "/path/to/server", decoded["path"])
	assert.Equal(t, "critical", decoded["risk"])

	manifests := decoded["manifests"].([]interface{})
	assert.Len(t, manifests, 1)

	findings := decoded["findings"].([]interface{})
	assert.Len(t, findings, 2)

	first := findings[0].(map[string]interface{})
	assert.Equal(t, "critical", first["severity"])
	assert.Equal(t, "litellm", first["package"])
	assert.Equal(t, "PYSEC-2026-XXXX", first["vuln_id"])
}

// --- Version pinning warning ---

func TestVersionPinningWarning(t *testing.T) {
	dir := t.TempDir()
	// 3 out of 4 are unpinned = 75%
	content := `flask>=2.3.1
requests>=2.28.0
numpy~=1.24.0
pandas==2.0.3
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(content), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte("{}"), 0644))

	srv := newMockOSVServer(nil)
	defer srv.Close()

	scanner := newScannerWithMockOSV(srv)
	result, err := scanner.Scan(dir)
	require.NoError(t, err)

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "unpinned versions") {
			assert.Equal(t, "warning", f.Severity)
			assert.Contains(t, f.Message, "75%")
			found = true
			break
		}
	}
	assert.True(t, found, "expected version pinning warning")
}

// --- Test helpers ---

// rewriteTransport rewrites all request URLs to the target test server.
type rewriteTransport struct {
	base   http.RoundTripper
	target string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(t.target, "http://")
	return t.base.RoundTrip(req)
}

// newMockOSVServer creates a test server that returns vulnerabilities for specific packages.
func newMockOSVServer(vulns map[string][]osvVuln) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q osvQuery
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := osvResponse{}
		if vulns != nil {
			if v, ok := vulns[q.Package.Name]; ok {
				resp.Vulns = v
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func newScannerWithMockOSV(srv *httptest.Server) *Scanner {
	scanner := NewScanner(nil)
	scanner.httpClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &rewriteTransport{base: http.DefaultTransport, target: srv.URL},
	}
	return scanner
}

