// Package guard monitors AI tool config files for unauthorized modifications.
// It uses fsnotify to watch critical paths (shell profiles, .claude/, .cursor/, etc.)
// and scans changed content through the MEM-* detection rules.
package guard

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/oktsec/oktsec/internal/engine"
)

// maxFileSize is the maximum bytes to read from a watched file.
const maxFileSize = 64 * 1024

// debounceWindow collapses rapid events on the same path.
// Editors fire 2-4 events per save (temp create, write, rename, chmod).
const debounceWindow = 200 * time.Millisecond

// rescanInterval is how often we check for newly created watch targets.
const rescanInterval = 60 * time.Second

// Event is emitted when a watched file changes.
type Event struct {
	Path      string                  `json:"path"`
	Operation string                  `json:"operation"`
	Hash      string                  `json:"hash"`
	PrevHash  string                  `json:"prev_hash,omitempty"`
	Findings  []engine.FindingSummary `json:"findings,omitempty"`
	Verdict   engine.ScanVerdict      `json:"verdict"`
	Timestamp time.Time               `json:"timestamp"`
}

// EventHandler is called for each detected filesystem event.
type EventHandler func(Event)

// Guard watches critical AI tool config files for unauthorized changes.
type Guard struct {
	watcher    *fsnotify.Watcher
	scanner    *engine.Scanner
	handler    EventHandler
	logger     *slog.Logger
	extraPaths []string

	mu     sync.RWMutex
	hashes map[string]string // path -> last known SHA-256
	paths  map[string]bool   // set of watched file paths

	pendingMu sync.Mutex
	pending   map[string]*time.Timer
}

// New creates a guard. The scanner is shared with the proxy (thread-safe).
func New(scanner *engine.Scanner, handler EventHandler, logger *slog.Logger) (*Guard, error) {
	if logger == nil {
		logger = slog.Default()
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher: %w", err)
	}
	return &Guard{
		watcher: w,
		scanner: scanner,
		handler: handler,
		logger:  logger,
		hashes:  make(map[string]string),
		paths:   make(map[string]bool),
		pending: make(map[string]*time.Timer),
	}, nil
}

// SetExtraPaths stores extra user-configured paths for rescan discovery.
func (g *Guard) SetExtraPaths(paths []string) {
	g.extraPaths = paths
}

// Watch adds a path to the watch list.
// Directories are watched directly. Files are watched via their parent
// directory to handle atomic writes (temp -> rename).
func (g *Guard) Watch(path string) error {
	expanded := expandHome(path)

	info, err := os.Stat(expanded)
	if err != nil {
		return nil // path doesn't exist, skip
	}

	watchPath := expanded
	if !info.IsDir() {
		watchPath = filepath.Dir(expanded)
	}

	if err := g.watcher.Add(watchPath); err != nil {
		return fmt.Errorf("watch %s: %w", watchPath, err)
	}

	g.mu.Lock()
	g.paths[expanded] = true
	g.mu.Unlock()

	// Snapshot initial hash for files.
	if !info.IsDir() {
		if h, err := hashFile(expanded); err == nil {
			g.mu.Lock()
			g.hashes[expanded] = h
			g.mu.Unlock()
		}
	}

	g.logger.Debug("watching", "path", expanded)
	return nil
}

// Run starts the event loop and periodic rescan. Blocks until ctx is cancelled.
func (g *Guard) Run(ctx context.Context) error {
	defer func() { _ = g.watcher.Close() }()

	// Periodic rescan for newly created paths.
	rescanTicker := time.NewTicker(rescanInterval)
	defer rescanTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-g.watcher.Events:
			if !ok {
				return nil
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
				g.debounce(event)
			}
		case err, ok := <-g.watcher.Errors:
			if !ok {
				return nil
			}
			g.logger.Error("watcher error", "error", err)
		case <-rescanTicker.C:
			g.rescan()
		}
	}
}

// WatchCount returns the number of paths being watched.
func (g *Guard) WatchCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.paths)
}

func (g *Guard) debounce(event fsnotify.Event) {
	path := event.Name
	if !g.isWatchedPath(path) {
		return
	}

	g.pendingMu.Lock()
	defer g.pendingMu.Unlock()

	if t, ok := g.pending[path]; ok {
		t.Stop()
	}
	op := event.Op.String()
	g.pending[path] = time.AfterFunc(debounceWindow, func() {
		g.processEvent(path, op)
		g.pendingMu.Lock()
		delete(g.pending, path)
		g.pendingMu.Unlock()
	})
}

func (g *Guard) processEvent(path, op string) {
	content, err := readFileCapped(path, maxFileSize)
	if err != nil {
		g.logger.Debug("cannot read file", "path", path, "error", err)
		return
	}

	newHash := sha256Hex(content)

	g.mu.RLock()
	prevHash := g.hashes[path]
	g.mu.RUnlock()

	if newHash == prevHash {
		return
	}

	outcome, err := g.scanner.ScanContent(context.Background(), string(content))
	if err != nil {
		g.logger.Error("scan failed", "path", path, "error", err)
		return
	}

	g.mu.Lock()
	g.hashes[path] = newHash
	g.mu.Unlock()

	g.handler(Event{
		Path:      path,
		Operation: op,
		Hash:      newHash,
		PrevHash:  prevHash,
		Findings:  outcome.Findings,
		Verdict:   outcome.Verdict,
		Timestamp: time.Now().UTC(),
	})
}

func (g *Guard) isWatchedPath(path string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.paths[path] {
		return true
	}
	// Check if file is inside a watched directory.
	for wp := range g.paths {
		if strings.HasPrefix(path, wp+"/") {
			return true
		}
	}
	return false
}

func (g *Guard) rescan() {
	allPaths := DefaultWatchPaths()
	allPaths = append(allPaths, g.extraPaths...)
	for _, p := range allPaths {
		expanded := expandHome(p)
		if !g.isWatchedPath(expanded) {
			if err := g.Watch(p); err == nil {
				g.logger.Info("new path discovered", "path", expanded)
			}
		}
	}
}
