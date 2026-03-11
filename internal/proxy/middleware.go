package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type contextKey string

const requestIDKey contextKey = "request_id"

// securityHeaders sets standard security headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "interest-cohort=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"font-src 'self'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'")
		if strings.HasPrefix(r.URL.Path, "/dashboard") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// requestID injects a unique ID into each request.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// logging logs each request with slog.
// Static assets, health checks, and SSE streams are logged at debug level
// to keep the console clean during normal operation.
func logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)

			p := r.URL.Path
			attrs := []any{
				"method", r.Method,
				"path", p,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", w.Header().Get("X-Request-ID"),
			}

			// Demote noisy paths to debug: static assets, health, favicon, SSE
			if strings.HasPrefix(p, "/dashboard/static/") ||
				strings.HasPrefix(p, "/dashboard/api/graph") ||
				p == "/health" || p == "/favicon.ico" ||
				strings.HasSuffix(p, "/stream") {
				logger.Debug("request", attrs...)
			} else {
				logger.Info("request", attrs...)
			}
		})
	}
}

// recovery catches panics and returns 500.
func recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered", "error", err, "path", r.URL.Path)
					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Flush forwards to the underlying ResponseWriter if it supports flushing.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter so http.NewResponseController can
// reach the original writer for features like SetWriteDeadline.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
