package proxy

import (
	"net/http"
	"testing"
)

func TestCopyHeaders_SkipsHopByHop(t *testing.T) {
	src := http.Header{
		"Content-Type": {"application/json"},
		"Connection":   {"keep-alive"},
		"X-Custom":     {"value"},
	}
	dst := http.Header{}
	copyHeaders(dst, src)

	if dst.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should be copied")
	}
	if dst.Get("X-Custom") != "value" {
		t.Error("X-Custom should be copied")
	}
	if dst.Get("Connection") != "" {
		t.Error("Connection (hop-by-hop) should not be copied")
	}
}

func TestCopyHeaders_AllHopByHop(t *testing.T) {
	hopHeaders := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer",
		"Transfer-Encoding", "Upgrade",
	}
	src := http.Header{}
	for _, h := range hopHeaders {
		src.Set(h, "test")
	}
	src.Set("X-Safe", "ok")

	dst := http.Header{}
	copyHeaders(dst, src)

	for _, h := range hopHeaders {
		if dst.Get(h) != "" {
			t.Errorf("%s should not be copied", h)
		}
	}
	if dst.Get("X-Safe") != "ok" {
		t.Error("X-Safe should be copied")
	}
}
