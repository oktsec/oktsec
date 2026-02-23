package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMessageWindow_AddAndConcatenate(t *testing.T) {
	w := NewMessageWindow(10, time.Hour)

	w.Add("agent-a", "first message")
	w.Add("agent-a", "second message")

	got := w.Concatenated("agent-a")
	want := "first message\n---\nsecond message"
	if got != want {
		t.Errorf("Concatenated =\n%s\nwant:\n%s", got, want)
	}
}

func TestMessageWindow_SingleMessageReturnsEmpty(t *testing.T) {
	w := NewMessageWindow(10, time.Hour)

	w.Add("agent-a", "only one")

	got := w.Concatenated("agent-a")
	if got != "" {
		t.Errorf("single message should return empty, got: %q", got)
	}
}

func TestMessageWindow_MaxSizeEviction(t *testing.T) {
	w := NewMessageWindow(3, time.Hour)

	w.Add("agent-a", "msg-1")
	w.Add("agent-a", "msg-2")
	w.Add("agent-a", "msg-3")
	w.Add("agent-a", "msg-4") // should evict msg-1

	got := w.Concatenated("agent-a")
	want := "msg-2\n---\nmsg-3\n---\nmsg-4"
	if got != want {
		t.Errorf("Concatenated =\n%s\nwant:\n%s", got, want)
	}
}

func TestMessageWindow_MaxAgeEviction(t *testing.T) {
	w := NewMessageWindow(10, 50*time.Millisecond)

	w.Add("agent-a", "old message")
	time.Sleep(100 * time.Millisecond)
	w.Add("agent-a", "new message")

	// "old message" should be evicted by age; only one entry remains → empty
	got := w.Concatenated("agent-a")
	if got != "" {
		t.Errorf("expired messages should be evicted, got: %q", got)
	}
}

func TestMessageWindow_IsolatesSenders(t *testing.T) {
	w := NewMessageWindow(10, time.Hour)

	w.Add("agent-a", "a-msg-1")
	w.Add("agent-a", "a-msg-2")
	w.Add("agent-b", "b-msg-1")

	gotA := w.Concatenated("agent-a")
	if gotA != "a-msg-1\n---\na-msg-2" {
		t.Errorf("agent-a Concatenated = %q", gotA)
	}

	gotB := w.Concatenated("agent-b")
	if gotB != "" {
		t.Errorf("agent-b single message should be empty, got: %q", gotB)
	}
}

func TestMessageWindow_ConcurrentAccess(t *testing.T) {
	w := NewMessageWindow(100, time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			agent := fmt.Sprintf("agent-%d", id%3)
			for j := 0; j < 20; j++ {
				w.Add(agent, fmt.Sprintf("msg-%d-%d", id, j))
				_ = w.Concatenated(agent)
			}
		}(i)
	}
	wg.Wait()
}
