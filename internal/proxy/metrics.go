package proxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for the oktsec proxy.
var (
	messagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "oktsec",
		Name:      "messages_total",
		Help:      "Total messages processed, by status and policy decision.",
	}, []string{"status", "policy_decision"})

	messageLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "oktsec",
		Name:      "message_latency_seconds",
		Help:      "Message processing latency in seconds.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	}, []string{"status"})

	rulesTriggered = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "oktsec",
		Name:      "rules_triggered_total",
		Help:      "Detection rules triggered, by rule_id and severity.",
	}, []string{"rule_id", "severity"})

	rateLimitHits = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "oktsec",
		Name:      "rate_limit_hits_total",
		Help:      "Total requests rejected by rate limiting.",
	})

	quarantinePending = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "oktsec",
		Name:      "quarantine_pending",
		Help:      "Number of messages currently in quarantine awaiting review.",
	})

	signatureVerified = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "oktsec",
		Name:      "signature_verifications_total",
		Help:      "Signature verification outcomes.",
	}, []string{"result"})
)
