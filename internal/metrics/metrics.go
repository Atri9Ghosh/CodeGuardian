package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ScansTotal tracks the total number of scans performed
	ScansTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "codeguardian_scans_total",
			Help: "Total number of security scans performed",
		},
		[]string{"repository", "status"},
	)

	// IssuesFound tracks the number of security issues detected
	IssuesFound = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "codeguardian_issues_found",
			Help: "Number of security issues detected",
		},
		[]string{"repository", "severity", "category"},
	)

	// ScanDuration tracks the duration of security scans
	ScanDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "codeguardian_scan_duration_seconds",
			Help:    "Duration of security scans in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"repository"},
	)

	// AIAPICalls tracks the number of AI API calls made
	AIAPICalls = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "codeguardian_ai_api_calls_total",
			Help: "Total number of AI API calls made",
		},
		[]string{"model", "status"},
	)

	// AITokensUsed tracks the number of tokens used in AI API calls
	AITokensUsed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "codeguardian_ai_tokens_used_total",
			Help: "Total number of tokens used in AI API calls",
		},
		[]string{"model"},
	)

	// GitHubWebhooks tracks the number of GitHub webhook events received
	GitHubWebhooks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "codeguardian_github_webhooks_total",
			Help: "Total number of GitHub webhook events received",
		},
		[]string{"event_type", "action"},
	)

	// ActiveScans tracks the number of currently active scans
	ActiveScans = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "codeguardian_active_scans",
			Help: "Number of currently active security scans",
		},
		[]string{"repository"},
	)

	// SecurityScore tracks the security score for repositories
	SecurityScore = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "codeguardian_security_score",
			Help: "Security score for repositories (0-10)",
		},
		[]string{"repository"},
	)

	// HTTPRequests tracks HTTP request metrics
	HTTPRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "codeguardian_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	// HTTPRequestDuration tracks HTTP request duration
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "codeguardian_http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
)

// Init initializes the metrics
func Init() {
	// This function can be used to initialize any metrics-specific setup
	// Currently, Prometheus auto-registration handles everything
}

// RecordScan records metrics for a completed scan
func RecordScan(repository, status string, duration float64, issuesFound int) {
	ScansTotal.WithLabelValues(repository, status).Inc()
	ScanDuration.WithLabelValues(repository).Observe(duration)
}

// RecordIssue records metrics for a detected security issue
func RecordIssue(repository, severity, category string) {
	IssuesFound.WithLabelValues(repository, severity, category).Inc()
}

// RecordAICall records metrics for an AI API call
func RecordAICall(model, status string, tokensUsed int) {
	AIAPICalls.WithLabelValues(model, status).Inc()
	if tokensUsed > 0 {
		AITokensUsed.WithLabelValues(model).Add(float64(tokensUsed))
	}
}

// RecordGitHubWebhook records metrics for a GitHub webhook event
func RecordGitHubWebhook(eventType, action string) {
	GitHubWebhooks.WithLabelValues(eventType, action).Inc()
}

// SetActiveScans sets the number of active scans for a repository
func SetActiveScans(repository string, count int) {
	ActiveScans.WithLabelValues(repository).Set(float64(count))
}

// SetSecurityScore sets the security score for a repository
func SetSecurityScore(repository string, score float64) {
	SecurityScore.WithLabelValues(repository).Set(score)
}

// RecordHTTPRequest records metrics for an HTTP request
func RecordHTTPRequest(method, endpoint, status string, duration float64) {
	HTTPRequests.WithLabelValues(method, endpoint, status).Inc()
	HTTPRequestDuration.WithLabelValues(method, endpoint).Observe(duration)
}
