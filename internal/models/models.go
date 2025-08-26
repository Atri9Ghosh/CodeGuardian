package models

import (
	"time"
)

// GitHubWebhookPayload represents a GitHub webhook payload
type GitHubWebhookPayload struct {
	Action      string `json:"action"`
	PullRequest struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		Body   string `json:"body"`
		User   struct {
			Login string `json:"login"`
		} `json:"user"`
		Base struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
		Head struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
		Files []struct {
			Filename  string `json:"filename"`
			Status    string `json:"status"`
			Additions int    `json:"additions"`
			Deletions int    `json:"deletions"`
			Changes   int    `json:"changes"`
		} `json:"files"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

// ManualScanRequest represents a manual scan request
type ManualScanRequest struct {
	Repository  string `json:"repository" binding:"required"`
	PullRequest int    `json:"pull_request" binding:"required"`
	BaseSHA     string `json:"base_sha" binding:"required"`
	HeadSHA     string `json:"head_sha" binding:"required"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	ScanID        string    `json:"scan_id"`
	Repository    string    `json:"repository"`
	PullRequest   string    `json:"pull_request"`
	Status        string    `json:"status"`
	IssuesFound   int       `json:"issues_found"`
	SecurityScore float64   `json:"security_score"`
	Duration      float64   `json:"duration"`
	Timestamp     time.Time `json:"timestamp"`
	Issues        []Issue   `json:"issues,omitempty"`
}

// Issue represents a security issue
type Issue struct {
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Column     int     `json:"column"`
	Severity   string  `json:"severity"`
	Category   string  `json:"category"`
	Message    string  `json:"message"`
	Code       string  `json:"code"`
	Confidence float64 `json:"confidence"`
	RuleID     string  `json:"rule_id"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Version   string            `json:"version"`
	Services  map[string]string `json:"services"`
}

// ConfigResponse represents a configuration response
type ConfigResponse struct {
	Environment string                 `json:"environment"`
	AIModel     string                 `json:"ai_model"`
	Rules       map[string]interface{} `json:"rules"`
}

// ScanHistoryResponse represents a scan history response
type ScanHistoryResponse struct {
	Scans []ScanHistoryItem `json:"scans"`
	Total int               `json:"total"`
}

// ScanHistoryItem represents a scan history item
type ScanHistoryItem struct {
	ScanID        string    `json:"scan_id"`
	Repository    string    `json:"repository"`
	PullRequest   string    `json:"pull_request"`
	Status        string    `json:"status"`
	IssuesFound   int       `json:"issues_found"`
	SecurityScore float64   `json:"security_score"`
	Duration      float64   `json:"duration"`
	Timestamp     time.Time `json:"timestamp"`
}

// GitHubComment represents a GitHub PR comment
type GitHubComment struct {
	Body string `json:"body"`
}

// CommentTemplate represents a comment template
type CommentTemplate struct {
	Issues        []Issue
	Summary       ScanSummary
	SecurityScore float64
	Repository    string
	PullRequest   string
}

// ScanSummary represents a scan summary
type ScanSummary struct {
	TotalIssues    int            `json:"total_issues"`
	CriticalIssues int            `json:"critical_issues"`
	HighIssues     int            `json:"high_issues"`
	MediumIssues   int            `json:"medium_issues"`
	LowIssues      int            `json:"low_issues"`
	ByCategory     map[string]int `json:"by_category"`
}
