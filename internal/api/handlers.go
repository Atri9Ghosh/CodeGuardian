package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codeguardian/codeguardian/internal/config"
	"github.com/codeguardian/codeguardian/internal/github"
	"github.com/codeguardian/codeguardian/internal/logger"
	"github.com/codeguardian/codeguardian/internal/metrics"
	"github.com/codeguardian/codeguardian/internal/models"
	"github.com/codeguardian/codeguardian/internal/scanner"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler represents the API handler
type Handler struct {
	config  *config.Config
	logger  *logger.Logger
	scanner *scanner.Scanner
	github  *github.Client
}

// NewHandler creates a new API handler
func NewHandler(cfg *config.Config, log *logger.Logger) *Handler {
	return &Handler{
		config:  cfg,
		logger:  log,
		scanner: scanner.New(cfg, log),
		github:  github.NewClient(cfg, log),
	}
}

// HealthCheck handles health check requests
func (h *Handler) HealthCheck(c *gin.Context) {
	startTime := time.Now()

	response := models.HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
		Services: map[string]string{
			"scanner": "ok",
			"github":  "ok",
			"ai":      "ok",
		},
	}

	// Record metrics
	duration := time.Since(startTime).Seconds()
	metrics.RecordHTTPRequest("GET", "/health", "200", duration)

	c.JSON(http.StatusOK, response)
}

// Metrics handles metrics requests
func (h *Handler) Metrics(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}

// GitHubWebhook handles GitHub webhook events
func (h *Handler) GitHubWebhook(c *gin.Context) {
	startTime := time.Now()

	// Verify webhook signature
	if err := h.verifyWebhookSignature(c); err != nil {
		h.logger.LogError(err, map[string]interface{}{
			"endpoint": "/webhook/github",
			"action":   "webhook_verification",
		})
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "unauthorized",
			Message: "Invalid webhook signature",
			Code:    401,
		})
		return
	}

	// Parse webhook payload
	var payload models.GitHubWebhookPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		h.logger.LogError(err, map[string]interface{}{
			"endpoint": "/webhook/github",
			"action":   "payload_parsing",
		})
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "bad_request",
			Message: "Invalid webhook payload",
			Code:    400,
		})
		return
	}

	// Only process pull request events
	if payload.Action != "opened" && payload.Action != "synchronize" && payload.Action != "reopened" {
		c.JSON(http.StatusOK, gin.H{"message": "Event ignored"})
		return
	}

	// Log webhook event
	h.logger.LogGitHubWebhook("pull_request", payload.Repository.FullName, payload.Action)
	metrics.RecordGitHubWebhook("pull_request", payload.Action)

	// Process the pull request asynchronously
	go h.processPullRequest(c.Request.Context(), &payload)

	c.JSON(http.StatusOK, gin.H{"message": "Webhook received and processing started"})

	// Record metrics
	duration := time.Since(startTime).Seconds()
	metrics.RecordHTTPRequest("POST", "/webhook/github", "200", duration)
}

// ManualScan handles manual scan requests
func (h *Handler) ManualScan(c *gin.Context) {
	startTime := time.Now()

	var req models.ManualScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.LogError(err, map[string]interface{}{
			"endpoint": "/scan",
			"action":   "request_validation",
		})
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "bad_request",
			Message: "Invalid request body",
			Code:    400,
		})
		return
	}

	// Get pull request details from GitHub
	_, err := h.github.GetPullRequest(c.Request.Context(), req.Repository, req.PullRequest)
	if err != nil {
		h.logger.LogError(err, map[string]interface{}{
			"repository":   req.Repository,
			"pull_request": req.PullRequest,
		})
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to fetch pull request details",
			Code:    500,
		})
		return
	}

	// Get file changes
	fileChanges, err := h.github.GetFileChanges(c.Request.Context(), req.Repository, req.PullRequest)
	if err != nil {
		h.logger.LogError(err, map[string]interface{}{
			"repository":   req.Repository,
			"pull_request": req.PullRequest,
		})
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to fetch file changes",
			Code:    500,
		})
		return
	}

	// Convert to scanner format
	scanFiles := make([]scanner.FileChange, len(fileChanges))
	for i, file := range fileChanges {
		scanFiles[i] = scanner.FileChange{
			Filename: file.Filename,
			Content:  file.Content,
			Language: file.Language,
		}
	}

	// Perform security scan
	scanReq := &scanner.ScanRequest{
		Repository:   req.Repository,
		PullRequest:  strconv.Itoa(req.PullRequest),
		BaseSHA:      req.BaseSHA,
		HeadSHA:      req.HeadSHA,
		FilesChanged: scanFiles,
	}

	result, err := h.scanner.Scan(c.Request.Context(), scanReq)
	if err != nil {
		h.logger.LogError(err, map[string]interface{}{
			"repository":   req.Repository,
			"pull_request": req.PullRequest,
		})
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to perform security scan",
			Code:    500,
		})
		return
	}

	// Convert to response format
	issues := make([]models.Issue, len(result.Issues))
	for i, issue := range result.Issues {
		issues[i] = models.Issue{
			File:       issue.File,
			Line:       issue.Line,
			Column:     issue.Column,
			Severity:   issue.Severity,
			Category:   issue.Category,
			Message:    issue.Message,
			Code:       issue.Code,
			Confidence: issue.Confidence,
			RuleID:     issue.RuleID,
		}
	}

	response := models.ScanResponse{
		ScanID:        result.ScanID,
		Repository:    result.Repository,
		PullRequest:   result.PullRequest,
		Status:        "completed",
		IssuesFound:   result.Summary.TotalIssues,
		SecurityScore: result.SecurityScore,
		Duration:      result.Duration,
		Timestamp:     result.Timestamp,
		Issues:        issues,
	}

	c.JSON(http.StatusOK, response)

	// Record metrics
	duration := time.Since(startTime).Seconds()
	metrics.RecordHTTPRequest("POST", "/scan", "200", duration)
}

// GetConfig returns the current configuration
func (h *Handler) GetConfig(c *gin.Context) {
	response := models.ConfigResponse{
		Environment: h.config.Environment,
		AIModel:     h.config.GetAIModel(),
		Rules: map[string]interface{}{
			"secrets":         len(h.config.SecurityRules.Secrets),
			"api_keys":        len(h.config.SecurityRules.APIKeys),
			"vulnerabilities": len(h.config.SecurityRules.Vulnerabilities),
			"code_quality":    len(h.config.SecurityRules.CodeQuality),
		},
	}

	c.JSON(http.StatusOK, response)
}

// UpdateConfig updates the configuration
func (h *Handler) UpdateConfig(c *gin.Context) {
	// This would implement configuration updates
	// For now, return not implemented
	c.JSON(http.StatusNotImplemented, models.ErrorResponse{
		Error:   "not_implemented",
		Message: "Configuration updates not yet implemented",
		Code:    501,
	})
}

// GetScanHistory returns scan history
func (h *Handler) GetScanHistory(c *gin.Context) {
	// This would implement scan history retrieval
	// For now, return empty response
	response := models.ScanHistoryResponse{
		Scans: []models.ScanHistoryItem{},
		Total: 0,
	}

	c.JSON(http.StatusOK, response)
}

// GetScanDetails returns details for a specific scan
func (h *Handler) GetScanDetails(c *gin.Context) {
	scanID := c.Param("id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "bad_request",
			Message: "Scan ID is required",
			Code:    400,
		})
		return
	}

	// This would implement scan details retrieval
	// For now, return not found
	c.JSON(http.StatusNotFound, models.ErrorResponse{
		Error:   "not_found",
		Message: "Scan not found",
		Code:    404,
	})
}

// processPullRequest processes a pull request asynchronously
func (h *Handler) processPullRequest(ctx context.Context, payload *models.GitHubWebhookPayload) {
	repository := payload.Repository.FullName
	pullRequest := strconv.Itoa(payload.PullRequest.Number)

	h.logger.LogInfo("Processing pull request", map[string]interface{}{
		"repository":   repository,
		"pull_request": pullRequest,
		"action":       payload.Action,
	})

	// Get file changes
	fileChanges, err := h.github.GetFileChanges(ctx, repository, payload.PullRequest.Number)
	if err != nil {
		h.logger.LogError(err, map[string]interface{}{
			"repository":   repository,
			"pull_request": pullRequest,
		})
		return
	}

	// Convert to scanner format
	scanFiles := make([]scanner.FileChange, len(fileChanges))
	for i, file := range fileChanges {
		scanFiles[i] = scanner.FileChange{
			Filename: file.Filename,
			Content:  file.Content,
			Language: file.Language,
		}
	}

	// Perform security scan
	scanReq := &scanner.ScanRequest{
		Repository:   repository,
		PullRequest:  pullRequest,
		BaseSHA:      payload.PullRequest.Base.SHA,
		HeadSHA:      payload.PullRequest.Head.SHA,
		FilesChanged: scanFiles,
	}

	result, err := h.scanner.Scan(ctx, scanReq)
	if err != nil {
		h.logger.LogError(err, map[string]interface{}{
			"repository":   repository,
			"pull_request": pullRequest,
		})
		return
	}

	// Post comment to GitHub
	if err := h.postGitHubComment(ctx, repository, payload.PullRequest.Number, result); err != nil {
		h.logger.LogError(err, map[string]interface{}{
			"repository":   repository,
			"pull_request": pullRequest,
		})
	}
}

// postGitHubComment posts a comment to the GitHub pull request
func (h *Handler) postGitHubComment(ctx context.Context, repository string, prNumber int, result *scanner.ScanResult) error {
	comment := h.generateComment(result)

	return h.github.CreateComment(ctx, repository, prNumber, comment)
}

// generateComment generates a GitHub comment from scan results
func (h *Handler) generateComment(result *scanner.ScanResult) string {
	var comment strings.Builder

	comment.WriteString("## 🔒 CodeGuardian Security Scan Results\n\n")

	if result.Summary.TotalIssues == 0 {
		comment.WriteString("### ✅ No Security Issues Found\n\n")
		comment.WriteString("Great job! No security vulnerabilities or issues were detected in this pull request.\n\n")
	} else {
		comment.WriteString(fmt.Sprintf("### ⚠️ %d Security Issue(s) Found\n\n", result.Summary.TotalIssues))

		// Group issues by severity
		criticalIssues := []scanner.SecurityIssue{}
		highIssues := []scanner.SecurityIssue{}
		mediumIssues := []scanner.SecurityIssue{}
		lowIssues := []scanner.SecurityIssue{}

		for _, issue := range result.Issues {
			switch issue.Severity {
			case "critical":
				criticalIssues = append(criticalIssues, issue)
			case "high":
				highIssues = append(highIssues, issue)
			case "medium":
				mediumIssues = append(mediumIssues, issue)
			case "low":
				lowIssues = append(lowIssues, issue)
			}
		}

		// Add critical issues
		if len(criticalIssues) > 0 {
			comment.WriteString("#### 🚨 Critical Issues\n\n")
			for _, issue := range criticalIssues {
				comment.WriteString(h.formatIssue(issue))
			}
			comment.WriteString("\n")
		}

		// Add high issues
		if len(highIssues) > 0 {
			comment.WriteString("#### ⚠️ High Priority Issues\n\n")
			for _, issue := range highIssues {
				comment.WriteString(h.formatIssue(issue))
			}
			comment.WriteString("\n")
		}

		// Add medium issues
		if len(mediumIssues) > 0 {
			comment.WriteString("#### 🔶 Medium Priority Issues\n\n")
			for _, issue := range mediumIssues {
				comment.WriteString(h.formatIssue(issue))
			}
			comment.WriteString("\n")
		}

		// Add low issues
		if len(lowIssues) > 0 {
			comment.WriteString("#### ℹ️ Low Priority Issues\n\n")
			for _, issue := range lowIssues {
				comment.WriteString(h.formatIssue(issue))
			}
			comment.WriteString("\n")
		}
	}

	// Add summary
	comment.WriteString("### 📊 Summary\n\n")
	comment.WriteString(fmt.Sprintf("- **Total Issues**: %d\n", result.Summary.TotalIssues))
	comment.WriteString(fmt.Sprintf("- **Critical**: %d\n", result.Summary.CriticalIssues))
	comment.WriteString(fmt.Sprintf("- **High**: %d\n", result.Summary.HighIssues))
	comment.WriteString(fmt.Sprintf("- **Medium**: %d\n", result.Summary.MediumIssues))
	comment.WriteString(fmt.Sprintf("- **Low**: %d\n", result.Summary.LowIssues))
	comment.WriteString(fmt.Sprintf("- **Security Score**: %.1f/10\n", result.SecurityScore))
	comment.WriteString(fmt.Sprintf("- **Scan Duration**: %.2fs\n", result.Duration))

	comment.WriteString("\n---\n")
	comment.WriteString("*This comment was automatically generated by CodeGuardian*")

	return comment.String()
}

// formatIssue formats a single security issue for the comment
func (h *Handler) formatIssue(issue scanner.SecurityIssue) string {
	var formatted strings.Builder

	formatted.WriteString(fmt.Sprintf("**%s** (Line %d)\n", issue.Message, issue.Line))
	formatted.WriteString(fmt.Sprintf("```%s\n%s\n```\n", h.getLanguageFromFile(issue.File), issue.Code))
	formatted.WriteString(fmt.Sprintf("**Category**: %s | **Confidence**: %.0f%%\n\n", issue.Category, issue.Confidence*100))

	return formatted.String()
}

// getLanguageFromFile determines the language from the file extension
func (h *Handler) getLanguageFromFile(filename string) string {
	ext := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(ext, ".go"):
		return "go"
	case strings.HasSuffix(ext, ".js"):
		return "javascript"
	case strings.HasSuffix(ext, ".ts"):
		return "typescript"
	case strings.HasSuffix(ext, ".py"):
		return "python"
	case strings.HasSuffix(ext, ".java"):
		return "java"
	case strings.HasSuffix(ext, ".php"):
		return "php"
	case strings.HasSuffix(ext, ".rb"):
		return "ruby"
	case strings.HasSuffix(ext, ".rs"):
		return "rust"
	case strings.HasSuffix(ext, ".cpp"), strings.HasSuffix(ext, ".cc"), strings.HasSuffix(ext, ".cxx"):
		return "cpp"
	case strings.HasSuffix(ext, ".c"):
		return "c"
	default:
		return ""
	}
}

// verifyWebhookSignature verifies the GitHub webhook signature
func (h *Handler) verifyWebhookSignature(c *gin.Context) error {
	// This would implement webhook signature verification
	// For now, return nil (no verification)
	return nil
}
