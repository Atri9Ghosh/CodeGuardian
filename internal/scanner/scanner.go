package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/codeguardian/codeguardian/internal/ai"
	"github.com/codeguardian/codeguardian/internal/config"
	"github.com/codeguardian/codeguardian/internal/logger"
	"github.com/codeguardian/codeguardian/internal/metrics"
)

// Scanner represents the security scanner
type Scanner struct {
	config *config.Config
	logger *logger.Logger
	ai     *ai.Client
}

// New creates a new scanner instance
func New(cfg *config.Config, log *logger.Logger) *Scanner {
	return &Scanner{
		config: cfg,
		logger: log,
		ai:     ai.NewClient(cfg),
	}
}

// ScanRequest represents a scan request
type ScanRequest struct {
	Repository   string       `json:"repository"`
	PullRequest  string       `json:"pull_request"`
	BaseSHA      string       `json:"base_sha"`
	HeadSHA      string       `json:"head_sha"`
	FilesChanged []FileChange `json:"files_changed"`
}

// FileChange represents a changed file
type FileChange struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
	Language string `json:"language"`
}

// ScanResult represents the result of a security scan
type ScanResult struct {
	Repository    string          `json:"repository"`
	PullRequest   string          `json:"pull_request"`
	ScanID        string          `json:"scan_id"`
	Timestamp     time.Time       `json:"timestamp"`
	Duration      float64         `json:"duration"`
	Issues        []SecurityIssue `json:"issues"`
	Summary       ScanSummary     `json:"summary"`
	SecurityScore float64         `json:"security_score"`
}

// SecurityIssue represents a detected security issue
type SecurityIssue struct {
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

// ScanSummary provides a summary of the scan results
type ScanSummary struct {
	TotalIssues    int            `json:"total_issues"`
	CriticalIssues int            `json:"critical_issues"`
	HighIssues     int            `json:"high_issues"`
	MediumIssues   int            `json:"medium_issues"`
	LowIssues      int            `json:"low_issues"`
	ByCategory     map[string]int `json:"by_category"`
}

// Scan performs a comprehensive security scan on the provided code changes
func (s *Scanner) Scan(ctx context.Context, req *ScanRequest) (*ScanResult, error) {
	startTime := time.Now()

	s.logger.LogScanStart(req.Repository, req.PullRequest, req.BaseSHA, req.HeadSHA)

	// Generate scan ID
	scanID := generateScanID(req.Repository, req.PullRequest)

	// Initialize result
	result := &ScanResult{
		Repository:  req.Repository,
		PullRequest: req.PullRequest,
		ScanID:      scanID,
		Timestamp:   startTime,
		Issues:      []SecurityIssue{},
	}

	// Perform pattern-based scanning
	patternIssues := s.scanWithPatterns(req.FilesChanged)
	result.Issues = append(result.Issues, patternIssues...)

	// Perform AI-based scanning
	aiIssues, err := s.scanWithAI(ctx, req.FilesChanged)
	if err != nil {
		s.logger.LogError(err, map[string]interface{}{
			"repository":   req.Repository,
			"pull_request": req.PullRequest,
			"scan_id":      scanID,
		})
	} else {
		result.Issues = append(result.Issues, aiIssues...)
	}

	// Calculate summary and score
	result.Summary = s.calculateSummary(result.Issues)
	result.SecurityScore = s.calculateSecurityScore(result.Summary)
	result.Duration = time.Since(startTime).Seconds()

	// Record metrics
	metrics.RecordScan(req.Repository, "completed", result.Duration, result.Summary.TotalIssues)
	metrics.SetSecurityScore(req.Repository, result.SecurityScore)

	s.logger.LogScanComplete(req.Repository, req.PullRequest, result.Summary.TotalIssues, result.Duration)

	return result, nil
}

// scanWithPatterns performs pattern-based security scanning
func (s *Scanner) scanWithPatterns(files []FileChange) []SecurityIssue {
	var issues []SecurityIssue

	for _, file := range files {
		// Skip binary files and large files
		if s.shouldSkipFile(file) {
			continue
		}

		// Scan for secrets
		secretIssues := s.scanForSecrets(file)
		issues = append(issues, secretIssues...)

		// Scan for API keys
		apiKeyIssues := s.scanForAPIKeys(file)
		issues = append(issues, apiKeyIssues...)

		// Scan for vulnerabilities
		vulnIssues := s.scanForVulnerabilities(file)
		issues = append(issues, vulnIssues...)

		// Scan for code quality issues
		qualityIssues := s.scanForCodeQuality(file)
		issues = append(issues, qualityIssues...)
	}

	return issues
}

// scanWithAI performs AI-based security scanning
func (s *Scanner) scanWithAI(ctx context.Context, files []FileChange) ([]SecurityIssue, error) {
	var allIssues []SecurityIssue

	for _, file := range files {
		if s.shouldSkipFile(file) {
			continue
		}

		// Prepare context for AI analysis
		context := fmt.Sprintf("Analyzing file: %s (Language: %s)\n\nCode:\n%s",
			file.Filename, file.Language, file.Content)

		// Get AI analysis
		analysis, err := s.ai.AnalyzeSecurity(ctx, context)
		if err != nil {
			s.logger.LogError(err, map[string]interface{}{
				"file":     file.Filename,
				"language": file.Language,
			})
			continue
		}

		// Convert AI analysis to security issues
		issues := s.convertAIAnalysisToIssues(file, analysis)
		allIssues = append(allIssues, issues...)
	}

	return allIssues, nil
}

// scanForSecrets scans for hardcoded secrets
func (s *Scanner) scanForSecrets(file FileChange) []SecurityIssue {
	var issues []SecurityIssue

	for _, rule := range s.config.SecurityRules.Secrets {
		re := regexp.MustCompile(rule.Pattern)
		matches := re.FindAllStringSubmatchIndex(file.Content, -1)

		for _, match := range matches {
			line, column := s.getLineAndColumn(file.Content, match[0])

			issue := SecurityIssue{
				File:       file.Filename,
				Line:       line,
				Column:     column,
				Severity:   rule.Severity,
				Category:   rule.Category,
				Message:    rule.Message,
				Code:       file.Content[match[0]:match[1]],
				Confidence: 0.9,
				RuleID:     fmt.Sprintf("secret_%s", rule.Pattern),
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

// scanForAPIKeys scans for API keys and tokens
func (s *Scanner) scanForAPIKeys(file FileChange) []SecurityIssue {
	var issues []SecurityIssue

	for _, rule := range s.config.SecurityRules.APIKeys {
		re := regexp.MustCompile(rule.Pattern)
		matches := re.FindAllStringSubmatchIndex(file.Content, -1)

		for _, match := range matches {
			line, column := s.getLineAndColumn(file.Content, match[0])

			issue := SecurityIssue{
				File:       file.Filename,
				Line:       line,
				Column:     column,
				Severity:   rule.Severity,
				Category:   rule.Category,
				Message:    rule.Message,
				Code:       file.Content[match[0]:match[1]],
				Confidence: 0.85,
				RuleID:     fmt.Sprintf("api_key_%s", rule.Pattern),
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

// scanForVulnerabilities scans for security vulnerabilities
func (s *Scanner) scanForVulnerabilities(file FileChange) []SecurityIssue {
	var issues []SecurityIssue

	for _, rule := range s.config.SecurityRules.Vulnerabilities {
		re := regexp.MustCompile(rule.Pattern)
		matches := re.FindAllStringSubmatchIndex(file.Content, -1)

		for _, match := range matches {
			line, column := s.getLineAndColumn(file.Content, match[0])

			issue := SecurityIssue{
				File:       file.Filename,
				Line:       line,
				Column:     column,
				Severity:   rule.Severity,
				Category:   rule.Category,
				Message:    rule.Message,
				Code:       file.Content[match[0]:match[1]],
				Confidence: 0.8,
				RuleID:     fmt.Sprintf("vuln_%s", rule.Pattern),
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

// scanForCodeQuality scans for code quality security issues
func (s *Scanner) scanForCodeQuality(file FileChange) []SecurityIssue {
	var issues []SecurityIssue

	for _, rule := range s.config.SecurityRules.CodeQuality {
		re := regexp.MustCompile(rule.Pattern)
		matches := re.FindAllStringSubmatchIndex(file.Content, -1)

		for _, match := range matches {
			line, column := s.getLineAndColumn(file.Content, match[0])

			issue := SecurityIssue{
				File:       file.Filename,
				Line:       line,
				Column:     column,
				Severity:   rule.Severity,
				Category:   rule.Category,
				Message:    rule.Message,
				Code:       file.Content[match[0]:match[1]],
				Confidence: 0.7,
				RuleID:     fmt.Sprintf("quality_%s", rule.Pattern),
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

// shouldSkipFile determines if a file should be skipped during scanning
func (s *Scanner) shouldSkipFile(file FileChange) bool {
	// Skip binary files
	binaryExtensions := []string{".exe", ".dll", ".so", ".dylib", ".bin", ".jpg", ".png", ".gif", ".pdf"}
	for _, ext := range binaryExtensions {
		if strings.HasSuffix(strings.ToLower(file.Filename), ext) {
			return true
		}
	}

	// Skip large files (over 1MB)
	if len(file.Content) > 1024*1024 {
		return true
	}

	// Skip generated files
	generatedPatterns := []string{"node_modules/", "vendor/", "dist/", "build/", ".git/"}
	for _, pattern := range generatedPatterns {
		if strings.Contains(file.Filename, pattern) {
			return true
		}
	}

	return false
}

// getLineAndColumn calculates the line and column number for a given position
func (s *Scanner) getLineAndColumn(content string, pos int) (line, column int) {
	line = 1
	column = 1

	for i := 0; i < pos && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}

	return line, column
}

// convertAIAnalysisToIssues converts AI analysis results to security issues
func (s *Scanner) convertAIAnalysisToIssues(file FileChange, analysis *ai.SecurityAnalysis) []SecurityIssue {
	var issues []SecurityIssue

	for _, finding := range analysis.Findings {
		issue := SecurityIssue{
			File:       file.Filename,
			Line:       finding.Line,
			Column:     finding.Column,
			Severity:   finding.Severity,
			Category:   finding.Category,
			Message:    finding.Description,
			Code:       finding.Code,
			Confidence: finding.Confidence,
			RuleID:     fmt.Sprintf("ai_%s", finding.Type),
		}
		issues = append(issues, issue)
	}

	return issues
}

// calculateSummary calculates a summary of the scan results
func (s *Scanner) calculateSummary(issues []SecurityIssue) ScanSummary {
	summary := ScanSummary{
		ByCategory: make(map[string]int),
	}

	for _, issue := range issues {
		summary.TotalIssues++
		summary.ByCategory[issue.Category]++

		switch issue.Severity {
		case "critical":
			summary.CriticalIssues++
		case "high":
			summary.HighIssues++
		case "medium":
			summary.MediumIssues++
		case "low":
			summary.LowIssues++
		}
	}

	return summary
}

// calculateSecurityScore calculates a security score (0-10) based on the issues found
func (s *Scanner) calculateSecurityScore(summary ScanSummary) float64 {
	// Base score starts at 10
	score := 10.0

	// Deduct points based on severity and count
	score -= float64(summary.CriticalIssues) * 3.0
	score -= float64(summary.HighIssues) * 2.0
	score -= float64(summary.MediumIssues) * 1.0
	score -= float64(summary.LowIssues) * 0.5

	// Ensure score is between 0 and 10
	if score < 0 {
		score = 0
	}
	if score > 10 {
		score = 10
	}

	return score
}

// generateScanID generates a unique scan ID
func generateScanID(repository, pullRequest string) string {
	return fmt.Sprintf("%s_%s_%d",
		strings.ReplaceAll(repository, "/", "_"),
		pullRequest,
		time.Now().Unix())
}
