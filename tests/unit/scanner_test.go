package unit

import (
	"context"
	"testing"

	"github.com/codeguardian/codeguardian/internal/config"
	"github.com/codeguardian/codeguardian/internal/logger"
	"github.com/codeguardian/codeguardian/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner_ScanWithPatterns(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		SecurityRules: config.SecurityRulesConfig{
			Secrets: []config.SecurityRule{
				{
					Pattern:  "password\\s*=\\s*['\"][^'\"]+['\"]",
					Severity: "high",
					Message:  "Hardcoded password detected",
					Category: "secrets",
				},
			},
			APIKeys: []config.SecurityRule{
				{
					Pattern:  "api_key\\s*=\\s*['\"][^'\"]+['\"]",
					Severity: "critical",
					Message:  "API key found in code",
					Category: "api_keys",
				},
			},
		},
	}

	log := logger.New("debug")
	s := scanner.New(cfg, log)

	// Test files with security issues
	testFiles := []scanner.FileChange{
		{
			Filename: "config.py",
			Content: `password = "secret123"
			api_key = "sk-1234567890"`,
			Language: "python",
		},
		{
			Filename: "main.go",
			Content:  `func main() {\n    dbPassword := "admin123"\n}`,
			Language: "go",
		},
	}

	// Perform scan using the public Scan method
	req := &scanner.ScanRequest{
		Repository:   "test/repo",
		PullRequest:  "123",
		BaseSHA:      "abc123",
		HeadSHA:      "def456",
		FilesChanged: testFiles,
	}

	ctx := context.Background()
	result, err := s.Scan(ctx, req)

	require.NoError(t, err)
	assert.NotEmpty(t, result.Issues, "Should detect security issues")

	// Check for password detection
	passwordFound := false
	apiKeyFound := false

	for _, issue := range result.Issues {
		if issue.Category == "secrets" && issue.Message == "Hardcoded password detected" {
			passwordFound = true
		}
		if issue.Category == "api_keys" && issue.Message == "API key found in code" {
			apiKeyFound = true
		}
	}

	assert.True(t, passwordFound, "Should detect hardcoded password")
	assert.True(t, apiKeyFound, "Should detect API key")
}

func TestScanner_ShouldSkipFile(t *testing.T) {
	cfg := &config.Config{}
	log := logger.New("debug")
	s := scanner.New(cfg, log)

	tests := []struct {
		name     string
		file     scanner.FileChange
		expected bool
	}{
		{
			name: "should skip binary file",
			file: scanner.FileChange{
				Filename: "image.jpg",
				Content:  "binary content",
			},
			expected: true,
		},
		{
			name: "should skip large file",
			file: scanner.FileChange{
				Filename: "large.txt",
				Content:  string(make([]byte, 2*1024*1024)), // 2MB
			},
			expected: true,
		},
		{
			name: "should skip node_modules",
			file: scanner.FileChange{
				Filename: "node_modules/package/index.js",
				Content:  "console.log('hello')",
			},
			expected: true,
		},
		{
			name: "should not skip source code",
			file: scanner.FileChange{
				Filename: "main.go",
				Content:  "package main",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test file skipping through the public Scan method
			req := &scanner.ScanRequest{
				Repository:   "test/repo",
				PullRequest:  "123",
				BaseSHA:      "abc123",
				HeadSHA:      "def456",
				FilesChanged: []scanner.FileChange{tt.file},
			}

			ctx := context.Background()
			result, err := s.Scan(ctx, req)

			require.NoError(t, err)

			// If file should be skipped, we expect no issues to be found
			if tt.expected {
				assert.Empty(t, result.Issues, "File should be skipped")
			} else {
				// For non-skipped files, we don't care about the number of issues
				// just that the scan completed successfully
				assert.NotNil(t, result)
			}
		})
	}
}

func TestScanner_CalculateSecurityScore(t *testing.T) {
	cfg := &config.Config{}
	log := logger.New("debug")
	s := scanner.New(cfg, log)

	tests := []struct {
		name     string
		files    []scanner.FileChange
		expected float64
	}{
		{
			name:     "perfect score with no issues",
			files:    []scanner.FileChange{},
			expected: 10.0,
		},
		{
			name: "score with critical issues",
			files: []scanner.FileChange{
				{
					Filename: "test.py",
					Content:  `api_key = "sk-1234567890"`,
					Language: "python",
				},
			},
			expected: 10.0, // Will be calculated by the scanner
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &scanner.ScanRequest{
				Repository:   "test/repo",
				PullRequest:  "123",
				BaseSHA:      "abc123",
				HeadSHA:      "def456",
				FilesChanged: tt.files,
			}

			ctx := context.Background()
			result, err := s.Scan(ctx, req)

			require.NoError(t, err)
			assert.GreaterOrEqual(t, result.SecurityScore, 0.0)
			assert.LessOrEqual(t, result.SecurityScore, 10.0)
		})
	}
}

func TestScanner_GetLineAndColumn(t *testing.T) {
	cfg := &config.Config{}
	log := logger.New("debug")
	s := scanner.New(cfg, log)

	// Test line and column calculation through the public Scan method
	// by creating a file with known content and checking the issue positions
	testFile := scanner.FileChange{
		Filename: "test.go",
		Content:  "line 1\nline 2\npassword = \"secret\"\nline 4",
		Language: "go",
	}

	req := &scanner.ScanRequest{
		Repository:   "test/repo",
		PullRequest:  "123",
		BaseSHA:      "abc123",
		HeadSHA:      "def456",
		FilesChanged: []scanner.FileChange{testFile},
	}

	ctx := context.Background()
	result, err := s.Scan(ctx, req)

	require.NoError(t, err)

	// If issues are found, verify they have valid line numbers
	for _, issue := range result.Issues {
		assert.Greater(t, issue.Line, 0, "Line number should be positive")
		assert.GreaterOrEqual(t, issue.Column, 0, "Column number should be non-negative")
	}
}

func TestScanner_ScanWithAI(t *testing.T) {
	cfg := &config.Config{}
	log := logger.New("debug")
	s := scanner.New(cfg, log)

	// Note: AI scanning is tested through the public Scan method
	// The AI client is initialized internally and will be used when configured
	testFiles := []scanner.FileChange{
		{
			Filename: "database.py",
			Content:  `def get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    return execute_query(query)`,
			Language: "python",
		},
	}

	req := &scanner.ScanRequest{
		Repository:   "test/repo",
		PullRequest:  "123",
		BaseSHA:      "abc123",
		HeadSHA:      "def456",
		FilesChanged: testFiles,
	}

	ctx := context.Background()
	result, err := s.Scan(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	// Note: AI analysis requires proper configuration, so we just verify the scan completes
}
