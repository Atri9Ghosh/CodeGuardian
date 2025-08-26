package integration

import (
	"context"
	"testing"

	"github.com/codeguardian/codeguardian/internal/config"
	"github.com/codeguardian/codeguardian/internal/logger"
	"github.com/codeguardian/codeguardian/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScannerIntegration(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		Environment: "test",
		LogLevel:    "debug",
		SecurityRules: config.SecurityRulesConfig{
			Secrets: []config.SecurityRule{
				{
					Pattern:  "password\\s*=\\s*['\"][^'\"]+['\"]",
					Severity: "high",
					Message:  "Hardcoded password detected",
					Category: "secrets",
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
			Content:  `password = "secret123"`,
			Language: "python",
		},
		{
			Filename: "main.go",
			Content:  `func main() {\n    dbPassword := "admin123"\n}`,
			Language: "go",
		},
	}

	// Perform scan
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
	assert.NotEmpty(t, result.Issues, "Should detect security issues")

	// Verify scan metadata
	assert.Equal(t, "test/repo", result.Repository)
	assert.Equal(t, "123", result.PullRequest)
	assert.Greater(t, result.Duration, 0.0)
	assert.GreaterOrEqual(t, result.SecurityScore, 0.0)
	assert.LessOrEqual(t, result.SecurityScore, 10.0)
}
