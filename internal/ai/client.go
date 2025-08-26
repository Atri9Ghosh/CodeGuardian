package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/codeguardian/codeguardian/internal/config"
	"github.com/codeguardian/codeguardian/internal/logger"
	"github.com/codeguardian/codeguardian/internal/metrics"
	"github.com/sashabaranov/go-openai"
)

// Client represents an AI client for security analysis
type Client struct {
	config *config.Config
	logger *logger.Logger
	openai *openai.Client
}

// SecurityAnalysis represents the result of AI security analysis
type SecurityAnalysis struct {
	Findings []SecurityFinding `json:"findings"`
	Summary  string            `json:"summary"`
	Score    float64           `json:"score"`
}

// SecurityFinding represents a single security finding from AI analysis
type SecurityFinding struct {
	Type           string  `json:"type"`
	Severity       string  `json:"severity"`
	Category       string  `json:"category"`
	Description    string  `json:"description"`
	Line           int     `json:"line"`
	Column         int     `json:"column"`
	Code           string  `json:"code"`
	Confidence     float64 `json:"confidence"`
	Recommendation string  `json:"recommendation"`
}

// NewClient creates a new AI client
func NewClient(cfg *config.Config) *Client {
	var openaiClient *openai.Client
	if cfg.OpenAIApiKey != "" {
		openaiClient = openai.NewClient(cfg.OpenAIApiKey)
	}

	return &Client{
		config: cfg,
		openai: openaiClient,
	}
}

// AnalyzeSecurity performs AI-powered security analysis on the provided code
func (c *Client) AnalyzeSecurity(ctx context.Context, codeContext string) (*SecurityAnalysis, error) {
	// Prepare the prompt for security analysis
	prompt := c.buildSecurityAnalysisPrompt(codeContext)

	// Use OpenAI for analysis
	if c.openai != nil {
		return c.analyzeWithOpenAI(ctx, prompt)
	}

	// Fallback to Anthropic if configured
	if c.config.AnthropicApiKey != "" {
		return c.analyzeWithAnthropic(ctx, prompt)
	}

	return nil, fmt.Errorf("no AI provider configured")
}

// analyzeWithOpenAI performs security analysis using OpenAI
func (c *Client) analyzeWithOpenAI(ctx context.Context, prompt string) (*SecurityAnalysis, error) {
	startTime := time.Now()

	resp, err := c.openai.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model: c.config.GetAIModel(),
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: "You are a security expert specializing in code security analysis. Analyze the provided code for security vulnerabilities, secrets, and best practices.",
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
			Temperature: 0.1,
			MaxTokens:   2000,
		},
	)

	if err != nil {
		metrics.RecordAICall(c.config.GetAIModel(), "error", 0)
		return nil, fmt.Errorf("OpenAI API error: %w", err)
	}

	// Parse the response
	analysis, err := c.parseAIResponse(resp.Choices[0].Message.Content)
	if err != nil {
		metrics.RecordAICall(c.config.GetAIModel(), "parse_error", resp.Usage.TotalTokens)
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	// Record metrics
	duration := time.Since(startTime).Seconds()
	metrics.RecordAICall(c.config.GetAIModel(), "success", resp.Usage.TotalTokens)
	c.logger.LogAIAnalysis("", "", c.config.GetAIModel(), resp.Usage.TotalTokens, duration)

	return analysis, nil
}

// analyzeWithAnthropic performs security analysis using Anthropic Claude
func (c *Client) analyzeWithAnthropic(ctx context.Context, prompt string) (*SecurityAnalysis, error) {
	// This would be implemented when Anthropic Go SDK is available
	// For now, return an error
	return nil, fmt.Errorf("Anthropic analysis not yet implemented")
}

// buildSecurityAnalysisPrompt builds the prompt for security analysis
func (c *Client) buildSecurityAnalysisPrompt(codeContext string) string {
	return fmt.Sprintf(`Please analyze the following code for security vulnerabilities, secrets, and security best practices.

Code to analyze:
%s

Please provide your analysis in the following JSON format:
{
  "findings": [
    {
      "type": "vulnerability|secret|code_quality",
      "severity": "critical|high|medium|low",
      "category": "injection|authentication|authorization|secrets|encryption|etc",
      "description": "Detailed description of the issue",
      "line": 123,
      "column": 45,
      "code": "The problematic code snippet",
      "confidence": 0.95,
      "recommendation": "How to fix this issue"
    }
  ],
  "summary": "Overall security assessment",
  "score": 7.5
}

Focus on:
1. Hardcoded secrets, passwords, API keys
2. SQL injection vulnerabilities
3. XSS vulnerabilities
4. Command injection
5. Insecure authentication/authorization
6. Weak encryption or hashing
7. Input validation issues
8. Path traversal vulnerabilities
9. Insecure deserialization
10. Code quality security issues

Be thorough but avoid false positives. Only report issues you are confident about.`, codeContext)
}

// parseAIResponse parses the AI response into a SecurityAnalysis struct
func (c *Client) parseAIResponse(response string) (*SecurityAnalysis, error) {
	// Clean up the response - extract JSON if it's wrapped in markdown
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")

	if jsonStart == -1 || jsonEnd == -1 {
		return nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]

	var analysis SecurityAnalysis
	if err := json.Unmarshal([]byte(jsonStr), &analysis); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Validate and clean up the analysis
	c.validateAnalysis(&analysis)

	return &analysis, nil
}

// validateAnalysis validates and cleans up the AI analysis
func (c *Client) validateAnalysis(analysis *SecurityAnalysis) {
	// Ensure score is within bounds
	if analysis.Score < 0 {
		analysis.Score = 0
	}
	if analysis.Score > 10 {
		analysis.Score = 10
	}

	// Validate findings
	var validFindings []SecurityFinding
	for _, finding := range analysis.Findings {
		// Ensure confidence is within bounds
		if finding.Confidence < 0 {
			finding.Confidence = 0
		}
		if finding.Confidence > 1 {
			finding.Confidence = 1
		}

		// Ensure severity is valid
		switch finding.Severity {
		case "critical", "high", "medium", "low":
			// Valid severity
		default:
			finding.Severity = "medium" // Default to medium if invalid
		}

		// Ensure line and column are positive
		if finding.Line < 0 {
			finding.Line = 0
		}
		if finding.Column < 0 {
			finding.Column = 0
		}

		validFindings = append(validFindings, finding)
	}

	analysis.Findings = validFindings
}

// SetLogger sets the logger for the AI client
func (c *Client) SetLogger(logger *logger.Logger) {
	c.logger = logger
}
