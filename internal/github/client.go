package github

import (
	"context"
	"fmt"
	"strings"

	"github.com/codeguardian/codeguardian/internal/config"
	"github.com/codeguardian/codeguardian/internal/logger"
	"github.com/google/go-github/v57/github"
	"golang.org/x/oauth2"
)

// Client represents a GitHub client
type Client struct {
	config *config.Config
	logger *logger.Logger
	client *github.Client
}

// PullRequest represents a GitHub pull request
type PullRequest struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
	User   string `json:"user"`
	Base   struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo string `json:"repo"`
	} `json:"base"`
	Head struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo string `json:"repo"`
	} `json:"head"`
}

// FileChange represents a file change in a pull request
type FileChange struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
	Language string `json:"language"`
	Status   string `json:"status"`
}

// NewClient creates a new GitHub client
func NewClient(cfg *config.Config, log *logger.Logger) *Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: cfg.GitHubToken},
	)
	tc := oauth2.NewClient(context.Background(), ts)
	client := github.NewClient(tc)

	return &Client{
		config: cfg,
		logger: log,
		client: client,
	}
}

// GetPullRequest retrieves a pull request by number
func (c *Client) GetPullRequest(ctx context.Context, repository string, prNumber int) (*PullRequest, error) {
	owner, repo := c.parseRepository(repository)

	pr, _, err := c.client.PullRequests.Get(ctx, owner, repo, prNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get pull request: %w", err)
	}

	return &PullRequest{
		Number: pr.GetNumber(),
		Title:  pr.GetTitle(),
		Body:   pr.GetBody(),
		State:  pr.GetState(),
		User:   pr.GetUser().GetLogin(),
		Base: struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo string `json:"repo"`
		}{
			Ref:  pr.Base.GetRef(),
			SHA:  pr.Base.GetSHA(),
			Repo: pr.Base.GetRepo().GetFullName(),
		},
		Head: struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo string `json:"repo"`
		}{
			Ref:  pr.Head.GetRef(),
			SHA:  pr.Head.GetSHA(),
			Repo: pr.Head.GetRepo().GetFullName(),
		},
	}, nil
}

// GetFileChanges retrieves the file changes for a pull request
func (c *Client) GetFileChanges(ctx context.Context, repository string, prNumber int) ([]FileChange, error) {
	owner, repo := c.parseRepository(repository)

	// Get the list of files changed in the PR
	files, _, err := c.client.PullRequests.ListFiles(ctx, owner, repo, prNumber, &github.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}

	var fileChanges []FileChange

	for _, file := range files {
		// Skip deleted files
		if file.GetStatus() == "removed" {
			continue
		}

		// Get the file content
		content, err := c.getFileContent(ctx, owner, repo, file.GetSHA())
		if err != nil {
			c.logger.LogWarning("Failed to get file content", map[string]interface{}{
				"file":   file.GetFilename(),
				"error":  err.Error(),
				"status": file.GetStatus(),
			})
			continue
		}

		fileChange := FileChange{
			Filename: file.GetFilename(),
			Content:  content,
			Language: c.detectLanguage(file.GetFilename()),
			Status:   file.GetStatus(),
		}

		fileChanges = append(fileChanges, fileChange)
	}

	return fileChanges, nil
}

// CreateComment creates a comment on a pull request
func (c *Client) CreateComment(ctx context.Context, repository string, prNumber int, comment string) error {
	owner, repo := c.parseRepository(repository)

	commentReq := &github.IssueComment{
		Body: &comment,
	}

	_, _, err := c.client.Issues.CreateComment(ctx, owner, repo, prNumber, commentReq)
	if err != nil {
		return fmt.Errorf("failed to create comment: %w", err)
	}

	c.logger.LogInfo("Comment created successfully", map[string]interface{}{
		"repository":   repository,
		"pull_request": prNumber,
	})

	return nil
}

// getFileContent retrieves the content of a file by its SHA
func (c *Client) getFileContent(ctx context.Context, owner, repo, sha string) (string, error) {
	// For simplicity, we'll use the GitHub API to get the blob content
	// In a production environment, you might want to use git operations directly
	blob, _, err := c.client.Git.GetBlob(ctx, owner, repo, sha)
	if err != nil {
		return "", fmt.Errorf("failed to get blob: %w", err)
	}

	// Decode the content (GitHub returns it base64 encoded)
	content := blob.GetContent()

	return content, nil
}

// detectLanguage detects the programming language based on file extension
func (c *Client) detectLanguage(filename string) string {
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
	case strings.HasSuffix(ext, ".cs"):
		return "csharp"
	case strings.HasSuffix(ext, ".swift"):
		return "swift"
	case strings.HasSuffix(ext, ".kt"):
		return "kotlin"
	case strings.HasSuffix(ext, ".scala"):
		return "scala"
	case strings.HasSuffix(ext, ".sh"):
		return "bash"
	case strings.HasSuffix(ext, ".ps1"):
		return "powershell"
	case strings.HasSuffix(ext, ".sql"):
		return "sql"
	case strings.HasSuffix(ext, ".html"), strings.HasSuffix(ext, ".htm"):
		return "html"
	case strings.HasSuffix(ext, ".css"):
		return "css"
	case strings.HasSuffix(ext, ".scss"), strings.HasSuffix(ext, ".sass"):
		return "scss"
	case strings.HasSuffix(ext, ".json"):
		return "json"
	case strings.HasSuffix(ext, ".xml"):
		return "xml"
	case strings.HasSuffix(ext, ".yaml"), strings.HasSuffix(ext, ".yml"):
		return "yaml"
	case strings.HasSuffix(ext, ".toml"):
		return "toml"
	case strings.HasSuffix(ext, ".ini"):
		return "ini"
	case strings.HasSuffix(ext, ".md"):
		return "markdown"
	case strings.HasSuffix(ext, ".txt"):
		return "text"
	default:
		return "unknown"
	}
}

// parseRepository parses a repository string into owner and repo
func (c *Client) parseRepository(repository string) (owner, repo string) {
	parts := strings.Split(repository, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

// ValidateWebhookSignature validates the GitHub webhook signature
func (c *Client) ValidateWebhookSignature(payload []byte, signature string) error {
	// This would implement webhook signature validation
	// For now, return nil (no validation)
	return nil
}
