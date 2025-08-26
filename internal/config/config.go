package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	// Server configuration
	Port        int    `mapstructure:"PORT"`
	Environment string `mapstructure:"ENVIRONMENT"`
	LogLevel    string `mapstructure:"LOG_LEVEL"`

	// GitHub configuration
	GitHubToken         string `mapstructure:"GITHUB_TOKEN"`
	GitHubWebhookSecret string `mapstructure:"GITHUB_WEBHOOK_SECRET"`

	// AI configuration
	OpenAIApiKey    string `mapstructure:"OPENAI_API_KEY"`
	AnthropicApiKey string `mapstructure:"ANTHROPIC_API_KEY"`
	AIModel         string `mapstructure:"AI_MODEL"`

	// Security configuration
	JWTSecret         string        `mapstructure:"JWT_SECRET"`
	RateLimitRequests int           `mapstructure:"RATE_LIMIT_REQUESTS"`
	RateLimitWindow   time.Duration `mapstructure:"RATE_LIMIT_WINDOW"`

	// Database configuration
	DatabaseURL string `mapstructure:"DATABASE_URL"`

	// Security rules configuration
	SecurityRules SecurityRulesConfig `mapstructure:"SECURITY_RULES"`
}

// SecurityRulesConfig holds configuration for security scanning rules
type SecurityRulesConfig struct {
	Secrets         []SecurityRule `mapstructure:"secrets"`
	APIKeys         []SecurityRule `mapstructure:"api_keys"`
	Vulnerabilities []SecurityRule `mapstructure:"vulnerabilities"`
	CodeQuality     []SecurityRule `mapstructure:"code_quality"`
}

// SecurityRule defines a single security scanning rule
type SecurityRule struct {
	Pattern  string `mapstructure:"pattern"`
	Severity string `mapstructure:"severity"`
	Message  string `mapstructure:"message"`
	Category string `mapstructure:"category"`
}

// Load reads configuration from environment variables and config files
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/codeguardian")

	// Set default values
	setDefaults()

	// Read environment variables
	viper.AutomaticEnv()

	// Read config file if it exists
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	viper.SetDefault("PORT", 8080)
	viper.SetDefault("ENVIRONMENT", "development")
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("AI_MODEL", "gpt-4")
	viper.SetDefault("RATE_LIMIT_REQUESTS", 100)
	viper.SetDefault("RATE_LIMIT_WINDOW", "1m")

	// Set default security rules
	setDefaultSecurityRules()
}

// setDefaultSecurityRules sets default security scanning rules
func setDefaultSecurityRules() {
	defaultRules := map[string]interface{}{
		"SECURITY_RULES": map[string]interface{}{
			"secrets": []map[string]string{
				{
					"pattern":  "password\\s*=\\s*['\"][^'\"]+['\"]",
					"severity": "high",
					"message":  "Hardcoded password detected",
					"category": "secrets",
				},
				{
					"pattern":  "secret\\s*=\\s*['\"][^'\"]+['\"]",
					"severity": "critical",
					"message":  "Secret found in code",
					"category": "secrets",
				},
			},
			"api_keys": []map[string]string{
				{
					"pattern":  "api_key\\s*=\\s*['\"][^'\"]+['\"]",
					"severity": "critical",
					"message":  "API key found in code",
					"category": "api_keys",
				},
				{
					"pattern":  "token\\s*=\\s*['\"][^'\"]+['\"]",
					"severity": "high",
					"message":  "Token found in code",
					"category": "api_keys",
				},
			},
			"vulnerabilities": []map[string]string{
				{
					"pattern":  "eval\\s*\\(",
					"severity": "high",
					"message":  "Dangerous eval() function detected",
					"category": "vulnerabilities",
				},
				{
					"pattern":  "exec\\s*\\(",
					"severity": "high",
					"message":  "Dangerous exec() function detected",
					"category": "vulnerabilities",
				},
				{
					"pattern":  "SELECT.*WHERE.*\\+",
					"severity": "high",
					"message":  "Potential SQL injection detected",
					"category": "vulnerabilities",
				},
			},
			"code_quality": []map[string]string{
				{
					"pattern":  "Math\\.random\\(\\)",
					"severity": "medium",
					"message":  "Insecure random number generation",
					"category": "code_quality",
				},
				{
					"pattern":  "md5\\s*\\(",
					"severity": "medium",
					"message":  "Weak MD5 hash function used",
					"category": "code_quality",
				},
			},
		},
	}

	for key, value := range defaultRules {
		viper.SetDefault(key, value)
	}
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", config.Port)
	}

	if config.GitHubToken == "" {
		return fmt.Errorf("GITHUB_TOKEN is required")
	}

	if config.OpenAIApiKey == "" && config.AnthropicApiKey == "" {
		return fmt.Errorf("either OPENAI_API_KEY or ANTHROPIC_API_KEY is required")
	}

	if config.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET is required")
	}

	if config.RateLimitRequests <= 0 {
		return fmt.Errorf("RATE_LIMIT_REQUESTS must be positive")
	}

	if config.RateLimitWindow <= 0 {
		return fmt.Errorf("RATE_LIMIT_WINDOW must be positive")
	}

	return nil
}

// GetRateLimitWindow returns the rate limit window as a time.Duration
func (c *Config) GetRateLimitWindow() time.Duration {
	if c.RateLimitWindow == 0 {
		// Parse from string if not already parsed
		if windowStr := viper.GetString("RATE_LIMIT_WINDOW"); windowStr != "" {
			if duration, err := time.ParseDuration(windowStr); err == nil {
				return duration
			}
		}
		return time.Minute // default
	}
	return c.RateLimitWindow
}

// IsProduction returns true if the environment is production
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// GetAIModel returns the configured AI model
func (c *Config) GetAIModel() string {
	if c.AIModel == "" {
		return "gpt-4"
	}
	return c.AIModel
}

// GetLogLevel returns the configured log level
func (c *Config) GetLogLevel() string {
	if c.LogLevel == "" {
		return "info"
	}
	return c.LogLevel
}
