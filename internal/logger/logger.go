package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus.Logger to provide a consistent logging interface
type Logger struct {
	*logrus.Logger
}

// New creates a new logger instance with the specified log level
func New(level string) *Logger {
	logger := logrus.New()

	// Set log level
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)

	// Set output to stdout
	logger.SetOutput(os.Stdout)

	// Set formatter for structured logging
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	return &Logger{Logger: logger}
}

// WithField adds a field to the logger
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{Logger: l.Logger.WithField(key, value).Logger}
}

// WithFields adds multiple fields to the logger
func (l *Logger) WithFields(fields logrus.Fields) *Logger {
	return &Logger{Logger: l.Logger.WithFields(fields).Logger}
}

// WithError adds an error field to the logger
func (l *Logger) WithError(err error) *Logger {
	return &Logger{Logger: l.Logger.WithError(err).Logger}
}

// WithContext adds context fields to the logger
func (l *Logger) WithContext(ctx map[string]interface{}) *Logger {
	return &Logger{Logger: l.Logger.WithFields(ctx).Logger}
}

// LogScanStart logs the start of a security scan
func (l *Logger) LogScanStart(repository, pullRequest string, baseSHA, headSHA string) {
	l.WithFields(logrus.Fields{
		"repository":   repository,
		"pull_request": pullRequest,
		"base_sha":     baseSHA,
		"head_sha":     headSHA,
		"action":       "scan_start",
	}).Logger.Info("Starting security scan")
}

// LogScanComplete logs the completion of a security scan
func (l *Logger) LogScanComplete(repository, pullRequest string, issuesFound int, duration float64) {
	l.WithFields(logrus.Fields{
		"repository":   repository,
		"pull_request": pullRequest,
		"issues_found": issuesFound,
		"duration":     duration,
		"action":       "scan_complete",
	}).Logger.Info("Security scan completed")
}

// LogSecurityIssue logs a detected security issue
func (l *Logger) LogSecurityIssue(repository, pullRequest, file, line, severity, message string) {
	l.WithFields(logrus.Fields{
		"repository":   repository,
		"pull_request": pullRequest,
		"file":         file,
		"line":         line,
		"severity":     severity,
		"message":      message,
		"action":       "security_issue",
	}).Logger.Warn("Security issue detected")
}

// LogAIAnalysis logs AI analysis events
func (l *Logger) LogAIAnalysis(repository, pullRequest, model string, tokensUsed int, duration float64) {
	l.WithFields(logrus.Fields{
		"repository":   repository,
		"pull_request": pullRequest,
		"model":        model,
		"tokens_used":  tokensUsed,
		"duration":     duration,
		"action":       "ai_analysis",
	}).Logger.Info("AI analysis completed")
}

// LogGitHubWebhook logs GitHub webhook events
func (l *Logger) LogGitHubWebhook(eventType, repository, action string) {
	l.WithFields(logrus.Fields{
		"event_type": eventType,
		"repository": repository,
		"action":     action,
		"webhook":    "github",
	}).Logger.Info("GitHub webhook received")
}

// LogError logs an error with context
func (l *Logger) LogError(err error, context map[string]interface{}) {
	l.WithError(err).WithFields(context).Logger.Error("Error occurred")
}

// LogWarning logs a warning with context
func (l *Logger) LogWarning(message string, context map[string]interface{}) {
	l.WithFields(context).Logger.Warn(message)
}

// LogInfo logs an info message with context
func (l *Logger) LogInfo(message string, context map[string]interface{}) {
	l.WithFields(context).Logger.Info(message)
}

// LogDebug logs a debug message with context
func (l *Logger) LogDebug(message string, context map[string]interface{}) {
	l.WithFields(context).Logger.Debug(message)
}
