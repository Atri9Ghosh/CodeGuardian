# CodeGuardian 🔒

A security-focused AI DevOps tool that automatically scans pull requests for security vulnerabilities, secrets, and hardcoded credentials using AI-powered analysis. Built with Go, Docker, and modern AI APIs.

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com/)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Ready-green.svg)](https://github.com/features/actions)

## 🚀 Features

- **AI-Powered Security Scanning**: Uses advanced AI models to detect security issues in code changes
- **Secret Detection**: Identifies hardcoded passwords, API keys, tokens, and other sensitive data
- **Vulnerability Analysis**: Scans for common security vulnerabilities and anti-patterns
- **Automated PR Reviews**: Leaves detailed, actionable comments on GitHub pull requests
- **Docker Integration**: Containerized for easy deployment and scaling
- **GitHub Actions**: Seamless integration with CI/CD pipelines

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GitHub PR     │───▶│  CodeGuardian   │───▶│   AI Analysis   │
│                 │    │   (Go Service)  │    │   (OpenAI/Claude)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  PR Comments    │◀───│  Security Rules │    │  Vulnerability  │
│  (Automated)    │    │   Engine        │    │   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🛠️ Tech Stack

- **Backend**: Go (Gin framework)
- **AI Integration**: OpenAI GPT-4 / Anthropic Claude
- **Containerization**: Docker
- **CI/CD**: GitHub Actions
- **Security**: JWT authentication, rate limiting
- **Monitoring**: Structured logging, metrics

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- Docker and Docker Compose
- GitHub Personal Access Token
- OpenAI API Key (or Anthropic API Key)

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/codeguardian.git
   cd codeguardian
   ```

2. **Set up environment variables**
   ```bash
   cp env.example .env
   # Edit .env with your API keys and configuration
   ```

3. **Run with Docker (Recommended)**
   ```bash
   # Build and start the application
   make docker-run
   
   # Or with monitoring (Prometheus + Grafana)
   make docker-run-monitoring
   ```

4. **Or run locally**
   ```bash
   # Install dependencies
   make install
   
   # Run the application
   make run
   ```

5. **Run tests**
   ```bash
   # Run all tests
   make test
   
   # Run with coverage
   make coverage
   ```

### GitHub Actions Setup

1. **Add secrets to your repository**:
   - `CODEGUARDIAN_API_KEY`: Your CodeGuardian API key
   - `GITHUB_TOKEN`: GitHub Personal Access Token

2. **Add the workflow file** to `.github/workflows/codeguardian.yml`

3. **Configure the service** in your repository settings

### Webhook Setup (Optional)

For automatic scanning on pull requests:

1. Go to your repository settings
2. Navigate to Webhooks → Add webhook
3. Set the payload URL to: `https://your-domain.com/api/v1/webhook/github`
4. Set content type to: `application/json`
5. Select events: `Pull requests`
6. Add the webhook secret to your `.env` file

## 📋 Configuration

### Environment Variables

```env
# Server Configuration
PORT=8080
ENVIRONMENT=development
LOG_LEVEL=info

# GitHub Configuration
GITHUB_TOKEN=your_github_token
GITHUB_WEBHOOK_SECRET=your_webhook_secret

# AI Configuration
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
AI_MODEL=gpt-4
AI_MAX_TOKENS=2000
AI_TEMPERATURE=0.1

# Security Configuration
JWT_SECRET=your_jwt_secret
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=1m

# Scan Configuration
MAX_FILE_SIZE=1048576
SCAN_TIMEOUT=300
CONCURRENT_SCANS=5
CONFIDENCE_THRESHOLD=0.7
```

### Security Rules Configuration

The tool uses a configurable rules engine for security scanning. Edit `config/config.yaml`:

```yaml
security_rules:
  secrets:
    - pattern: "password\\s*=\\s*['\"][^'\"]+['\"]"
      severity: "high"
      message: "Hardcoded password detected"
      category: "secrets"
    
  api_keys:
    - pattern: "api_key\\s*=\\s*['\"][^'\"]+['\"]"
      severity: "critical"
      message: "API key found in code"
      category: "api_keys"
    
  vulnerabilities:
    - pattern: "eval\\s*\\("
      severity: "critical"
      message: "Dangerous eval() usage detected"
      category: "code_execution"
    - pattern: "f\"SELECT.*\\{.*\\}\""
      severity: "high"
      message: "Potential SQL injection detected"
      category: "sql_injection"
```

## 🔍 Security Scanning Capabilities

### 1. Secret Detection
- Hardcoded passwords and credentials
- API keys and tokens
- Database connection strings
- Private keys and certificates
- OAuth secrets

### 2. Vulnerability Analysis
- SQL injection patterns
- XSS vulnerabilities
- Command injection
- Insecure deserialization
- Path traversal issues

### 3. Code Quality Security
- Insecure random number generation
- Weak encryption algorithms
- Missing input validation
- Unsafe file operations

### 4. AI-Powered Analysis
- Context-aware security assessment
- False positive reduction
- Custom security rule suggestions
- Code improvement recommendations

## 📊 Example Output

### GitHub PR Comment

```markdown
## 🔒 CodeGuardian Security Scan Results

### ⚠️ High Priority Issues Found

1. **Hardcoded API Key** (Line 45)
   ```python
   api_key = "sk-1234567890abcdef"
   ```
   **Risk**: API key exposed in source code
   **Recommendation**: Use environment variables or secret management

2. **SQL Injection Risk** (Line 78)
   ```python
   query = f"SELECT * FROM users WHERE id = {user_id}"
   ```
   **Risk**: Potential SQL injection vulnerability
   **Recommendation**: Use parameterized queries

### ✅ Security Improvements
- Good use of HTTPS endpoints
- Proper input validation on user data
- Secure session management

### 📈 Overall Security Score: 7.2/10
```

## 🔧 API Endpoints

### Webhook Endpoint
```
POST /api/v1/webhook/github
```
Handles GitHub webhook events for pull request scanning.

### Manual Scan Endpoint
```
POST /api/v1/scan
{
  "repository": "owner/repo",
  "pull_request": 123,
  "base_sha": "abc123",
  "head_sha": "def456"
}
```

### Health Check
```
GET /health
```

### Metrics Endpoint
```
GET /metrics
```
Prometheus metrics for monitoring.

### Configuration Endpoint
```
GET /api/v1/config
```
Returns current configuration status.

## 🧪 Testing

```bash
# Run all tests
make test

# Run unit tests
go test ./tests/unit/...

# Run integration tests
go test ./tests/integration/...

# Run with coverage
make coverage

# Run linting
make lint

# Format code
make fmt
```

## 📈 Monitoring & Metrics

The service exposes Prometheus metrics at `/metrics`:

- `codeguardian_scans_total`: Total number of scans performed
- `codeguardian_issues_found`: Number of security issues detected
- `codeguardian_scan_duration`: Scan duration in seconds
- `codeguardian_ai_api_calls`: Number of AI API calls made
- `codeguardian_github_webhooks`: GitHub webhook events received
- `codeguardian_security_score`: Security scores distribution

### Grafana Dashboards

When running with monitoring, access Grafana at `http://localhost:3000`:
- Username: `admin`
- Password: `admin`

### Logging

The application uses structured logging with configurable levels:
- `debug`: Detailed debugging information
- `info`: General operational information
- `warn`: Warning messages
- `error`: Error messages

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and ensure tests pass (`make test`)
4. Format your code (`make fmt`)
5. Run linting (`make lint`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
# Clone and setup
git clone https://github.com/your-org/codeguardian.git
cd codeguardian

# Install dependencies
make install

# Run tests
make test

# Start development server
make run
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OpenAI for providing the GPT models
- GitHub for the excellent API
- The Go community for amazing tooling
- All contributors and security researchers

---

**Made with ❤️ for secure code**
