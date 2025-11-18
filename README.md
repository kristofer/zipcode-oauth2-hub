# ZipCode Wilmington OAuth2 Hub

**ZipCode OAuth2 Hub** is a production-ready OAuth2/OpenID Connect authentication and authorization microservice designed specifically for educational environments. Built with Go and Keycloak, it provides secure single sign-on (SSO), fine-grained authorization policies, and educational-specific access controls for ZipCode Wilmington's ecosystem of productivity applications.

Currently, it uses generic Linux production host. It needs to change to:

- use a AWS EC2 host
- use a postgres database on a non-standard port
- use CADDY as reverse-proxy instead of nginx
- _kyounger, Nov 2025_

## 🎯 Overview

The ZipCode OAuth2 Hub enables educational applications to:
- **Authenticate students and instructors** with industry-standard OAuth2 flows
- **Authorize access** with cohort-based and time-sensitive permissions
- **Manage educational policies** including exam windows and submission deadlines
- **Secure APIs** with JWT-based token authentication and custom authorization policies
- **Scale seamlessly** across multiple educational applications and services
- **Support educational workflows** with instructor, student, and admin role management

## 📚 Documentation

### For Developers
- **[Client Integration Guide](./CLIENT_INTEGRATION_GUIDE.md)** ⭐ - Complete guide for integrating your application
- **[Getting Started](./GETTING_STARTED.md)** - Quick start integration examples
- **[Example Apps](./examples/)** - Working example applications for students and instructors
- **[API Specification](./API_SPECIFICATION.md)** - Complete API reference with examples

### For Administrators
- **[Administrator Guide](./AdminGuide/)** ⭐ - Complete administrator documentation
- **[Keycloak User Setup](./AdminGuide/KEYCLOAK_USER_SETUP.md)** - User management and configuration guide

### Core Documentation
- **[OAuth2 Architecture](./OAUTH2_ARCHITECTURE.md)** - System architecture and educational-specific design
- **[Deployment Guide](./DEPLOYMENT_GUIDE.md)** - Production deployment instructions
- **[Security Best Practices](./SECURITY_BEST_PRACTICES.md)** - Security guidelines for educational environments
- **[Configuration Reference](./CONFIGURATION.md)** - Complete configuration guide
- **[Documentation Index](./DOCUMENTATION_INDEX.md)** - Complete documentation catalog

## 🏗️ Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Student Portal │     │ Instructor App  │     │  Admin Panel    │
│   (React SPA)   │     │  (Web/Mobile)   │     │   (Dashboard)   │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┴───────────────────────┘
                                 │ OAuth2/OIDC + JWT
                        ┌────────▼────────┐
                        │   API Gateway   │
                        │ (JWT Validation │
                        │ & Policy Engine)│
                        └────────┬────────┘
                                 │
         ┌───────────────────────┴───────────────────────┐
         │                                               │
┌────────▼────────┐                             ┌────────▼────────┐
│  Auth Server    │                             │  Resource APIs  │
│  (Keycloak)     │◄─── JWKS ────────────────── │   (Protected)   │
│ • User Management│                             │ • Assignments   │
│ • Role Assignment│                             │ • Submissions   │
│ • Realm Config   │                             │ • Cohort Data   │
└────────┬────────┘                             └─────────────────┘
         │
┌────────▼────────┐     ┌─────────────────┐     ┌─────────────────┐
│  User Database  │     │  Session Store  │     │ Policy Cache    │
│   (PostgreSQL)  │     │    (Redis)      │     │    (Redis)      │
│ • Students      │     │ • Sessions      │     │ • Auth Decisions│
│ • Instructors   │     │ • Refresh Tokens│     │ • Cohort Rules  │
│ • Cohort Data   │     │ • Rate Limits   │     │ • Time Policies │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## ✨ Features

### Authentication
- ✅ Student and instructor user management
- ✅ Password-based authentication with secure hashing
- ✅ Single Sign-On (SSO) across all productivity applications
- ✅ OAuth2/OIDC compliant authentication flows
- ✅ PKCE support for public clients (SPAs)
- ✅ Session management with Redis caching
- ✅ JWT token validation and refresh

### OAuth2 Flows
- ✅ Authorization Code Flow (with PKCE)
- ✅ Client Credentials Flow
- ✅ Refresh Token Flow
- ✅ Resource Owner Password Flow (legacy support)

### Educational Authorization
- ✅ **Cohort-Based Access Control** - Students can only access their cohort resources
- ✅ **Time-Based Restrictions** - Exam windows and lab hour enforcement  
- ✅ **Submission Policies** - Assignment deadline and attempt limit enforcement
- ✅ **Role-Based Access Control (RBAC)** with instructor, student, and admin roles
- ✅ **Custom Policy Engine** for educational-specific authorization rules
- ✅ **Redis caching** for high-performance authorization decisions

### Security & Performance
- ✅ JWT tokens with RS256 signing via Keycloak
- ✅ PKCE for public clients
- ✅ Rate limiting and DDoS protection
- ✅ Comprehensive audit logging
- ✅ Go-based implementation for high performance
- ✅ Educational environment security best practices

### Administration
- ✅ Keycloak-based user and client management
- ✅ Cohort assignment and management
- ✅ Educational policy configuration
- ✅ System monitoring and health checks
- ✅ Audit log access and reporting

## Project Structure

```
zipcode-oauth2-hub/
├── cmd/
│   ├── gateway/          # API Gateway with JWT validation
│   └── resource-server/  # Protected resource server
├── pkg/
│   ├── auth/            # Authentication utilities
│   ├── authorization/   # Policy engine and custom policies
│   └── client/          # OAuth2 client SDK
├── config/
│   ├── docker/          # Docker Compose configurations
│   └── keycloak/        # Keycloak realm and client configs
├── examples/
│   ├── productivity-app1/  # Example student portal app
│   └── productivity-app2/  # Example instructor app
├── scripts/             # Deployment and utility scripts
└── docs/               # Additional documentation
```

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- Docker and Docker Compose  
- Make (recommended for easier commands)
- Git (for cloning the repository)

### Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/zipcodewilmington/oauth2-hub.git
cd oauth2-hub
```

#### 2. Quick Setup with Make
```bash
# Complete setup in one command
make setup         # Install dependencies and create .env
make docker-up     # Start all infrastructure services
make dev          # Run gateway + example app (in parallel)
```

#### 3. Manual Setup (Alternative)

**Start Infrastructure Services:**
```bash
# Start Keycloak, PostgreSQL, and Redis
cd config/docker
docker-compose up -d

# Wait for services to be ready (takes ~30 seconds)
docker-compose logs -f keycloak  # Monitor startup
```

**Configure Environment:**
```bash
# Copy and customize environment configuration
cp .env.example .env
# Edit .env with your specific settings if needed
```

**Install Dependencies:**
```bash
go mod download
```

### 4. Verify Installation

**Check Services:**
- **Keycloak Admin Console:** <http://localhost:8080> (admin/admin)
- **API Gateway Health:** <http://localhost:8081/health>
- **Student Portal Example:** <http://localhost:3000>

**Test Authentication Flow:**
1. Visit the student portal at <http://localhost:3000>
2. Click "Login with ZipCode SSO"  
3. Use default test credentials or create new user in Keycloak
4. Verify successful authentication and dashboard access

### 5. Run Individual Components

**API Gateway:**
```bash
# From project root
go run cmd/gateway/main.go
# Gateway available at http://localhost:8081
```

**Example Student Portal:**
```bash
# In a new terminal
cd examples/productivity-app1
go run main.go
# Student portal available at http://localhost:3000
```

**Example Instructor App:**
```bash
cd examples/productivity-app2  
go run main.go
# Instructor app available at http://localhost:3001
```

## 📖 API Examples

### Health Check
```bash
curl -X GET http://localhost:8081/health
```

### Get User Information (Protected)
```bash
curl -X GET http://localhost:8081/api/user/info \
  -H "Authorization: Bearer <access_token>"
```

### OAuth2 Authorization Flow
```bash
# Step 1: Redirect user to authorization endpoint
GET /realms/zipcodewilmington/protocol/openid-connect/auth?
  client_id=productivity-app-frontend&
  redirect_uri=http://localhost:3000/callback&
  response_type=code&
  scope=openid+profile+email&
  state=random_state&
  code_challenge=CHALLENGE&
  code_challenge_method=S256

# Step 2: Exchange authorization code for tokens
POST /realms/zipcodewilmington/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=http://localhost:3000/callback&
client_id=productivity-app-frontend&
code_verifier=VERIFIER
```

### Instructor API Examples
```bash
# Get cohorts (instructor only)
curl -X GET http://localhost:8081/api/instructor/cohorts \
  -H "Authorization: Bearer <instructor_token>"

# Get students in cohort
curl -X GET http://localhost:8081/api/instructor/students \
  -H "Authorization: Bearer <instructor_token>"
```

### Student API Examples  
```bash
# Get assignments
curl -X GET http://localhost:8081/api/student/assignments \
  -H "Authorization: Bearer <student_token>"

# Submit assignment
curl -X POST http://localhost:8081/api/student/submissions \
  -H "Authorization: Bearer <student_token>" \
  -H "Content-Type: application/json" \
  -d '{"assignment_id": "1", "content": "My solution"}'
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Keycloak Configuration
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=zipcodewilmington

# Gateway Configuration
GATEWAY_PORT=8081
GATEWAY_HOST=localhost

# Redis Configuration  
REDIS_URL=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0

# Database Configuration (for Keycloak)
DB_HOST=localhost
DB_NAME=keycloak
DB_USER=keycloak
DB_PASSWORD=keycloak_pass

# Application Configuration
CLIENT_ID=productivity-app-frontend
REDIRECT_URI=http://localhost:3000/callback
APP_PORT=3000

# Security Configuration
JWT_ISSUER=http://localhost:8080/realms/zipcodewilmington
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
RATE_LIMIT_REQUESTS_PER_MINUTE=60

# Educational Policy Configuration
EXAM_TIME_BUFFER_MINUTES=5
LAB_HOURS_START=8
LAB_HOURS_END=20
MAX_SUBMISSION_ATTEMPTS=3
ALLOW_LATE_SUBMISSIONS=false
```

See [Configuration Reference](./CONFIGURATION.md) for complete configuration options.

### Custom Authorization Policies

The system includes several built-in policies:

1. **Cohort-Based Access**: Students can only access resources from their assigned cohort
2. **Time-Based Access**: Exams and labs have time window restrictions
3. **Submission Policies**: Assignment deadline and attempt limit enforcement

To add custom policies, modify `pkg/authorization/policy_engine.go`:

```go
func (pe *PolicyEngine) customPolicy(request PolicyRequest) *PolicyDecision {
    // Your custom policy logic here
}
```

## API Gateway Endpoints

### Public Endpoints
- `GET /health` - Health check
- `GET /auth/login` - Initiate OAuth2 login flow

### Protected Endpoints (Require valid JWT)
- `GET /api/user/info` - Get current user information

### Role-Specific Endpoints
- `GET /api/instructor/*` - Instructor-only endpoints
- `GET /api/student/*` - Student-only endpoints  
- `GET /api/admin/*` - Admin-only endpoints

## Client SDK Usage

### Initialize Client
```go
import "github.com/zipcodewilmington/oauth2-hub/pkg/client"

ssoClient := client.NewZipSSOClient(
    "http://localhost:8080/realms/zipcodewilmington",
    "your-client-id",
    "your-client-secret", // Empty for public clients
    "http://localhost:3000/callback",
)
```

### Authorization Code Flow with PKCE
```go
// Generate PKCE challenge
pkce, _ := ssoClient.GeneratePKCE()

// Get authorization URL
authURL := ssoClient.GetAuthURL("state", pkce, []string{"openid", "profile"})

// After callback, exchange code for tokens
tokens, _ := ssoClient.ExchangeCode(ctx, authorizationCode, pkce)
```

### Service-to-Service Authentication
```go
// Client credentials flow
tokens, _ := ssoClient.ClientCredentials(ctx, []string{"api:read"})
```

## Security Considerations

1. **Always use HTTPS in production**
2. **Enable PKCE for all public clients**
3. **Use short-lived access tokens** (15-30 minutes)
4. **Implement token refresh properly**
5. **Store tokens securely** (never in localStorage for SPAs)
6. **Validate JWTs properly** including signature and claims
7. **Implement proper CORS policies**

## Deployment

### Docker Deployment

Build the Gateway image:
```bash
docker build -f cmd/gateway/Dockerfile -t zipcode-oauth-gateway .
```

### Kubernetes Deployment

See `deployments/kubernetes/` for Kubernetes manifests (to be added)

## Development

### Running Tests
```bash
go test ./...
```

### Adding New Productivity Apps

1. Register new client in Keycloak
2. Use the client SDK or implement OAuth2 flow
3. Configure redirect URIs and CORS origins
4. Implement token validation middleware

### Monitoring and Logging

- Gateway access logs include user ID and roles
- Authorization decisions are logged with context
- Failed authentication attempts are tracked
- Integrate with ELK stack for centralized logging

## Troubleshooting

### Common Issues

1. **"Invalid token" errors**
   - Check if Keycloak is running
   - Verify JWKS endpoint is accessible
   - Check token expiration

2. **CORS errors**
   - Add origin to Keycloak client web origins
   - Check gateway CORS middleware

3. **"Cohort mismatch" authorization errors**
   - Verify user's cohortId attribute in Keycloak
   - Check resource cohort attributes

## 📊 Technology Stack

### Core Technologies
- **Language**: Go 1.21+
- **Web Framework**: Gin HTTP web framework
- **Authentication**: Keycloak (OAuth2/OIDC server)
- **Database**: PostgreSQL 15+ (for Keycloak)
- **Cache**: Redis 7+ (sessions, policies, rate limiting)

### Libraries & Dependencies
- **JWT Handling**: `golang-jwt/jwt/v5`, `lestrrat-go/jwx/v2`
- **Database**: `jackc/pgx/v5` (PostgreSQL driver)
- **Redis**: `redis/go-redis/v9`
- **Configuration**: `spf13/viper`, `joho/godotenv`
- **Testing**: `stretchr/testify`

### Infrastructure
- **Containerization**: Docker & Docker Compose
- **Process Management**: Make-based build system
- **Deployment**: Kubernetes (optional)
- **Monitoring**: Health check endpoints, structured logging

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run linting
make lint

# Integration tests (requires running infrastructure)
go test -tags=integration ./tests/integration/...
```

## 📦 Deployment

### Docker Deployment
```bash
# Build gateway image
docker build -f cmd/gateway/Dockerfile -t zipcode-oauth-gateway .

# Run with Docker Compose
make docker-up
```

### Production Deployment
```bash
# Build all binaries
make build

# Deploy to production (customize for your environment)
./bin/gateway
```

See [Deployment Guide](./DEPLOYMENT_GUIDE.md) for detailed production deployment instructions.

## 🛡️ Security

The ZipCode OAuth2 Hub implements educational environment security best practices:

- **OAuth 2.0 RFC 6749** compliant
- **PKCE** (RFC 7636) for public clients
- **JWT** with RS256 signing via Keycloak
- **TLS 1.2+** encryption in production
- **Rate limiting** and DDoS protection
- **Educational-specific policies** for time-based and cohort-based access
- **Comprehensive audit logging**

See [Security Best Practices](./SECURITY_BEST_PRACTICES.md) for detailed security guidelines.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`make test`)
6. Submit a pull request

See [Contributing Guide](./CONTRIBUTING.md) for detailed guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- **Getting Started Guide**: [GETTING_STARTED.md](./GETTING_STARTED.md)
- **Complete Documentation Index**: [DOCUMENTATION_INDEX.md](./DOCUMENTATION_INDEX.md)
- **FAQ**: [FAQ.md](./FAQ.md)

### Technical Support
- **Issues**: [GitHub Issues](https://github.com/zipcodewilmington/oauth2-hub/issues)
- **Security Issues**: Email security@zipcodewilmington.edu
- **General Questions**: Contact the ZipCode Wilmington IT team

## 🙏 Acknowledgments

Built for educational excellence at ZipCode Wilmington using:
- OAuth 2.0 and OpenID Connect standards
- Keycloak identity and access management
- Go ecosystem and community
- Educational security best practices

---

**Status**: Production Ready  
**Version**: 1.0.0  
**Last Updated**: 2025-11-18

**Ready to secure your educational applications!** 🚀
