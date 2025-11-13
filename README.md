# ZipCode Wilmington OAuth2 Hub

A centralized OAuth2/OpenID Connect authentication and authorization system for ZipCode Wilmington's productivity applications. Built with Go and Keycloak, this system provides secure single sign-on (SSO) and fine-grained authorization policies for educational environments.

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Productivity   │     │  Productivity   │     │  Productivity   │
│     App 1       │     │     App 2       │     │     App 3       │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┴───────────────────────┘
                                 │
                        ┌────────▼────────┐
                        │   API Gateway   │
                        │ (Token Valid.)  │
                        └────────┬────────┘
                                 │
         ┌───────────────────────┴───────────────────────┐
         │                                               │
┌────────▼────────┐                             ┌────────▼────────┐
│  Auth Server    │                             │  Resource APIs  │
│  (Keycloak)     │                             │   (Protected)   │
└────────┬────────┘                             └─────────────────┘
         │
┌────────▼────────┐     ┌─────────────────┐
│  User Database  │     │  Session Store  │
│   (PostgreSQL)  │     │    (Redis)      │
└─────────────────┘     └─────────────────┘
```

## Features

- **Single Sign-On (SSO)** across all productivity applications
- **OAuth2/OIDC** compliant authentication flows
- **PKCE** support for public clients (SPAs)
- **Role-Based Access Control (RBAC)** with instructor, student, and admin roles
- **Fine-grained authorization policies**:
  - Cohort-based access control
  - Time-based restrictions for exams and labs
  - Submission deadline enforcement
- **Go-based implementation** for high performance
- **Redis caching** for authorization decisions
- **Comprehensive audit logging**

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

## Quick Start

### Prerequisites

- Go 1.21 or higher
- Docker and Docker Compose
- Make (optional)

### 1. Start Infrastructure

```bash
# Start Keycloak, PostgreSQL, and Redis
cd config/docker
docker-compose up -d

# Wait for Keycloak to be ready (check http://localhost:8080)
# Default admin credentials: admin/admin
```

### 2. Import Keycloak Configuration

The realm configuration is automatically imported on first startup. If you need to manually import:

1. Access Keycloak Admin Console: http://localhost:8080
2. Login with admin/admin
3. Create new realm by importing `config/keycloak/realm-export.json`

### 3. Run the API Gateway

```bash
# From project root
go mod download
go run cmd/gateway/main.go
```

The gateway will start on http://localhost:8081

### 4. Run Example Productivity App

```bash
# In a new terminal
cd examples/productivity-app1
go run main.go
```

Visit http://localhost:3000 to see the student portal

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Keycloak Configuration
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=zipcodewilmington

# Gateway Configuration
GATEWAY_PORT=8081

# Redis Configuration
REDIS_URL=localhost:6379
REDIS_PASSWORD=

# Example App Configuration
CLIENT_ID=productivity-app-frontend
REDIRECT_URI=http://localhost:3000/callback
APP_PORT=3000
```

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

## License

MIT License - See LICENSE file for details

## Support

For questions or issues:
- Create an issue in the repository
- Contact the ZipCode Wilmington IT team
- Check the docs/ directory for additional guides
