# ZipCode OAuth2 Hub - API Specification

Complete REST API reference documentation for the ZipCode OAuth2 Hub authentication and authorization system.

## 📖 Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Base URLs and Versioning](#base-urls-and-versioning)
- [Common Response Formats](#common-response-formats)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Public Endpoints](#public-endpoints)
- [OAuth2 Endpoints](#oauth2-endpoints)
- [Protected API Endpoints](#protected-api-endpoints)
- [Educational Policy Endpoints](#educational-policy-endpoints)
- [Administrative Endpoints](#administrative-endpoints)
- [Health and Monitoring](#health-and-monitoring)
- [Webhook Support](#webhook-support)

---

## Overview

The ZipCode OAuth2 Hub provides a RESTful API for authentication, authorization, and educational resource management. The API follows OAuth 2.0 and OpenID Connect standards with educational-specific extensions for cohort management and time-based policies.

### Key Features
- OAuth 2.0/OIDC compliant authentication
- JWT-based authorization with educational policies  
- Cohort-based access control
- Time-sensitive exam and lab access
- Role-based permissions (student, instructor, admin)
- Comprehensive audit logging

---

## Authentication

### Supported Flows

#### Authorization Code Flow (with PKCE)
**Recommended for web applications and SPAs**

```http
GET /realms/zipcodewilmington/protocol/openid-connect/auth
  ?client_id=your-client-id
  &redirect_uri=https://yourapp.com/callback
  &response_type=code
  &scope=openid+profile+email
  &state=random-state-value
  &code_challenge=PKCE_CHALLENGE
  &code_challenge_method=S256
```

#### Client Credentials Flow
**For service-to-service authentication**

```http
POST /realms/zipcodewilmington/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=your-service-client
&client_secret=your-secret
&scope=api:read+api:write
```

### JWT Token Format

```json
{
  "sub": "user-id-12345",
  "iss": "http://localhost:8080/realms/zipcodewilmington",
  "aud": "productivity-app-frontend",
  "exp": 1700000000,
  "iat": 1699996400,
  "auth_time": 1699996400,
  "preferred_username": "john.doe",
  "email": "john.doe@zipcodewilmington.edu",
  "email_verified": true,
  "realm_access": {
    "roles": ["student"]
  },
  "cohort_id": "2024-fall-java",
  "enrollment_date": "2024-01-15",
  "graduation_date": "2024-12-15"
}
```

---

## Base URLs and Versioning

### API Gateway
- **Development**: `http://localhost:8081`
- **Production**: `https://auth.zipcodewilmington.edu`

### Keycloak (OAuth2/OIDC)
- **Development**: `http://localhost:8080/realms/zipcodewilmington`
- **Production**: `https://auth.zipcodewilmington.edu/realms/zipcodewilmington`

### API Versioning
- **Current Version**: `v1`
- **Base Path**: `/api/v1`
- **Versioning Strategy**: URL path versioning

---

## Common Response Formats

### Success Response
```json
{
  "success": true,
  "data": {
    // Response data
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req-12345"
}
```

### Error Response
```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or expired token",
    "details": "The provided JWT token has expired",
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req-12345"
  }
}
```

### Pagination
```json
{
  "success": true,
  "data": {
    "items": [...],
    "pagination": {
      "page": 1,
      "per_page": 25,
      "total_items": 150,
      "total_pages": 6,
      "has_next": true,
      "has_previous": false
    }
  }
}
```

---

## Error Handling

### HTTP Status Codes

| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource conflict (duplicate, etc.) |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

### Error Code Reference

```json
{
  "INVALID_TOKEN": "Token is malformed or invalid",
  "EXPIRED_TOKEN": "Token has expired",
  "INSUFFICIENT_SCOPE": "Required scope not granted",
  "COHORT_MISMATCH": "User not authorized for this cohort resource",
  "TIME_RESTRICTION": "Access not allowed at this time",
  "EXAM_NOT_ACTIVE": "Exam is not currently active",
  "SUBMISSION_DEADLINE_PASSED": "Assignment submission deadline has passed",
  "MAX_ATTEMPTS_EXCEEDED": "Maximum submission attempts reached",
  "RATE_LIMIT_EXCEEDED": "Too many requests"
}
```

---

## Rate Limiting

### Limits by Endpoint Type

| Endpoint Type | Requests per Minute | Burst Limit |
|---------------|-------------------|-------------|
| Authentication | 10 | 20 |
| Public API | 60 | 100 |
| Protected API | 120 | 200 |
| Admin API | 30 | 50 |

### Rate Limit Headers
```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1640995200
Retry-After: 60
```

---

## Public Endpoints

### Health Check

#### `GET /health`

Check service health and status.

**Parameters:** None

**Response:**
```json
{
  "status": "healthy",
  "service": "zipcode-oauth2-hub",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "dependencies": {
    "keycloak": "healthy",
    "redis": "healthy",
    "database": "healthy"
  }
}
```

### Service Info

#### `GET /info`

Get service information and capabilities.

**Response:**
```json
{
  "name": "ZipCode OAuth2 Hub",
  "version": "1.0.0",
  "api_version": "v1",
  "oauth2": {
    "issuer": "http://localhost:8080/realms/zipcodewilmington",
    "authorization_endpoint": "/protocol/openid-connect/auth",
    "token_endpoint": "/protocol/openid-connect/token",
    "jwks_uri": "/protocol/openid-connect/certs",
    "supported_flows": ["authorization_code", "client_credentials"]
  },
  "educational_features": [
    "cohort_access_control",
    "time_based_policies", 
    "exam_scheduling",
    "submission_management"
  ]
}
```

---

## OAuth2 Endpoints

All OAuth2/OIDC endpoints are provided by Keycloak. The API Gateway validates tokens issued by Keycloak.

### Authorization Endpoint

#### `GET /realms/zipcodewilmington/protocol/openid-connect/auth`

Initiate OAuth2 authorization flow.

**Parameters:**
- `client_id` (required): Client identifier
- `redirect_uri` (required): Callback URL
- `response_type` (required): `code` for authorization code flow
- `scope` (required): Requested scopes (e.g., `openid profile email`)
- `state` (required): CSRF protection value
- `code_challenge` (optional): PKCE challenge for public clients
- `code_challenge_method` (optional): `S256` for PKCE

### Token Endpoint

#### `POST /realms/zipcodewilmington/protocol/openid-connect/token`

Exchange authorization code for tokens.

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**
- `grant_type`: `authorization_code` or `client_credentials`
- `client_id`: Client identifier
- `client_secret`: Client secret (if confidential client)
- `code`: Authorization code (for authorization code flow)
- `redirect_uri`: Must match authorization request
- `code_verifier`: PKCE verifier (if PKCE used)

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "scope": "openid profile email"
}
```

### User Info Endpoint  

#### `GET /realms/zipcodewilmington/protocol/openid-connect/userinfo`

Get user information using access token.

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "sub": "user-12345",
  "preferred_username": "john.doe", 
  "email": "john.doe@zipcodewilmington.edu",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "cohort_id": "2024-fall-java",
  "enrollment_date": "2024-01-15",
  "roles": ["student"]
}
```

---

## Protected API Endpoints

All API endpoints require valid JWT token in the Authorization header:

```http
Authorization: Bearer <access_token>
```

### User Management

#### `GET /api/v1/user/info`

Get current user's profile information.

**Response:**
```json
{
  "success": true,
  "data": {
    "user_id": "user-12345",
    "username": "john.doe",
    "email": "john.doe@zipcodewilmington.edu",
    "name": "John Doe",
    "roles": ["student"],
    "cohort_id": "2024-fall-java",
    "enrollment_date": "2024-01-15T00:00:00Z",
    "last_login": "2024-01-15T10:25:00Z"
  }
}
```

#### `PUT /api/v1/user/profile`

Update user profile information.

**Request:**
```json
{
  "name": "John Smith",
  "preferred_contact": "email",
  "timezone": "America/New_York"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Profile updated successfully"
  }
}
```

---

## Educational Policy Endpoints

### Student Endpoints

#### `GET /api/v1/student/assignments`

Get assignments for the student's cohort.

**Query Parameters:**
- `status` (optional): Filter by status (`active`, `completed`, `overdue`)
- `subject` (optional): Filter by subject
- `page` (optional): Page number (default: 1)
- `per_page` (optional): Items per page (default: 25)

**Response:**
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": "assignment-123",
        "title": "OAuth2 Implementation Project",
        "description": "Implement OAuth2 authorization server",
        "subject": "Security",
        "cohort_id": "2024-fall-java",
        "due_date": "2024-12-15T23:59:59Z",
        "status": "active",
        "max_attempts": 3,
        "current_attempts": 1,
        "allow_late_submission": false,
        "estimated_hours": 8
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 25,
      "total_items": 15,
      "total_pages": 1,
      "has_next": false,
      "has_previous": false
    }
  }
}
```

#### `POST /api/v1/student/submissions`

Submit an assignment.

**Request:**
```json
{
  "assignment_id": "assignment-123",
  "submission_type": "file_upload",
  "content": {
    "repository_url": "https://github.com/student/oauth2-project",
    "branch": "main",
    "notes": "Implemented all required features"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "submission_id": "submission-456",
    "assignment_id": "assignment-123",
    "status": "submitted",
    "submitted_at": "2024-01-15T10:30:00Z",
    "attempt_number": 2,
    "auto_grade": {
      "score": 85,
      "tests_passed": 17,
      "tests_total": 20
    }
  }
}
```

#### `GET /api/v1/student/exams`

Get available exams for student.

**Response:**
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": "exam-789",
        "title": "Midterm Java Assessment",
        "cohort_id": "2024-fall-java",
        "start_time": "2024-01-20T09:00:00Z",
        "end_time": "2024-01-20T11:00:00Z",
        "duration_minutes": 120,
        "status": "scheduled",
        "attempts_allowed": 1,
        "time_buffer_minutes": 5
      }
    ]
  }
}
```

#### `POST /api/v1/student/exams/{exam_id}/start`

Start an exam (if within time window).

**Response:**
```json
{
  "success": true,
  "data": {
    "exam_session_id": "session-101",
    "exam_id": "exam-789", 
    "started_at": "2024-01-20T09:05:00Z",
    "must_complete_by": "2024-01-20T11:05:00Z",
    "questions": [
      {
        "id": "question-1",
        "type": "multiple_choice",
        "question": "Which OAuth2 flow is recommended for SPAs?",
        "options": [
          "Authorization Code with PKCE",
          "Implicit Flow",
          "Client Credentials",
          "Resource Owner Password"
        ]
      }
    ]
  }
}
```

### Instructor Endpoints

**Required Role:** `instructor`

#### `GET /api/v1/instructor/cohorts`

Get cohorts assigned to instructor.

**Response:**
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": "2024-fall-java",
        "name": "Fall 2024 Java Cohort",
        "start_date": "2024-09-01T00:00:00Z",
        "end_date": "2024-12-15T00:00:00Z",
        "student_count": 24,
        "status": "active"
      }
    ]
  }
}
```

#### `GET /api/v1/instructor/students`

Get students in instructor's cohorts.

**Query Parameters:**
- `cohort_id` (optional): Filter by specific cohort
- `status` (optional): Filter by status (`active`, `graduated`, `withdrawn`)

**Response:**
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "user_id": "user-12345",
        "username": "john.doe",
        "name": "John Doe",
        "email": "john.doe@zipcodewilmington.edu",
        "cohort_id": "2024-fall-java",
        "enrollment_date": "2024-09-01T00:00:00Z",
        "status": "active",
        "progress": {
          "assignments_completed": 8,
          "assignments_total": 12,
          "average_score": 87.5
        }
      }
    ]
  }
}
```

#### `POST /api/v1/instructor/assignments`

Create a new assignment.

**Request:**
```json
{
  "title": "Spring Boot REST API",
  "description": "Create a REST API using Spring Boot",
  "cohort_id": "2024-fall-java",
  "subject": "Web Development",
  "due_date": "2024-02-01T23:59:59Z",
  "max_attempts": 3,
  "allow_late_submission": true,
  "late_penalty_percent": 10,
  "estimated_hours": 6
}
```

#### `GET /api/v1/instructor/submissions`

Get submissions for instructor's assignments.

**Query Parameters:**
- `assignment_id` (optional): Filter by assignment
- `student_id` (optional): Filter by student
- `status` (optional): Filter by status

**Response:**
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "submission_id": "submission-456",
        "assignment_id": "assignment-123", 
        "student_id": "user-12345",
        "student_name": "John Doe",
        "submitted_at": "2024-01-15T10:30:00Z",
        "attempt_number": 2,
        "status": "graded",
        "grade": {
          "score": 85,
          "max_score": 100,
          "feedback": "Good implementation, minor optimization needed"
        }
      }
    ]
  }
}
```

---

## Administrative Endpoints

**Required Role:** `admin`

### User Management

#### `GET /api/v1/admin/users`

Get all users in the system.

**Query Parameters:**
- `role` (optional): Filter by role
- `cohort_id` (optional): Filter by cohort
- `status` (optional): Filter by status

#### `PUT /api/v1/admin/users/{user_id}`

Update user information.

#### `DELETE /api/v1/admin/users/{user_id}`

Deactivate a user account.

### System Management

#### `GET /api/v1/admin/statistics`

Get system statistics and metrics.

**Response:**
```json
{
  "success": true,
  "data": {
    "users": {
      "total": 450,
      "active": 425,
      "students": 380,
      "instructors": 25,
      "admins": 3
    },
    "cohorts": {
      "active": 8,
      "total": 15
    },
    "assignments": {
      "active": 45,
      "completed_this_month": 234
    },
    "system": {
      "uptime_hours": 168,
      "api_requests_today": 15420,
      "error_rate_percent": 0.02
    }
  }
}
```

#### `GET /api/v1/admin/audit-logs`

Get audit logs for compliance and monitoring.

**Query Parameters:**
- `user_id` (optional): Filter by user
- `action` (optional): Filter by action type
- `start_date` (optional): Start date for logs
- `end_date` (optional): End date for logs

---

## Health and Monitoring

### Detailed Health Check

#### `GET /api/v1/health/detailed`

Get detailed health information.

**Response:**
```json
{
  "status": "healthy",
  "checks": {
    "keycloak": {
      "status": "healthy",
      "response_time_ms": 45,
      "last_check": "2024-01-15T10:30:00Z"
    },
    "redis": {
      "status": "healthy", 
      "response_time_ms": 2,
      "connection_pool": {
        "active": 5,
        "idle": 10,
        "max": 20
      }
    },
    "policy_engine": {
      "status": "healthy",
      "cache_hit_rate": 0.94,
      "decisions_per_second": 150
    }
  }
}
```

### Metrics

#### `GET /api/v1/metrics`

Get system metrics (Prometheus format).

```
# HELP api_requests_total Total API requests
# TYPE api_requests_total counter
api_requests_total{method="GET",endpoint="/api/v1/user/info",status="200"} 1245

# HELP jwt_validations_total Total JWT validations
# TYPE jwt_validations_total counter
jwt_validations_total{status="valid"} 9876
jwt_validations_total{status="expired"} 123
jwt_validations_total{status="invalid"} 45
```

---

## Webhook Support

### Webhook Events

The system can send webhooks for various educational events:

- `assignment.submitted`
- `assignment.graded`  
- `exam.started`
- `exam.completed`
- `user.enrolled`
- `cohort.completed`

### Webhook Configuration

#### `POST /api/v1/admin/webhooks`

Configure a new webhook endpoint.

**Request:**
```json
{
  "url": "https://your-app.com/webhooks/zipcode-oauth2",
  "events": ["assignment.submitted", "exam.completed"],
  "secret": "webhook-secret-key",
  "active": true
}
```

### Webhook Payload Example

```json
{
  "event": "assignment.submitted",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "submission_id": "submission-456",
    "assignment_id": "assignment-123",
    "student_id": "user-12345",
    "cohort_id": "2024-fall-java",
    "attempt_number": 2
  }
}
```

---

## SDK and Integration Examples

### JavaScript/TypeScript
```javascript
// OAuth2 client integration
import { ZipCodeOAuth2Client } from '@zipcode/oauth2-client';

const client = new ZipCodeOAuth2Client({
  authUrl: 'http://localhost:8080/realms/zipcodewilmington',
  clientId: 'your-client-id',
  redirectUri: 'http://localhost:3000/callback'
});

// Start authentication
await client.authenticate(['openid', 'profile', 'email']);
```

### Go  
```go
// Using the official Go client SDK
import "github.com/zipcodewilmington/oauth2-hub/pkg/client"

client := client.NewZipSSOClient(
    "http://localhost:8080/realms/zipcodewilmington",
    "your-client-id",
    "",
    "http://localhost:3000/callback",
)

tokens, err := client.ExchangeCode(ctx, authCode, pkceChallenge)
```

---

**API Version**: v1  
**Last Updated**: 2025-11-18  
**Status**: Production Ready

For implementation examples and detailed integration guides, see the [Client Integration Guide](./CLIENT_INTEGRATION_GUIDE.md).