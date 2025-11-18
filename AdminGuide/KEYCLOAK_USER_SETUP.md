# Keycloak User Setup Guide for ZipCode OAuth2 Hub

This comprehensive guide covers everything you need to know about setting up users in Keycloak to work with the ZipCode OAuth2 Hub authentication and authorization system for educational environments.

## 📖 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Accessing Keycloak Admin Console](#accessing-keycloak-admin-console)
- [Creating Users](#creating-users)
- [Required User Configuration](#required-user-configuration)
- [Educational Roles and Permissions](#educational-roles-and-permissions)
- [User Attributes for Educational Features](#user-attributes-for-educational-features)
- [Client Scope Configuration](#client-scope-configuration)
- [Example User Configurations](#example-user-configurations)
- [Testing User Access](#testing-user-access)
- [Educational Access Control Rules](#educational-access-control-rules)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting Common Issues](#troubleshooting-common-issues)
- [JWT Token Claims Reference](#jwt-token-claims-reference)
- [Advanced Configuration](#advanced-configuration)

---

## Overview

The ZipCode OAuth2 Hub implements educational-specific authentication and authorization features including:

- **Cohort-based Access Control**: Students can only access resources from their assigned cohort
- **Role-based Permissions**: Different access levels for students, instructors, and administrators
- **Time-based Policies**: Exam windows, assignment deadlines, and lab hours
- **Educational Data Models**: Integration with educational workflows and systems

This guide will walk you through setting up users in Keycloak to leverage all these features.

---

## Prerequisites

Before setting up users, ensure you have:

1. **ZipCode OAuth2 Hub running**: Docker services should be active
2. **Keycloak accessible**: Admin console available at http://localhost:8080/admin
3. **Realm imported**: The `zipcodewilmington` realm should be configured
4. **Admin access**: Credentials to access Keycloak admin console

### Verify Prerequisites

Check if Keycloak is running:
```bash
curl -I http://localhost:8080/admin
```

Expected response: `HTTP/1.1 302 Found` (redirect to admin console)

---

## Accessing Keycloak Admin Console

### Step 1: Open Admin Console
Navigate to: **http://localhost:8080/admin**

### Step 2: Login with Admin Credentials
- **Username**: `admin`
- **Password**: `admin`

### Step 3: Switch to Educational Realm
1. Click the realm dropdown (top-left, probably shows "Master")
2. Select **`zipcodewilmington`** realm
3. Verify you're in the correct realm before proceeding

---

## Creating Users

### Navigate to User Management
1. In the left sidebar, click **`Users`**
2. Click **`Add User`** button
3. Fill in the user creation form

### Basic User Information Required

| Field | Description | Example |
|-------|-------------|---------|
| **Username** | Unique identifier | `student1`, `instructor.smith` |
| **Email** | Valid email address | `student1@zipcodewilmington.edu` |
| **First Name** | User's given name | `John` |
| **Last Name** | User's family name | `Doe` |
| **Email Verified** | Enable this checkbox | ✅ |

### User Creation Process

1. **Fill Basic Info**: Complete all required fields
2. **Save User**: Click `Save` to create the user
3. **Configure Details**: Proceed to detailed configuration tabs

---

## Required User Configuration

After creating a user, configure these essential tabs:

### 1. Attributes Tab (Critical for Educational Features)

Educational users require specific attributes for cohort management and academic workflows:

#### Required Attributes:
```yaml
cohortId: "2024-fall-java"
graduationDate: "2025-05-15"
enrollmentDate: "2024-09-01"
```

#### Adding Attributes:
1. Click **`Attributes`** tab
2. Click **`Add`** for each attribute
3. Enter **Key** and **Value**
4. Click **`Save`**

#### Attribute Descriptions:

| Attribute | Purpose | Example Values |
|-----------|---------|----------------|
| `cohortId` | **REQUIRED** - Cohort assignment for access control | `2024-fall-java`, `2024-spring-python`, `instructor-all` |
| `graduationDate` | Expected graduation date | `2025-05-15` |
| `enrollmentDate` | Program start date | `2024-09-01` |
| `studentId` | Institution student ID | `ZCW2024001` |
| `campus` | Physical location | `wilmington`, `remote` |

### 2. Credentials Tab (Set Password)

1. Click **`Credentials`** tab
2. Enter a **password**
3. **Uncheck** "Temporary" for permanent passwords
4. Click **`Set Password`**

#### Password Recommendations:
- **Development**: Simple passwords like `student123`
- **Production**: Complex passwords with password policy enforcement
- **Enable password reset**: Configure SMTP for forgot password functionality

### 3. Role Mappings Tab (Assign Permissions)

Educational roles determine what users can access:

#### Available Roles:
- **`student`**: Basic access to own cohort resources
- **`instructor`**: Manage assigned cohorts, grade assignments
- **`admin`**: Full system access (includes instructor and student roles)

#### Assigning Roles:
1. Click **`Role Mappings`** tab
2. Select **`Realm Roles`**
3. Choose appropriate roles from **`Available Roles`**
4. Click **`Add selected`**

---

## Educational Roles and Permissions

### Student Role (`student`)
**Access Level**: Own cohort only

**Permitted Actions**:
- View assignments for their cohort
- Submit assignments and projects
- Access course materials
- View grades and feedback
- Participate in cohort discussions

**Restricted From**:
- Other cohorts' resources
- Administrative functions
- Instructor-level features

### Instructor Role (`instructor`)
**Access Level**: Assigned cohorts + instructor functions

**Permitted Actions**:
- Manage multiple cohorts
- Create and grade assignments
- View student submissions
- Access cohort analytics and reports
- Manage course content

**Additional Permissions**:
- Cross-cohort resource access
- Student progress monitoring
- Grade management

### Admin Role (`admin`)
**Access Level**: Full system access

**Permitted Actions**:
- All instructor and student capabilities
- User and cohort management
- System configuration
- Access audit logs
- Manage security policies

**Composite Role**: Automatically includes `instructor` and `student` roles

---

## User Attributes for Educational Features

### Cohort Management

The `cohortId` attribute is **critical** for educational access control:

#### Standard Cohort Format:
```
{academic-year}-{season}-{program}
```

#### Examples:
- `2024-fall-java` - Fall 2024 Java Bootcamp
- `2024-spring-python` - Spring 2024 Python Course
- `2025-summer-fullstack` - Summer 2025 Full Stack Program

#### Special Cohort IDs:
- `instructor-all` - Instructor access to all cohorts
- `admin-all` - Administrative access

### Academic Dates

Date attributes support educational policies and reporting:

#### Date Format: `YYYY-MM-DD`

```yaml
enrollmentDate: "2024-09-01"    # Program start
graduationDate: "2025-05-15"   # Expected completion
withdrawalDate: "2024-12-15"   # If applicable
```

### Extended Attributes (Optional)

For enhanced educational features:

```yaml
# Academic Information
program: "Java Full Stack Development"
track: "accelerated"
status: "active"

# Contact Information  
phoneNumber: "+1-555-0123"
emergencyContact: "Jane Doe: +1-555-0456"

# Institution Data
studentId: "ZCW2024001"
campus: "wilmington"
advisor: "instructor.smith"
```

---

## Client Scope Configuration

Ensure educational attributes are included in JWT tokens:

### Required Mappers

Navigate to **Client Scopes** → **roles** → **Mappers**

#### Cohort ID Mapper
- **Name**: `cohort-id`
- **Mapper Type**: `User Attribute`
- **User Attribute**: `cohortId`
- **Token Claim Name**: `cohortId`
- **Claim JSON Type**: `String`
- **Add to ID token**: ✅
- **Add to access token**: ✅
- **Add to userinfo**: ✅

#### Role Mapper (Should exist by default)
- **Name**: `realm roles`
- **Mapper Type**: `User Realm Role`
- **Multivalued**: ✅
- **Token Claim Name**: `realm_access.roles`

### Verify Mappers

Test that tokens contain required claims:
1. Generate test token
2. Decode JWT at jwt.io
3. Verify `cohortId` and `roles` claims present

---

## Example User Configurations

### Student User Example

```yaml
Basic Information:
  Username: student1
  Email: student1@zipcodewilmington.edu
  First Name: John
  Last Name: Doe
  Email Verified: ✅

Attributes:
  cohortId: "2024-fall-java"
  graduationDate: "2025-05-15"
  enrollmentDate: "2024-09-01"
  studentId: "ZCW2024001"
  program: "Java Full Stack Development"

Role Mappings:
  - student

Credentials:
  Password: student123 (development)
  Temporary: ❌
```

### Instructor User Example

```yaml
Basic Information:
  Username: instructor.smith
  Email: jane.smith@zipcodewilmington.edu
  First Name: Jane
  Last Name: Smith
  Email Verified: ✅

Attributes:
  cohortId: "instructor-all"
  hireDate: "2024-01-15"
  department: "Software Development"
  specialization: "Java, Spring Framework"

Role Mappings:
  - instructor
  - student (optional, for testing)

Credentials:
  Password: instructor123 (development)
  Temporary: ❌
```

### Admin User Example

```yaml
Basic Information:
  Username: admin.wilson
  Email: admin@zipcodewilmington.edu
  First Name: Administrator
  Last Name: Wilson
  Email Verified: ✅

Attributes:
  cohortId: "admin-all"
  role: "system-administrator"
  department: "IT Operations"
  accessLevel: "full"

Role Mappings:
  - admin (automatically includes instructor and student)

Credentials:
  Password: admin123 (development)
  Temporary: ❌
```

### Batch User Creation Script

For creating multiple users, consider this approach:

```bash
# Create multiple students for a cohort
for i in {1..25}; do
  echo "Creating student$i for 2024-fall-java cohort"
  # Use Keycloak Admin REST API or manual creation
done
```

---

## Testing User Access

### Step 1: Start Application Services

Ensure all services are running:
```bash
cd /path/to/zipcode-oauth2-hub
make docker-up
```

### Step 2: Start Productivity App

```bash
cd examples/productivity-app1
go run main.go
```

### Step 3: Test Authentication Flow

1. **Open Application**: http://localhost:3000
2. **Click Login**: "Login with ZipCode SSO" button
3. **Authenticate**: Use created user credentials
4. **Verify Claims**: Check displayed user information

### Step 4: Expected User Info Display

After successful login, verify these details appear:

```
Welcome, John Doe!
Username: student1
Email: student1@zipcodewilmington.edu
Cohort: 2024-fall-java
Roles: student
```

### Step 5: Test API Endpoints

**For Students**:
```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8081/api/student/assignments
```

**For Instructors**:
```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8081/api/instructor/cohorts
```

**For Admins**:
```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8081/api/admin/users
```

---

## Educational Access Control Rules

The OAuth2 Hub enforces these access control policies:

### Cohort-Based Access
- **Students**: Can only access resources tagged with their `cohortId`
- **Cross-cohort access**: Denied by default
- **Resource isolation**: Enforced at API gateway level

### Role-Based Permissions
- **Hierarchical roles**: Admin > Instructor > Student
- **Endpoint protection**: Different APIs for different roles
- **Function-level security**: Method-level authorization

### Time-Based Policies
- **Exam windows**: Students can only access exams during specified times
- **Assignment deadlines**: Automatic submission cutoffs
- **Lab hours**: Resource access limited to campus hours (configurable)

### Policy Examples

#### Cohort Access Policy
```go
// Students can only access their cohort's assignments
if userCohort != resourceCohort {
    return AccessDenied("Cohort mismatch")
}
```

#### Time-Based Exam Policy
```go
// Exams only accessible during exam window
if currentTime < examStart || currentTime > examEnd {
    return AccessDenied("Outside exam window")
}
```

#### Role-Based API Access
```go
// Instructor endpoints require instructor role
if !hasRole("instructor") {
    return AccessDenied("Insufficient permissions")
}
```

---

## Security Best Practices

### Production Password Policies

Configure strong password requirements:

1. **Navigate**: Authentication → Password Policy
2. **Configure policies**:
   - Minimum length: 12 characters
   - Require uppercase, lowercase, numbers, symbols
   - Password history: Prevent reuse of last 5 passwords
   - Maximum age: 90 days

### Account Security

**Enable account protection**:
- **Brute force protection**: Already enabled in realm
- **Account lockout**: After failed attempts
- **Password reset**: Configure SMTP server

**Example Brute Force Settings**:
```yaml
Max Login Failures: 5
Wait Increment: 60 seconds
Max Wait: 900 seconds (15 minutes)
Failure Reset Time: 12 hours
```

### Email Configuration

For password resets and notifications:

1. **Navigate**: Realm Settings → Email
2. **Configure SMTP**:
   ```yaml
   Host: smtp.gmail.com
   Port: 587
   From: noreply@zipcodewilmington.edu
   Enable StartTLS: ✅
   Enable Authentication: ✅
   Username: your-smtp-username
   Password: your-smtp-password
   ```

### SSL/TLS Configuration

**For Production Deployment**:
- Use HTTPS for all Keycloak URLs
- Configure proper SSL certificates
- Enable strict transport security
- Update redirect URIs to use HTTPS

### User Data Privacy

**FERPA Compliance Considerations**:
- Minimize user data collection
- Implement proper data retention policies
- Enable audit logging
- Regular security reviews

---

## Troubleshooting Common Issues

### Issue: "Cohort mismatch" errors

**Symptoms**: Users can't access expected resources

**Diagnosis**:
1. Check user's `cohortId` attribute in Keycloak
2. Verify resource cohort tagging
3. Review access control policies

**Solutions**:
```bash
# Check user attributes
GET /admin/realms/zipcodewilmington/users/{user-id}

# Verify cohortId is set correctly
"attributes": {
    "cohortId": ["2024-fall-java"]
}
```

### Issue: "Insufficient permissions" errors

**Symptoms**: Access denied despite expected roles

**Diagnosis**:
1. Check role assignments in Keycloak
2. Verify JWT token contains correct roles
3. Review API endpoint role requirements

**Solutions**:
- Ensure roles are assigned in `Role Mappings` tab
- Check client scope includes role mapper
- Verify composite roles include expected sub-roles

### Issue: User claims missing from JWT

**Symptoms**: Application doesn't display user attributes

**Diagnosis**:
1. Decode JWT token at jwt.io
2. Check if `cohortId` claim is present
3. Verify client scope mappers

**Solutions**:
1. **Add User Attribute Mapper**:
   - Client Scopes → roles → Mappers → Create
   - Mapper Type: User Attribute
   - User Attribute: cohortId
   - Token Claim Name: cohortId

### Issue: Login redirect fails

**Symptoms**: "Invalid redirect URI" error

**Diagnosis**:
1. Check client configuration in Keycloak
2. Verify redirect URIs match application URLs
3. Ensure protocol (http/https) matches

**Solutions**:
1. **Update Client Redirect URIs**:
   - Clients → productivity-app-frontend → Settings
   - Valid Redirect URIs: `http://localhost:3000/*`
   - Web Origins: `http://localhost:3000`

### Issue: Session timeouts

**Symptoms**: Users frequently logged out

**Diagnosis**:
1. Check session timeout settings
2. Review token lifespans
3. Verify refresh token configuration

**Solutions**:
1. **Adjust Session Settings**:
   - Realm Settings → Sessions
   - SSO Session Idle: 30 minutes
   - SSO Session Max: 10 hours
   - Access Token Lifespan: 15 minutes

### Issue: CORS errors in browser

**Symptoms**: Cross-origin request failures

**Solutions**:
1. **Update Client Web Origins**:
   - Add application domains to Web Origins
   - Include development URLs: `http://localhost:3000`
   - For production: Add actual domain

### Debugging Tools

**Check User Token**:
```bash
# Get token for user
curl -d "client_id=productivity-app-frontend" \
     -d "username=student1" \
     -d "password=student123" \
     -d "grant_type=password" \
     http://localhost:8080/realms/zipcodewilmington/protocol/openid-connect/token
```

**Decode Token**:
- Copy `access_token` from response
- Paste into https://jwt.io
- Verify claims in payload

**Check User Info**:
```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8080/realms/zipcodewilmington/protocol/openid-connect/userinfo
```

---

## JWT Token Claims Reference

After successful configuration, JWT tokens will contain these claims:

### Standard Claims
```json
{
  "iss": "http://localhost:8080/realms/zipcodewilmington",
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "aud": "productivity-app-frontend",
  "exp": 1638360000,
  "iat": 1638356400,
  "auth_time": 1638356400
}
```

### User Information Claims
```json
{
  "preferred_username": "student1",
  "given_name": "John",
  "family_name": "Doe", 
  "name": "John Doe",
  "email": "student1@zipcodewilmington.edu",
  "email_verified": true
}
```

### Educational Claims
```json
{
  "cohortId": "2024-fall-java",
  "realm_access": {
    "roles": ["student"]
  },
  "resource_access": {
    "productivity-app-frontend": {
      "roles": ["user"]
    }
  }
}
```

### Custom Attribute Claims
```json
{
  "graduationDate": "2025-05-15",
  "enrollmentDate": "2024-09-01", 
  "studentId": "ZCW2024001",
  "program": "Java Full Stack Development"
}
```

---

## Advanced Configuration

### Bulk User Import

For importing many users at once:

#### 1. Prepare JSON Import File
```json
{
  "realm": "zipcodewilmington",
  "users": [
    {
      "username": "student1",
      "email": "student1@zipcodewilmington.edu",
      "firstName": "John",
      "lastName": "Doe",
      "emailVerified": true,
      "enabled": true,
      "attributes": {
        "cohortId": ["2024-fall-java"],
        "enrollmentDate": ["2024-09-01"],
        "graduationDate": ["2025-05-15"]
      },
      "realmRoles": ["student"],
      "credentials": [{
        "type": "password",
        "value": "student123",
        "temporary": false
      }]
    }
  ]
}
```

#### 2. Import via Admin Console
1. **Navigate**: Import
2. **Select file**: Upload JSON file
3. **Choose strategy**: Skip existing or overwrite
4. **Import**: Execute import

#### 3. Import via CLI
```bash
# Export current realm first (backup)
docker exec zipcode-keycloak /opt/keycloak/bin/kc.sh export \
  --dir /tmp --realm zipcodewilmington

# Import users
docker exec zipcode-keycloak /opt/keycloak/bin/kc.sh import \
  --file /path/to/users.json
```

### Custom Authentication Flows

For educational-specific authentication:

#### 1. Create Custom Flow
1. **Navigate**: Authentication → Flows
2. **Copy existing flow**: Browser
3. **Modify**: Add educational validations

#### 2. Educational Validations
- **Enrollment status check**: Verify student is enrolled
- **Academic period validation**: Check if in active semester
- **Campus location**: Restrict access by location

### Integration with Student Information Systems

#### LDAP/Active Directory Integration
1. **Navigate**: User Federation → Add LDAP
2. **Configure connection**: Point to institutional LDAP
3. **Map attributes**: cohortId from LDAP groups
4. **Sync users**: Import existing students/staff

#### SCIM Protocol Support
For automated user provisioning:
- Enable SCIM endpoints in Keycloak
- Configure SIS to push user updates
- Map educational attributes automatically

### Reporting and Analytics

#### User Access Reports
```bash
# Export user access logs
docker exec zipcode-keycloak /opt/keycloak/bin/kc.sh \
  export --dir /tmp --realm zipcodewilmington \
  --users-per-file 500
```

#### Cohort Analytics
- Track login patterns by cohort
- Monitor assignment access
- Generate completion reports

---

## Quick Reference

### Essential User Attributes
| Attribute | Required | Purpose | Example |
|-----------|----------|---------|---------|
| `cohortId` | ✅ | Access control | `2024-fall-java` |
| `enrollmentDate` | ❌ | Academic tracking | `2024-09-01` |
| `graduationDate` | ❌ | Program planning | `2025-05-15` |

### Role Hierarchy
```
admin (full access)
  ├── instructor (cohort management)
  └── student (own cohort only)
```

### Default URLs
- **Keycloak Admin**: http://localhost:8080/admin
- **API Gateway**: http://localhost:8081
- **Example App**: http://localhost:3000

### Common Commands
```bash
# Start services
make docker-up

# Run example app  
cd examples/productivity-app1 && go run main.go

# Check Keycloak status
curl -I http://localhost:8080/admin
```

---

## Support and Additional Resources

- **ZipCode OAuth2 Hub Documentation**: [../README.md](../README.md)
- **API Documentation**: [../API_SPECIFICATION.md](../API_SPECIFICATION.md)
- **Client Integration Guide**: [../CLIENT_INTEGRATION_GUIDE.md](../CLIENT_INTEGRATION_GUIDE.md)
- **Deployment Guide**: [../DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md)
- **Keycloak Documentation**: https://www.keycloak.org/documentation

For technical support or questions about user setup, please refer to the project documentation or open an issue in the GitHub repository.

---

**Last Updated**: November 18, 2025  
**Version**: 1.0.0  
**Keycloak Version**: 22.0.5