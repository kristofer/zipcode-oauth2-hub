# GitHub Authentication Integration Guide

Complete guide for integrating GitHub authentication with the ZipCode OAuth2 Hub to control student access based on GitHub accounts, organization membership, and repository permissions.

## 📖 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [GitHub Organization Setup](#github-organization-setup)
- [GitHub OAuth App Configuration](#github-oauth-app-configuration)
- [Keycloak GitHub Identity Provider](#keycloak-github-identity-provider)
- [Student Access Control](#student-access-control)
- [Automated User Provisioning](#automated-user-provisioning)
- [Team-Based Access Control](#team-based-access-control)
- [Repository-Based Permissions](#repository-based-permissions)
- [Cohort Synchronization](#cohort-synchronization)
- [Administrative Procedures](#administrative-procedures)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

---

## Overview

This integration allows you to:

- **Authenticate students using GitHub accounts** instead of manual user creation
- **Control access based on GitHub organization membership** (e.g., ZipCode Wilmington org)
- **Automatically assign cohorts based on GitHub teams** (e.g., 2024-fall-cohort)
- **Grant repository-based permissions** for specific assignments or projects
- **Synchronize student enrollment** with GitHub organization changes
- **Leverage GitHub's existing access controls** for educational resources

### Benefits

- **Simplified onboarding**: Students use existing GitHub accounts
- **Automatic enrollment**: Join GitHub org = automatic OAuth2 Hub access
- **Granular permissions**: Control access per repository, team, or assignment
- **Real-time synchronization**: Changes in GitHub reflect immediately in OAuth2 Hub
- **Audit trail**: GitHub activity logs provide comprehensive access tracking

---

## Prerequisites

### GitHub Requirements

- **GitHub Organization** (e.g., `zipcodewilmington`)
- **Organization Owner permissions** to configure OAuth Apps and manage members
- **GitHub Teams** set up for different cohorts (e.g., `2024-fall-cohort`, `instructors`)
- **Repository structure** organized by course, assignment, or project

### OAuth2 Hub Requirements

- **Keycloak 22.0+** with admin access
- **ZipCode OAuth2 Hub** deployed and running
- **Network access** from Keycloak to GitHub API (`api.github.com`)
- **SSL/TLS configuration** for production deployments

### Administrative Access

- GitHub Organization Owner/Admin
- Keycloak realm administrator
- OAuth2 Hub system administrator

---

## GitHub Organization Setup

### Create Educational GitHub Organization

If you don't have one already:

```bash
# Organization setup checklist:
# 1. Create organization at https://github.com/organizations/new
# 2. Choose "Education" as organization type
# 3. Apply for GitHub Education benefits
# 4. Configure organization settings
```

### Organization Configuration

```yaml
# Recommended GitHub Organization Settings
Organization Name: ZipCode Wilmington
Username: zipcodewilmington
Email: admin@zipcodewilmington.com

# Security Settings
Two-factor authentication: Required for all members
Member privileges: 
  - Repository creation: Organization owners and admin
  - Repository deletion: Organization owners only
  - Issue deletion: Organization owners and admin

# Member visibility: Private (for student privacy)
# Base permissions: None (explicit permissions only)
```

### Create GitHub Teams for Cohorts

```bash
# Example team structure
zipcodewilmington/
├── instructors              # All instructors
├── admin                   # Administrative staff
├── 2024-fall-cohort        # Fall 2024 students
├── 2024-spring-cohort      # Spring 2024 students
├── 2025-fall-cohort        # Fall 2025 students
└── alumni                  # Graduated students
```

**Creating teams via GitHub CLI:**

```bash
# Install GitHub CLI
gh auth login

# Create cohort teams
gh api orgs/zipcodewilmington/teams \
  --field name='2024-fall-cohort' \
  --field description='Fall 2024 Cohort Students' \
  --field privacy='closed'

gh api orgs/zipcodewilmington/teams \
  --field name='instructors' \
  --field description='Course Instructors' \
  --field privacy='closed'

gh api orgs/zipcodewilmington/teams \
  --field name='admin' \
  --field description='Administrative Staff' \
  --field privacy='closed'
```

### Repository Organization

```bash
# Example repository structure
zipcodewilmington/
├── 2024-fall-fundamentals      # Course materials
├── 2024-fall-labs             # Lab assignments
├── 2024-fall-projects         # Student projects
├── instructor-resources       # Teaching materials
├── assessment-templates       # Exam templates
└── infrastructure            # DevOps and deployment
```

---

## GitHub OAuth App Configuration

### Create GitHub OAuth Application

1. **Navigate to GitHub Organization Settings**
   - Go to `https://github.com/organizations/zipcodewilmington/settings`
   - Click "Developer settings" → "OAuth Apps" → "New OAuth App"

2. **Configure OAuth Application**

```yaml
Application name: ZipCode OAuth2 Hub
Homepage URL: https://portal.yourinstitution.edu
Authorization callback URL: https://auth.yourinstitution.edu/realms/zipcodewilmington/broker/github/endpoint
Application description: Educational OAuth2 Hub for ZipCode Wilmington students and instructors
```

3. **Generate Client Credentials**

```bash
# After creating the OAuth App, note these values:
CLIENT_ID=Iv1.a629723cfbc52195        # GitHub provides this
CLIENT_SECRET=your_secret_here         # Generate and copy immediately

# Store these securely - you'll need them for Keycloak configuration
```

### Configure OAuth App Permissions

**Required OAuth Scopes:**

```yaml
Scopes:
  - user:email          # Access user email addresses
  - read:org           # Read organization membership
  - read:user          # Read user profile information
  - repo:status        # Access commit status (for assignment tracking)

Optional Scopes (for advanced features):
  - read:repo_hook     # Read repository webhooks
  - read:public_key    # Read user's public SSH keys
  - read:gpg_key       # Read user's GPG keys
```

---

## Keycloak GitHub Identity Provider

### Add GitHub Identity Provider

1. **Access Keycloak Admin Console**
   - URL: `https://auth.yourinstitution.edu/admin`
   - Login with admin credentials

2. **Navigate to Identity Providers**
   - Realm: `zipcodewilmington`
   - Identity Providers → Add provider → GitHub

3. **Configure GitHub Provider**

```yaml
# Basic Configuration
Alias: github
Display Name: GitHub
Enabled: ON
Store Tokens: ON
Stored Tokens Readable: ON
Trust Email: ON
Account Linking Only: OFF

# GitHub OAuth Settings
Client ID: Iv1.a629723cfbc52195          # From GitHub OAuth App
Client Secret: your_secret_here           # From GitHub OAuth App

# Advanced Settings
Default Scopes: user:email read:org read:user
Accepts Prompt None Forward Mode: OFF
Disable User Info: OFF
Hide On Login Page: OFF
GUI Order: 1

# First Login Flow
First Login Flow: github first login flow
Post Login Flow: github post login flow
Sync Mode: IMPORT
```

### Configure First Login Flow

Create a custom authentication flow for GitHub users:

1. **Create Authentication Flow**
   - Authentication → Flows → New
   - Alias: `github first login flow`
   - Description: `First time login flow for GitHub users`

2. **Add Flow Steps**

```yaml
Flow Steps:
1. Review Profile (Required)
   - Provider: Review Profile
   - Requirement: REQUIRED
   
2. Create User If Unique (Required)
   - Provider: Create User If Unique  
   - Requirement: ALTERNATIVE
   
3. GitHub Attribute Mapping (Required)
   - Provider: Attribute Importer
   - Requirement: REQUIRED
```

### Configure Attribute Mapping

Map GitHub attributes to Keycloak user attributes:

1. **GitHub Identity Provider → Mappers → Add Mapper**

```yaml
# Username Mapper
Name: github-username
Type: Attribute Importer
Social Profile JSON Field Path: login
User Attribute Name: github_username

# Email Mapper  
Name: github-email
Type: Attribute Importer
Social Profile JSON Field Path: email
User Attribute Name: email

# Name Mapper
Name: github-name
Type: Attribute Importer
Social Profile JSON Field Path: name
User Attribute Name: firstName

# Organization Mapper (Custom)
Name: github-organizations
Type: Advanced Attribute to Role
Social Profile JSON Field Path: organizations_url
User Attribute Name: github_organizations

# Team Mapper (Custom - requires API call)
Name: github-teams
Type: Script Mapper
Script: |
  var githubToken = user.getFirstAttribute('github_token');
  var teams = getGitHubTeams(githubToken, 'zipcodewilmington');
  user.setSingleAttribute('github_teams', JSON.stringify(teams));
```

---

## Student Access Control

### Organization-Based Access Control

Configure Keycloak to only allow users who are members of your GitHub organization:

1. **Create Organization Validation Script**

Create `/opt/keycloak/scripts/github-org-validator.js`:

```javascript
/**
 * GitHub Organization Membership Validator
 * Validates that user is a member of the required GitHub organization
 */

function validateGitHubOrgMembership(user, context) {
    var requiredOrg = 'zipcodewilmington';
    var githubToken = user.getFirstAttribute('github_token');
    
    if (!githubToken) {
        context.failure('NO_GITHUB_TOKEN');
        return false;
    }
    
    // Check organization membership
    var orgMembership = checkOrgMembership(githubToken, requiredOrg);
    
    if (!orgMembership.isMember) {
        context.failure('NOT_ORG_MEMBER', 
            'Access denied: You must be a member of the ' + requiredOrg + ' organization');
        return false;
    }
    
    // Store organization info
    user.setSingleAttribute('github_org', requiredOrg);
    user.setSingleAttribute('github_org_role', orgMembership.role);
    
    return true;
}

function checkOrgMembership(token, org) {
    var url = 'https://api.github.com/orgs/' + org + '/members/' + user.getUsername();
    
    try {
        var response = httpClient.get(url, {
            'Authorization': 'token ' + token,
            'Accept': 'application/vnd.github.v3+json'
        });
        
        if (response.status === 204) {
            return { isMember: true, role: 'member' };
        } else if (response.status === 302) {
            return { isMember: true, role: 'public' };
        } else {
            return { isMember: false, role: null };
        }
    } catch (error) {
        logger.error('Failed to check GitHub org membership: ' + error.message);
        return { isMember: false, role: null };
    }
}
```

2. **Add Script to Authentication Flow**
   - Authentication → Flows → `github first login flow`
   - Add Execution → Script → GitHub Org Validator

### Team-Based Role Assignment

Automatically assign Keycloak roles based on GitHub team membership:

```javascript
/**
 * GitHub Team to Role Mapper
 * Maps GitHub teams to Keycloak roles
 */

function mapGitHubTeamsToRoles(user, context) {
    var githubToken = user.getFirstAttribute('github_token');
    var teamMappings = {
        'instructors': ['instructor', 'user'],
        'admin': ['admin', 'instructor', 'user'],
        '2024-fall-cohort': ['student', 'cohort-2024-fall', 'user'],
        '2024-spring-cohort': ['student', 'cohort-2024-spring', 'user'],
        '2025-fall-cohort': ['student', 'cohort-2025-fall', 'user'],
        'alumni': ['alumni', 'user']
    };
    
    var userTeams = getUserTeams(githubToken, 'zipcodewilmington');
    var assignedRoles = [];
    
    // Map teams to roles
    for (var team of userTeams) {
        var roles = teamMappings[team.slug];
        if (roles) {
            assignedRoles = assignedRoles.concat(roles);
        }
    }
    
    // Remove duplicates and assign roles
    var uniqueRoles = [...new Set(assignedRoles)];
    
    for (var role of uniqueRoles) {
        var keycloakRole = realm.getRole(role);
        if (keycloakRole) {
            user.grantRole(keycloakRole);
        }
    }
    
    // Store team information
    user.setSingleAttribute('github_teams', JSON.stringify(userTeams));
    user.setSingleAttribute('assigned_roles', JSON.stringify(uniqueRoles));
    
    return true;
}

function getUserTeams(token, org) {
    var url = 'https://api.github.com/user/teams';
    
    try {
        var response = httpClient.get(url, {
            'Authorization': 'token ' + token,
            'Accept': 'application/vnd.github.v3+json'
        });
        
        if (response.status === 200) {
            var allTeams = JSON.parse(response.body);
            // Filter teams for our organization
            return allTeams.filter(team => team.organization.login === org);
        } else {
            return [];
        }
    } catch (error) {
        logger.error('Failed to get GitHub teams: ' + error.message);
        return [];
    }
}
```

---

## Automated User Provisioning

### Real-time User Synchronization

Set up webhooks to automatically sync user changes from GitHub:

1. **Create Webhook Endpoint**

Create `/opt/zipcode-oauth2/webhooks/github-sync.go`:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    
    "github.com/gorilla/mux"
    "github.com/Nerzal/gocloak/v13"
)

type GitHubWebhook struct {
    Action       string `json:"action"`
    Organization struct {
        Login string `json:"login"`
    } `json:"organization"`
    Member struct {
        Login string `json:"login"`
        Email string `json:"email"`
    } `json:"member"`
    Team struct {
        Name string `json:"name"`
        Slug string `json:"slug"`
    } `json:"team"`
}

var keycloakClient *gocloak.GoCloak
var token *gocloak.JWT

func main() {
    // Initialize Keycloak client
    keycloakClient = gocloak.NewClient(os.Getenv("KEYCLOAK_URL"))
    
    // Authenticate with Keycloak
    var err error
    token, err = keycloakClient.LoginAdmin(
        context.Background(),
        os.Getenv("KEYCLOAK_ADMIN"),
        os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
        "master",
    )
    if err != nil {
        log.Fatal("Failed to login to Keycloak:", err)
    }
    
    router := mux.NewRouter()
    router.HandleFunc("/webhook/github", handleGitHubWebhook).Methods("POST")
    
    log.Println("GitHub webhook server starting on :8082")
    log.Fatal(http.ListenAndServe(":8082", router))
}

func handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
    var webhook GitHubWebhook
    
    if err := json.NewDecoder(r.Body).Decode(&webhook); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // Verify webhook is from our organization
    if webhook.Organization.Login != "zipcodewilmington" {
        http.Error(w, "Unauthorized organization", http.StatusUnauthorized)
        return
    }
    
    switch r.Header.Get("X-GitHub-Event") {
    case "membership":
        handleMembershipEvent(webhook)
    case "team":
        handleTeamEvent(webhook)
    case "organization":
        handleOrganizationEvent(webhook)
    }
    
    w.WriteHeader(http.StatusOK)
}

func handleMembershipEvent(webhook GitHubWebhook) {
    switch webhook.Action {
    case "added":
        // User added to organization - enable their account
        enableUserAccount(webhook.Member.Login)
    case "removed":
        // User removed from organization - disable their account
        disableUserAccount(webhook.Member.Login)
    }
}

func handleTeamEvent(webhook GitHubWebhook) {
    switch webhook.Action {
    case "added_to_repository":
        // Team added to repository - update permissions
        updateTeamPermissions(webhook.Team.Slug)
    case "removed_from_repository":
        // Team removed from repository - revoke permissions
        revokeTeamPermissions(webhook.Team.Slug)
    }
}

func enableUserAccount(githubUsername string) {
    // Find user by GitHub username
    users, err := keycloakClient.GetUsers(
        context.Background(),
        token.AccessToken,
        "zipcodewilmington",
        gocloak.GetUsersParams{
            Username: &githubUsername,
        },
    )
    
    if err != nil || len(users) == 0 {
        log.Printf("User not found: %s", githubUsername)
        return
    }
    
    user := users[0]
    enabled := true
    user.Enabled = &enabled
    
    err = keycloakClient.UpdateUser(
        context.Background(),
        token.AccessToken,
        "zipcodewilmington",
        *user,
    )
    
    if err != nil {
        log.Printf("Failed to enable user %s: %v", githubUsername, err)
    } else {
        log.Printf("Enabled user account: %s", githubUsername)
    }
}

func disableUserAccount(githubUsername string) {
    // Similar to enableUserAccount but set Enabled = false
    // Implementation follows same pattern
}
```

2. **Configure GitHub Webhook**

In your GitHub organization settings:

```yaml
# Webhook Configuration
Payload URL: https://api.yourinstitution.edu/webhook/github
Content type: application/json
Secret: your_webhook_secret_here

Events:
  - Member added to organization
  - Member removed from organization  
  - Team added to repository
  - Team removed from repository
  - Repository created/deleted
```

### Batch User Import

For initial setup, create a script to import existing GitHub organization members:

```bash
#!/bin/bash
# scripts/import-github-users.sh

GITHUB_TOKEN="your_github_token_here"
ORG="zipcodewilmington"
KEYCLOAK_URL="https://auth.yourinstitution.edu"
REALM="zipcodewilmington"

# Get organization members
echo "Fetching GitHub organization members..."
MEMBERS=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/orgs/$ORG/members" | jq -r '.[].login')

for username in $MEMBERS; do
    echo "Processing user: $username"
    
    # Get user details
    USER_DATA=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/users/$username")
    
    EMAIL=$(echo $USER_DATA | jq -r '.email // empty')
    NAME=$(echo $USER_DATA | jq -r '.name // .login')
    
    # Get user's teams in the organization
    TEAMS=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/orgs/$ORG/teams" | \
        jq -r --arg user "$username" '.[] | select(.members_url | contains($user)) | .slug')
    
    # Create user in Keycloak
    create_keycloak_user "$username" "$EMAIL" "$NAME" "$TEAMS"
done

create_keycloak_user() {
    local username=$1
    local email=$2
    local name=$3
    local teams=$4
    
    # Get Keycloak admin token
    ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$KEYCLOAK_ADMIN" \
        -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" | jq -r '.access_token')
    
    # Create user
    USER_PAYLOAD=$(cat <<EOF
{
    "username": "$username",
    "email": "$email",
    "firstName": "$name",
    "lastName": "",
    "enabled": true,
    "attributes": {
        "github_username": ["$username"],
        "github_teams": ["$teams"],
        "import_source": ["github_bulk_import"]
    }
}
EOF
    )
    
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/users" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$USER_PAYLOAD"
    
    echo "Created user: $username ($email)"
}
```

---

## Team-Based Access Control

### Repository Access Permissions

Configure fine-grained access control based on GitHub repository permissions:

1. **Repository Permission Mapping**

```yaml
# Repository to Resource Mapping
Repositories:
  2024-fall-fundamentals:
    Resources:
      - course-materials
      - lecture-videos
      - reading-assignments
    Required Teams:
      - 2024-fall-cohort
      - instructors
    Permissions:
      Students: read
      Instructors: read, write
      
  2024-fall-labs:
    Resources:
      - lab-assignments
      - code-templates
      - submission-portal
    Required Teams:
      - 2024-fall-cohort
      - instructors
    Permissions:
      Students: read, submit
      Instructors: read, write, grade
      
  instructor-resources:
    Resources:
      - answer-keys
      - grading-rubrics
      - administrative-tools
    Required Teams:
      - instructors
      - admin
    Permissions:
      Instructors: read
      Admin: read, write
```

2. **Dynamic Permission Evaluation**

Create a permission evaluator that checks GitHub repository access:

```javascript
/**
 * GitHub Repository Permission Evaluator
 * Checks if user has required repository access for resource
 */

function evaluateRepositoryPermission(user, resource, action) {
    var githubToken = user.getFirstAttribute('github_token');
    var resourceConfig = getResourceConfig(resource);
    
    if (!resourceConfig) {
        return false; // Resource not configured
    }
    
    // Check repository access
    for (var repo of resourceConfig.repositories) {
        var hasAccess = checkRepositoryAccess(
            githubToken, 
            'zipcodewilmington', 
            repo, 
            action
        );
        
        if (hasAccess) {
            return true;
        }
    }
    
    return false;
}

function checkRepositoryAccess(token, org, repo, permission) {
    var url = `https://api.github.com/repos/${org}/${repo}/collaborators/${user.getUsername()}/permission`;
    
    try {
        var response = httpClient.get(url, {
            'Authorization': 'token ' + token,
            'Accept': 'application/vnd.github.v3+json'
        });
        
        if (response.status === 200) {
            var data = JSON.parse(response.body);
            var userPermission = data.permission;
            
            // Check if user permission allows requested action
            return isPermissionSufficient(userPermission, permission);
        }
        
        return false;
    } catch (error) {
        logger.error('Failed to check repository access: ' + error.message);
        return false;
    }
}

function isPermissionSufficient(userPermission, requiredPermission) {
    var permissionLevels = {
        'read': 1,
        'triage': 2,
        'write': 3,
        'maintain': 4,
        'admin': 5
    };
    
    var userLevel = permissionLevels[userPermission] || 0;
    var requiredLevel = permissionLevels[requiredPermission] || 1;
    
    return userLevel >= requiredLevel;
}
```

### Assignment-Based Access Control

Control access to specific assignments based on GitHub repository structure:

```yaml
# Assignment Configuration
Assignments:
  java-fundamentals-week1:
    Repository: 2024-fall-labs
    Path: /week-1/java-fundamentals
    Available From: 2024-09-01T00:00:00Z
    Due Date: 2024-09-07T23:59:59Z
    Required Teams:
      - 2024-fall-cohort
    Submission:
      Type: pull-request
      Target Branch: submissions/week-1
      Review Required: true
      
  midterm-project:
    Repository: 2024-fall-projects  
    Path: /midterm
    Available From: 2024-10-15T00:00:00Z
    Due Date: 2024-10-29T23:59:59Z
    Required Teams:
      - 2024-fall-cohort
    Submission:
      Type: repository-fork
      Template: midterm-project-template
      Private: true
```

---

## Cohort Synchronization

### Automatic Cohort Assignment

Synchronize Keycloak cohorts with GitHub teams:

1. **Team to Cohort Mapping Configuration**

```yaml
# config/github-cohort-mapping.yml
Team Mappings:
  2024-fall-cohort:
    Keycloak Cohort: fall-2024
    Academic Year: 2024-2025
    Semester: fall
    Start Date: 2024-09-01
    End Date: 2024-12-15
    Status: active
    
  2024-spring-cohort:
    Keycloak Cohort: spring-2024
    Academic Year: 2023-2024
    Semester: spring
    Start Date: 2024-01-15
    End Date: 2024-05-15
    Status: completed
    
  2025-fall-cohort:
    Keycloak Cohort: fall-2025
    Academic Year: 2025-2026
    Semester: fall
    Start Date: 2025-09-01
    End Date: 2025-12-15
    Status: upcoming

Instructor Teams:
  instructors:
    Keycloak Roles:
      - instructor
      - user
    Cross Cohort Access: true
    
  admin:
    Keycloak Roles:
      - admin
      - instructor
      - user
    Full Access: true
```

2. **Cohort Synchronization Service**

```go
// services/cohort-sync.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "time"
    
    "github.com/google/go-github/v45/github"
    "github.com/Nerzal/gocloak/v13"
    "golang.org/x/oauth2"
)

type CohortSyncService struct {
    githubClient   *github.Client
    keycloakClient *gocloak.GoCloak
    keycloakToken  *gocloak.JWT
    orgName        string
    realmName      string
}

func NewCohortSyncService(githubToken, keycloakURL, realm string) *CohortSyncService {
    // Initialize GitHub client
    ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: githubToken})
    tc := oauth2.NewClient(context.Background(), ts)
    githubClient := github.NewClient(tc)
    
    // Initialize Keycloak client
    keycloakClient := gocloak.NewClient(keycloakURL)
    
    return &CohortSyncService{
        githubClient:   githubClient,
        keycloakClient: keycloakClient,
        orgName:        "zipcodewilmington",
        realmName:      realm,
    }
}

func (s *CohortSyncService) SynchronizeCohorts() error {
    // Get all GitHub teams
    teams, _, err := s.githubClient.Teams.ListTeams(
        context.Background(), 
        s.orgName, 
        nil,
    )
    if err != nil {
        return fmt.Errorf("failed to get GitHub teams: %w", err)
    }
    
    for _, team := range teams {
        if isCohortTeam(team.GetSlug()) {
            err := s.syncCohortTeam(team)
            if err != nil {
                log.Printf("Failed to sync team %s: %v", team.GetSlug(), err)
            }
        }
    }
    
    return nil
}

func (s *CohortSyncService) syncCohortTeam(team *github.Team) error {
    // Get team members
    members, _, err := s.githubClient.Teams.ListTeamMembersBySlug(
        context.Background(),
        s.orgName,
        team.GetSlug(),
        nil,
    )
    if err != nil {
        return fmt.Errorf("failed to get team members: %w", err)
    }
    
    // Get or create corresponding Keycloak group
    groupName := fmt.Sprintf("cohort-%s", team.GetSlug())
    group, err := s.getOrCreateKeycloakGroup(groupName)
    if err != nil {
        return fmt.Errorf("failed to get/create Keycloak group: %w", err)
    }
    
    // Sync members
    for _, member := range members {
        err := s.addUserToGroup(member.GetLogin(), group.ID)
        if err != nil {
            log.Printf("Failed to add user %s to group %s: %v", 
                member.GetLogin(), groupName, err)
        }
    }
    
    return nil
}

func (s *CohortSyncService) getOrCreateKeycloakGroup(name string) (*gocloak.Group, error) {
    // Check if group exists
    groups, err := s.keycloakClient.GetGroups(
        context.Background(),
        s.keycloakToken.AccessToken,
        s.realmName,
        gocloak.GetGroupsParams{
            Search: &name,
        },
    )
    
    if err != nil {
        return nil, err
    }
    
    // Return existing group if found
    for _, group := range groups {
        if group.Name != nil && *group.Name == name {
            return group, nil
        }
    }
    
    // Create new group
    group := gocloak.Group{
        Name: &name,
        Attributes: &map[string][]string{
            "source": {"github-sync"},
            "type":   {"cohort"},
        },
    }
    
    groupID, err := s.keycloakClient.CreateGroup(
        context.Background(),
        s.keycloakToken.AccessToken,
        s.realmName,
        group,
    )
    
    if err != nil {
        return nil, err
    }
    
    group.ID = &groupID
    return &group, nil
}

func isCohortTeam(teamSlug string) bool {
    cohortPatterns := []string{
        "cohort",
        "fall",
        "spring",
        "summer", 
        "2024",
        "2025",
    }
    
    for _, pattern := range cohortPatterns {
        if strings.Contains(teamSlug, pattern) {
            return true
        }
    }
    
    return false
}
```

3. **Scheduled Synchronization**

```bash
#!/bin/bash
# scripts/sync-cohorts.sh

# Run cohort synchronization every hour
echo "Starting cohort synchronization at $(date)"

# Execute cohort sync service
/opt/zipcode-oauth2/bin/cohort-sync \
    -github-token="$GITHUB_SYNC_TOKEN" \
    -keycloak-url="$KEYCLOAK_URL" \
    -realm="zipcodewilmington" \
    -org="zipcodewilmington"

echo "Cohort synchronization completed at $(date)"

# Add to crontab:
# 0 * * * * /opt/zipcode-oauth2/scripts/sync-cohorts.sh >> /var/log/zipcode-oauth2/cohort-sync.log 2>&1
```

---

## Administrative Procedures

### Student Onboarding Process

**Automated GitHub-based onboarding:**

1. **Instructor adds student to GitHub organization**
   - Student receives GitHub organization invitation
   - Student accepts invitation and joins appropriate team (e.g., `2024-fall-cohort`)

2. **Automatic account creation in OAuth2 Hub**
   - GitHub webhook triggers user provisioning
   - Keycloak account created with GitHub identity provider
   - User assigned to appropriate cohort and roles

3. **Student first login**
   - Student clicks "Login with GitHub" on OAuth2 Hub
   - GitHub OAuth flow authenticates student
   - Keycloak links GitHub account to local user
   - Student gains access to cohort resources

**Manual verification checklist:**

```bash
#!/bin/bash
# scripts/verify-student-setup.sh

STUDENT_GITHUB_USERNAME="$1"
ORG="zipcodewilmington"

if [ -z "$STUDENT_GITHUB_USERNAME" ]; then
    echo "Usage: $0 <github_username>"
    exit 1
fi

echo "Verifying setup for student: $STUDENT_GITHUB_USERNAME"

# Check GitHub organization membership
echo "1. Checking GitHub organization membership..."
gh api "orgs/$ORG/members/$STUDENT_GITHUB_USERNAME" --silent
if [ $? -eq 0 ]; then
    echo "✅ Student is a member of $ORG organization"
else
    echo "❌ Student is NOT a member of $ORG organization"
fi

# Check team membership
echo "2. Checking team membership..."
TEAMS=$(gh api "orgs/$ORG/teams" --jq '.[].slug')
for team in $TEAMS; do
    gh api "orgs/$ORG/teams/$team/members/$STUDENT_GITHUB_USERNAME" --silent
    if [ $? -eq 0 ]; then
        echo "✅ Student is member of team: $team"
    fi
done

# Check Keycloak account
echo "3. Checking Keycloak account..."
KEYCLOAK_USER=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/zipcodewilmington/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -G -d "username=$STUDENT_GITHUB_USERNAME" | jq -r '.[0].id // empty')

if [ -n "$KEYCLOAK_USER" ]; then
    echo "✅ Keycloak account exists: $KEYCLOAK_USER"
else
    echo "❌ No Keycloak account found"
fi

echo "Verification completed for $STUDENT_GITHUB_USERNAME"
```

### Bulk Operations

**Add multiple students to cohort:**

```bash
#!/bin/bash
# scripts/bulk-add-students.sh

COHORT_TEAM="2024-fall-cohort"
STUDENTS_FILE="$1"  # File with one GitHub username per line

if [ ! -f "$STUDENTS_FILE" ]; then
    echo "Usage: $0 <students_file>"
    echo "Students file should contain one GitHub username per line"
    exit 1
fi

echo "Adding students from $STUDENTS_FILE to team $COHORT_TEAM"

while IFS= read -r username; do
    if [ -n "$username" ]; then
        echo "Adding $username to $COHORT_TEAM..."
        
        # Add to GitHub team
        gh api -X PUT "orgs/zipcodewilmington/teams/$COHORT_TEAM/memberships/$username" \
            --field role=member
        
        if [ $? -eq 0 ]; then
            echo "✅ Successfully added $username to GitHub team"
            
            # Trigger Keycloak sync (optional - webhook should handle this)
            curl -X POST "$WEBHOOK_URL/sync-user" \
                -H "Content-Type: application/json" \
                -d "{\"username\": \"$username\", \"team\": \"$COHORT_TEAM\"}"
                
        else
            echo "❌ Failed to add $username to GitHub team"
        fi
    fi
done < "$STUDENTS_FILE"

echo "Bulk student addition completed"
```

**Remove graduated students:**

```bash
#!/bin/bash
# scripts/graduate-cohort.sh

COHORT_TEAM="2024-spring-cohort"
ALUMNI_TEAM="alumni"

echo "Graduating students from $COHORT_TEAM to $ALUMNI_TEAM"

# Get current cohort members
STUDENTS=$(gh api "orgs/zipcodewilmington/teams/$COHORT_TEAM/members" --jq '.[].login')

for student in $STUDENTS; do
    echo "Processing graduation for $student..."
    
    # Remove from cohort team
    gh api -X DELETE "orgs/zipcodewilmington/teams/$COHORT_TEAM/memberships/$student"
    
    # Add to alumni team
    gh api -X PUT "orgs/zipcodewilmington/teams/$ALUMNI_TEAM/memberships/$student" \
        --field role=member
    
    # Update Keycloak user attributes
    update_keycloak_user_status "$student" "graduated"
    
    echo "✅ Graduated $student"
done

echo "Cohort graduation completed"
```

---

## Troubleshooting

### Common Integration Issues

#### GitHub OAuth App Configuration

**Problem:** "Invalid redirect URI" error during login

```bash
# Verify OAuth App redirect URI
gh api "applications/client-id"

# Should match exactly:
# https://auth.yourinstitution.edu/realms/zipcodewilmington/broker/github/endpoint
```

**Solution:**
1. Check OAuth App settings in GitHub organization
2. Ensure redirect URI matches exactly (no trailing slashes)
3. Verify domain name and path are correct

#### Token Permissions

**Problem:** "Insufficient permissions" when accessing GitHub API

```bash
# Check token scopes
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Required scopes: user:email, read:org, read:user
```

**Solution:**
1. Regenerate GitHub token with correct scopes
2. Update Keycloak identity provider configuration
3. Test API access manually

#### User Synchronization Issues

**Problem:** Users not appearing in Keycloak after GitHub team changes

```bash
# Check webhook delivery
gh api "orgs/zipcodewilmington/hooks"

# Verify webhook endpoint is accessible
curl -X POST "https://api.yourinstitution.edu/webhook/github/test"

# Check webhook logs
tail -f /var/log/zipcode-oauth2/webhook.log
```

**Solution:**
1. Verify webhook endpoint is properly configured and accessible
2. Check webhook secret matches configuration
3. Manually trigger synchronization if needed

### Debug Commands

**Test GitHub API connectivity:**

```bash
#!/bin/bash
# scripts/test-github-integration.sh

GITHUB_TOKEN="your_token_here"
ORG="zipcodewilmington"

echo "Testing GitHub API connectivity..."

# Test basic API access
echo "1. Testing basic API access..."
curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/user" | jq '.login'

# Test organization access
echo "2. Testing organization access..."
curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/orgs/$ORG" | jq '.name'

# Test team listing
echo "3. Testing team listing..."
curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/orgs/$ORG/teams" | jq '.[].name'

# Test member listing
echo "4. Testing member listing..."
curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/orgs/$ORG/members" | jq 'length'

echo "GitHub integration test completed"
```

**Verify Keycloak GitHub provider:**

```bash
#!/bin/bash
# scripts/test-keycloak-github.sh

KEYCLOAK_URL="https://auth.yourinstitution.edu"
REALM="zipcodewilmington"

# Test GitHub identity provider configuration
curl -s "$KEYCLOAK_URL/realms/$REALM/.well-known/openid_configuration" | \
    jq '.authorization_endpoint'

# Test GitHub login endpoint
curl -I "$KEYCLOAK_URL/realms/$REALM/broker/github/login"

echo "Keycloak GitHub provider test completed"
```

---

## Security Considerations

### Token Management

**GitHub Token Security:**

```yaml
Token Requirements:
  Type: Personal Access Token (Classic)
  Scopes: user:email, read:org, read:user
  Expiration: 90 days maximum
  Storage: Encrypted in Keycloak configuration
  Rotation: Automated monthly rotation

Security Practices:
  - Use organization-owned service account
  - Limit token permissions to minimum required
  - Monitor token usage and API calls
  - Implement token rotation automation
  - Log all API access for audit trail
```

**Keycloak Token Security:**

```yaml
Configuration:
  Store Tokens: Enabled (required for API calls)
  Stored Tokens Readable: Enabled (for permission checks)
  Token Encryption: AES-256
  Token Expiration: 24 hours
  Refresh Token: Enabled
  
Access Control:
  - Admin-only access to stored tokens
  - Encrypted storage of sensitive data
  - Regular security audits
  - Monitor for suspicious access patterns
```

### Data Privacy

**Student Data Protection:**

```yaml
Privacy Measures:
  GitHub Profile: Public data only
  Email Access: Explicit consent required
  Organization Membership: Private by default
  Team Membership: Educational purposes only
  
Data Minimization:
  - Collect only necessary GitHub information
  - Regular cleanup of inactive accounts  
  - Automatic deletion of graduated students
  - Audit trail for data access
  
Compliance:
  - FERPA compliance for educational records
  - GDPR considerations for EU students
  - Institutional privacy policies
  - Student consent management
```

### Access Control Hardening

**Multi-layered Security:**

```yaml
Layer 1: GitHub Organization
  - Two-factor authentication required
  - Private organization membership
  - Limited team visibility
  - Repository access controls

Layer 2: OAuth2 Hub Authentication  
  - GitHub identity verification
  - Organization membership validation
  - Team-based role assignment
  - Session management

Layer 3: Resource Access Control
  - Repository permission validation
  - Time-based access restrictions
  - Assignment-specific permissions
  - Audit logging

Layer 4: Application Security
  - HTTPS enforcement
  - CSRF protection
  - XSS prevention
  - Rate limiting
```

This comprehensive GitHub integration guide provides everything needed to set up GitHub-based authentication and access control for the ZipCode OAuth2 Hub, enabling streamlined student onboarding and fine-grained permission management based on GitHub organization and team membership.

---

**Security Note:** This guide handles sensitive GitHub tokens and student data. Ensure all credentials are properly secured and follow your institution's privacy and security policies.

**Last Updated:** November 18, 2025  
**Version:** 1.0.0