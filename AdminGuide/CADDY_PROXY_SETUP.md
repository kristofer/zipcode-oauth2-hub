# Caddy Reverse Proxy Setup for Hugo Sites

Guide for protecting Hugo static sites with the ZipCode OAuth2 Hub using Caddy as a reverse proxy with OAuth2 authentication.

## Overview

This method provides OAuth2 authentication for Hugo static sites without requiring application-level changes. Caddy handles authentication at the proxy level, making it ideal for static content with educational access control.

## Prerequisites

- ZipCode OAuth2 Hub running and accessible
- Hugo static site built and ready for deployment
- Caddy with OAuth2 plugin
- Domain name configured with DNS

## Installation

### 1. Install Caddy with OAuth2 Plugin

```bash
# Install xcaddy (Caddy builder)
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with OAuth2 security plugin
xcaddy build --with github.com/greenpau/caddy-security

# Move to system path
sudo mv caddy /usr/local/bin/
```

### 2. Register Hugo Site in Keycloak

1. Access Keycloak Admin Console: `https://auth.zipcodewilmington.edu`
2. Navigate to **Clients** → **Create Client**
3. Configure client settings:

```json
{
  "client_id": "hugo-site-client",
  "name": "Hugo Static Site", 
  "client_type": "confidential",
  "redirect_uris": [
    "https://hugo.zipcodewilmington.edu/oauth/callback"
  ],
  "web_origins": [
    "https://hugo.zipcodewilmington.edu"
  ],
  "grant_types": ["authorization_code"],
  "scopes": ["openid", "profile", "email", "cohort_access"]
}
```

1. Save the **Client Secret** for configuration

## Configuration

### Caddyfile Setup

Create `/etc/caddy/Caddyfile`:

```caddyfile
# Hugo site with OAuth2 protection
hugo.zipcodewilmington.edu {
    # OAuth2 configuration
    oauth {
        provider oidc
        client_id hugo-site-client
        client_secret {env.HUGO_CLIENT_SECRET}
        
        # ZipCode OAuth2 Hub endpoints
        auth_url https://auth.zipcodewilmington.edu/realms/zipcodewilmington/protocol/openid-connect/auth
        token_url https://auth.zipcodewilmington.edu/realms/zipcodewilmington/protocol/openid-connect/token
        user_url https://auth.zipcodewilmington.edu/realms/zipcodewilmington/protocol/openid-connect/userinfo
        
        # Scopes and redirect
        scopes openid profile email cohort_access
        redirect_uri https://hugo.zipcodewilmington.edu/oauth/callback
        
        # JWT validation
        jwt_verification_key https://auth.zipcodewilmington.edu/realms/zipcodewilmington/protocol/openid-connect/certs
        
        # Educational access control
        required_claims {
            cohort_id "2024-fall-java,2024-spring-python"  # Allow specific cohorts
            realm_access.roles "student,instructor"        # Allow these roles
        }
    }
    
    # Serve Hugo static files
    root * /var/www/hugo-site
    file_server
    
    # Security headers
    header {
        X-Frame-Options DENY
        X-Content-Type-Options nosniff
        X-XSS-Protection "1; mode=block"
        Referrer-Policy strict-origin-when-cross-origin
    }
    
    # Health check (bypass auth)
    handle /health {
        respond "OK" 200
    }
}

# OAuth2 callback handler
hugo.zipcodewilmington.edu/oauth/* {
    oauth_callback
}
```

### Environment Variables

Create `/etc/caddy/env`:

```bash
# Hugo site client secret from Keycloak
HUGO_CLIENT_SECRET=your-client-secret-here
```

## Deployment

### 1. Prepare Hugo Site

```bash
# Build Hugo site
cd /path/to/hugo/source
hugo --destination /var/www/hugo-site

# Set appropriate permissions
sudo chown -R caddy:caddy /var/www/hugo-site
sudo chmod -R 755 /var/www/hugo-site
```

### 2. Start Caddy Service

**Create systemd service file** `/etc/systemd/system/caddy.service`:

```ini
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE
EnvironmentFile=/etc/caddy/env

[Install]
WantedBy=multi-user.target
```

**Enable and start service:**

```bash
# Create caddy user
sudo useradd --system --home /var/lib/caddy --shell /bin/false caddy

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable caddy
sudo systemctl start caddy

# Check status
sudo systemctl status caddy
```

## Educational Access Control

### Cohort-Based Access

Modify the `required_claims` section to control access by cohort:

```caddyfile
required_claims {
    cohort_id "2024-fall-java"              # Single cohort
    # OR
    cohort_id "2024-fall-java,2024-spring-python"  # Multiple cohorts
}
```

### Role-Based Content

Serve different content based on user roles:

```caddyfile
hugo.zipcodewilmington.edu {
    oauth { /* oauth config */ }
    
    # Student-specific content
    @students {
        header X-User-Role "student"
    }
    handle @students {
        root * /var/www/hugo-site/student
        file_server
    }
    
    # Instructor-specific content  
    @instructors {
        header X-User-Role "instructor"
    }
    handle @instructors {
        root * /var/www/hugo-site/instructor
        file_server
    }
    
    # Default content
    handle {
        root * /var/www/hugo-site/public
        file_server
    }
}
```

### Time-Based Restrictions

Add time-based access control:

```caddyfile
oauth {
    # ... other config ...
    
    # Lab hours restriction
    access_control {
        time_windows {
            lab_hours "08:00-20:00"
            days "monday,tuesday,wednesday,thursday,friday"
        }
    }
}
```

## Testing

### 1. Verify Configuration

```bash
# Test Caddy configuration
sudo caddy validate --config /etc/caddy/Caddyfile

# Check OAuth2 endpoints
curl -I https://auth.zipcodewilmington.edu/realms/zipcodewilmington/.well-known/openid_configuration
```

### 2. Test Authentication Flow

1. Visit `https://hugo.zipcodewilmington.edu`
2. Should redirect to OAuth2 login
3. Login with test credentials
4. Should redirect back to Hugo site
5. Verify user can access content

### 3. Test Access Controls

```bash
# Test with different user roles/cohorts
# Verify appropriate access restrictions
```

## Troubleshooting

### Common Issues

**1. OAuth2 redirect URI mismatch:**

- Verify redirect URI in Keycloak matches Caddyfile
- Check for trailing slashes and protocol (http vs https)

**2. Token validation errors:**

- Verify JWKS endpoint is accessible
- Check client secret is correct

**3. Access denied errors:**

- Review `required_claims` configuration
- Check user's cohort and role assignments in Keycloak

### Debug Commands

```bash
# View Caddy logs
sudo journalctl -u caddy -f

# Test OAuth2 endpoints
curl -v https://auth.zipcodewilmington.edu/realms/zipcodewilmington/protocol/openid-connect/auth

# Validate JWT tokens
curl -H "Authorization: Bearer TOKEN" https://auth.zipcodewilmington.edu/api/v1/user/info
```

## Maintenance

### Updates

```bash
# Update Hugo site
cd /path/to/hugo/source
hugo --destination /var/www/hugo-site
sudo systemctl reload caddy
```

### SSL Certificate Renewal

Caddy automatically handles Let's Encrypt certificates, but you can force renewal:

```bash
sudo caddy reload --config /etc/caddy/Caddyfile
```

## Security Considerations

1. **Always use HTTPS** in production
2. **Secure client secret** - use environment variables
3. **Regular updates** - keep Caddy and plugins updated
4. **Monitor logs** - watch for authentication failures
5. **Backup configuration** - version control Caddyfile

## Benefits of This Approach

- ✅ **No Hugo site modifications** required
- ✅ **Educational policy enforcement** at proxy level  
- ✅ **High performance** static file serving
- ✅ **Automatic SSL** certificate management
- ✅ **Cohort and role-based** access control
- ✅ **Easy maintenance** and updates

---

**Documentation Version:** 1.0  
**Last Updated:** November 18, 2025  
**Compatible with:** ZipCode OAuth2 Hub v1.0+
