# Production Setup Guide - ZipCode OAuth2 Hub

Complete step-by-step guide for deploying the ZipCode OAuth2 Hub to production on a Docker host with proper security, DNS configuration, and operational setup.

## 📖 Table of Contents

- [Pre-Production Checklist](#pre-production-checklist)
- [Infrastructure Requirements](#infrastructure-requirements)
- [DNS and Network Configuration](#dns-and-network-configuration)
- [SSL/TLS Certificate Setup](#ssltls-certificate-setup)
- [Production Environment Variables](#production-environment-variables)
- [Database Setup](#database-setup)
- [Docker Production Deployment](#docker-production-deployment)
- [Reverse Proxy Configuration](#reverse-proxy-configuration)
- [Security Hardening](#security-hardening)
- [Monitoring and Logging](#monitoring-and-logging)
- [Backup and Recovery](#backup-and-recovery)
- [Operational Procedures](#operational-procedures)
- [Troubleshooting](#troubleshooting)

---

## Pre-Production Checklist

### 🔒 Security Requirements

- [ ] **Server Security**
  - [ ] Firewall configured (only necessary ports open)
  - [ ] SSH key-based authentication enabled
  - [ ] Root login disabled
  - [ ] Fail2ban installed and configured
  - [ ] Security updates automated

- [ ] **SSL/TLS Certificates**
  - [ ] Valid SSL certificates obtained (Let's Encrypt or CA)
  - [ ] Certificate renewal automated
  - [ ] Strong cipher suites configured

- [ ] **Access Control**
  - [ ] Production passwords generated (complex, unique)
  - [ ] Database passwords rotated from defaults
  - [ ] Admin accounts secured
  - [ ] Network access restricted to authorized IPs

### 🌐 Network and DNS

- [ ] **Domain Names Registered**
  - [ ] Authentication server domain (e.g., `auth.yourinstitution.edu`)
  - [ ] API gateway domain (e.g., `api.yourinstitution.edu`)
  - [ ] Application domains (e.g., `portal.yourinstitution.edu`)

- [ ] **DNS Configuration**
  - [ ] A records pointing to production server IP
  - [ ] CNAME records for subdomains
  - [ ] TTL values set appropriately (300-3600 seconds)

### 💾 Infrastructure

- [ ] **Production Server**
  - [ ] Minimum 8 vCPU, 16 GB RAM, 500 GB SSD
  - [ ] Docker and Docker Compose installed
  - [ ] Backup storage configured
  - [ ] Monitoring tools installed

- [ ] **Network Setup**
  - [ ] Load balancer configured (if multiple servers)
  - [ ] Content Delivery Network (CDN) set up
  - [ ] Database backups configured

---

## Infrastructure Requirements

### Production Server Specifications

**Recommended Configuration:**
- **CPU**: 8+ vCPU (4+ cores)
- **Memory**: 16+ GB RAM
- **Storage**: 500+ GB SSD with high IOPS
- **Network**: 1 Gbps connection
- **OS**: Ubuntu 22.04 LTS or RHEL 9

### Docker Host Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install docker-compose-plugin

# Install additional tools
sudo apt install -y nginx certbot python3-certbot-nginx fail2ban ufw htop
```

### Firewall Configuration

```bash
# Configure UFW firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow essential services
sudo ufw allow ssh
sudo ufw allow 80/tcp   # HTTP (for Let's Encrypt)
sudo ufw allow 443/tcp  # HTTPS
sudo ufw allow 22/tcp   # SSH

# Enable firewall
sudo ufw enable
```

---

## DNS and Network Configuration

### Required DNS Records

Create these DNS records with your domain registrar:

```dns
# Primary authentication server
auth.yourinstitution.edu.        A     YOUR_SERVER_IP
auth.yourinstitution.edu.        AAAA  YOUR_SERVER_IPv6  # If IPv6 enabled

# API Gateway
api.yourinstitution.edu.         A     YOUR_SERVER_IP

# Student portal
portal.yourinstitution.edu.      A     YOUR_SERVER_IP

# Admin dashboard  
admin.yourinstitution.edu.       A     YOUR_SERVER_IP

# Wildcard for development (optional)
*.dev.yourinstitution.edu.       A     YOUR_SERVER_IP
```

### Network Security

```bash
# Restrict SSH access to specific IPs (replace with your IPs)
sudo ufw allow from YOUR_ADMIN_IP to any port 22

# If using a jump server
sudo ufw allow from JUMP_SERVER_IP to any port 22

# Allow health check access (if using load balancer)
sudo ufw allow from LB_IP_RANGE to any port 8080
sudo ufw allow from LB_IP_RANGE to any port 8081
```

### Load Balancer Configuration (If Applicable)

**AWS Application Load Balancer:**
```yaml
# Target Groups
Auth-Server-TG:
  - Port: 8080
  - Health Check: /realms/zipcodewilmington/.well-known/openid_configuration
  
API-Gateway-TG:
  - Port: 8081  
  - Health Check: /health

Portal-App-TG:
  - Port: 3000
  - Health Check: /
```

---

## SSL/TLS Certificate Setup

### Option 1: Let's Encrypt (Recommended)

```bash
# Stop nginx if running
sudo systemctl stop nginx

# Obtain certificates for all domains
sudo certbot certonly --standalone -d auth.yourinstitution.edu
sudo certbot certonly --standalone -d api.yourinstitution.edu  
sudo certbot certonly --standalone -d portal.yourinstitution.edu
sudo certbot certonly --standalone -d admin.yourinstitution.edu

# Set up auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Option 2: Commercial Certificate

```bash
# Generate private key
openssl genrsa -out yourinstitution.edu.key 2048

# Generate certificate signing request
openssl req -new -key yourinstitution.edu.key -out yourinstitution.edu.csr

# Submit CSR to your Certificate Authority
# Install received certificates in /etc/ssl/certs/
```

### Certificate Verification

```bash
# Check certificate validity
openssl x509 -in /etc/letsencrypt/live/auth.yourinstitution.edu/cert.pem -text -noout

# Test SSL configuration
curl -I https://auth.yourinstitution.edu
```

---

## Production Environment Variables

### Create Production .env File

```bash
# Create secure production environment file
sudo mkdir -p /opt/zipcode-oauth2
sudo chown $USER:$USER /opt/zipcode-oauth2
cd /opt/zipcode-oauth2

# Clone repository
git clone https://github.com/zipcodewilmington/oauth2-hub.git .

# Create production .env
cp .env.example .env.production
```

### Production Environment Configuration

```bash
# Edit production environment
nano .env.production
```

```properties
# =============================================================================
# PRODUCTION ENVIRONMENT - ZipCode OAuth2 Hub
# =============================================================================

# =============================================================================
# Domain Configuration
# =============================================================================
DOMAIN_NAME=yourinstitution.edu
AUTH_DOMAIN=auth.yourinstitution.edu
API_DOMAIN=api.yourinstitution.edu
PORTAL_DOMAIN=portal.yourinstitution.edu

# =============================================================================
# Keycloak Production Configuration
# =============================================================================
KEYCLOAK_URL=https://auth.yourinstitution.edu
KEYCLOAK_REALM=zipcodewilmington
KC_HOSTNAME=auth.yourinstitution.edu
KC_HOSTNAME_STRICT=true
KC_HTTP_ENABLED=false
KC_HOSTNAME_STRICT_HTTPS=true
KC_PROXY=edge

# Keycloak Admin (CHANGE THESE!)
KEYCLOAK_ADMIN=CHANGE_THIS_ADMIN_USERNAME
KEYCLOAK_ADMIN_PASSWORD=CHANGE_THIS_SECURE_ADMIN_PASSWORD_123!

# =============================================================================
# Database Production Configuration  
# =============================================================================
POSTGRES_DB=keycloak_prod
POSTGRES_USER=keycloak_prod_user
POSTGRES_PASSWORD=CHANGE_THIS_DB_PASSWORD_456!

# External database (if using managed service)
DB_HOST=your-postgres-host.amazonaws.com
DB_PORT=5432
DB_NAME=keycloak_prod
DB_USER=keycloak_prod_user
DB_PASSWORD=CHANGE_THIS_DB_PASSWORD_456!
DB_SSL_MODE=require

# =============================================================================
# Redis Production Configuration
# =============================================================================
REDIS_URL=your-redis-host:6379
REDIS_PASSWORD=CHANGE_THIS_REDIS_PASSWORD_789!
REDIS_DB=0
REDIS_SSL=true

# =============================================================================
# API Gateway Production Configuration
# =============================================================================
GATEWAY_PORT=8081
GATEWAY_HOST=api.yourinstitution.edu

# =============================================================================
# OAuth2 Client Production Configuration
# =============================================================================
CLIENT_ID=zipcode-portal-production
CLIENT_SECRET=CHANGE_THIS_CLIENT_SECRET_ABC123!
REDIRECT_URI=https://portal.yourinstitution.edu/callback
JWT_ISSUER=https://auth.yourinstitution.edu/realms/zipcodewilmington

# =============================================================================
# Application Production Configuration
# =============================================================================
APP_PORT=3000
NODE_ENV=production
DEBUG_MODE=false
USE_MOCK_DATA=false

# =============================================================================
# Security Configuration
# =============================================================================
SESSION_SECRET=CHANGE_THIS_SESSION_SECRET_64_CHARS_RANDOM_STRING_XYZ789!
SESSION_TIMEOUT=3600
CORS_ORIGIN=https://yourinstitution.edu,https://portal.yourinstitution.edu

# Rate limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW=900
RATE_LIMIT_MAX=100

# =============================================================================
# SSL/TLS Configuration
# =============================================================================
SSL_CERT_PATH=/etc/letsencrypt/live/yourinstitution.edu/fullchain.pem
SSL_KEY_PATH=/etc/letsencrypt/live/yourinstitution.edu/privkey.pem

# =============================================================================
# Monitoring and Logging
# =============================================================================
LOG_LEVEL=warn
ENABLE_METRICS=true
METRICS_PORT=9090

# Logging
LOG_FORMAT=json
LOG_FILE=/var/log/zipcode-oauth2/app.log
AUDIT_LOG_ENABLED=true
AUDIT_LOG_FILE=/var/log/zipcode-oauth2/audit.log

# =============================================================================
# Email Configuration (Production SMTP)
# =============================================================================
SMTP_HOST=smtp.yourinstitution.edu
SMTP_PORT=587
SMTP_USER=noreply@yourinstitution.edu
SMTP_PASSWORD=CHANGE_THIS_SMTP_PASSWORD_DEF456!
SMTP_FROM=ZipCode OAuth2 Hub <noreply@yourinstitution.edu>
SMTP_SECURE=true

# =============================================================================
# File Storage Configuration
# =============================================================================
STORAGE_TYPE=s3
S3_BUCKET=zipcode-oauth2-production
S3_REGION=us-east-1
S3_ACCESS_KEY=YOUR_S3_ACCESS_KEY
S3_SECRET_KEY=YOUR_S3_SECRET_KEY

# =============================================================================
# Backup Configuration
# =============================================================================
BACKUP_ENABLED=true
BACKUP_SCHEDULE=0 2 * * *  # Daily at 2 AM
BACKUP_RETENTION_DAYS=30
BACKUP_S3_BUCKET=zipcode-oauth2-backups

# =============================================================================
# Educational Institution Settings
# =============================================================================
INSTITUTION_NAME=Your Institution Name
INSTITUTION_DOMAIN=yourinstitution.edu
DEFAULT_COHORT=2024-fall-production
ENABLE_TIME_POLICIES=true
ENABLE_COHORT_ISOLATION=true

# Academic calendar
ACADEMIC_YEAR=2024-2025
SEMESTER_START=2024-09-01
SEMESTER_END=2025-05-15

# =============================================================================
# Performance Configuration
# =============================================================================
MAX_CONNECTIONS=100
CONNECTION_TIMEOUT=30000
KEEP_ALIVE_TIMEOUT=5000

# JVM settings for Keycloak
JAVA_OPTS=-Xms2g -Xmx4g -XX:+UseG1GC
```

### Secure Environment File

```bash
# Set secure permissions on production environment
chmod 600 .env.production
sudo chown root:root .env.production

# Create symlink for easy access
ln -sf .env.production .env
```

---

## Database Setup

### Option 1: Managed Database Service (Recommended)

**AWS RDS PostgreSQL:**
```bash
# Create RDS instance
aws rds create-db-instance \
    --db-name keycloak_prod \
    --db-instance-identifier zipcode-oauth2-prod \
    --db-instance-class db.t3.large \
    --engine postgres \
    --engine-version 15.3 \
    --master-username keycloak_prod_user \
    --master-user-password "SECURE_PASSWORD_HERE" \
    --allocated-storage 100 \
    --storage-type gp3 \
    --storage-encrypted \
    --vpc-security-group-ids sg-12345678 \
    --backup-retention-period 7 \
    --multi-az
```

### Option 2: Self-Hosted PostgreSQL

```bash
# Create production PostgreSQL container
docker run -d \
  --name postgres-prod \
  --restart unless-stopped \
  -e POSTGRES_DB=keycloak_prod \
  -e POSTGRES_USER=keycloak_prod_user \
  -e POSTGRES_PASSWORD="SECURE_PASSWORD_HERE" \
  -v postgres_prod_data:/var/lib/postgresql/data \
  -v /opt/zipcode-oauth2/backups:/backups \
  --network zipcode-auth-network \
  postgres:15

# Secure PostgreSQL configuration
docker exec -it postgres-prod psql -U keycloak_prod_user -d keycloak_prod -c "
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 1000;
SELECT pg_reload_conf();
"
```

### Database Initialization

```sql
-- Connect to production database
-- Create additional security configurations
CREATE ROLE keycloak_readonly;
GRANT CONNECT ON DATABASE keycloak_prod TO keycloak_readonly;
GRANT USAGE ON SCHEMA public TO keycloak_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO keycloak_readonly;

-- Create backup user
CREATE ROLE backup_user WITH LOGIN PASSWORD 'BACKUP_PASSWORD_HERE';
GRANT pg_read_all_data TO backup_user;
```

---

## Docker Production Deployment

### Production Docker Compose

Create `/opt/zipcode-oauth2/docker-compose.production.yml`:

```yaml
version: '3.8'

services:
  # Keycloak Authentication Server
  keycloak:
    image: quay.io/keycloak/keycloak:22.0
    container_name: zipcode-keycloak-prod
    restart: unless-stopped
    environment:
      # Database
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=require
      KC_DB_USERNAME: ${DB_USER}
      KC_DB_PASSWORD: ${DB_PASSWORD}
      
      # Hostname and SSL
      KC_HOSTNAME: ${KC_HOSTNAME}
      KC_HOSTNAME_STRICT: ${KC_HOSTNAME_STRICT}
      KC_HTTP_ENABLED: ${KC_HTTP_ENABLED}
      KC_HOSTNAME_STRICT_HTTPS: ${KC_HOSTNAME_STRICT_HTTPS}
      KC_PROXY: ${KC_PROXY}
      
      # Admin credentials
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      
      # JVM Performance
      JAVA_OPTS: ${JAVA_OPTS}
      
    command: start --import-realm --optimized
    ports:
      - "127.0.0.1:8080:8080"  # Only bind to localhost
    volumes:
      - ./config/keycloak/realm-export.json:/opt/keycloak/data/import/realm.json:ro
      - keycloak_data:/opt/keycloak/data
      - /var/log/zipcode-oauth2:/var/log/keycloak
    networks:
      - zipcode-auth-network
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/health/ready || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 90s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # API Gateway
  api-gateway:
    build:
      context: .
      dockerfile: cmd/gateway/Dockerfile
    container_name: zipcode-gateway-prod
    restart: unless-stopped
    environment:
      - KEYCLOAK_URL=${KEYCLOAK_URL}
      - KEYCLOAK_REALM=${KEYCLOAK_REALM}
      - GATEWAY_PORT=${GATEWAY_PORT}
      - GATEWAY_HOST=${GATEWAY_HOST}
      - LOG_LEVEL=${LOG_LEVEL}
      - METRICS_PORT=${METRICS_PORT}
    ports:
      - "127.0.0.1:8081:8081"  # Only bind to localhost
    depends_on:
      - keycloak
    networks:
      - zipcode-auth-network
    volumes:
      - /var/log/zipcode-oauth2:/var/log/gateway
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8081/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Redis Cache (if not using external)
  redis:
    image: redis:7-alpine
    container_name: zipcode-redis-prod
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - redis_prod_data:/data
      - ./config/redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
    networks:
      - zipcode-auth-network
    healthcheck:
      test: ["CMD-SHELL", "redis-cli --pass ${REDIS_PASSWORD} ping | grep PONG"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Example Application (Production)
  student-portal:
    build:
      context: .
      dockerfile: examples/productivity-app1/Dockerfile
    container_name: zipcode-portal-prod
    restart: unless-stopped
    environment:
      - KEYCLOAK_URL=${KEYCLOAK_URL}
      - CLIENT_ID=${CLIENT_ID}
      - REDIRECT_URI=${REDIRECT_URI}
      - APP_PORT=${APP_PORT}
      - NODE_ENV=${NODE_ENV}
    ports:
      - "127.0.0.1:3000:3000"
    depends_on:
      - api-gateway
    networks:
      - zipcode-auth-network
    volumes:
      - /var/log/zipcode-oauth2:/var/log/portal
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:3000 || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  keycloak_data:
    driver: local
  redis_prod_data:
    driver: local

networks:
  zipcode-auth-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### Production Dockerfile for Gateway

Create `cmd/gateway/Dockerfile`:

```dockerfile
FROM golang:1.21-alpine AS builder

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o gateway cmd/gateway/main.go

FROM alpine:3.18

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates curl

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/gateway .

# Create non-root user
RUN addgroup -g 1001 -S gateway && \
    adduser -u 1001 -S gateway -G gateway

USER gateway

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8081/health || exit 1

CMD ["./gateway"]
```

### Deploy to Production

```bash
# Navigate to production directory
cd /opt/zipcode-oauth2

# Create log directories
sudo mkdir -p /var/log/zipcode-oauth2
sudo chown $USER:docker /var/log/zipcode-oauth2

# Pull latest images
docker-compose -f docker-compose.production.yml pull

# Start production services
docker-compose -f docker-compose.production.yml up -d

# Verify services are running
docker-compose -f docker-compose.production.yml ps

# Check logs
docker-compose -f docker-compose.production.yml logs -f
```

---

## Reverse Proxy Configuration

### Nginx Configuration

Create `/etc/nginx/sites-available/zipcode-oauth2`:

```nginx
# Rate limiting
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;

# Upstream servers
upstream keycloak_backend {
    server 127.0.0.1:8080 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

upstream api_gateway_backend {
    server 127.0.0.1:8081 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

upstream portal_backend {
    server 127.0.0.1:3000 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

# Authentication Server (Keycloak)
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.yourinstitution.edu;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/auth.yourinstitution.edu/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourinstitution.edu/privkey.pem;
    
    # SSL Security Headers
    include /etc/nginx/snippets/ssl-params.conf;
    
    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;" always;

    # Rate limiting
    limit_req zone=auth_limit burst=20 nodelay;

    # Logging
    access_log /var/log/nginx/auth.yourinstitution.edu.access.log;
    error_log /var/log/nginx/auth.yourinstitution.edu.error.log;

    # Proxy settings
    location / {
        proxy_pass http://keycloak_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # Keycloak specific headers
        proxy_set_header X-Forwarded-Host $host;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
    }

    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://keycloak_backend/health/ready;
    }
}

# API Gateway
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.yourinstitution.edu;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/api.yourinstitution.edu/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourinstitution.edu/privkey.pem;
    
    include /etc/nginx/snippets/ssl-params.conf;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate limiting
    limit_req zone=api_limit burst=200 nodelay;

    # Logging
    access_log /var/log/nginx/api.yourinstitution.edu.access.log;
    error_log /var/log/nginx/api.yourinstitution.edu.error.log;

    location / {
        proxy_pass http://api_gateway_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # CORS headers
        add_header Access-Control-Allow-Origin "https://portal.yourinstitution.edu" always;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Authorization, Content-Type, Accept" always;
        
        if ($request_method = 'OPTIONS') {
            return 204;
        }
    }

    location /health {
        access_log off;
        proxy_pass http://api_gateway_backend/health;
    }
}

# Student Portal
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name portal.yourinstitution.edu;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/portal.yourinstitution.edu/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/portal.yourinstitution.edu/privkey.pem;
    
    include /etc/nginx/snippets/ssl-params.conf;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logging
    access_log /var/log/nginx/portal.yourinstitution.edu.access.log;
    error_log /var/log/nginx/portal.yourinstitution.edu.error.log;

    location / {
        proxy_pass http://portal_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name auth.yourinstitution.edu api.yourinstitution.edu portal.yourinstitution.edu;
    
    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # Redirect everything else to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}
```

### SSL Configuration Snippet

Create `/etc/nginx/snippets/ssl-params.conf`:

```nginx
# SSL Configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_prefer_server_ciphers off;

# SSL Session Configuration
ssl_session_timeout 10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### Enable Nginx Configuration

```bash
# Test configuration
sudo nginx -t

# Enable site
sudo ln -s /etc/nginx/sites-available/zipcode-oauth2 /etc/nginx/sites-enabled/

# Reload nginx
sudo systemctl reload nginx
```

---

## Security Hardening

### Operating System Security

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install security tools
sudo apt install -y fail2ban rkhunter chkrootkit aide

# Configure automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Fail2ban Configuration

Create `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[nginx-req-limit]
enabled = true
filter = nginx-req-limit
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 600
bantime = 7200
```

### Docker Security

```bash
# Create Docker security configuration
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true,
    "seccomp-profile": "/etc/docker/seccomp.json"
}
EOF

sudo systemctl restart docker
```

### Application Security

```bash
# Create secure directories
sudo mkdir -p /var/log/zipcode-oauth2
sudo mkdir -p /opt/zipcode-oauth2/backups
sudo mkdir -p /opt/zipcode-oauth2/secrets

# Set proper permissions
sudo chown root:docker /opt/zipcode-oauth2
sudo chmod 750 /opt/zipcode-oauth2
sudo chmod 600 /opt/zipcode-oauth2/.env.production
```

---

## Monitoring and Logging

### Prometheus Configuration

Create `/opt/zipcode-oauth2/monitoring/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alerts.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'keycloak'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'

  - job_name: 'api-gateway'
    static_configs:
      - targets: ['localhost:9091']
    metrics_path: '/metrics'

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['localhost:9187']
```

### Grafana Dashboard Configuration

```bash
# Start monitoring stack
docker run -d \
  --name prometheus \
  --restart unless-stopped \
  -p 127.0.0.1:9090:9090 \
  -v /opt/zipcode-oauth2/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro \
  prom/prometheus

docker run -d \
  --name grafana \
  --restart unless-stopped \
  -p 127.0.0.1:3001:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=SECURE_GRAFANA_PASSWORD \
  grafana/grafana
```

### Log Management

```bash
# Configure rsyslog for centralized logging
sudo tee /etc/rsyslog.d/30-zipcode-oauth2.conf <<EOF
# ZipCode OAuth2 Hub Logs
$template ZipCodeOAuth2Format,"%timegenerated% %hostname% %syslogtag% %msg%\n"

# Application logs
:programname,isequal,"zipcode-oauth2" /var/log/zipcode-oauth2/application.log;ZipCodeOAuth2Format
:programname,isequal,"zipcode-oauth2" ~

# Audit logs
:programname,isequal,"zipcode-audit" /var/log/zipcode-oauth2/audit.log;ZipCodeOAuth2Format
:programname,isequal,"zipcode-audit" ~
EOF

sudo systemctl restart rsyslog
```

### Health Monitoring Script

Create `/opt/zipcode-oauth2/scripts/health-check.sh`:

```bash
#!/bin/bash

# Health check script for ZipCode OAuth2 Hub
LOG_FILE="/var/log/zipcode-oauth2/health.log"
ALERT_EMAIL="admin@yourinstitution.edu"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

check_service() {
    SERVICE=$1
    URL=$2
    
    if curl -f -s --max-time 10 $URL > /dev/null; then
        log_message "✅ $SERVICE is healthy"
        return 0
    else
        log_message "❌ $SERVICE is down"
        echo "$SERVICE is down at $(date)" | mail -s "ALERT: $SERVICE Down" $ALERT_EMAIL
        return 1
    fi
}

# Check all services
check_service "Keycloak" "https://auth.yourinstitution.edu/health/ready"
check_service "API Gateway" "https://api.yourinstitution.edu/health"
check_service "Student Portal" "https://portal.yourinstitution.edu/"

# Check Docker containers
if ! docker-compose -f /opt/zipcode-oauth2/docker-compose.production.yml ps | grep -q "Up"; then
    log_message "❌ Some Docker containers are not running"
    echo "Docker containers status issue at $(date)" | mail -s "ALERT: Container Status" $ALERT_EMAIL
fi

log_message "Health check completed"
```

```bash
# Make executable and add to cron
chmod +x /opt/zipcode-oauth2/scripts/health-check.sh

# Add to crontab (check every 5 minutes)
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/zipcode-oauth2/scripts/health-check.sh") | crontab -
```

---

## Backup and Recovery

### Database Backup Script

Create `/opt/zipcode-oauth2/scripts/backup-database.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/opt/zipcode-oauth2/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="keycloak_prod"
DB_USER="keycloak_prod_user"
DB_HOST="your-postgres-host.amazonaws.com"
S3_BUCKET="zipcode-oauth2-backups"

# Create backup directory
mkdir -p $BACKUP_DIR

# Create database dump
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME | gzip > $BACKUP_DIR/keycloak_backup_$DATE.sql.gz

# Upload to S3 (if configured)
if [ ! -z "$S3_BUCKET" ]; then
    aws s3 cp $BACKUP_DIR/keycloak_backup_$DATE.sql.gz s3://$S3_BUCKET/database/
fi

# Clean up local backups older than 7 days
find $BACKUP_DIR -name "keycloak_backup_*.sql.gz" -mtime +7 -delete

echo "Backup completed: keycloak_backup_$DATE.sql.gz"
```

### Application Data Backup

```bash
#!/bin/bash

# Backup Keycloak configuration and data
docker exec zipcode-keycloak-prod /opt/keycloak/bin/kc.sh export \
    --dir /tmp/backup \
    --realm zipcodewilmington

# Copy from container
docker cp zipcode-keycloak-prod:/tmp/backup/zipcodewilmington-realm.json \
    /opt/zipcode-oauth2/backups/realm-backup-$(date +%Y%m%d).json

# Backup application configuration
tar -czf /opt/zipcode-oauth2/backups/config-backup-$(date +%Y%m%d).tar.gz \
    /opt/zipcode-oauth2/.env.production \
    /opt/zipcode-oauth2/config/ \
    /etc/nginx/sites-available/zipcode-oauth2
```

### Automated Backup Schedule

```bash
# Add to root crontab
sudo crontab -e

# Add these lines:
# Database backup daily at 2 AM
0 2 * * * /opt/zipcode-oauth2/scripts/backup-database.sh >> /var/log/zipcode-oauth2/backup.log 2>&1

# Configuration backup weekly on Sunday at 3 AM
0 3 * * 0 /opt/zipcode-oauth2/scripts/backup-config.sh >> /var/log/zipcode-oauth2/backup.log 2>&1
```

### Recovery Procedures

```bash
# Database recovery
gunzip -c /opt/zipcode-oauth2/backups/keycloak_backup_YYYYMMDD_HHMMSS.sql.gz | \
    psql -h your-postgres-host.amazonaws.com -U keycloak_prod_user -d keycloak_prod

# Application recovery
docker-compose -f /opt/zipcode-oauth2/docker-compose.production.yml down
docker-compose -f /opt/zipcode-oauth2/docker-compose.production.yml up -d

# Keycloak realm recovery
docker exec -it zipcode-keycloak-prod /opt/keycloak/bin/kc.sh import \
    --file /tmp/backup/zipcodewilmington-realm.json
```

---

## Operational Procedures

### Deployment Checklist

**Pre-Deployment:**
- [ ] All passwords changed from defaults
- [ ] SSL certificates installed and valid
- [ ] DNS records configured and propagated
- [ ] Firewall rules configured
- [ ] Backup procedures tested
- [ ] Monitoring configured

**Deployment Steps:**
```bash
# 1. Pull latest code
cd /opt/zipcode-oauth2
git pull origin main

# 2. Update production configuration
nano .env.production

# 3. Stop services gracefully
docker-compose -f docker-compose.production.yml stop

# 4. Backup current state
./scripts/backup-database.sh
./scripts/backup-config.sh

# 5. Start services
docker-compose -f docker-compose.production.yml up -d

# 6. Verify deployment
./scripts/health-check.sh

# 7. Test authentication flow
curl -I https://auth.yourinstitution.edu/health/ready
curl -I https://api.yourinstitution.edu/health
curl -I https://portal.yourinstitution.edu/
```

### Maintenance Procedures

**Weekly Maintenance:**
```bash
#!/bin/bash
# /opt/zipcode-oauth2/scripts/weekly-maintenance.sh

# Update system packages
sudo apt update && sudo apt upgrade -y

# Clean Docker images
docker system prune -f

# Rotate logs
logrotate -f /etc/logrotate.d/zipcode-oauth2

# Check disk space
df -h | grep -E "(/$|/opt|/var)"

# Verify SSL certificates
./scripts/check-ssl-expiry.sh

# Generate weekly report
./scripts/generate-weekly-report.sh
```

**Monthly Maintenance:**
- Security audit and vulnerability scan
- Performance review and optimization
- Database maintenance (VACUUM, ANALYZE)
- SSL certificate renewal check
- Backup verification and recovery test

### Rolling Updates

```bash
#!/bin/bash
# /opt/zipcode-oauth2/scripts/rolling-update.sh

SERVICE=$1

if [ -z "$SERVICE" ]; then
    echo "Usage: $0 <service-name>"
    exit 1
fi

# Health check before update
./scripts/health-check.sh

# Update specific service
docker-compose -f docker-compose.production.yml pull $SERVICE
docker-compose -f docker-compose.production.yml up -d --no-deps $SERVICE

# Wait for service to be healthy
sleep 30
./scripts/health-check.sh

echo "Rolling update of $SERVICE completed"
```

---

## Troubleshooting

### Common Issues and Solutions

#### SSL Certificate Issues

**Problem:** SSL certificate not loading properly
```bash
# Check certificate validity
openssl x509 -in /etc/letsencrypt/live/auth.yourinstitution.edu/cert.pem -text -noout

# Renew certificate manually
sudo certbot renew --force-renewal

# Restart nginx
sudo systemctl reload nginx
```

#### Database Connection Issues

**Problem:** Keycloak cannot connect to database
```bash
# Check database connectivity
docker exec zipcode-keycloak-prod pg_isready -h $DB_HOST -U $DB_USER

# Check database logs
docker logs postgres-prod

# Verify environment variables
docker exec zipcode-keycloak-prod printenv | grep KC_DB
```

#### Performance Issues

**Problem:** Slow response times
```bash
# Check resource usage
htop
docker stats

# Check Keycloak logs for performance issues
docker logs zipcode-keycloak-prod | grep -i "slow"

# Analyze nginx access logs
tail -f /var/log/nginx/access.log | awk '{print $1,$4,$7,$9,$10}'
```

#### Memory Issues

**Problem:** Out of memory errors
```bash
# Check memory usage
free -h
docker stats --no-stream

# Increase JVM heap size for Keycloak
# Edit .env.production:
JAVA_OPTS=-Xms4g -Xmx8g -XX:+UseG1GC

# Restart Keycloak
docker-compose -f docker-compose.production.yml restart keycloak
```

### Emergency Procedures

#### Service Down Recovery

```bash
#!/bin/bash
# Emergency recovery script

echo "🚨 Emergency Recovery Started at $(date)"

# Stop all services
docker-compose -f /opt/zipcode-oauth2/docker-compose.production.yml down

# Check disk space
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 90 ]; then
    echo "❌ Disk space critical: ${DISK_USAGE}%"
    # Clean up logs
    find /var/log -name "*.log" -mtime +7 -delete
    docker system prune -f
fi

# Check database connectivity
if ! pg_isready -h $DB_HOST -U $DB_USER; then
    echo "❌ Database connectivity issue"
    # Implement database failover logic here
fi

# Restore from last known good backup if needed
if [ "$1" == "--restore" ]; then
    echo "🔄 Restoring from backup..."
    ./scripts/restore-from-backup.sh
fi

# Start services
docker-compose -f /opt/zipcode-oauth2/docker-compose.production.yml up -d

# Wait for services to stabilize
sleep 60

# Verify recovery
./scripts/health-check.sh

echo "✅ Emergency recovery completed at $(date)"
```

#### Security Incident Response

```bash
#!/bin/bash
# Security incident response

echo "🔒 Security incident response initiated"

# Immediately rotate all sensitive credentials
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Backup current environment
cp .env.production .env.backup.$TIMESTAMP

# Generate new passwords
KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
SESSION_SECRET=$(openssl rand -base64 64)

# Update environment file with new credentials
sed -i "s/KEYCLOAK_ADMIN_PASSWORD=.*/KEYCLOAK_ADMIN_PASSWORD=$KEYCLOAK_ADMIN_PASSWORD/" .env.production
sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$DB_PASSWORD/" .env.production
sed -i "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" .env.production
sed -i "s/SESSION_SECRET=.*/SESSION_SECRET=$SESSION_SECRET/" .env.production

# Restart all services with new credentials
docker-compose -f docker-compose.production.yml down
docker-compose -f docker-compose.production.yml up -d

# Force logout all users
curl -X POST "https://auth.yourinstitution.edu/admin/realms/zipcodewilmington/logout-all" \
    -H "Authorization: Bearer $ADMIN_TOKEN"

# Log security incident
echo "$(date): Security incident - credentials rotated, all users logged out" >> /var/log/zipcode-oauth2/security.log

# Send notification
echo "Security incident response completed. New credentials generated." | \
    mail -s "SECURITY: Credentials Rotated" admin@yourinstitution.edu

echo "🔒 Security incident response completed"
```

---

## Performance Optimization

### Keycloak Optimization

```bash
# Production JVM settings for Keycloak
JAVA_OPTS="-Xms4g -Xmx8g -XX:+UseG1GC -XX:MaxGCPauseMillis=100 -XX:+DisableExplicitGC"

# Database connection pool optimization
KC_DB_POOL_INITIAL_SIZE=20
KC_DB_POOL_MIN_SIZE=10
KC_DB_POOL_MAX_SIZE=50
```

### Database Optimization

```sql
-- PostgreSQL performance tuning
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET effective_cache_size = '6GB';
ALTER SYSTEM SET maintenance_work_mem = '512MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
ALTER SYSTEM SET work_mem = '64MB';

SELECT pg_reload_conf();
```

### Redis Optimization

```redis
# Redis configuration for production
maxmemory 4gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
tcp-keepalive 60
timeout 300
```

This comprehensive production setup guide provides everything needed to deploy the ZipCode OAuth2 Hub securely and reliably in a production environment. Make sure to customize all the placeholder values (domain names, passwords, etc.) for your specific institution and environment.

---

**Security Note:** This guide contains placeholder passwords and configurations. **ALL CREDENTIALS MUST BE CHANGED** before production deployment. Never use the example passwords or default values in a production environment.

**Last Updated:** November 18, 2025  
**Version:** 1.0.0