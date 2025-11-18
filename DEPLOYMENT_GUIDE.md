# ZipCode OAuth2 Hub - Deployment Guide

Complete production deployment guide for the ZipCode OAuth2 Hub authentication and authorization system.

## 📖 Table of Contents

- [Overview](#overview)
- [System Requirements](#system-requirements)
- [Development Environment](#development-environment)
- [Production Deployment](#production-deployment)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Configuration Management](#configuration-management)
- [SSL/TLS Setup](#ssltls-setup)
- [Monitoring and Observability](#monitoring-and-observability)
- [Backup and Recovery](#backup-and-recovery)
- [Security Hardening](#security-hardening)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)
- [Maintenance Procedures](#maintenance-procedures)

---

## Overview

The ZipCode OAuth2 Hub consists of several components that work together to provide authentication and authorization services:

- **Keycloak** - OAuth2/OIDC server for authentication
- **PostgreSQL** - Primary database for user data and configurations
- **Redis** - Caching layer for sessions and authorization decisions
- **API Gateway** - JWT validation and educational policy enforcement
- **Educational Applications** - Client applications that integrate with the hub

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Load Balancer                            │
│                     (nginx/AWS ALB)                             │
└─────────────────┬─────────────────┬─────────────────────────────┘
                  │                 │
                  │                 │
┌─────────────────▼─────────────────▼─────────────────────────────┐
│                    API Gateway Cluster                          │
│               (Multiple instances for HA)                       │
└─────────────────┬─────────────────────────────────────────────┘
                  │
┌─────────────────▼─────────────────────────────────────────────┐
│                   Keycloak Cluster                             │
│              (Active-Active configuration)                     │
└─────────────────┬─────────────────────────────────────────────┘
                  │
      ┌───────────▼───────────┐    ┌─────────────────────────────┐
      │    PostgreSQL         │    │         Redis              │
      │   (Primary/Replica)   │    │      (Sentinel/Cluster)    │
      └───────────────────────┘    └─────────────────────────────┘
```

---

## System Requirements

### Minimum Requirements (Development)

| Component | CPU | Memory | Storage | Network |
|-----------|-----|--------|---------|---------|
| **API Gateway** | 1 vCPU | 1 GB | 10 GB | 100 Mbps |
| **Keycloak** | 2 vCPU | 2 GB | 20 GB | 100 Mbps |
| **PostgreSQL** | 2 vCPU | 4 GB | 50 GB | 100 Mbps |
| **Redis** | 1 vCPU | 2 GB | 10 GB | 100 Mbps |

### Production Requirements

| Component | CPU | Memory | Storage | Network |
|-----------|-----|--------|---------|---------|
| **API Gateway** | 4 vCPU | 4 GB | 50 GB | 1 Gbps |
| **Keycloak** | 8 vCPU | 8 GB | 100 GB | 1 Gbps |
| **PostgreSQL** | 8 vCPU | 16 GB | 500 GB SSD | 1 Gbps |
| **Redis** | 4 vCPU | 8 GB | 100 GB | 1 Gbps |

### Supported Platforms
- **Operating Systems:** Ubuntu 20.04+, CentOS 8+, RHEL 8+, Amazon Linux 2
- **Container Platforms:** Docker 20.10+, Kubernetes 1.20+
- **Cloud Providers:** AWS, Azure, GCP, DigitalOcean

---

## Development Environment

### Quick Setup with Make

```bash
# Clone the repository
git clone https://github.com/zipcodewilmington/oauth2-hub.git
cd oauth2-hub

# Complete development setup
make setup          # Install dependencies and create .env
make docker-up      # Start all infrastructure services
make dev           # Run API gateway and example applications
```

### Manual Development Setup

#### 1. Prerequisites Installation

**Go Installation (1.21+):**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install golang-go

# CentOS/RHEL
sudo yum install golang

# macOS
brew install go

# Verify installation
go version
```

**Docker and Docker Compose:**
```bash
# Ubuntu/Debian
sudo apt install docker.io docker-compose

# CentOS/RHEL  
sudo yum install docker docker-compose

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker
```

#### 2. Environment Configuration

**Create `.env` file:**
```bash
cp .env.example .env
```

**Edit configuration:**
```env
# Development Configuration
NODE_ENV=development
LOG_LEVEL=debug

# Keycloak Configuration
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=zipcodewilmington
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=keycloak
DB_USER=keycloak
DB_PASSWORD=keycloak_pass

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=

# API Gateway Configuration
GATEWAY_PORT=8081
GATEWAY_HOST=0.0.0.0

# Security Configuration
JWT_ISSUER=http://localhost:8080/realms/zipcodewilmington
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
```

#### 3. Start Infrastructure Services

```bash
cd config/docker
docker-compose up -d

# Wait for services to start
docker-compose logs -f keycloak  # Monitor Keycloak startup
```

#### 4. Build and Run Applications

```bash
# Install Go dependencies
go mod download

# Build API Gateway
go build -o bin/gateway cmd/gateway/main.go

# Run API Gateway
./bin/gateway

# In separate terminals, run example applications
cd examples/productivity-app1
go run main.go
```

---

## Production Deployment

### Infrastructure Preparation

#### 1. Server Provisioning

**AWS Example (using Terraform):**
```hcl
# infrastructure/aws/main.tf
resource "aws_instance" "keycloak" {
  count           = 2
  ami             = "ami-0c02fb55956c7d316"  # Ubuntu 20.04
  instance_type   = "m5.xlarge"
  key_name        = var.key_pair_name
  security_groups = [aws_security_group.keycloak.name]
  
  tags = {
    Name = "keycloak-${count.index + 1}"
    Environment = "production"
  }
}

resource "aws_rds_instance" "postgres" {
  identifier     = "zipcode-oauth2-db"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.large"
  storage_type   = "gp2"
  allocated_storage = 500
  
  db_name  = "keycloak"
  username = var.db_username
  password = var.db_password
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "Sun:04:00-Sun:05:00"
  
  tags = {
    Name = "zipcode-oauth2-db"
    Environment = "production"
  }
}
```

#### 2. Network Configuration

**Security Groups (AWS):**
```hcl
resource "aws_security_group" "keycloak" {
  name = "zipcode-keycloak-sg"
  
  # HTTPS traffic
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # HTTP (redirect to HTTPS)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"  
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Internal communication
  ingress {
    from_port = 8080
    to_port   = 8080
    protocol  = "tcp"
    self      = true
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

### Application Deployment

#### 1. Binary Deployment

**Build for Production:**
```bash
# Build optimized binaries
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-w -s -X main.Version=$(git describe --tags --always)" \
  -o bin/gateway-linux-amd64 cmd/gateway/main.go

# Create deployment package
tar -czf zipcode-oauth2-hub-$(git describe --tags --always).tar.gz \
  bin/ config/ scripts/
```

**Deploy to Servers:**
```bash
# Upload to production servers
scp zipcode-oauth2-hub-*.tar.gz production-server:/opt/zipcode-oauth2/

# On production server
cd /opt/zipcode-oauth2
tar -xzf zipcode-oauth2-hub-*.tar.gz

# Install as systemd service
sudo cp scripts/systemd/zipcode-oauth2-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zipcode-oauth2-gateway
sudo systemctl start zipcode-oauth2-gateway
```

**Systemd Service File:**
```ini
# scripts/systemd/zipcode-oauth2-gateway.service
[Unit]
Description=ZipCode OAuth2 Hub API Gateway
After=network.target

[Service]
Type=simple
User=zipcode
Group=zipcode
WorkingDirectory=/opt/zipcode-oauth2
ExecStart=/opt/zipcode-oauth2/bin/gateway-linux-amd64
ExecReload=/bin/kill -USR1 $MAINPID
Restart=always
RestartSec=5

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/zipcode-oauth2/logs

# Environment
Environment=NODE_ENV=production
EnvironmentFile=/opt/zipcode-oauth2/.env

[Install]
WantedBy=multi-user.target
```

#### 2. Database Setup

**PostgreSQL Configuration:**
```bash
# Install PostgreSQL 15
sudo apt update
sudo apt install postgresql-15 postgresql-client-15

# Configure PostgreSQL
sudo -u postgres createuser keycloak
sudo -u postgres createdb keycloak -O keycloak
sudo -u postgres psql -c "ALTER USER keycloak WITH PASSWORD 'secure_password';"

# Tune PostgreSQL for production
sudo cp config/postgresql/postgresql.conf /etc/postgresql/15/main/
sudo systemctl restart postgresql
```

**Production PostgreSQL Settings:**
```ini
# config/postgresql/postgresql.conf
# Memory settings
shared_buffers = 2GB
effective_cache_size = 8GB
work_mem = 64MB
maintenance_work_mem = 512MB

# Connection settings
max_connections = 200
max_prepared_transactions = 200

# Performance settings
checkpoint_completion_target = 0.9
wal_buffers = 64MB
default_statistics_target = 100

# Logging
log_statement = 'mod'
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
```

#### 3. Redis Setup

**Redis Configuration:**
```bash
# Install Redis
sudo apt install redis-server

# Configure Redis for production
sudo cp config/redis/redis.conf /etc/redis/
sudo systemctl restart redis-server
```

**Production Redis Settings:**
```ini
# config/redis/redis.conf
# Network
bind 127.0.0.1
port 6379
timeout 300
tcp-keepalive 300

# Memory management
maxmemory 4gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000

# Security
requirepass secure_redis_password
```

---

## Docker Deployment

### Production Docker Configuration

**Multi-stage Dockerfile for API Gateway:**
```dockerfile
# Dockerfile.production
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o gateway cmd/gateway/main.go

FROM alpine:3.18
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

# Create non-root user
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

COPY --from=builder /app/gateway .
COPY --chown=appuser:appgroup config/ config/

USER appuser
EXPOSE 8081

CMD ["./gateway"]
```

**Production Docker Compose:**
```yaml
# docker-compose.production.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    container_name: zipcode-postgres
    environment:
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./config/postgresql/init:/docker-entrypoint-initdb.d
    networks:
      - zipcode-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER}"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    container_name: zipcode-redis
    command: redis-server /usr/local/etc/redis/redis.conf
    volumes:
      - redis_data:/data
      - ./config/redis/redis.conf:/usr/local/etc/redis/redis.conf
    networks:
      - zipcode-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    container_name: zipcode-keycloak
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres/${DB_NAME}
      KC_DB_USERNAME: ${DB_USER}
      KC_DB_PASSWORD: ${DB_PASSWORD}
      KC_HOSTNAME: ${KEYCLOAK_HOSTNAME}
      KC_HTTP_ENABLED: true
      KC_PROXY: edge
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
    ports:
      - "8080:8080"
    volumes:
      - ./config/keycloak/realm-export.json:/opt/keycloak/data/import/realm.json
      - ./config/keycloak/themes:/opt/keycloak/themes
    command: start --import-realm
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - zipcode-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  gateway:
    build:
      context: .
      dockerfile: Dockerfile.production
      args:
        VERSION: ${VERSION}
    container_name: zipcode-gateway
    environment:
      KEYCLOAK_URL: http://keycloak:8080
      REDIS_URL: redis://redis:6379
      GATEWAY_PORT: 8081
    ports:
      - "8081:8081"
    depends_on:
      keycloak:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - zipcode-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  postgres_data:
  redis_data:

networks:
  zipcode-network:
    driver: bridge
```

### Docker Deployment Commands

```bash
# Production deployment
docker-compose -f docker-compose.production.yml up -d

# View logs
docker-compose -f docker-compose.production.yml logs -f

# Update services
docker-compose -f docker-compose.production.yml pull
docker-compose -f docker-compose.production.yml up -d --remove-orphans

# Backup volumes
docker run --rm -v zipcode-postgres-data:/data -v $(pwd):/backup alpine \
  tar -czf /backup/postgres-backup-$(date +%Y%m%d).tar.gz -C /data .
```

---

## Kubernetes Deployment

### Namespace and RBAC

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: zipcode-oauth2
  labels:
    name: zipcode-oauth2

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: zipcode-oauth2-sa
  namespace: zipcode-oauth2

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: zipcode-oauth2-role
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: zipcode-oauth2-binding
subjects:
- kind: ServiceAccount
  name: zipcode-oauth2-sa
  namespace: zipcode-oauth2
roleRef:
  kind: ClusterRole
  name: zipcode-oauth2-role
  apiGroup: rbac.authorization.k8s.io
```

### ConfigMap and Secrets

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: zipcode-oauth2-config
  namespace: zipcode-oauth2
data:
  KEYCLOAK_REALM: "zipcodewilmington"
  GATEWAY_PORT: "8081"
  DB_NAME: "keycloak"
  LOG_LEVEL: "info"

---
apiVersion: v1
kind: Secret
metadata:
  name: zipcode-oauth2-secrets
  namespace: zipcode-oauth2
type: Opaque
stringData:
  DB_PASSWORD: "secure_db_password"
  KEYCLOAK_ADMIN_PASSWORD: "secure_admin_password"
  REDIS_PASSWORD: "secure_redis_password"
```

### PostgreSQL Deployment

```yaml
# k8s/postgres.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: zipcode-oauth2
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      serviceAccountName: zipcode-oauth2-sa
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_DB
          valueFrom:
            configMapKeyRef:
              name: zipcode-oauth2-config
              key: DB_NAME
        - name: POSTGRES_USER
          value: "keycloak"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: zipcode-oauth2-secrets
              key: DB_PASSWORD
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - keycloak
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - keycloak
          initialDelaySeconds: 5
          periodSeconds: 5
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 100Gi

---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: zipcode-oauth2
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
```

### Keycloak Deployment

```yaml
# k8s/keycloak.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: zipcode-oauth2
spec:
  replicas: 2
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      serviceAccountName: zipcode-oauth2-sa
      containers:
      - name: keycloak
        image: quay.io/keycloak/keycloak:23.0
        args:
        - start
        - --db=postgres
        - --hostname-strict=false
        - --http-enabled=true
        - --import-realm
        env:
        - name: KC_DB_URL
          value: "jdbc:postgresql://postgres:5432/keycloak"
        - name: KC_DB_USERNAME
          value: "keycloak"
        - name: KC_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: zipcode-oauth2-secrets
              key: DB_PASSWORD
        - name: KEYCLOAK_ADMIN
          value: "admin"
        - name: KEYCLOAK_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: zipcode-oauth2-secrets
              key: KEYCLOAK_ADMIN_PASSWORD
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"

---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: zipcode-oauth2
spec:
  selector:
    app: keycloak
  ports:
  - port: 8080
    targetPort: 8080
  type: ClusterIP
```

### API Gateway Deployment

```yaml
# k8s/gateway.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway
  namespace: zipcode-oauth2
spec:
  replicas: 3
  selector:
    matchLabels:
      app: gateway
  template:
    metadata:
      labels:
        app: gateway
    spec:
      serviceAccountName: zipcode-oauth2-sa
      containers:
      - name: gateway
        image: zipcodewilmington/oauth2-hub-gateway:latest
        env:
        - name: KEYCLOAK_URL
          value: "http://keycloak:8080"
        - name: REDIS_URL
          value: "redis://redis:6379"
        - name: GATEWAY_PORT
          valueFrom:
            configMapKeyRef:
              name: zipcode-oauth2-config
              key: GATEWAY_PORT
        ports:
        - containerPort: 8081
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 10
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"

---
apiVersion: v1
kind: Service
metadata:
  name: gateway
  namespace: zipcode-oauth2
spec:
  selector:
    app: gateway
  ports:
  - port: 80
    targetPort: 8081
  type: ClusterIP

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: zipcode-oauth2-ingress
  namespace: zipcode-oauth2
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - auth.zipcodewilmington.edu
    secretName: zipcode-oauth2-tls
  rules:
  - host: auth.zipcodewilmington.edu
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: gateway
            port:
              number: 80
      - path: /
        pathType: Prefix
        backend:
          service:
            name: keycloak
            port:
              number: 8080
```

### Deployment Commands

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n zipcode-oauth2
kubectl get services -n zipcode-oauth2

# View logs
kubectl logs -f deployment/keycloak -n zipcode-oauth2
kubectl logs -f deployment/gateway -n zipcode-oauth2

# Scale services
kubectl scale deployment gateway --replicas=5 -n zipcode-oauth2

# Update deployment
kubectl set image deployment/gateway gateway=zipcodewilmington/oauth2-hub-gateway:v1.1.0 -n zipcode-oauth2
```

---

## SSL/TLS Setup

### Certificate Management

**Using Let's Encrypt with Certbot:**
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificates
sudo certbot --nginx -d auth.zipcodewilmington.edu

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

**Certificate Configuration for nginx:**
```nginx
# /etc/nginx/sites-available/zipcode-oauth2
server {
    listen 80;
    server_name auth.zipcodewilmington.edu;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.zipcodewilmington.edu;

    ssl_certificate /etc/letsencrypt/live/auth.zipcodewilmington.edu/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.zipcodewilmington.edu/privkey.pem;
    
    # SSL Security
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    # API Gateway
    location /api/ {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Keycloak
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
}
```

---

## Configuration Management

### Environment-Specific Configuration

**Production Configuration Template:**
```env
# Production Environment Configuration
NODE_ENV=production
LOG_LEVEL=info

# Keycloak Configuration
KEYCLOAK_URL=https://auth.zipcodewilmington.edu
KEYCLOAK_REALM=production
KEYCLOAK_ADMIN=${KEYCLOAK_ADMIN_USER}
KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD}

# Database Configuration
DB_HOST=${RDS_ENDPOINT}
DB_PORT=5432
DB_NAME=keycloak
DB_USER=keycloak
DB_PASSWORD=${DB_PASSWORD_SECRET}
DB_SSL_MODE=require

# Redis Configuration
REDIS_URL=redis://${ELASTICACHE_ENDPOINT}:6379
REDIS_PASSWORD=${REDIS_PASSWORD_SECRET}
REDIS_SSL=true

# API Gateway Configuration
GATEWAY_PORT=8081
GATEWAY_HOST=0.0.0.0

# Security Configuration
JWT_ISSUER=https://auth.zipcodewilmington.edu/realms/production
CORS_ALLOWED_ORIGINS=https://portal.zipcodewilmington.edu,https://student.zipcodewilmington.edu
RATE_LIMIT_REQUESTS_PER_MINUTE=120

# Monitoring Configuration
ENABLE_METRICS=true
METRICS_PORT=9090
HEALTH_CHECK_INTERVAL=30s

# Educational Configuration
DEFAULT_COHORT_DURATION_WEEKS=12
EXAM_TIME_BUFFER_MINUTES=5
LAB_HOURS_START=8
LAB_HOURS_END=20
MAX_SUBMISSION_ATTEMPTS=3
```

### Configuration Validation

**Configuration Checker Script:**
```bash
#!/bin/bash
# scripts/check-config.sh

set -e

echo "Validating ZipCode OAuth2 Hub configuration..."

# Check required environment variables
REQUIRED_VARS=(
    "KEYCLOAK_URL"
    "KEYCLOAK_REALM"
    "DB_HOST"
    "DB_NAME"
    "DB_USER"
    "DB_PASSWORD"
    "REDIS_URL"
    "JWT_ISSUER"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var}" ]]; then
        echo "ERROR: Required environment variable $var is not set"
        exit 1
    fi
done

# Check database connection
echo "Checking database connection..."
if ! PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null; then
    echo "ERROR: Cannot connect to database"
    exit 1
fi

# Check Redis connection
echo "Checking Redis connection..."
if ! redis-cli -u "$REDIS_URL" ping > /dev/null; then
    echo "ERROR: Cannot connect to Redis"
    exit 1
fi

# Check Keycloak connection
echo "Checking Keycloak connection..."
if ! curl -sf "$KEYCLOAK_URL/health" > /dev/null; then
    echo "ERROR: Cannot connect to Keycloak"
    exit 1
fi

echo "Configuration validation passed!"
```

---

## Monitoring and Observability

### Prometheus Metrics

**Gateway Metrics Endpoint:**
```go
// Add to cmd/gateway/main.go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    httpRequests = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "http_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "endpoint", "status"},
    )
    
    httpDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "http_request_duration_seconds",
            Help: "HTTP request duration in seconds",
        },
        []string{"method", "endpoint"},
    )
)

func init() {
    prometheus.MustRegister(httpRequests)
    prometheus.MustRegister(httpDuration)
}

// Add metrics endpoint
r.GET("/metrics", gin.WrapH(promhttp.Handler()))
```

**Prometheus Configuration:**
```yaml
# config/prometheus/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'zipcode-oauth2-gateway'
    static_configs:
    - targets: ['localhost:8081']
    metrics_path: /metrics
    scrape_interval: 10s

  - job_name: 'keycloak'
    static_configs:
    - targets: ['localhost:8080']
    metrics_path: /metrics

rule_files:
  - "zipcode-oauth2-rules.yml"

alerting:
  alertmanagers:
  - static_configs:
    - targets:
      - alertmanager:9093
```

### Grafana Dashboards

**Example Dashboard JSON:**
```json
{
  "dashboard": {
    "title": "ZipCode OAuth2 Hub",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph", 
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"4..|5..\"}[5m]) / rate(http_requests_total[5m])",
            "legendFormat": "Error Rate"
          }
        ]
      }
    ]
  }
}
```

### Log Management

**Structured Logging Configuration:**
```go
// pkg/logger/logger.go
import (
    "github.com/sirupsen/logrus"
)

func InitLogger() *logrus.Logger {
    log := logrus.New()
    
    if os.Getenv("NODE_ENV") == "production" {
        log.SetFormatter(&logrus.JSONFormatter{})
        log.SetLevel(logrus.InfoLevel)
    } else {
        log.SetFormatter(&logrus.TextFormatter{
            FullTimestamp: true,
        })
        log.SetLevel(logrus.DebugLevel)
    }
    
    return log
}
```

**Fluentd Configuration for Log Aggregation:**
```xml
# config/fluentd/fluent.conf
<source>
  @type tail
  path /var/log/zipcode-oauth2/*.log
  pos_file /var/log/fluentd/zipcode-oauth2.log.pos
  tag zipcode.oauth2
  format json
</source>

<match zipcode.**>
  @type elasticsearch
  host elasticsearch.example.com
  port 9200
  index_name zipcode-oauth2
  type_name access_log
</match>
```

---

This is a comprehensive deployment guide. Would you like me to continue with the remaining sections (Backup and Recovery, Security Hardening, Performance Tuning, etc.) or move on to creating the remaining documentation files?