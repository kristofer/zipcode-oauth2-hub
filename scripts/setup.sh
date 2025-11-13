#!/bin/bash

# ZipCode OAuth2 Hub Setup Script

set -e

echo "🚀 ZipCode OAuth2 Hub Setup"
echo "=========================="

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21 or higher."
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose."
    exit 1
fi

echo "✅ All prerequisites installed"

# Copy environment file
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✅ Created .env file"
else
    echo "ℹ️  .env file already exists"
fi

# Install Go dependencies
echo "Installing Go dependencies..."
go mod download
echo "✅ Go dependencies installed"

# Start Docker services
echo "Starting Docker services (Keycloak, PostgreSQL, Redis)..."
cd config/docker
docker-compose up -d
cd ../..

echo "Waiting for services to start (30 seconds)..."
sleep 30

# Check if Keycloak is running
echo "Checking Keycloak status..."
if curl -s http://localhost:8080/health > /dev/null; then
    echo "✅ Keycloak is running"
else
    echo "⚠️  Keycloak may still be starting. Check http://localhost:8080"
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Access Keycloak Admin Console: http://localhost:8080"
echo "   Username: admin"
echo "   Password: admin"
echo ""
echo "2. Start the API Gateway:"
echo "   make run-gateway"
echo ""
echo "3. Start the example app:"
echo "   make run-example"
echo ""
echo "4. Visit http://localhost:3000 to see the student portal"
echo ""
echo "For more information, see README.md"
