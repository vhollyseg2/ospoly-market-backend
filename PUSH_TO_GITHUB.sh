#!/bin/bash

echo "=========================================="
echo "   OSPOLY MARKET - PUSH TO GITHUB"
echo "=========================================="
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed!"
    echo "Please install git first: https://git-scm.com/downloads"
    exit 1
fi

echo "📦 Preparing Backend..."
cd /home/user/backend

# Initialize git if not already
git init 2>/dev/null || true

# Add all files
git add .

# Commit
git commit -m "Ospoly Market Backend - Production Ready"

echo ""
echo "📦 Preparing Frontend..."
cd /home/user/frontend

git init 2>/dev/null || true
git add .
git commit -m "Ospoly Market Frontend - Production Ready"

echo ""
echo "=========================================="
echo "   ✅ CODE PREPARED FOR DEPLOYMENT!"
echo "=========================================="
echo ""
echo "NEXT STEPS:"
echo "1. Go to https://github.com"
echo "2. Create 2 repos: ospoly-market-backend & ospoly-market-frontend"
echo "3. Push your code using commands below"
echo ""
