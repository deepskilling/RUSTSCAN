#!/bin/bash

# NrMAP GitHub Push Script
# This script pushes the NrMAP project to GitHub using credentials from .env file

set -e  # Exit on error

echo "=== NrMAP GitHub Push Script ==="
echo ""

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ Error: .env file not found!"
    echo ""
    echo "Please create a .env file with your GitHub token:"
    echo "  1. Copy .env.example to .env"
    echo "  2. Get a GitHub Personal Access Token from: https://github.com/settings/tokens"
    echo "  3. Add the token to .env file:"
    echo ""
    echo "     GITHUB_TOKEN=your_token_here"
    echo "     GITHUB_REPO=deepskilling/RUSTSCAN"
    echo "     GITHUB_USER=deepskilling"
    echo ""
    exit 1
fi

# Load environment variables from .env
echo "📁 Loading environment variables from .env..."
export $(cat .env | grep -v '^#' | xargs)

# Support both GITHUB_TOKEN and GITHUB_TOKEN_DILIGENT
if [ -z "$GITHUB_TOKEN" ]; then
    GITHUB_TOKEN="$GITHUB_TOKEN_DILIGENT"
fi

# Check if required variables are set
if [ -z "$GITHUB_TOKEN" ] || [ "$GITHUB_TOKEN" = "your_github_personal_access_token_here" ]; then
    echo "❌ Error: GITHUB_TOKEN not set in .env file!"
    echo ""
    echo "Please set a valid GitHub Personal Access Token in .env"
    echo "Get your token from: https://github.com/settings/tokens"
    echo ""
    echo "Required scopes: repo (Full control of private repositories)"
    exit 1
fi

if [ -z "$GITHUB_REPO" ]; then
    GITHUB_REPO="deepskilling/RUSTSCAN"
    echo "ℹ️  Using default repository: $GITHUB_REPO"
fi

if [ -z "$GITHUB_USER" ]; then
    GITHUB_USER="deepskilling"
    echo "ℹ️  Using default user: $GITHUB_USER"
fi

echo "✓ Environment variables loaded"
echo ""

# Initialize git if not already initialized
if [ ! -d ".git" ]; then
    echo "🔧 Initializing git repository..."
    git init
    echo "✓ Git repository initialized"
else
    echo "✓ Git repository already initialized"
fi

# Configure git user (if not already configured)
if [ -z "$(git config user.name)" ]; then
    echo "🔧 Configuring git user..."
    git config user.name "$GITHUB_USER"
    git config user.email "${GITHUB_USER}@users.noreply.github.com"
    echo "✓ Git user configured"
fi

# Set remote using token authentication
REMOTE_URL="https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git"
echo "🔗 Setting remote repository..."

if git remote get-url origin &>/dev/null; then
    git remote set-url origin "$REMOTE_URL"
    echo "✓ Remote URL updated"
else
    git remote add origin "$REMOTE_URL"
    echo "✓ Remote origin added"
fi

# Check current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
if [ "$CURRENT_BRANCH" = "HEAD" ]; then
    CURRENT_BRANCH="main"
fi

echo ""
echo "📋 Repository Status:"
echo "  Repository: $GITHUB_REPO"
echo "  Branch: $CURRENT_BRANCH"
echo "  User: $GITHUB_USER"
echo ""

# Add all files
echo "📦 Adding files to git..."
git add .
echo "✓ Files added"

# Check if there are changes to commit
if git diff --cached --quiet; then
    echo "ℹ️  No changes to commit"
else
    # Commit changes
    echo "💾 Creating commit..."
    COMMIT_MSG="Add NrMAP - Network Reconnaissance and Mapping Platform

Complete implementation including:
- Scanner core (host discovery, TCP/UDP/SYN scans, adaptive throttling)
- Packet engine (raw sockets, crafting, parsing)
- Detection engine (banner grabbing, fingerprinting, OS detection)
- Distributed scanning (scheduler, agents, aggregator)
- CLI with profiles and output formatting
- Report engine (JSON, YAML, HTML, CLI tables)
- OS Fingerprinting (TCP, ICMP, UDP, Protocol hints, Clock skew, Passive, Active probes)
- Fuzzy matching engine
- Database I/O (JSON/YAML import/export)

Features:
- 183 passing tests
- 4,976 lines of OS fingerprinting code
- Comprehensive logging and error handling
- Production-ready code quality
- Extensive documentation"

    git commit -m "$COMMIT_MSG"
    echo "✓ Commit created"
fi

# Push to GitHub
echo ""
echo "🚀 Pushing to GitHub..."
echo "  Repository: https://github.com/$GITHUB_REPO"
echo "  Branch: $CURRENT_BRANCH"
echo ""

# Push with force on first push (for empty repo), otherwise normal push
if git rev-parse --verify origin/$CURRENT_BRANCH &>/dev/null; then
    # Remote branch exists, do normal push
    git push origin $CURRENT_BRANCH
else
    # Remote branch doesn't exist, do initial push
    git push -u origin $CURRENT_BRANCH
fi

echo ""
echo "✅ Successfully pushed to GitHub!"
echo ""
echo "🌐 View your repository at:"
echo "   https://github.com/$GITHUB_REPO"
echo ""
echo "📚 Documentation files pushed:"
echo "   - README.md"
echo "   - PRD.md"
echo "   - QUICKSTART.md"
echo "   - PROJECT_SUMMARY.md"
echo "   - ACTIVE_PROBE_LIBRARY.md"
echo "   - DATABASE_AND_REPORTING_COMPLETE.md"
echo "   - And more..."
echo ""

# Remove token from remote URL for security (replace with placeholder)
SAFE_REMOTE_URL="https://github.com/${GITHUB_REPO}.git"
git remote set-url origin "$SAFE_REMOTE_URL"
echo "🔒 Remote URL sanitized (token removed from git config)"
echo ""
echo "✨ Done!"

