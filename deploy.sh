#!/bin/bash
# Quick deployment script for Telnyx Webhook to Vercel

set -e

echo "🚀 Telnyx Webhook Deployment Script"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if git is initialized
if [ ! -d .git ]; then
    echo -e "${YELLOW}Initializing git repository...${NC}"
    git init
fi

# Check for .env file
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file from template...${NC}"
    cp .env.example .env
    echo -e "${RED}⚠️  Please edit .env and add your actual API keys before deploying!${NC}"
    echo ""
fi

# Install dependencies if needed
if [ ! -d node_modules ]; then
    echo "Installing dependencies..."
    npm install
fi

# Add all files
echo "Staging files..."
git add .

# Check if there are changes to commit
if git diff --cached --quiet; then
    echo -e "${YELLOW}No changes to commit${NC}"
else
    echo "Enter commit message (or press Enter for default):"
    read -r commit_msg
    if [ -z "$commit_msg" ]; then
        commit_msg="Update Telnyx webhook configuration $(date '+%Y-%m-%d %H:%M:%S')"
    fi
    git commit -m "$commit_msg"
fi

# Push to GitHub
echo ""
echo -e "${GREEN}Pushing to GitHub...${NC}"
read -p "Enter your GitHub repository URL (or press Enter to skip push): " repo_url
if [ -n "$repo_url" ]; then
    git remote add origin "$repo_url" 2>/dev/null || true
    git branch -M main
    git push -u origin main
fi

echo ""
echo -e "${GREEN}✅ Deployment preparation complete!${NC}"
echo ""
echo "📋 Next Steps:"
echo "1. Edit .env with your actual API keys"
echo "2. Push to GitHub (done if you entered URL above)"
echo "3. Go to https://vercel.com and import your repository"
echo "4. Add environment variables in Vercel dashboard"
echo "5. Deploy and configure Telnyx webhook URL"
echo ""
echo -e "${YELLOW}⚠️  Don't forget to set your webhook URL in Telnyx portal after deployment!${NC}"
