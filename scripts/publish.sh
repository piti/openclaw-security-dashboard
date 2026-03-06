#!/bin/bash
set -e

VERSION=$(node -p "require('./package.json').version")
TAG="v$VERSION"

echo "Publishing openclaw-security-dashboard $TAG"
echo ""

# Ensure we're on main and clean
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
  echo "ERROR: Must be on main branch (currently on $BRANCH)"
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "ERROR: Working directory not clean. Commit or stash changes first."
  exit 1
fi

# Check if tag already exists
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "ERROR: Tag $TAG already exists. Bump version first."
  exit 1
fi

# Tag
echo "Tagging $TAG..."
git tag -a "$TAG" -m "$TAG"
git push origin "$TAG"

# Publish to npm
echo "Publishing to npm..."
npm publish

# Create GitHub release
echo "Creating GitHub release..."
gh release create "$TAG" --title "$TAG" --generate-notes

echo ""
echo "Published $TAG to npm + GitHub"
echo "  npm: https://www.npmjs.com/package/openclaw-security-dashboard"
echo "  GitHub: https://github.com/piti/openclaw-security-dashboard/releases/tag/$TAG"
