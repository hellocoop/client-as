#!/bin/bash

# Check if jq is installed
if ! command -v jq &> /dev/null
then
    echo "jq could not be found. Please install jq to continue."
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    echo "Docker could not be found. Please install Docker to continue."
    exit 1
fi

# Check for Docker Buildx support
if ! command -v docker buildx &> /dev/null
then
    echo "Docker Buildx is not available. Please ensure you have Docker 19.03 or later installed."
    exit 1
fi

# Check if Buildx supports multi-platform builds
BUILDX_CHECK=$(docker buildx inspect --bootstrap)
if ! echo "$BUILDX_CHECK" | grep "Platforms:" &> /dev/null; then
    echo "Docker Buildx does not support multi-platform builds. Please configure a Buildx builder with multi-platform support."
    exit 1
fi

# Check if the repository is clean (no uncommitted changes)
if ! git diff-index --quiet HEAD --; then
    echo "The repository has uncommitted changes. Please commit or stash them before proceeding."
    exit 1
fi

# Extract version from package.json using jq
VERSION=$(jq -r '.version' package.json)

# Docker details
DOCKER_USERNAME="hellocoop"  
DOCKER_IMAGE_NAME="client-as"  
DOCKER_TAG="$DOCKER_USERNAME/$DOCKER_IMAGE_NAME"


# Get the latest published version of the Docker image
PUBLISHED_VERSION=$(curl -s "https://hub.docker.com/v2/repositories/${DOCKER_TAG}/tags/?page_size=1" | jq -r '.results[0].name')
echo "Latest published version: $PUBLISHED_VERSION"

# Compare the versions
if [ "$VERSION" = "$PUBLISHED_VERSION" ]; then
    echo "Current version is the same as the published version. Incrementing the version."

    # Increment the version using npm version patch
    npm version patch

    # Update VERSION variable to new version
    VERSION=$(jq -r '.version' package.json)

    echo "New version: $VERSION"

    # Commit and push the changes to the repository
    git add package.json
    git commit -m "Increment version to $VERSION"
    git push origin main

    echo "Updated package.json has been pushed to the repository."
fi

# Building Docker image
echo "Building Docker amd64 and arm64 image with tag: $VERSION and pushing to Docker Hub"
docker buildx build --platform linux/amd64,linux/arm64 -t "$DOCKER_TAG:latest" -t "$DOCKER_TAG:$VERSION" . --push

# Pushing the image to Docker Hub
echo "Pushing latest tag to Docker Hub"
docker push "$DOCKER_TAG:latest"

echo "Pushing version $VERSION tag to Docker Hub"
docker push "$DOCKER_TAG:$VERSION"

