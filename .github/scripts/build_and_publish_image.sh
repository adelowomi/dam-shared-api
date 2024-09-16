#!/bin/bash

set -e
ECR_REGISTRY=$1
BRANCH_NAME=${GITHUB_REF#refs/heads/}
HASH=$(git rev-parse --short "$GITHUB_SHA")
TAG_NAME="${HASH}_${BRANCH_NAME}"
echo ${TAG_NAME}

docker build -t asset-mgt-fe:"${TAG_NAME}" .
docker tag asset-mgt-fe:"${TAG_NAME}" ${ECR_REGISTRY}:"${TAG_NAME}"
docker push ${ECR_REGISTRY}:"${TAG_NAME}"
mkdir -p workspace
echo "${TAG_NAME}" > workspace/tag_name.txt
