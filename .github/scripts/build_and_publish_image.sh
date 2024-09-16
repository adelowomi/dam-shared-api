#!/bin/bash

set -e
BRANCH_NAME=${GITHUB_REF#refs/heads/}
HASH=$(git rev-parse --short "$GITHUB_SHA")
TAG_NAME="${HASH}_${BRANCH_NAME}"
echo ${TAG_NAME}

docker build -t asset-mgt-fe:"${TAG_NAME}" .
docker tag asset-mgt-fe:"${TAG_NAME}" 963850480156.dkr.ecr.eu-west-2.amazonaws.com/asset-mgt-fe:"${TAG_NAME}"
docker push 963850480156.dkr.ecr.eu-west-2.amazonaws.com/asset-mgt-fe:"${TAG_NAME}"
mkdir -p workspace
echo "${TAG_NAME}" > workspace/tag_name.txt
