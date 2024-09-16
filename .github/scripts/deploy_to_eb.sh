#!/bin/bash

TAG_NAME=$(cat "tag_name.txt")
ENVIRONMENT=$1
APPLICATION=$2
AWS_REGION=$3
ECR_REGISTRY=$4
ECR_IMAGE="${ECR_REGISTRY}:${TAG_NAME}"

set -e

pip install --upgrade awsebcli --no-warn-script-location
eb init -p Docker -r $AWS_REGION $APPLICATION
eb use $ENVIRONMENT
export IMAGE=$ECR_IMAGE && envsubst < docker-compose.yaml > tmp.yaml && mv tmp.yaml docker-compose.yaml
git add docker-compose.yaml
eb deploy --staged