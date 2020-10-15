#!/#!/usr/bin/env bash

COMMIT_SHA_SHORT=$(git rev-parse --short HEAD)

DOCKER_BUILDKIT=1 docker build --network=host -f dockerfiles/apim/Dockerfile -t smartcommunitylab/wso2am:2.6.0-${COMMIT_SHA_SHORT} -t smartcommunitylab/wso2am:2.6.0-latest . && \
docker push smartcommunitylab/wso2am:2.6.0-${COMMIT_SHA_SHORT} && \
docker push smartcommunitylab/wso2am:2.6.0-latest
