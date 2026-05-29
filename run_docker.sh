#!/usr/bin/env bash

set -euo pipefail

IMAGE_NAME="${1:-vul4j:local}"

docker run -d -it \
  --platform linux/amd64 \
  --name vul4j \
  "${IMAGE_NAME}"
