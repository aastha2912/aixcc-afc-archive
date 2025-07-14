#!/usr/bin/env bash

cd "$(dirname "$0")"

echo "running with args: $PYTEST_ARGS"

if [ ! -d "./projects" ]; then
  echo "projects/ directory does not exist - you may want to mount them into the container"
  exit 1
fi

# Loop until 'docker info' succeeds
while ! docker info >/dev/null 2>&1; do
  echo "Waiting for Docker to be available at $DOCKER_HOST..."
  sleep 1
done

bash -c "source .venv/bin/activate && python -m pytest $PYTEST_ARGS"
