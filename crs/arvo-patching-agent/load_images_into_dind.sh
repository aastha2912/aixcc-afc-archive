#!/usr/bin/env bash
set -euo pipefail

# Load prebuilt images from the *host* Docker daemon into the CRS DinD daemon.
#
# Why: The CRS stack uses DOCKER_HOST=tcp://docker-daemon:2375, which means CRS
# sees images stored inside the DinD daemon, not the host daemon.
#
# Usage:
#   crs/arvo-patching-agent/load_images_into_dind.sh 10084 20061
#   crs/arvo-patching-agent/load_images_into_dind.sh --file crs/arvo-patching-agent/ids.csv
#
# Notes:
# - Images are expected to be tagged as: vulpatch:<id>-vul
# - This is safe to rerun: it skips images already present in DinD.

IMAGE_PREFIX="${IMAGE_PREFIX:-vulpatch}"
IMAGE_SUFFIX="${IMAGE_SUFFIX:--vul}"

usage() {
  echo "Usage:"
  echo "  $0 <id> [id ...]"
  echo "  $0 --file <ids.csv|ids.txt>"
  echo
  echo "Env:"
  echo "  IMAGE_PREFIX (default: vulpatch)"
  echo "  IMAGE_SUFFIX (default: -vul)"
}

ids=()

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

if [[ "${1:-}" == "--file" ]]; then
  file="${2:-}"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo "ERROR: missing/invalid --file path: $file" >&2
    exit 2
  fi
  while IFS= read -r line; do
    line="${line//[$'\r\n\t ']/}"
    [[ -z "$line" || "$line" == "id" ]] && continue
    ids+=("$line")
  done < "$file"
else
  ids=("$@")
fi

if [[ ${#ids[@]} -eq 0 ]]; then
  echo "No IDs provided." >&2
  exit 2
fi

for id in "${ids[@]}"; do
  img="${IMAGE_PREFIX}:${id}${IMAGE_SUFFIX}"
  echo "==> Ensuring image in DinD: $img"

  if docker compose exec -T docker-daemon docker image inspect "$img" >/dev/null 2>&1; then
    echo "    already present in DinD"
    continue
  fi

  # Ensure host has it
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    echo "    ERROR: host daemon missing image: $img" >&2
    echo "    (tag it appropriately or docker load it on host first)" >&2
    exit 1
  fi

  echo "    loading host -> DinD (docker save | docker load)"
  docker save "$img" | docker compose exec -T docker-daemon docker load >/dev/null
  echo "    loaded"
done

echo "Done."

