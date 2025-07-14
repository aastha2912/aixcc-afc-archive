#!/usr/bin/env bash

# 1. Check for the existence of .git directory
if [ ! -d ".git" ]; then
  echo "Warning: No .git directory found in the current working directory."
  exit 0
fi

PACK_DIR=".git/objects/pack"

# If there are no packfiles, nothing to do.
if [ ! -d "$PACK_DIR" ]; then
  echo "No .git/objects/pack directory found. Nothing to unpack."
  exit 0
fi

# Create a temporary directory to move pack files out of .git/objects/pack
TMP_DIR="$(mktemp -d)"

# 2. Move any .pack files to a temporary directory
shopt -s nullglob
packfiles=( "$PACK_DIR"/*.pack )
if [ ${#packfiles[@]} -eq 0 ]; then
  echo "No .pack files found in $PACK_DIR. Nothing to unpack."
  exit 0
fi

echo "Moving packfiles to temporary directory..."
for packfile in "${packfiles[@]}"; do
  mv "$packfile" "$TMP_DIR/"
done
shopt -u nullglob

# 3. Unpack each packfile using git unpack-objects
for packfile in $TMP_DIR/*.pack; do
  echo "Unpacking $packfile..."
  git unpack-objects < "$packfile"
done

# 4. Clean up (optional)
echo "Cleaning up temporary directory..."
rm -rf "$TMP_DIR"