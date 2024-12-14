#!/bin/bash
# Define repository URLs
XRPL_REPO="https://github.com/XRPLF/rippled.git" 
OSSEC_REPO="https://github.com/ossec/ossec-hids.git"

# Define target directories
TARGET_DIR_XRPL="xrpl-dev-portal"
TARGET_DIR_OSSEC="ossec-hids"

# Function to clone or pull a repository
clone_or_pull() {
  local REPO_URL=$1
  local TARGET_DIR=$2

  if [ -d "$TARGET_DIR" ]; then
    echo "Directory $TARGET_DIR exists. Pulling latest changes..."
    cd "$TARGET_DIR"
    git pull || { echo "Failed to pull latest changes for $TARGET_DIR"; exit 1; }
    cd ..
  else
    echo "Cloning repository $REPO_URL into $TARGET_DIR..."
    git clone "$REPO_URL" "$TARGET_DIR" || { echo "Failed to clone $REPO_URL"; exit 1; }
  fi
}

# Clone or pull XRPL repository
clone_or_pull "$XRPL_REPO" "$TARGET_DIR_XRPL"

# Clone or pull OSSEC repository
clone_or_pull "$OSSEC_REPO" "$TARGET_DIR_OSSEC"

echo "Repositories updated successfully."

