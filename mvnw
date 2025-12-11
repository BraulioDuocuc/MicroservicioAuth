#!/bin/sh
set -e
BASE_DIR="$(cd "$(dirname "$0")"; pwd)"
WRAPPER_DIR="$BASE_DIR/.mvn/wrapper"
DIST_URL="https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip"
TMP_DIR="$WRAPPER_DIR/d"
mkdir -p "$TMP_DIR"
ZIP_PATH="$TMP_DIR/maven.zip"
curl -fsSL "$DIST_URL" -o "$ZIP_PATH"
unzip -qo "$ZIP_PATH" -d "$TMP_DIR"
MVN_HOME=$(find "$TMP_DIR" -maxdepth 1 -type d -name 'apache-maven-*' | head -n 1)
exec "$MVN_HOME/bin/mvn" "$@"
