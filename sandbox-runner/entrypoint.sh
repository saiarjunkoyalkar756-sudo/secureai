#!/bin/bash
LANGUAGE=$1
CODE_FILE=$2
TIMEOUT=${3:-30}

case $LANGUAGE in
  python3.11)
    timeout $TIMEOUT python3 "$CODE_FILE"
    ;;
  node20)
    timeout $TIMEOUT node "$CODE_FILE"
    ;;
  go1.21)
    timeout $TIMEOUT /usr/local/go/bin/go run "$CODE_FILE"
    ;;
  bash)
    timeout $TIMEOUT bash "$CODE_FILE"
    ;;
  *)
    echo "Unknown language: $LANGUAGE"
    exit 1
    ;;
esac
